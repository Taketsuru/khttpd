/*-
 * Copyright (c) 2016 Taketsuru <taketsuru11@gmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/un.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>

#include <vm/uma.h>

#include <netinet/in.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* ------------------------------------------------------- type definitions */

enum {
	KHTTPD_LOG_DEBUG,
	KHTTPD_LOG_ERROR,
	KHTTPD_LOG_ACCESS,

	KHTTPD_LOG_END
};

/* possible values of khttpd_state */
enum {
	/* the server process has not finished its initialization yet */
	KHTTPD_LOADING = 0,

	/* the server process is exiting. */
	KHTTPD_UNLOADING,

	/* failed to initialize and the requester has not noticed it yet. */
	KHTTPD_FAILED,

	/* the server is ready to serve http requests.	*/
	KHTTPD_READY,
};

/* possible values of khttpd_logger_state */
enum {
	/* not ready yet. */
	KHTTPD_LOGGER_INITIALIZING = 0,

	/* waiting for a log entry. */
	KHTTPD_LOGGER_IDLE,

	/* processing a log entry. */
	KHTTPD_LOGGER_BUSY,

	/* suspend request is not acknowledged yet */
	KHTTPD_LOGGER_SUSPENDING,

	/* the logger is pausing. */
	KHTTPD_LOGGER_SUSPENDED,

	/* termination request is not acknowledged yet */
	KHTTPD_LOGGER_EXITING,

	/* the logger thread has exited. */
	KHTTPD_LOGGER_EXITED,

};

struct khttpd_log {
	int		fd;
	int		in_flight_count;
	boolean_t	waiting;
};

struct khttpd_log_entry {
	struct bintime		timestamp;
	struct khttpd_log	*target;
	union {
		struct {
			lwpid_t		tid;
			const char	*func;
		} debug;
		struct {
			int	severity;
		} error;
		struct {
			struct khttpd_socket *socket;
			struct khttpd_request *request;
		} access;
	};
	char			type;
};

struct khttpd_command;

struct khttpd_command {
	STAILQ_ENTRY(khttpd_command) link;
	khttpd_command_proc_t command;
	void		*argument;
	int		status;
};

STAILQ_HEAD(khttpd_command_list, khttpd_command);

struct khttpd_kevent_args {
	const struct kevent *changelist;
	struct kevent	    *eventlist;
};

typedef void (*khttpd_handle_event_t)(struct kevent *);

struct khttpd_event_type {
	khttpd_handle_event_t handle_event;
};

struct khttpd_server_port {
	/* must be &event_type == &<this struct> */
	struct khttpd_event_type	event_type;
	SLIST_ENTRY(khttpd_server_port)	link;
	struct khttpd_server		*server;
	int				fd;
};

SLIST_HEAD(khttpd_server_port_list, khttpd_server_port);

typedef int (*khttpd_receive_t)(struct khttpd_socket *);

struct khttpd_socket {
	/* must be &event_type == &<this struct> */
	struct khttpd_event_type event_type;
	LIST_ENTRY(khttpd_socket) link;
	STAILQ_HEAD(, khttpd_request) xmit_queue;
	struct khttpd_server_port *port;
	cap_rights_t		rights;
	khttpd_receive_t	receive;
	khttpd_transmit_t	transmit;

	/*
	 * Members from khttpd_socket_zctor_begin to khttpd_socket_zctor_end
	 * is cleared by ctor.
	 */
#define khttpd_socket_zctor_begin recv_limit
	off_t			recv_limit;
	struct file		*fp;
	struct mbuf		*recv_leftovers;
	struct mbuf		*recv_ptr;
	struct mbuf		*recv_bol_ptr;
	struct khttpd_request	*recv_request;
	struct mbuf		*recv_tail;
	struct mbuf		*xmit_buf;
	u_int			recv_off;
	u_int			recv_bol_off;
	unsigned		in_sockets_list:1;
	unsigned		recv_found_bol:1;
	unsigned		recv_eof:1;
	unsigned		recv_drain:1;
	unsigned		xmit_busy:1;

#define khttpd_socket_zctor_end	peer_addr
	struct sockaddr_storage peer_addr;
	int		fd;
	u_int		refcount;
};

LIST_HEAD(khttpd_socket_list, khttpd_socket);

struct khttpd_request {
	STAILQ_ENTRY(khttpd_request) link;
	struct sbuf		target;
	khttpd_request_dtor_t	dtor;
	khttpd_received_body_t	received_body;
	khttpd_end_of_message_t	end_of_message;

	/*
	 * Members from khttpd_request_zctor_begin to khttpd_request_zctor_end
	 * is cleared by ctor.
	 */
#define khttpd_request_zctor_begin	content_length
	off_t			content_length;
	off_t			payload_size;
	struct khttpd_mbuf_pos	header;
	struct mbuf		*request_line;
	struct mbuf		*trailer;
	struct khttpd_response	*response;
	struct khttpd_route	*route;
	void		*data;
	const char	*query;
	const char	*suffix;
	u_int		transfer_encoding_count;
	unsigned	may_respond:1;
	unsigned	has_content_length:1;
	unsigned	has_transfer_encoding:1;
	unsigned	transfer_encoding_chunked:1;
	unsigned	receiving_chunk_and_trailer:1;
	unsigned	continue_response:1;
	unsigned	close:1;
	char		method;
	char		version_minor;

#define khttpd_request_zctor_end	ref_count
	u_int		ref_count;
	char		method_name[24];
};

struct khttpd_response {
	/*
	 * Members from khttpd_response_zctor_begin to
	 * khttpd_response_zctor_end is cleared by ctor.
	 */
#define khttpd_response_zctor_begin content_length
	off_t		content_length;
	off_t		payload_size;
	khttpd_transmit_t transmit_body;
	struct mbuf	*header;
	struct mbuf	*trailer;
	struct mbuf	*body;
	u_int		body_refcnt;
	unsigned	has_content_length:1;
	unsigned	has_transfer_encoding:1;
	unsigned	transfer_encoding_chunked:1;
	unsigned	header_closed:1;
	unsigned	close:1;
	short		status;

#define khttpd_response_zctor_end version_minor
	char		version_minor;
};

struct khttpd_route;
SPLAY_HEAD(khttpd_route_tree, khttpd_route);
LIST_HEAD(khttpd_route_list, khttpd_route);

struct khttpd_route {
	LIST_ENTRY(khttpd_route)	children_link;
	SPLAY_ENTRY(khttpd_route)	children_node;
	struct khttpd_route_tree	children_tree;
	struct khttpd_route_list	children_list;
	khttpd_route_dtor_t		dtor;
	struct khttpd_route_type	*type;
	struct khttpd_route		*parent;
	const char	*label;
	const char	*path;
	void		*data;
	u_int		refcount;
	int		label_len;
};

struct khttpd_server {
	SLIST_ENTRY(khttpd_server)	link;
	struct khttpd_log		access_log;
	struct khttpd_log		error_log;
	struct khttpd_server_port_list	ports;
	struct cdev			*dev;
	struct khttpd_route		*route_root;
	const char			*name;
};

SLIST_HEAD(khttpd_server_list, khttpd_server);

struct khttpd_label {
	const char	*name;
	int		id;
	SLIST_ENTRY(khttpd_label) link;
};

SLIST_HEAD(khttpd_label_list, khttpd_label);

struct khttpd_config_proc_args {
	struct khttpd_server	*server;
	struct filedescent	*fdes;
	int			nfdes;
};

/* -------------------------------------------------- prototype declrations */

static int khttpd_route_compare(struct khttpd_route *x,
    struct khttpd_route *y);

static void khttpd_kevent_nop(struct kevent *event);

static int khttpd_transmit_status_line_and_header
    (struct khttpd_socket *socket, struct khttpd_request *request,
	struct khttpd_response *response, struct mbuf **out);

static int khttpd_receive_chunk(struct khttpd_socket *socket);
static int khttpd_receive_body(struct khttpd_socket *socket);
static int khttpd_receive_header_or_trailer(struct khttpd_socket *socket);
static int khttpd_receive_request_line(struct khttpd_socket *socket);

static void khttpd_socket_transmit(struct khttpd_socket *socket);
static void khttpd_handle_socket_event(struct kevent *event);

static void khttpd_asterisc_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request);

static int khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

SPLAY_PROTOTYPE(khttpd_route_tree, khttpd_route, children_node,
    khttpd_route_compare);
SPLAY_GENERATE(khttpd_route_tree, khttpd_route, children_node,
    khttpd_route_compare);

#pragma clang diagnostic pop

/* --------------------------------------------------- variable definitions */

/*
 * module variables
 */

MALLOC_DEFINE(M_KHTTPD, "khttpd", "khttpd buffer");

static struct khttpd_command_list khttpd_command_queue = 
    STAILQ_HEAD_INITIALIZER(khttpd_command_queue);

static struct khttpd_label khttpd_methods[] = {
	{ "ACL" },
	{ "BASELINE-CONTROL" },
	{ "BIND" },
	{ "CHECKIN" },
	{ "CHECKOUT" },
	{ "CONNECT" },
	{ "COPY" },
	{ "DELETE" },
	{ "GET" },
	{ "HEAD" },
	{ "LABEL" },
	{ "LINK" },
	{ "LOCK" },
	{ "MERGE" },
	{ "MKACTIVITY" },
	{ "MKCALENDAR" },
	{ "MKCOL" },
	{ "MKREDIRECTREF" },
	{ "MKWORKSPACE" },
	{ "MOVE" },
	{ "OPTIONS" },
	{ "ORDERPATCH" },
	{ "PATCH" },
	{ "POST" },
	{ "PRI" },
	{ "PROPFIND" },
	{ "PROPPATCH" },
	{ "PUT" },
	{ "REBIND" },
	{ "REPORT" },
	{ "SEARCH" },
	{ "TRACE" },
	{ "UNBIND" },
	{ "UNCHECKOUT" },
	{ "UNLINK" },
	{ "UNLOCK" },
	{ "UPDATE" },
	{ "UPDATEREDIRECTREF" },
	{ "VERSION-CONTROL" },
};

static struct khttpd_label khttpd_fields[] = {
	{ "Content-Length" },
	{ "Transfer-Encoding" },
	{ "Connection" },
#if 0
	{ "Cookie" },
	{ "Expect" },
	{ "Host" },
	{ "Referer" },
	{ "Upgrade" },
	{ "User-Agent" },
	{ "Vary" },
	{ "WWW-Authenticate" },
	{ "If" },
	{ "If-Match" },
	{ "If-Modified-Since" },
	{ "If-None-Match" },
	{ "If-Range" },
	{ "If-Schedule-Tag-Match" },
	{ "If-Unmodified-Since" }
#endif
};

static const char *khttpd_default_mime_type_rules =
    "application/javascript js\n"
    "text/html html htm\n"
    "text/plain txt\n"
    "text/css css\n";

/*
 * This value must be larger than the length of the longest name in
 * khttpd_fields.
 */
#define KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH	32

static struct khttpd_label_list khttpd_method_hash_table[64];
static struct khttpd_label_list khttpd_field_hash_table[16];

static struct mtx khttpd_lock;
struct proc *khttpd_proc;
static struct thread *khttpd_logger_thread;
static struct mbufq khttpd_logger_queue;
static size_t khttpd_message_size_limit = 16384;
static pid_t khttpd_pid;
int khttpd_debug_mask;
static int khttpd_listen_backlog = 128;
static int khttpd_logger_state;
static int khttpd_state;
static int khttpd_server_status;
static boolean_t khttpd_logger_waiting_empty_slot;
static boolean_t khttpd_logger_waiting_state_change;

const char khttpd_crlf[] = { '\r', '\n' };

static struct cdevsw khttpd_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl   = khttpd_ioctl,
	.d_name	   = "khttpd"
};

/*
 * khttpd process-local variables
 */

static struct khttpd_event_type khttpd_stop_request_type = {
	.handle_event = khttpd_kevent_nop
};

static struct khttpd_route_type khttpd_route_type_null = {
	.name = "<no route>",
	.received_header = khttpd_received_header_null,
};

static struct khttpd_route_type khttpd_route_type_asterisc = {
	.name = "asterisc",
	.received_header = khttpd_asterisc_received_header
};

static struct khttpd_socket_list khttpd_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static struct khttpd_server_list khttpd_servers =
    SLIST_HEAD_INITIALIZER(khttpd_server_list);

static uma_zone_t khttpd_route_zone;
static uma_zone_t khttpd_socket_zone;
static uma_zone_t khttpd_request_zone;
static uma_zone_t khttpd_response_zone;
static int khttpd_kqueue;
static struct khttpd_log khttpd_debug_log;

/* --------------------------------------------------- function definitions */

void *khttpd_malloc(size_t size)
{

	return malloc(size, M_KHTTPD, M_WAITOK);
}

void khttpd_free(void *mem)
{

	free(mem, M_KHTTPD);
}

static void khttpd_log_init(struct khttpd_log *log)
{
	log->fd = -1;
	log->in_flight_count = 0;
	log->waiting = FALSE;
}

static void khttpd_log_wait_to_drain(struct khttpd_log *log)
{
	mtx_lock(&khttpd_lock);
	while (0 < log->in_flight_count) {
		log->waiting = TRUE;
		mtx_sleep(&log->in_flight_count, &khttpd_lock, 0,
		    "khttpd-log-flush", 0);
	}
	mtx_unlock(&khttpd_lock);
}

static void khttpd_log_close(struct khttpd_log *log)
{
	khttpd_log_wait_to_drain(log);

	if (log->fd != -1) {
		kern_close(curthread, log->fd);
		log->fd = -1;
	}
}

static void khttpd_log_set_fd(struct khttpd_log *log, int fd)
{
	int old_fd;

	khttpd_log_wait_to_drain(log);

	old_fd = log->fd;
	log->fd = fd;
	if (old_fd != -1)
		kern_close(curthread, old_fd);
}

static struct mbuf *
khttpd_log_entry_alloc(int type, struct khttpd_log_entry **entry,
    struct khttpd_log *log)
{
	struct mbuf *m;
	struct khttpd_log_entry *e;

	m = m_get(M_WAITOK, MT_DATA);
	m_align(m, rounddown2(MLEN, sizeof(void*)));
	m->m_len = sizeof(*e);

	e = mtod(m, struct khttpd_log_entry *);
	e->type = type;
	e->target = log;
	bintime(&e->timestamp);

	return (m);
}

static void
khttpd_log_entry_dtor(struct khttpd_log_entry *entry)
{
	switch (entry->type) {

	case KHTTPD_LOG_ACCESS:
		khttpd_socket_free(entry->access.socket);
		khttpd_request_free(entry->access.request);
		break;

	default:
		break;
	}
}

/*
 * method & field name lookup
 */

static void
khttpd_label_hash_init(struct khttpd_label_list *table,
    int hash_size, struct khttpd_label *labels, int n, boolean_t ncase)
{
	uint32_t h;
	int i, last_id;

	KASSERT((hash_size & -hash_size) == hash_size,
	    ("hash_size=%d", hash_size));

	for (i = 0; i < hash_size; ++i)
		SLIST_INIT(&table[i]);

	last_id = 0;
	for (i = 0; i < n; ++i) {
		if (labels[i].id == 0)
			labels[i].id = ++last_id;
		else
			last_id = labels[i].id;
		h = (ncase ? khttpd_hash32_str_ci : hash32_str)
		    (labels[i].name, 0) & (hash_size - 1);
		SLIST_INSERT_HEAD(&table[h], &labels[i], link);
	}
}

static int
khttpd_label_hash_find(struct khttpd_label_list *table, int hash_size,
    const char *begin, const char *end)
{
	struct khttpd_label *ptr;
	uint32_t h;

	KASSERT((hash_size & -hash_size) == hash_size,
	    ("hash_size=%d", hash_size));

	h = hash32_buf(begin, end - begin, 0) & (hash_size - 1);
	SLIST_FOREACH(ptr, &table[h], link)
		if (strncmp(begin, ptr->name, end - begin) == 0)
			return (ptr->id);

	return (-1);
}

static int
khttpd_label_hash_find_ci(struct khttpd_label_list *table, int hash_size,
    const char *begin, const char *end)
{
	struct khttpd_label *ptr;
	uint32_t h;

	KASSERT((hash_size & -hash_size) == hash_size,
	    ("hash_size=%d", hash_size));

	h = khttpd_hash32_buf_ci(begin, end, 0) & (hash_size - 1);
	SLIST_FOREACH(ptr, &table[h], link)
		if (strncasecmp(begin, ptr->name, end - begin) == 0)
			return (ptr->id);

	return (-1);
}

static int
khttpd_method_find(const char *begin, const char *end)
{
	return (khttpd_label_hash_find(khttpd_method_hash_table,
		sizeof(khttpd_method_hash_table) /
		sizeof(khttpd_method_hash_table[0]), begin, end));
}

static int
khttpd_field_find(const char *begin, const char *end)
{
	return (khttpd_label_hash_find_ci(khttpd_field_hash_table,
		sizeof(khttpd_field_hash_table) /
		sizeof(khttpd_field_hash_table[0]), begin, end));
}

/*
 * kevent
 */

static void
khttpd_kevent_nop(struct kevent *event)
{
	TRACE("enter");
}

static int
khttpd_kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args;
	
	args = arg;
	bcopy(kevp, args->eventlist, count * sizeof(*kevp));
	args->eventlist += count;

	return (0);
}

static int
khttpd_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args;

	args = arg;
	bcopy(args->changelist, kevp, count * sizeof(*kevp));
	args->changelist += count;

	return (0);
}

static int
khttpd_kevent_add_read(int kq, int fd, struct khttpd_event_type *etype)
{

	TRACE("enter %d", fd);

	struct kevent change = {
		.ident	     = fd,
		.filter	     = EVFILT_READ,
		.flags	     = EV_ADD,
		.fflags	     = 0,
		.data	     = 0,
		.udata	     = etype
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_add_read_write(int kq, int fd, struct khttpd_event_type *etype)
{

	TRACE("enter %d", fd);

	struct kevent changes[] = {
		{
			.ident	     = fd,
			.filter	     = EVFILT_READ,
			.flags	     = EV_ADD,
			.fflags	     = 0,
			.data	     = 0,
			.udata	     = etype
		},
		{
			.ident	     = fd,
			.filter	     = EVFILT_WRITE,
			.flags	     = EV_ADD|EV_DISABLE,
			.fflags	     = 0,
			.data	     = 0,
			.udata	     = etype
		}
	};

	struct khttpd_kevent_args args = {
		.changelist = changes,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq,
		sizeof(changes) / sizeof(changes[0]), 0, &k_ops, NULL));
}

static int
khttpd_kevent_enable_write(int kq, int fd, boolean_t enable,
    struct khttpd_event_type *etype)
{

	TRACE("enter %d %d", fd, enable);

	struct kevent change = {
		.ident	= fd,
		.filter	= EVFILT_WRITE,
		.flags	= enable ? EV_ENABLE : EV_DISABLE,
		.fflags	= 0,
		.udata	= etype
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_delete_read(int kq, int fd)
{

	TRACE("enter %d", fd);

	struct kevent change = {
		.ident	= fd,
		.filter	= EVFILT_READ,
		.flags	= EV_DELETE,
		.fflags	= 0,
		.data	= 0,
		.udata	= NULL
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_add_signal(int kq, int signo, struct khttpd_event_type *etype)
{

	TRACE("enter");

	struct kevent change = {
		.ident	= signo,
		.filter = EVFILT_SIGNAL,
		.flags	= EV_ADD,
		.fflags = 0,
		.data	= 0,
		.udata	= &khttpd_stop_request_type
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL,
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_get(int kq, struct kevent *event)
{
	int error;

	TRACE("enter");

	struct khttpd_kevent_args args = {
		.changelist = NULL,
		.eventlist  = event
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	error = kern_kevent(curthread, kq, 0, 1, &k_ops, NULL);

	if (error == 0 && curthread->td_retval[0] == 0)
		error = ETIMEDOUT;

	return (error);
}

/*
 * route
 */

static void
khttpd_route_dtor_null(struct khttpd_route *route)
{
}

static int
khttpd_route_init(void *mem, int size, int flags)
{
	struct khttpd_route *route;

	route = mem;
	LIST_INIT(&route->children_list);
	SPLAY_INIT(&route->children_tree);

	return (0);
}

static int
khttpd_route_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_route *route;

	TRACE("enter %p", mem);

	route = mem;
	route->dtor = khttpd_route_dtor_null;
	route->type = arg;
	route->data = NULL;
	route->refcount = 1;

	return (0);
}

static void
khttpd_route_dtor(void *mem, int size, void *arg)
{
	struct khttpd_route *route;

	route = mem;

	TRACE("enter %p", mem);

	KASSERT(route->refcount == 0,
	    ("%p->refcount == %d", route, route->refcount));
	KASSERT(SPLAY_EMPTY(&route->children_tree),
	    ("%p->children_tree not empty", route));
	KASSERT(LIST_EMPTY(&route->children_list),
	    ("%p->children_list not empty", route));
	route->dtor(route);
}

static void
khttpd_route_hold(struct khttpd_route *route)
{

	++route->refcount;
}

static void
khttpd_route_free(struct khttpd_route *route)
{

	if (route != NULL && --route->refcount == 0)
		uma_zfree(khttpd_route_zone, route);
}

static int
khttpd_route_compare(struct khttpd_route *x, struct khttpd_route *y)
{
	int len, result;

	len = MIN(x->label_len, y->label_len);
	result = strncmp(x->label, y->label, len);
	return (result != 0 ? result : x->label_len - y->label_len);
}

struct khttpd_route *
khttpd_route_find(struct khttpd_route *root,
    const char *target, const char **suffix)
{
	struct khttpd_route key;
	struct khttpd_route *ptr, *parent;
	const char *cp, *end;

	TRACE("enter %s", target);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	parent = root;
	cp = target;
	end = target + strlen(cp);
	while (!SPLAY_EMPTY(&parent->children_tree)) {
		key.label = cp;
		key.label_len = end - cp;
		ptr = SPLAY_FIND(khttpd_route_tree, &parent->children_tree,
		    &key);
		if (ptr != NULL) {
			TRACE("hit %s", ptr->path);
			if (suffix != NULL)
				*suffix = end;
			return (ptr);
		}

		ptr = SPLAY_ROOT(&parent->children_tree);
		if (0 < khttpd_route_compare(ptr, &key))
			ptr = LIST_PREV(ptr, &parent->children_list,
			    khttpd_route, children_link);

		if (ptr == NULL ||
		    strncmp(ptr->label, cp, ptr->label_len) != 0 ||
		    (cp + ptr->label_len < end && cp[ptr->label_len] != '/'))
			break;

		parent = ptr;
		cp += ptr->label_len;
	}

	if (parent == root)
		return (NULL);

	if (suffix != NULL)
		*suffix = cp;

	return (parent);
}

int
khttpd_route_add(struct khttpd_route *root, const char *path,
    struct khttpd_route_type *type)
{
	struct khttpd_route key;
	struct khttpd_route *next, *parent, *ptr, *prev, *route;
	const char *lbegin, *lend;
	size_t len;

	TRACE("enter %s", path);

	if (type->received_header == NULL)
		type->received_header = khttpd_received_header_null;

	route = uma_zalloc_arg(khttpd_route_zone, type, M_WAITOK);
	lbegin = route->path = path;
	len = strlen(lbegin);
	lend = lbegin + len;
	route->label = lbegin;
	route->label_len = len;

	parent = root;

	for (;;) {
		if (SPLAY_EMPTY(&parent->children_tree)) {
			LIST_INSERT_HEAD(&parent->children_list,
			    route, children_link);
			break;
		}

		len = lend - lbegin;
		key.label = lbegin;
		key.label_len = len;
		ptr = SPLAY_FIND(khttpd_route_tree, &parent->children_tree,
		    &key);
		if (ptr == NULL) {
			ptr = SPLAY_ROOT(&parent->children_tree);
			if (0 < khttpd_route_compare(ptr, &key))
				ptr = LIST_PREV(ptr, &parent->children_list,
				    khttpd_route, children_link);

			if (ptr == NULL ||
			    strncmp
				(ptr->label, lbegin, ptr->label_len) != 0 ||
			    (lbegin + ptr->label_len < lend &&
				lbegin[ptr->label_len] != '/')) {
				if (ptr == NULL)
					LIST_INSERT_HEAD
					    (&parent->children_list,
						route, children_link);
				else
					LIST_INSERT_AFTER(ptr, route,
					    children_link);

				for (ptr = LIST_NEXT(route, children_link),
					 prev = NULL;
				     ptr != NULL &&
					 strncmp
					     (ptr->label, lbegin, len) == 0;
				     prev = ptr, ptr = next) {
					next = LIST_NEXT(ptr, children_link);

					SPLAY_REMOVE(khttpd_route_tree,
					    &parent->children_tree, ptr);
					LIST_REMOVE(ptr, children_link);

					ptr->parent = route;
					ptr->label += len;
					ptr->label_len -= len;

					SPLAY_INSERT(khttpd_route_tree,
					    &route->children_tree, ptr);
					if (prev != NULL)
						LIST_INSERT_AFTER(prev, ptr,
						    children_link);
					else
						LIST_INSERT_HEAD
						    (&route->children_list,
						     ptr, children_link);
					prev = ptr;
				}

				break;
			}
		}

		lbegin += len;

		if (lbegin == lend) {
			khttpd_route_free(route);
			return (EEXIST);
		}

		parent = ptr;
	}

	route->parent = parent;
	SPLAY_INSERT(khttpd_route_tree, &parent->children_tree, route);

	return (0);
}

void
khttpd_route_remove(struct khttpd_route *route)
{
	struct khttpd_route *parent, *ptr;
	size_t len;

	TRACE("enter %s", route->path);

	len = route->label_len;
	parent = route->parent;
	SPLAY_REMOVE(khttpd_route_tree, &parent->children_tree, route);

	SPLAY_INIT(&route->children_tree);
	while ((ptr = LIST_FIRST(&route->children_list)) != NULL) {
		LIST_REMOVE(ptr, children_link);

		ptr->parent = parent;
		ptr->label -= len;
		ptr->label_len += len;

		SPLAY_INSERT(khttpd_route_tree, &parent->children_tree, ptr);
		LIST_INSERT_AFTER(route, ptr, children_link);
	}

	LIST_REMOVE(route, children_link);

	khttpd_route_free(route);
}

static void
khttpd_route_clear_all(struct khttpd_route *root)
{
	struct khttpd_route *parent, *ptr;

	TRACE("enter");

	SPLAY_INIT(&root->children_tree);
	parent = root;
	for (;;) {
		if ((ptr = LIST_FIRST(&parent->children_list)) != NULL) {
			SPLAY_INIT(&ptr->children_tree);
			LIST_REMOVE(ptr, children_link);
			parent = ptr;
			continue;
		}

		ptr = parent;
		parent = ptr->parent;
		if (parent == NULL)
			break;

		khttpd_route_free(ptr);
	}
}

void khttpd_route_set_data(struct khttpd_route *route, void *data,
    khttpd_route_dtor_t dtor)
{

	if (route->data != NULL)
		route->dtor(route);
	route->data = data;
	route->dtor = dtor != NULL ? dtor : khttpd_route_dtor_null;
}

void *khttpd_route_data(struct khttpd_route *route)
{

	return (route->data);
}

const char *khttpd_route_path(struct khttpd_route *route)
{

	return (route->path);
}

struct khttpd_route_type *khttpd_route_type(struct khttpd_route *route)
{

	return (route->type);
}

/*
 * request
 */

static int
khttpd_request_init(void *mem, int size, int flags)
{
	struct khttpd_request *request;

	request = mem;
	sbuf_new(&request->target, NULL, 32, SBUF_AUTOEXTEND);

	return (0);
}

static void
khttpd_request_fini(void *mem, int size)
{
	struct khttpd_request *request;

	request = mem;
	sbuf_delete(&request->target);
}

static int
khttpd_request_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_request *request;

	request = mem;
	request->dtor = khttpd_request_dtor_null;
	request->received_body = khttpd_received_body_null;
	request->end_of_message = khttpd_end_of_message_null;

	bzero(&request->khttpd_request_zctor_begin, 
	    offsetof(struct khttpd_request, khttpd_request_zctor_end) -
	    offsetof(struct khttpd_request, khttpd_request_zctor_begin));

	request->ref_count = 2;	/* recv_request & xmit_queue */
	request->method_name[0] = '\0';

	return (0);
}

static void
khttpd_request_dtor(void *mem, int size, void *arg)
{
	struct khttpd_request *request;

	request = mem;

	request->dtor(request, request->data);

	sbuf_clear(&request->target);
	m_freem(request->request_line);
	m_freem(request->trailer);
	uma_zfree(khttpd_response_zone, request->response);
	khttpd_route_free(request->route);
}

void khttpd_request_hold(struct khttpd_request *request)
{

	++request->ref_count;
}

void khttpd_request_free(struct khttpd_request *request)
{

	if (request != NULL && --request->ref_count == 0)
		uma_zfree(khttpd_request_zone, request);
}

void
khttpd_request_dtor_null(struct khttpd_request *request, void *data)
{
}

const char *
khttpd_request_target(struct khttpd_request *request)
{

	return (sbuf_data(&request->target));
}

const char *
khttpd_request_suffix(struct khttpd_request *request)
{

	return (request->suffix);
}

void khttpd_request_set_body_proc(struct khttpd_request *request,
    khttpd_received_body_t received_body,
    khttpd_end_of_message_t end_of_message)
{

	request->received_body = received_body;
	request->end_of_message = end_of_message;
}

void
khttpd_request_set_data(struct khttpd_request *request, void *data,
    khttpd_request_dtor_t dtor)
{

	request->data = data;
	request->dtor = dtor;
}

void *
khttpd_request_data(struct khttpd_request *request)
{

	return (request->data);
}

int khttpd_request_method(struct khttpd_request *request)
{

	return (request->method);
}

struct khttpd_route *khttpd_request_route(struct khttpd_request *request)
{

	return (request->route);
}

/*
 * response
 */

static void 
khttpd_response_free_body_extbuf(struct mbuf *m, void *arg1, void *arg2)
{
	void (*func)(void *);

	func = arg1;
	func(arg2);
}

static void 
khttpd_response_free_body_extbuf_null(struct mbuf *m, void *arg1, void *arg2)
{

}

static int
khttpd_response_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_response *response;

	response = mem;
	response->version_minor = 1;

	bzero(&response->khttpd_response_zctor_begin,
	    offsetof(struct khttpd_response, khttpd_response_zctor_end) -
	    offsetof(struct khttpd_response, khttpd_response_zctor_begin));

	return (0);
}

static void
khttpd_response_dtor(void *mem, int size, void *arg)
{
	struct khttpd_response *response;

	response = mem;

	m_freem(response->header);
	m_freem(response->trailer);
	m_freem(response->body);
}

struct khttpd_response *
khttpd_response_alloc(void)
{

	return (uma_zalloc(khttpd_response_zone, M_WAITOK));
}

void
khttpd_response_free(struct khttpd_response *response)
{

	uma_zfree(khttpd_response_zone, response);
}

void khttpd_response_add_field(struct khttpd_response *response,
    const char *field, const char *value_fmt, ...)
{
	va_list vl;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	va_start(vl, value_fmt);
	khttpd_response_vadd_field(response, field, value_fmt, vl);
	va_end(vl);
}

void khttpd_response_vadd_field(struct khttpd_response *response,
    const char *field, const char *value_fmt, va_list vl)
{
	struct mbuf *m;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response->header_closed) {
		if (!response->transfer_encoding_chunked)
			panic("Field %s is added to a closed header.", field);
		m = response->trailer;
		if (m == NULL)
			response->trailer = m = m_gethdr(M_WAITOK, MT_DATA);
	} else {
		m = response->header;
		if (m == NULL)
			response->header = m = m_gethdr(M_WAITOK, MT_DATA);
	}

	khttpd_mbuf_printf(m, "%s: ", field);
	khttpd_mbuf_vprintf(m, value_fmt, vl);
	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));
}

void
khttpd_response_set_status(struct khttpd_response *response, int status)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	KASSERT(response->status == 0, ("status=%d", response->status));
	response->status = status;
}

static void
khttpd_response_set_content_length(struct khttpd_response *response,
    off_t length)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(!response->has_content_length,
	    ("Content-Length has already been set"));

	khttpd_response_add_field(response, "Content-Length", "%jd",
	    (uintmax_t)length);
	response->has_content_length = TRUE;
	response->content_length = length;
}

void
khttpd_response_set_connection_close(struct khttpd_response *response)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response->close)
		return;
	khttpd_response_add_field(response, "Connection", "%s", "close");
	response->close = TRUE;
}

void
khttpd_response_set_body_proc(struct khttpd_response *response,
    khttpd_transmit_t proc, off_t content_length)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(!response->has_transfer_encoding && 
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, "
		"has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	response->payload_size = content_length;
	response->transmit_body = proc;
	khttpd_response_set_content_length(response, content_length);
}

void
khttpd_response_set_body_mbuf(struct khttpd_response *response,
    struct mbuf *data)
{
	off_t len;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(response->body == NULL,
	    ("response %p has body %p", response, response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, "
		"has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	len = m_length(data, NULL);
	khttpd_response_set_content_length(response, len);
	response->payload_size = len;
	response->body = data;
}

void
khttpd_response_set_body_bytes(struct khttpd_response *response,
    void *data, size_t size, void (*free_data)(void *))
{
	struct mbuf *m;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(response->body == NULL,
	    ("response %p has body %p", response, response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, "
		"has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	khttpd_response_set_content_length(response, size);

	response->payload_size = size;
	response->body = m = m_get(M_WAITOK, MT_DATA);
	m->m_ext.ext_cnt = &response->body_refcnt;
	m_extadd(m, data, size, free_data == NULL ?
	    khttpd_response_free_body_extbuf_null :
	    khttpd_response_free_body_extbuf,
	    free_data, data, 0, EXT_EXTREF, M_WAITOK);
}

/*
 * socket
 */

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;

	socket = mem;

	socket->event_type.handle_event = khttpd_handle_socket_event;
	STAILQ_INIT(&socket->xmit_queue);
	cap_rights_init(&socket->rights, CAP_EVENT, CAP_RECV, CAP_SEND,
	    CAP_SETSOCKOPT, CAP_SHUTDOWN);

	return (0);
}

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	socket = mem;

	socket->receive = khttpd_receive_request_line;
	socket->transmit = khttpd_transmit_status_line_and_header;

	bzero(&socket->khttpd_socket_zctor_begin,
	    offsetof(struct khttpd_socket, khttpd_socket_zctor_end) - 
	    offsetof(struct khttpd_socket, khttpd_socket_zctor_begin));

	socket->fd = -1;
	socket->refcount = 1;
	socket->recv_limit = khttpd_message_size_limit;

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_socket *socket;
	struct thread *td;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	socket = mem;
	td = curthread;

	KASSERT(STAILQ_EMPTY(&socket->xmit_queue), ("orphan request"));
	KASSERT(!socket->in_sockets_list, ("still in sockets list."));
	KASSERT(socket->refcount == 0, ("refcount=%d", socket->refcount));

	m_freem(socket->recv_leftovers);
	m_freem(socket->xmit_buf);
	khttpd_request_free(socket->recv_request);

	if (socket->fd != -1)
		kern_close(td, socket->fd);

	if (socket->fp != NULL)
		fdrop(socket->fp, td);
}

void
khttpd_socket_hold(struct khttpd_socket *socket)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	++socket->refcount;
}

void
khttpd_socket_free(struct khttpd_socket *socket)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	if (socket != NULL && --socket->refcount == 0)
		uma_zfree(khttpd_socket_zone, socket);
}

int
khttpd_socket_fd(struct khttpd_socket *socket)
{

	return socket->fd;
}

static void
khttpd_socket_clear_all_requests(struct khttpd_socket *socket)
{
	struct khttpd_request *request;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	while ((request = STAILQ_FIRST(&socket->xmit_queue)) != NULL) {
		STAILQ_REMOVE_HEAD(&socket->xmit_queue, link);
		khttpd_request_free(request);
	}
	khttpd_request_free(socket->recv_request);
	socket->recv_request = NULL;
}

static void
khttpd_socket_close(struct khttpd_socket *socket)
{
	struct thread *td;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;

	if (socket->fd != -1) {
		kern_close(td, socket->fd);
		socket->fd = -1;
	}

	if (socket->fp != NULL) {
		fdrop(socket->fp, td);
		socket->fp = NULL;
	}

	socket->recv_eof = TRUE;

	khttpd_socket_clear_all_requests(socket);

	if (socket->in_sockets_list) {
		LIST_REMOVE(socket, link);
		socket->in_sockets_list = FALSE;
		khttpd_socket_free(socket);
	}
}

static void
khttpd_socket_drain(struct khttpd_socket *socket)
{
	struct mbuf *m;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	m = socket->recv_ptr;
	if (m != NULL) {
		m->m_len = socket->recv_off;
		m_freem(m->m_next);
		m->m_next = NULL;

		socket->recv_ptr = NULL;
		socket->recv_off = 0;
	}

	socket->recv_drain = TRUE;
}

static void
khttpd_socket_shutdown(struct khttpd_socket *socket)
{
	struct shutdown_args shutdown_args;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	shutdown_args.s = socket->fd;
	shutdown_args.how = SHUT_WR;
	sys_shutdown(curthread, &shutdown_args);

	khttpd_socket_drain(socket);
	khttpd_socket_clear_all_requests(socket);
}

static void
khttpd_socket_set_limit(struct khttpd_socket *socket, off_t size)
{
	int len;

	TRACE("enter %jd", (intmax_t)size);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	len = m_length(socket->recv_ptr, NULL) - socket->recv_off;
	socket->recv_limit = size - len;
	TRACE("enter %jd, %d", (intmax_t)socket->recv_limit, len);
}

static int
khttpd_socket_read(struct khttpd_socket *socket)
{
	struct uio auio;
	struct mbuf *m;
	struct thread *td;
	ssize_t resid;
	int error, flags;

	TRACE("enter %d", socket->recv_limit);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	resid = MIN(SSIZE_MAX, socket->recv_limit);
	if (resid <= 0) {
		TRACE("error resid %jd", (intmax_t)resid);
		return (ENOBUFS);
	}

	td = curthread;
	bzero(&auio, sizeof(auio));
	auio.uio_resid = resid;
	flags = 0;
	m = NULL;
	error = soreceive(socket->fp->f_data, NULL, &auio, &m, NULL, &flags);
	if (error != 0) {
		TRACE("error soreceive %d", error);
		return (error);
	}
	if (auio.uio_resid == resid) {
		TRACE("eof");
		socket->recv_eof = TRUE;
		return (0);
	}

	socket->recv_limit -= resid - auio.uio_resid;
	TRACE("limit %d (-%d)", socket->recv_limit, resid - auio.uio_resid);

	if (socket->recv_ptr == NULL)
		socket->recv_ptr = m;
	else {
		m_cat(socket->recv_tail, m);
		m = socket->recv_tail;
	}

	m_length(m, &socket->recv_tail);

	return (0);
}

static int
khttpd_socket_next_line(struct khttpd_socket *socket, 
    struct khttpd_mbuf_pos *bol)
{
	const char *begin, *cp, *end;
	struct mbuf *ptr;
	u_int off;
	int error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	/*
	 * If there is no receiving mbuf chain, receive from the socket.
	 */

	if (socket->recv_ptr == NULL) {
		error = khttpd_socket_read(socket);
		if (error != 0)
			return (error);
		if (socket->recv_eof) {
			khttpd_mbuf_pos_init(bol, NULL, 0);
			return (ENOENT);
		}
	}

	ptr = socket->recv_ptr;
	off = socket->recv_off;

	if (socket->recv_bol_ptr == NULL) {
		socket->recv_bol_ptr = ptr;
		socket->recv_bol_off = off;
	}

	for (;;) {
		/* Find the first '\n' in a mbuf. */

		begin = mtod(ptr, char *);
		end = begin + ptr->m_len;
		cp = khttpd_find_ch_in(begin + off, end, '\n');
		if (cp != NULL)
			break;

		/*
		 * No '\n' found.  Receive further if we reached the end of
		 * the chain.
		 */

		if (ptr->m_next == NULL) {
			socket->recv_ptr = ptr;
			socket->recv_off = off = ptr->m_len;
			error = khttpd_socket_read(socket);
			if (error != 0)
				return (error);
			if (socket->recv_eof) {
				khttpd_mbuf_pos_init(bol, socket->recv_bol_ptr,
				    socket->recv_bol_off);
				socket->recv_bol_ptr = NULL;
				return (ENOENT);
			}
			continue;
		}

		/* Advance to the next mbuf */

		ptr = ptr->m_next;
		off = 0;
	}

	socket->recv_ptr = ptr;
	socket->recv_off = cp + 1 - begin;
	khttpd_mbuf_pos_init(bol, socket->recv_bol_ptr, socket->recv_bol_off);
	socket->recv_bol_ptr = NULL;

	return (0);
}

/*
 * 
 */

static struct khttpd_server *
khttpd_server_alloc(const char *name)
{
	struct khttpd_server *result;

	result = khttpd_malloc(sizeof(struct khttpd_server));
	result->name = strdup(name, M_KHTTPD);
	result->dev = NULL;
	result->route_root = uma_zalloc_arg(khttpd_route_zone,
	    &khttpd_route_type_null, M_WAITOK);
	SLIST_INIT(&result->ports);
	khttpd_log_init(&result->access_log);
	khttpd_log_init(&result->error_log);

	return (result);
}

static void
khttpd_server_free(struct khttpd_server *server)
{
	struct thread *td;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;

	khttpd_log_close(&server->access_log);
	khttpd_log_close(&server->error_log);
	khttpd_route_clear_all(server->route_root);
	khttpd_route_free(server->route_root);
	if (server->dev != NULL)
		destroy_dev(server->dev);
	free((void *)server->name, M_KHTTPD);

	khttpd_free(server);
}

struct khttpd_server *
khttpd_server_find(const char *name)
{
	struct khttpd_server *server;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
 
	SLIST_FOREACH(server, &khttpd_servers, link)
		if (strcmp(server->name, name) == 0)
			return (server);

	return (NULL);
}

struct khttpd_route *
khttpd_server_route_root(struct khttpd_server *server)
{

	return server->route_root;
}

/*
 * 
 */

void
khttpd_set_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response->status == 0 || response->status / 100 == 1)
		panic("invalid status %d for %p.", response->status, response);

	if (request->close)
		khttpd_response_set_connection_close(response);

	if (request->response != NULL) {
		if (request->response->status / 100 == 2)
			panic("a successful response(%d) followed by a "
			    "response(%d)", request->response->status,
			    response->status);

		if (response->status / 100 == 2)
			panic("a response(%d) followed by a successful "
			    "response(%d)", request->response->status,
			    response->status);

		if (!response->close || request->response->close) {
			khttpd_response_free(response);
			return;
		}

		if (request->may_respond)
			panic("a non-closing response %p has already started "
			    "sending for request %p", request->response,
			    request);

		khttpd_response_free(request->response);
	}
	request->response = response;
	request->continue_response = FALSE;

	if (response->close) {
		khttpd_socket_drain(socket);
		request->may_respond = TRUE;
	}

	if (STAILQ_FIRST(&socket->xmit_queue) == request)
		khttpd_socket_transmit(socket);
}

static int
khttpd_transmit_end(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct thread *td;
	boolean_t close;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	KASSERT(request == STAILQ_FIRST(&socket->xmit_queue),
	    ("request %p, first %p", request,
		STAILQ_FIRST(&socket->xmit_queue)));

	td = curthread;
	close = response->close;

	STAILQ_REMOVE_HEAD(&socket->xmit_queue, link);
	khttpd_request_free(request);

	if (socket->recv_eof && STAILQ_EMPTY(&socket->xmit_queue))
		khttpd_socket_close(socket);
	else if (close)
		khttpd_socket_shutdown(socket);

	socket->transmit = khttpd_transmit_status_line_and_header;

	return (0);
}

static int
khttpd_transmit_trailer(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	*out = m = m_gethdr(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(m, "0\r\n");

	m_cat(m, response->trailer);
	response->trailer = NULL;

	khttpd_mbuf_printf(m, "\r\n");

	socket->transmit = khttpd_transmit_end;

	return (0);
}

static int
khttpd_transmit_chunk(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m, *head;
	off_t len;
	int error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	m = NULL;
	error = response->transmit_body(socket, request, response, &m);
	if (error != 0) {
		TRACE("error provide_chunk_data %d", error);
		return (error);
	}

	if (m == NULL) {
		socket->transmit = khttpd_transmit_trailer;
		return (0);
	}

	KASSERT(0 < m_length(m, NULL),
	    ("provide_chunk_data returned an empty chain"));

	*out = head = m_gethdr(M_WAITOK, MT_DATA);
	len = m_length(m, NULL);
	response->payload_size += len;
	khttpd_mbuf_printf(head, "%jx\r\n", (uintmax_t)len);
	m_cat(head, m);
	khttpd_mbuf_printf(head, "\r\n");

	return (0);
}

static int
khttpd_transmit_status_line_and_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	*out = m = m_gethdr(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(m, "HTTP/1.%d %d n/a\r\n", response->version_minor,
	    response->status);
	response->header_closed = TRUE;

	m_cat(m, response->header);
	response->header = NULL;

	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));

	if (response->status == 204 || response->status == 304 ||
	    request->method == KHTTPD_METHOD_HEAD)
		socket->transmit = khttpd_transmit_end;

	else if (response->transfer_encoding_chunked)
		socket->transmit = khttpd_transmit_chunk;

	else if (0 < response->content_length) {
		if (response->body == NULL)
			socket->transmit = response->transmit_body;
		else {
			response->payload_size = m_length(response->body,
			    NULL);
			m_cat(m, response->body);
			response->body = NULL;
			socket->transmit = khttpd_transmit_end;
		}
	} else
		socket->transmit = khttpd_transmit_end;

	return (0);
}

void khttpd_transmit_finished(struct khttpd_socket *socket)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(socket->transmit == 
	    STAILQ_FIRST(&socket->xmit_queue)->response->transmit_body,
	    ("khttpd_transmit_finished must not be called from other than "
		"the specified transmit function"));

	socket->transmit = khttpd_transmit_end;
}

void
khttpd_set_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *content, boolean_t close)
{

	TRACE("enter %d %d", status, close);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response == NULL)
		response = khttpd_response_alloc();

	khttpd_response_set_status(response, status);

	if (close)
		khttpd_response_set_connection_close(response);

	if (content != NULL) {
		khttpd_response_set_body_bytes(response, (void *)content,
		    strlen(content), NULL);
		khttpd_response_add_field(response, "Content-Type", "%s",
		    "text/html; charset=US-ASCII");
	}

	khttpd_set_response(socket, request, response);
}

void
khttpd_set_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *reason, const char *description, boolean_t close)
{
	static const char fmt[] = "<!DOCTYPE html>"
	    "<html lang='en'>"
		"<head>"
		    "<meta charset='US-ASCII' />"
		    "<title>%d %s</title>"
		"</head>"
		"<body>"
		    "<h1>%s</h1>"
		    "<p>%s</p>"
		"</body>"
	    "</html>";

	struct mbuf *mbuf;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response == NULL)
		response = khttpd_response_alloc();

	khttpd_response_set_status(response, status);

	if (close)
		khttpd_response_set_connection_close(response);

	mbuf = m_gethdr(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(mbuf, fmt, status, reason, reason, description);
	khttpd_response_set_body_mbuf(response, mbuf);
	khttpd_response_add_field(response, "Content-Type", "%s",
	    "text/html; charset=US-ASCII");
	khttpd_set_response(socket, request, response);
}

void
khttpd_set_moved_permanently_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *target)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response == NULL)
		response = khttpd_response_alloc();
	khttpd_response_add_field(response, "Location", "%s", target);
	khttpd_set_error_response(socket, request, response, 301,
	    "Moved Permanently",
	    "The target resource has been assigned a new permanent URI.",
	    FALSE);
}

void
khttpd_set_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 400,
	    "Bad Request",
	    "A request that this server could not understand was sent.",
	    TRUE);
}

void
khttpd_set_length_required_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 411,
	    "Length Required",
	    "The server refused to accept the request "
	    "without a defined Content-Length.",
	    TRUE);
}

void
khttpd_set_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 413,
	    "Payload Too Large",
	    "The request payload is larger than this server could handle.",
	    TRUE);
}

void
khttpd_set_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 501,
	    "Not Implemented",
	    "The server does not support the requested functionality.",
	    close);
}

void
khttpd_set_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 404,
	    "Not Found",
	    "The server does not have the requested resource.", close);
}

void
khttpd_set_method_not_allowed_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close,
    const char *allowed_methods)
{
	struct khttpd_response *response;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	response = khttpd_response_alloc();
	khttpd_response_add_field(response, "Allow", "%s", allowed_methods);
	khttpd_set_error_response(socket, request, response, 405,
	    "Method Not Allowed",
	    "The requested method is not supported by the target resource.",
	    close);
}

void
khttpd_set_conflict_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 404,
	    "Conflict",
	    "The request could not be completed due to a conflict with the "
	    "current state of the target resource.", close);
}

void
khttpd_set_uri_too_long_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 414,
	    "URI Too Long",
	    "The request target is longer than the "
	    "server is willing to interpret.", TRUE);
}

/*
 * See Also
 *	RFC6585
 */
void
khttpd_set_request_header_field_too_large_response
(struct khttpd_socket *socket, struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 431,
	    "Request Header Fields Too Large",
	    "The header fields in the request is too large.", TRUE);
}

void
khttpd_set_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_set_error_response(socket, request, NULL, 500,
	    "Internal Server Error",
	    "The server encountered an unexpected condition "
	    "that prevent it from fulfilling the request.", TRUE);
}

void
khttpd_set_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods)
{

	TRACE("enter %s", allowed_methods);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (response == NULL)
		response = khttpd_response_alloc();

	khttpd_response_set_status(response, 200);
	/* RFC7231 section 4.3.7 mandates to send Content-Length: 0 */
	khttpd_response_set_content_length(response, 0);
	khttpd_response_add_field(response, "Allow", "%s", allowed_methods);

	khttpd_set_response(socket, request, response);
}

void
khttpd_received_header_null(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
}

void
khttpd_received_body_null(struct khttpd_socket *socket,
    struct khttpd_request *request, struct mbuf *m)
{
}

void
khttpd_end_of_message_null(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
}

static void
khttpd_terminate_received_mbuf_chain(struct khttpd_socket *socket)
{
	struct mbuf *ptr;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	ptr = m_split(socket->recv_ptr, socket->recv_off, M_WAITOK);
	socket->recv_ptr = socket->recv_leftovers = ptr;
	socket->recv_off = 0;
	m_length(ptr, &socket->recv_tail);
}

static void
khttpd_finish_receiving_request(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (request->close)
		khttpd_socket_drain(socket);
	request->end_of_message(socket, request);
	socket->recv_request = NULL;
	khttpd_request_free(request);
	socket->receive = khttpd_receive_request_line;
	khttpd_socket_set_limit(socket, khttpd_message_size_limit);
}

static int
khttpd_receive_crlf_following_chunk_data(struct khttpd_socket *socket)
{
	struct khttpd_mbuf_pos pos;
	struct khttpd_request *request;
	int ch, error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	request = socket->recv_request;

	error = khttpd_socket_next_line(socket, &pos);
	if (error != 0)
		TRACE("error %d", error);
	if (error == ENOENT) {
		khttpd_set_bad_request_response(socket, request);
		return (0);
	}
	if (error != 0)
		return (error);

	ch = khttpd_mbuf_getc(&pos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&pos);
	if (ch != '\n')
		khttpd_set_bad_request_response(socket, request);

	socket->receive = khttpd_receive_chunk;

	return (0);
}

static int
khttpd_receive_chunk(struct khttpd_socket *socket)
{
	struct khttpd_mbuf_pos pos;
	off_t len;
	struct khttpd_request *request;
	int error, nibble;
	char ch;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	request = socket->recv_request;

	error = khttpd_socket_next_line(socket, &pos);
	if (error != 0) {
		TRACE("error next_line %d", error);
		khttpd_set_bad_request_response(socket, request);
		return (0);
	}

	len = 0;
	for (;;) {
		ch = khttpd_mbuf_getc(&pos);
		if (!isxdigit(ch)) {
			khttpd_mbuf_ungetc(&pos, ch);
			break;
		}

		nibble = isdigit(ch) ? ch - '0' :
		    'A' <= ch && ch <= 'F' ? ch - 'A' + 10 :
		    ch - 'a' + 10;

		if ((len << 4) < len) {
			TRACE("error range");
			khttpd_set_payload_too_large_response(socket,
			    request);
			return (0);
		}

		len = (len << 4) + nibble;
	}

	khttpd_terminate_received_mbuf_chain(socket);
	m_freem(pos.ptr);

	if (len == 0) {
		request->may_respond = TRUE;
		if (STAILQ_FIRST(&socket->xmit_queue) == request)
			khttpd_socket_transmit(socket);

		request->trailer = socket->recv_leftovers;
		socket->recv_leftovers = NULL;

		socket->receive = khttpd_receive_header_or_trailer;

	} else {
		request->payload_size += len;
		khttpd_socket_set_limit(socket, len);
		socket->receive = khttpd_receive_body;
	}

	return (0);
}

static int
khttpd_receive_body(struct khttpd_socket *socket)
{
	off_t resid;
	struct khttpd_request *request;
	struct thread *td;
	struct mbuf *m, *tail;
	int error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;
	request = socket->recv_request;
	resid = socket->recv_limit + m_length(socket->recv_leftovers, NULL);
	while (0 < resid) {
		m = socket->recv_leftovers;
		if (m == NULL) {
			error = khttpd_socket_read(socket);
			if (socket->recv_eof)
				error = 0;
			if (error != 0)
				return (error);
			m = socket->recv_leftovers;
		}

		tail = m_split(m, resid, M_WAITOK);

		resid = tail != NULL ? 0 : socket->recv_limit;
		socket->recv_leftovers = socket->recv_ptr = tail;
		socket->recv_off = 0;

		request->received_body(socket, request, m);
	}

	if (request->receiving_chunk_and_trailer) {
		khttpd_socket_set_limit(socket, khttpd_message_size_limit);
		socket->receive = khttpd_receive_crlf_following_chunk_data;

	} else
		khttpd_finish_receiving_request(socket, request);

	return (0);
}

static void
khttpd_receive_content_length_field(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_mbuf_pos *pos)
{
	uintmax_t value;
	int error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	error = khttpd_mbuf_parse_digits(pos, &value);

	if (error == ERANGE || OFF_MAX < value) {
		khttpd_set_payload_too_large_response(socket, request);
		return;
	}

	if (error != 0 || request->has_content_length) {
		khttpd_set_bad_request_response(socket, request);
		return;
	}

	request->has_content_length = TRUE;
	request->content_length = value;
}

static void
khttpd_receive_transfer_encoding_field(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_mbuf_pos *pos)
{
	char token_buffer[8];
	struct sbuf token;
	int count, error;
	boolean_t last_is_chunked;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	sbuf_new(&token, token_buffer, sizeof(token_buffer), SBUF_FIXEDLEN);

	last_is_chunked = request->transfer_encoding_chunked;
	count = request->transfer_encoding_count;
	for (;;) {
		sbuf_clear(&token);

		error = khttpd_mbuf_next_list_element(pos, &token);

		if (error == ENOMSG) {
			error = 0;
			break;
		}

		if (sbuf_len(&token) == 0)
			continue;

		last_is_chunked = error == 0 &&
		    strcasecmp(sbuf_data(&token), "chunked") == 0;
		++count;
	}

	sbuf_delete(&token);

	request->transfer_encoding_count = count;
	request->has_transfer_encoding = TRUE;
	request->transfer_encoding_chunked = last_is_chunked;

	if (1 < count || (0 < count && !last_is_chunked))
		khttpd_set_not_implemented_response(socket, request, TRUE);
}

static void
khttpd_receive_connection_field(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_mbuf_pos *pos)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	request->close = khttpd_mbuf_list_contains_token(pos, "close", TRUE);
	if (request->response != NULL) {
		khttpd_response_set_connection_close(request->response);

		khttpd_socket_drain(socket);
		request->may_respond = TRUE;

		if (STAILQ_FIRST(&socket->xmit_queue) == request)
			khttpd_socket_transmit(socket);
	}
}

static void
khttpd_receive_expect_field(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_mbuf_pos *pos)
{
	char token_buffer[16];
	struct sbuf token;
	int error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	if (request->version_minor < 1 || request->continue_response)
		return;

	sbuf_new(&token, token_buffer, sizeof(token_buffer), SBUF_FIXEDLEN);

	for (;;) {
		sbuf_clear(&token);

		error = khttpd_mbuf_next_list_element(pos, &token);
		if (error == ENOMSG)
			break;

		if (error != 0 || sbuf_len(&token) == 0)
			continue;

		if (strcasecmp(sbuf_data(&token), "100-continue") == 0) {
			request->continue_response = TRUE;
			break;
		}
	}

	sbuf_delete(&token);
}

static void
khttpd_end_of_header_or_trailer(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	khttpd_terminate_received_mbuf_chain(socket);

	/*
	 * If this is the end of a trailer, we've done for this request
	 * message.
	 */

	if (request->receiving_chunk_and_trailer) {
		khttpd_finish_receiving_request(socket, request);
		return;
	}

	/*
	 * Call route type's received_header handler.
	 */

	(*request->route->type->received_header)(socket, request);

	/*
	 * Start receiving chunked payload if chunked Transfer-Encoding is
	 * specified.
	 */

	request->receiving_chunk_and_trailer = 
	    request->transfer_encoding_chunked;
	if (request->receiving_chunk_and_trailer) {
		/*
		 * We don't set may_respond TRUE in this case.  Once the
		 * transmission of a response without 'Connection: close'
		 * starts, we can't cancel it.  So setting may_respond
		 * disables our ability to send an error response with
		 * 'Connection: close' later and we need such an ability if
		 * there is an error in a chunk.
		 */
		khttpd_socket_set_limit(socket, khttpd_message_size_limit);
		socket->receive = khttpd_receive_chunk;
		return;
	}

	/*
	 * After this code, the response corresponds to the request is
	 * transmitted to the request sender.
	 */

	request->may_respond = TRUE;
	if (STAILQ_FIRST(&socket->xmit_queue) == request)
		khttpd_socket_transmit(socket);

	/*
	 * Start receiving the payload of the request message.
	 */

	if (request->has_content_length ? request->content_length == 0 :
	    !request->transfer_encoding_chunked) {
		khttpd_finish_receiving_request(socket, request);
		return;
	}

	request->payload_size = request->content_length;
	khttpd_socket_set_limit(socket, request->content_length);
	socket->receive = khttpd_receive_body;
}

static int
khttpd_receive_header_or_trailer(struct khttpd_socket *socket)
{
	char field[KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH];
	struct khttpd_mbuf_pos pos, tmppos;
	struct khttpd_request *request;
	char *end;
	int ch, error, field_enum;
	boolean_t last_ch_is_ws;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	request = socket->recv_request;

	/* Get a line */

	error = khttpd_socket_next_line(socket, &pos);
	if (error != 0)
		TRACE("error next_line %d", error);
	switch (error) {
	case 0:
		break;
	case ENOBUFS:
		khttpd_set_request_header_field_too_large_response(socket, 
		    request);
		return (0);
	case ENOENT:
		khttpd_set_bad_request_response(socket, request);
		return (0);
	default:
		return (error);
	}

	/*
	 * If it's an empty line, we reached the end of a header or a trailer.
	 */

	khttpd_mbuf_pos_copy(&pos, &tmppos);
	ch = khttpd_mbuf_getc(&tmppos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&tmppos);
	if (ch == '\n') {
		khttpd_end_of_header_or_trailer(socket, request);
		return (0);
	}

	if (request->receiving_chunk_and_trailer) {
		/*
		 * If it's the first line of a trailer, take the ownership of
		 * the receiving mbuf chain.
		 */
		if (request->trailer == NULL) {
			request->trailer = socket->recv_leftovers;
			socket->recv_leftovers = NULL;
		}

		/* If it's a trailer, done. */
		return (0);
	}

	/*
	 * If it's the first line of a header, set the beginning of this line
	 * to request->header_pos.
	 */

	if (request->header.ptr == NULL)
		khttpd_mbuf_pos_copy(&pos, &request->header);

	/*
	 * Extract the field name from the line.  If the character just before
	 * ':' is a white space, set 'bad request' response.
	 */

	error = khttpd_mbuf_copy_segment(&pos, ':', field, sizeof(field) - 1,
	    &end);
	if (error != 0)
		TRACE("error copy_segment %d", error);
	if (error == ENOMEM) {
		/*
		 * Because this field is longer than any known field names,
		 * looking up the table is not necessary.
		 */

		last_ch_is_ws = end[-1] == ' ';
		for (;;) {
			ch = khttpd_mbuf_getc(&pos);
			if (ch == ':' && !last_ch_is_ws)
				break;
			if (ch == ':' || ch == '\n') {
				khttpd_set_bad_request_response(socket, 
				    request);
				break;
			}
			last_ch_is_ws = ch == ' ';
		}

		return (0);
	}
	if (error != 0 || end[-1] == ' ') {
		khttpd_set_bad_request_response(socket, request);
		return (0);
	}

	/*
	 * If the extracted field name is not a known name, done.
	 */

	*end = '\0';
	field_enum = khttpd_field_find(field, end);
	if (field_enum == KHTTPD_FIELD_UNKNOWN)
		return (0);

	/*
	 * Ignore any white spaces preceding the value of the field.
	 */

	while ((ch = khttpd_mbuf_getc(&pos)) == ' ')
		;		/* nothing */
	khttpd_mbuf_ungetc(&pos, ch);

	/*
	 * Apply a field handler.
	 */

	switch (field_enum) {

	case KHTTPD_FIELD_CONTENT_LENGTH:
		khttpd_receive_content_length_field(socket, request, &pos);
		break;

	case KHTTPD_FIELD_TRANSFER_ENCODING:
		khttpd_receive_transfer_encoding_field(socket, request, &pos);
		break;

	case KHTTPD_FIELD_CONNECTION:
		khttpd_receive_connection_field(socket, request, &pos);
		break;

	case KHTTPD_FIELD_EXPECT:
		khttpd_receive_expect_field(socket, request, &pos);
		break;

	default:
		break;
	}

	return (0);
}

static int
khttpd_parse_target_uri(struct khttpd_mbuf_pos *pos, struct sbuf *output, 
    const char **query)
{
	ssize_t query_off;
	int code, error, i, n;
	char ch;
	boolean_t invalid, notfound;

	TRACE("enter");

	error = 0;
	query_off = -1;
	invalid = notfound = FALSE;
	for (;;) {
		ch = khttpd_mbuf_getc(pos);
again:
		switch (ch) {

		case '\n':
			error = EBADMSG;
			goto end;

		case '\0':
			notfound = TRUE;
			continue;

		case ' ':
			goto end;

		case '?':
			sbuf_putc(output, '\0');
			query_off = sbuf_len(output);
			continue;

		case '%':
			code = 0;
			n = 0;
			for (i = 0; i < 2; ++i) {
				code <<= 4;
				ch = khttpd_mbuf_getc(pos);
				if ('0' <= ch && ch <= '9')
					code |= ch - '0';

				else if ('A' <= ch && ch <= 'F')
					code |= ch - 'A' + 10;

				else if ('a' <= ch && ch <= 'f')
					code |= ch - 'a' + 10;

				else {
					invalid = TRUE;
					goto again;
				}
			}

			if (code == 0)
				notfound = TRUE;
			else
				sbuf_putc(output, code);
			continue;

		default:
			sbuf_putc(output, ch);
		}
	}

end:
	error = sbuf_finish(output);
	if (error != 0)
		TRACE("error sbuf_finish %d", error);

	if (query != NULL && error == 0)
		*query = query_off < 0 ? NULL : sbuf_data(output) + query_off;

	return (error != 0 ? error : invalid ? EINVAL : notfound ? ENOENT : 0);
}

static int
khttpd_receive_request_line(struct khttpd_socket *socket)
{
	static const char version_prefix[] = "HTTP/1.";
	struct mbuf *m;
	struct khttpd_mbuf_pos pos, tmppos;
	const char *cp;
	char *end;
	struct khttpd_request *request;
	struct khttpd_route *route;
	int ch, error;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	/* 
	 * Get a line.
	 */

	error = khttpd_socket_next_line(socket, &pos);
	if (error != 0)
		TRACE("error next_line %d", error);
	if (error != 0 && error != ENOBUFS && error != ENOENT)
		return (error);
	if (error == ENOENT) {
		/*
		 * If EOF is found at the beginning of the line, return
		 * immediately.
		 */
		if (pos.unget == -1 && (pos.ptr == NULL ||
			(pos.ptr->m_next == NULL &&
			    pos.off == pos.ptr->m_len)))
			return (0);
	}
	if (error == 0) {
		if (socket->recv_eof)
			return (0);

		/* Ignore a line if it's empty. */
		khttpd_mbuf_pos_copy(&pos, &tmppos);
		ch = khttpd_mbuf_getc(&tmppos);
		if (ch == '\r')
			ch = khttpd_mbuf_getc(&tmppos);
		if (ch == '\n')
			return (0);

		socket->receive = khttpd_receive_header_or_trailer;
	}

	/* 
	 * Enlist a new request.
	 */

	socket->recv_request = request =
	    uma_zalloc(khttpd_request_zone, M_WAITOK);
	STAILQ_INSERT_TAIL(&socket->xmit_queue, request, link);

	/* 
	 * If the request line is longer than khttpd_message_size_limit or is
	 * terminated prematurely, send 'Bad Request' response message.
	 */

	if (error == ENOBUFS || error == ENOENT) {
		khttpd_set_bad_request_response(socket, request);
		return (0);
	}

	/*
	 * Take the ownership of the receiving mbuf chain.
	 */

	m = socket->recv_leftovers;
	if (pos.ptr != m || pos.off != 0) {
		khttpd_terminate_received_mbuf_chain(socket);
		m_freem(m);
		m = socket->recv_leftovers;
	}
	request->request_line = m;
	socket->recv_leftovers = NULL;

	/*
	 * Find the method of this request message.
	 */

	error = khttpd_mbuf_copy_segment(&pos, ' ', request->method_name,
	    sizeof(request->method_name) - 1, &end);

	if (error != 0)
		TRACE("error copy_segment(method) %d", error);

	if (error == 0) {
		*end = '\0';
		request->method =
		    khttpd_method_find(request->method_name, end);

	} else if (error == ENOMEM) {
		request->method = KHTTPD_METHOD_UNKNOWN;
		request->method_name[sizeof(request->method_name) - 1] = '\0';
		error = khttpd_mbuf_next_segment(&pos, ' ');
		khttpd_set_not_implemented_response(socket, request, FALSE);

	} else
		goto bad;

	/*
	 * Find the target URI of this request message.
	 */

	error = khttpd_parse_target_uri(&pos, &request->target,
	    &request->query);
	if (error != 0)
		TRACE("error parse_target_uri(target) %d", error);
	if (error == ENOENT)
		khttpd_set_not_found_response(socket, request, FALSE);
	else if (error != 0)
		goto bad;

	/*
	 * Find the route corresponds to the request target. 
	 */

	route = khttpd_route_find(khttpd_server_route_root
	    (socket->port->server),
	    sbuf_data(&request->target), &request->suffix);
	if (route == NULL) {
		khttpd_set_not_found_response(socket, request, FALSE);
		route = khttpd_server_route_root(socket->port->server);
	}
	khttpd_route_hold(route);
	request->route = route;

	/*
	 * Find the protocol version.
	 */

	for (cp = version_prefix; (ch = *cp) != '\0'; ++cp)
		if (khttpd_mbuf_getc(&pos) != ch)
			goto bad;

	ch = khttpd_mbuf_getc(&pos);
	if (!isdigit(ch))
		goto bad;

	request->version_minor = ch - '0';

	/*
	 * Expect the end of the line.  If it isn't, set 'bad request'
	 * response.
	 */

	ch = khttpd_mbuf_getc(&pos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&pos);
	if (ch != '\n')
		goto bad;

	return (0);

bad:
	khttpd_set_bad_request_response(socket, request);
	return (0);
}

static void
khttpd_accept_client(struct kevent *event)
{
	struct sockaddr *name;
	struct khttpd_server_port *port;
	struct khttpd_socket *socket;
	struct thread *td;
	socklen_t namelen;
	int error, fd;

	TRACE("enter %td", event->ident);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;
	port = event->udata;

	socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
	socket->port = port;

	error = kern_accept4(td, port->fd, &name, &namelen, SOCK_NONBLOCK, 
	    NULL);
	if (error != 0) {
		TRACE("error accept %d", error);
		goto bad;
	}
	fd = td->td_retval[0];

	bcopy(name, &socket->peer_addr, name->sa_len);

	TRACE("new_client %d", fd);

	socket->fd = fd;
	error = getsock_cap(td, socket->fd, &socket->rights, &socket->fp,
	    NULL);
	if (error != 0) {
		TRACE("error getsock_cap %d", error);
		goto bad;
	}

	error = khttpd_kevent_add_read_write(khttpd_kqueue, socket->fd, 
	    &socket->event_type);
	if (error != 0) {
		TRACE("error kevent_add_read_write %d", error);
		goto bad;
	}

	socket->in_sockets_list = TRUE;
	LIST_INSERT_HEAD(&khttpd_sockets, socket, link);

	return;

bad:
	khttpd_socket_free(socket);
}

static int
khttpd_socket_receive_null(struct khttpd_socket *socket)
{
	struct uio auio;
	struct socket *so;
	struct thread *td;
	struct mbuf *m;
	int error, flags;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;
	so = socket->fp->f_data;

	bzero(&auio, sizeof(auio));
	for (;;) {
		auio.uio_resid = INT_MAX;
		m = NULL;
		flags = 0;
		error = soreceive(so, NULL, &auio, &m, NULL, &flags);
		m_freem(m);

		if (error != 0) {
			TRACE("error soreceive %d", error);
			break;
		}

		if (auio.uio_resid == INT_MAX) {
			socket->recv_eof = TRUE;
			break;
		}
	}

	return (error);
}

static void
khttpd_socket_receive(struct khttpd_socket *socket)
{
	int error;

	TRACE("enter %d", socket->fd);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	while (!socket->recv_eof &&
	    (error = (socket->recv_drain ? khttpd_socket_receive_null :
		socket->receive)(socket) == 0))
		;	/* nothing */

	if (error != 0 && error != EWOULDBLOCK) {
		TRACE("error receive %d", error);
		khttpd_socket_close(socket);
		return;
	}

	if (socket->recv_eof && socket->fd != -1) {
		TRACE("error eof");
		if (STAILQ_EMPTY(&socket->xmit_queue))
			khttpd_socket_close(socket);
		else
			khttpd_kevent_delete_read(khttpd_kqueue, socket->fd);
	}
}

static void
khttpd_socket_transmit(struct khttpd_socket *socket)
{
	struct khttpd_request *request;
	struct khttpd_response *response;
	struct socket *so;
	struct thread *td;
	struct mbuf *m, *end, *head, *prev;
	ssize_t space, len;
	int error;
	boolean_t enable_new, enable_old;

	TRACE("enter %d", socket->fd);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	td = curthread;
	so = socket->fp->f_data;

	for (;;) {
		m = socket->xmit_buf;
		if (m != NULL) {
			SOCKBUF_LOCK(&so->so_snd);
			space = sbspace(&so->so_snd);
			SOCKBUF_UNLOCK(&so->so_snd);

			prev = NULL;
			len = 0;
			for (end = m; end != NULL && len + end->m_len <= space;
			     prev = end, end = end->m_next)
				len += end->m_len;
			if (prev == NULL) {
				error = EWOULDBLOCK;
				break;
			}

			TRACE("space=%d, len=%d, total=%d",
			    space, len, m_length(m, NULL));

			prev->m_next = NULL;
			socket->xmit_buf = end;
			if ((m->m_flags & M_PKTHDR) == 0) {
				head = m_gethdr(M_WAITOK, MT_DATA);
				m_cat(head, m);
				m = head;
			}
			m->m_pkthdr.len = len;

			error = sosend(so, NULL, NULL, m, NULL, 0, td);
			if (error != 0) {
				TRACE("error sosend(xmit_buf) %d", error);
				khttpd_socket_close(socket);
				return;
			}

			continue;
		}

		error = EINPROGRESS;

		request = STAILQ_FIRST(&socket->xmit_queue);
		if (request == NULL || !request->may_respond)
			break;

		if (request->continue_response) {
			socket->xmit_buf = m = m_gethdr(M_WAITOK, MT_DATA);
			khttpd_mbuf_printf(m, "HTTP/1.1 100 Continue\r\n\r\n");
			request->continue_response = FALSE;
			continue;
		}

		response = request->response;
		if (response == NULL)
			break;

		error = socket->transmit(socket, request, response,
		    &socket->xmit_buf);
		if (error == 0)
			continue;

		TRACE("error transmit %d", error);

		if (error != EWOULDBLOCK && error != EINPROGRESS) {
			khttpd_socket_close(socket);
			return;
		}
	}

	enable_old = socket->xmit_busy;
	socket->xmit_busy = enable_new = error == EWOULDBLOCK;

	if (enable_old != enable_new)
		khttpd_kevent_enable_write(khttpd_kqueue, socket->fd,
		    enable_new, &socket->event_type);
}

static void
khttpd_handle_socket_event(struct kevent *event)
{
	struct khttpd_socket *socket;

	TRACE("enter %td %d", event->ident, event->filter);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	socket = event->udata;
	khttpd_socket_hold(socket);

	switch (event->filter) {

	case EVFILT_READ:
		khttpd_socket_receive(socket);
		break;

	case EVFILT_WRITE:
		khttpd_socket_transmit(socket);
		break;

	default:
		panic("%s: unknown filter %d", __func__, event->filter);
	}

	khttpd_socket_free(socket);
}

/* --------------------------------------------------------------- asterisc */

static void
khttpd_asterisc_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter %d", socket->fd);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	switch (request->method) {

	case KHTTPD_METHOD_OPTIONS:
		khttpd_set_options_response(socket, request, NULL,
		    "OPTIONS, HEAD, GET, PUT, POST, DELETE");
		break;

	default:
		khttpd_set_not_implemented_response(socket, request, FALSE);
		break;
	}
}

/* ---------------------------------------------------------- logger thread */

static void
khttpd_logger_set_state(int state)
{

	mtx_assert(&khttpd_lock, MA_OWNED);

	khttpd_logger_state = state;
	if (khttpd_logger_waiting_state_change) {
		khttpd_logger_waiting_state_change = FALSE;
		wakeup(&khttpd_logger_state);
	}
}

static void
khttpd_logger_wait(const char *wmsg)
{

	mtx_assert(&khttpd_lock, MA_OWNED);

	khttpd_logger_waiting_state_change = TRUE;
	mtx_sleep(&khttpd_logger_state, &khttpd_lock, 0, wmsg, 0);
}

static void
khttpd_log_enqueue(struct mbuf *m)
{
	struct khttpd_log *log;

	KASSERT(curthread != khttpd_logger_thread,
	    ("current thread is the logger thread"));

	mtx_lock(&khttpd_lock);
	for (;;) {
		if (khttpd_logger_state == KHTTPD_LOGGER_INITIALIZING ||
		    khttpd_logger_state == KHTTPD_LOGGER_EXITING ||
		    khttpd_logger_state == KHTTPD_LOGGER_EXITED)
			break;

		if (mbufq_enqueue(&khttpd_logger_queue, m) == 0) {
			if (khttpd_logger_state == KHTTPD_LOGGER_IDLE &&
			    mbufq_len(&khttpd_logger_queue) == 1)
				khttpd_logger_set_state(KHTTPD_LOGGER_BUSY);

			log = mtod(m, struct khttpd_log_entry *)->target;
			++log->in_flight_count;

			m = NULL;
			break;
		}

		khttpd_logger_waiting_empty_slot = TRUE;
		mtx_sleep(&khttpd_logger_waiting_empty_slot, &khttpd_lock, 0,
		    "khttpd-slow-log", 0);
	}

	mtx_unlock(&khttpd_lock);

	if (m != NULL) {
		khttpd_log_entry_dtor(mtod(m, struct khttpd_log_entry *));
		m_freem(m);
	}
}

void
khttpd_access(struct khttpd_server *server, struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct mbuf *m;
	struct khttpd_log_entry *e;

	if (curthread == khttpd_logger_thread || server->error_log.fd == -1)
		return;

	m = khttpd_log_entry_alloc(KHTTPD_LOG_ACCESS, &e, &server->access_log);

	e = mtod(m, struct khttpd_log_entry *);
	e->access.socket = socket;
	khttpd_socket_hold(socket);
	e->access.request = request;
	khttpd_request_hold(request);

	khttpd_log_enqueue(m);
}

void
khttpd_error(struct khttpd_server *server, int severity, const char *fmt, ...)
{
	struct mbuf *m;
	struct khttpd_log_entry *e;
	va_list vl;

	if (curthread == khttpd_logger_thread || server->error_log.fd == -1)
		return;

	m = khttpd_log_entry_alloc(KHTTPD_LOG_ERROR, &e, &server->error_log);

	e = mtod(m, struct khttpd_log_entry *);
	e->error.severity = severity;

	va_start(vl, fmt);
	khttpd_mbuf_vprintf(m, fmt, vl);
	va_end(vl);

	khttpd_log_enqueue(m);
}

void
khttpd_debug(const char *func, const char *fmt, ...)
{
	struct mbuf *m;
	struct khttpd_log_entry *e;
	va_list vl;

	if (curthread == khttpd_logger_thread || khttpd_debug_log.fd == -1)
		return;

	m = khttpd_log_entry_alloc(KHTTPD_LOG_DEBUG, &e, &khttpd_debug_log);

	e = mtod(m, struct khttpd_log_entry *);
	e->debug.tid = curthread->td_tid;
	e->debug.func = func;

	va_start(vl, fmt);
	khttpd_mbuf_vprintf(m, fmt, vl);
	va_end(vl);

	khttpd_log_enqueue(m);
}

static void
khttpd_logger_put_request_line(struct mbuf *out,
    struct khttpd_request *request)
{
	struct mbuf *m, *e;
	const char *begin, *end;
	boolean_t no_last_ch;

	no_last_ch = request->header.off == 0 && request->header.unget != -1;

	e = request->header.ptr;
	for (m = request->request_line; m != e && m != NULL; m = m->m_next) {
		begin = mtod(m, char *);
		end = begin + m->m_len;
		if (no_last_ch && m->m_next == e)
			--end;
		khttpd_json_mbuf_append_string_wo_quote(out, begin, end);
	}
	if (m != NULL) {
		begin = mtod(m, char *);
		end = begin + request->header.off;
		if (request->header.unget != -1)
			--end;
		khttpd_json_mbuf_append_string_wo_quote(out, begin, end);
	}
}

static void
khttpd_logger_put_access_log(struct mbuf *out, struct timeval *tv,
    struct khttpd_log_entry *e)
{
	struct khttpd_socket *socket;
	struct khttpd_request *request;
	struct khttpd_response *response;

	socket = e->access.socket;
	request = e->access.request;
	response = request->response;

	khttpd_mbuf_printf(out, "{\"timestamp\": %ld, \"request\": \"",
	    tv->tv_sec);
	khttpd_logger_put_request_line(out, request);

	switch (socket->peer_addr.ss_family) {

	case AF_INET:
		khttpd_mbuf_printf(out, "\", \"family\": \"inet\""
		    "\"address\": \"");
		khttpd_mbuf_print_sockaddr_in(out,
		    (struct sockaddr_in *)&socket->peer_addr);
		khttpd_mbuf_append_ch(out, '"');
		break;

	case AF_INET6:
		khttpd_mbuf_printf(out, "\", \"family\": \"inet6\""
		    "\"address\": \"");
		khttpd_mbuf_print_sockaddr_in6(out,
		    (struct sockaddr_in6 *)&socket->peer_addr);
		khttpd_mbuf_append_ch(out, '"');
		break;

	case AF_UNIX:
		khttpd_mbuf_printf(out, "\", \"family\": \"unix\"");
		break;

	default:
		break;
	}

	khttpd_mbuf_printf(out, ", \"status\": %d", response->status);

	if (response->payload_size != 0)
		khttpd_mbuf_printf(out, ", \"responsePayloadSize\": %jd",
		    (uintmax_t)response->payload_size);

	if (request->payload_size != 0)
		khttpd_mbuf_printf(out, ", \"requestPayloadSize\": %jd",
		    (uintmax_t)response->payload_size);

	khttpd_mbuf_printf(out, "}\n");

	khttpd_log_entry_dtor(e);
}

static void
khttpd_logger_put(void)
{
	struct iovec iov[64];
	struct uio auio;
	struct timeval tv;
	const CODE *codep;
	struct mbuf *hd, *m, *n;
	struct khttpd_log_entry *e;
	struct khttpd_log *log;
	ssize_t resid;
	int error, i, len, type;

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	mtx_assert(&khttpd_lock, MA_OWNED);

	m = mbufq_flush(&khttpd_logger_queue);
	if (m == NULL) {
		if (khttpd_logger_state == KHTTPD_LOGGER_BUSY)
			khttpd_logger_set_state(KHTTPD_LOGGER_IDLE);
		return;
	}

	if (khttpd_logger_waiting_empty_slot) {
		khttpd_logger_waiting_empty_slot = FALSE;
		wakeup(&khttpd_logger_waiting_empty_slot);
	}

	mtx_unlock(&khttpd_lock);

	for (; m != NULL; m = n) {
		n = STAILQ_NEXT(m, m_stailqpkt);
		e = mtod(m, struct khttpd_log_entry *);

		bintime_add(&e->timestamp, &boottimebin);
		bintime2timeval(&e->timestamp, &tv);

		hd = m_get(M_WAITOK, MT_DATA);

		type = e->type;
		log = e->target;

		switch (type) {

		case KHTTPD_LOG_DEBUG:
			khttpd_mbuf_printf(hd, "%ld.%06ld %d %s ", tv.tv_sec,
			    tv.tv_usec, e->debug.tid, e->debug.func);
			khttpd_log_entry_dtor(e);
			m_adj(m, sizeof(struct khttpd_log_entry));
			m_cat(hd, m);
			khttpd_mbuf_append_ch(hd, '\n');
			break;

		case KHTTPD_LOG_ACCESS:
			khttpd_logger_put_access_log(hd, &tv, e);
			break;

		case KHTTPD_LOG_ERROR:
			for (codep = prioritynames; codep->c_name != NULL &&
				 codep->c_val != e->error.severity;
			     ++codep)
				; /* nothing */

			khttpd_mbuf_printf(hd,
			    "{\"timestamp\": %ld.%06ld, "
			    "\"priority\": \"%s\", \"description\": ",
			    tv.tv_sec, tv.tv_usec,
			    codep->c_name == NULL ? "unknown" : codep->c_name);
			khttpd_json_mbuf_append_string_in_mbuf(hd, m);
			khttpd_mbuf_printf(hd, "}\n");

			khttpd_log_entry_dtor(e);
			m_freem(m);
			break;

		default:
			panic("unknown log type: %d", type);
		}

		m = hd;
		i = 0;
		resid = 0;
		do {
			while (m != NULL && i < sizeof(iov) / sizeof(iov[0])) {
				len = m->m_len;
				iov[i].iov_base = mtod(m, void *);
				iov[i].iov_len = len;
				resid += len;
				++i;
				m = m->m_next;
			}

			auio.uio_iov = iov;
			auio.uio_segflg = UIO_SYSSPACE;
			auio.uio_rw = UIO_WRITE;
			auio.uio_td = curthread;
			auio.uio_iovcnt = i;
			auio.uio_resid = resid;
			auio.uio_offset = 0;
			while (auio.uio_resid) {
				error = kern_writev(curthread, log->fd, &auio);
				if (error != 0)
					break;
			}

			resid = 0;
			i = 0;
		} while (m != NULL);

		m_freem(hd);

		mtx_lock(&khttpd_lock);
		if (--log->in_flight_count == 0 && log->waiting) {
			log->waiting = FALSE;
			wakeup(&log->in_flight_count);
		}
		mtx_unlock(&khttpd_lock);
	}

	mtx_lock(&khttpd_lock);
}

static void
khttpd_logger_main(void *arg)
{

	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	mbufq_init(&khttpd_logger_queue, INT_MAX);

	mtx_lock(&khttpd_lock);
	khttpd_logger_set_state(KHTTPD_LOGGER_IDLE);

	for (;;) {
		switch (khttpd_logger_state) {

		case KHTTPD_LOGGER_BUSY:
			khttpd_logger_put();
			continue;

		case KHTTPD_LOGGER_SUSPENDING:
			khttpd_logger_put();
			if (khttpd_logger_state != KHTTPD_LOGGER_SUSPENDING)
				continue;
			khttpd_logger_set_state(KHTTPD_LOGGER_SUSPENDED);
			break;

		case KHTTPD_LOGGER_EXITING:
			khttpd_logger_put();
			khttpd_logger_set_state(KHTTPD_LOGGER_EXITED);
			mtx_unlock(&khttpd_lock);
			kthread_exit();

		default:
			break;
		}

		khttpd_logger_wait("khttpd-log");
	}
}

void
khttpd_logger_suspend(void)
{

	mtx_assert(&khttpd_lock, MA_OWNED);

	while (khttpd_logger_state == KHTTPD_LOGGER_SUSPENDING)
		khttpd_logger_wait("khttpd-log-susp");

	if (khttpd_logger_state == KHTTPD_LOGGER_IDLE ||
	    khttpd_logger_state == KHTTPD_LOGGER_BUSY) {
		khttpd_logger_set_state(KHTTPD_LOGGER_SUSPENDING);
		while (khttpd_logger_state != KHTTPD_LOGGER_SUSPENDED)
			khttpd_logger_wait("khttpd-log-susp");
	}
}

void
khttpd_logger_resume(void)
{

	mtx_assert(&khttpd_lock, MA_OWNED);

	if (khttpd_logger_state != KHTTPD_LOGGER_SUSPENDED)
		return;

	khttpd_logger_set_state(mbufq_len(&khttpd_logger_queue) == 0 ?
	    KHTTPD_LOGGER_IDLE : KHTTPD_LOGGER_BUSY);
}

/* ---------------------------------------------------------- khttpd daemon */

static void
khttpd_set_state(int state)
{
	int old_state;

	mtx_assert(&khttpd_lock, MA_OWNED);

	old_state = khttpd_state;
	if (old_state == state)
		return;
	if (old_state == KHTTPD_READY && khttpd_proc != NULL) {
		PROC_LOCK(khttpd_proc);
		kern_psignal(khttpd_proc, SIGUSR1);
		PROC_UNLOCK(khttpd_proc);
	}
	khttpd_state = state;
	wakeup(&khttpd_state);
}

static void
khttpd_main(void *arg)
{
	struct khttpd_command_list worklist;
	sigset_t sigmask;
	struct sigaction sigact;
	struct kevent event;
	struct khttpd_command *command;
	struct khttpd_server_port *port;
	struct khttpd_server *server;
	struct khttpd_socket *socket;
	struct thread *td;
	size_t longest, len;
	int error, i;

	TRACE("enter %p", arg);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	kthread_add(khttpd_logger_main, NULL, khttpd_proc,
	    &khttpd_logger_thread, 0, 0, "khttpd_logger");

	/*
	 * Wait for the logger to be ready.
	 */

	mtx_lock(&khttpd_lock);
	while (khttpd_logger_state == KHTTPD_LOGGER_INITIALIZING)
		khttpd_logger_wait("khttpd-log-ready");
	mtx_unlock(&khttpd_lock);

	STAILQ_INIT(&worklist);
	td = curthread;
	error = 0;

	khttpd_label_hash_init(khttpd_method_hash_table,
	    sizeof(khttpd_method_hash_table) /
	    sizeof(khttpd_method_hash_table[0]), khttpd_methods,
	    sizeof(khttpd_methods) / sizeof(khttpd_methods[0]), FALSE);

	longest = 0;
	for (i = 0; i < sizeof(khttpd_fields) / sizeof(khttpd_fields[0]);
	     ++i) {
		len = strlen(khttpd_fields[i].name) + 1;
		if (longest < len)
			longest = len;
	}
	if (KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH < longest)
		panic("longest known field name  expected:%zd, actual:%zd",
		    longest, KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH);

	khttpd_label_hash_init(khttpd_field_hash_table,
	    sizeof(khttpd_field_hash_table) /
	    sizeof(khttpd_field_hash_table[0]), khttpd_fields,
	    sizeof(khttpd_fields) / sizeof(khttpd_fields[0]), TRUE);

	khttpd_route_zone = uma_zcreate("khttp-route",
	    sizeof(struct khttpd_route),
	    khttpd_route_ctor, khttpd_route_dtor, khttpd_route_init, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_response_zone = uma_zcreate("khttpd-response",
	    sizeof(struct khttpd_response),
	    khttpd_response_ctor, khttpd_response_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_request_zone = uma_zcreate("khttpd-request",
	    sizeof(struct khttpd_request),
	    khttpd_request_ctor, khttpd_request_dtor, khttpd_request_init,
	    khttpd_request_fini, UMA_ALIGN_PTR, 0);

	khttpd_socket_zone = uma_zcreate("khttpd-socket",
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor, khttpd_socket_init, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_kqueue = -1;

	error = khttpd_json_init();
	if (error != 0)
		goto cont;

	error = kern_openat(td, AT_FDCWD, "/dev/console", UIO_SYSSPACE,
	    O_WRONLY, 0666);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to open the console: %d",
		    error);
		goto cont;
	}
	khttpd_log_set_fd(&khttpd_debug_log, td->td_retval[0]);
	khttpd_debug_mask = KHTTPD_DEBUG_ALL;

	bzero(&sigact, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	error = kern_sigaction(td, SIGUSR1, &sigact, NULL, 0);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: sigaction(SIGUSR1) failed: %d",
		    error);
		goto cont;
	}

	error = kern_sigaction(td, SIGPIPE, &sigact, NULL, 0);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: sigaction(SIGPIPE) failed: %d",
		    error);
		goto cont;
	}

	SIGEMPTYSET(sigmask);
	SIGADDSET(sigmask, SIGUSR1);
	error = kern_sigprocmask(td, SIG_UNBLOCK, &sigmask, NULL, 0);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: sigprocmask() failed: %d", error);
		goto cont;
	}

	error = sys_kqueue(td, NULL);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: kqueue() failed: %d", error);
		goto cont;
	}
	khttpd_kqueue = td->td_retval[0];

	error = khttpd_kevent_add_signal(khttpd_kqueue, SIGUSR1,
	    &khttpd_stop_request_type);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: kevent(EVFILT_SIGNAL, SIGUSR1) "
		    "failed: %d", error);
		goto cont;
	}

	error = khttpd_file_init();
	if (error != 0)
		goto cont;

	server = khttpd_server_alloc("ctrl");
	SLIST_INSERT_HEAD(&khttpd_servers, server, link);

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &server->dev,
	    &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "khttpd/%s",
	    server->name);
	if (error != 0) {
		log(LOG_ERR, "khttpd: failed to create the device file: %d",
		    error);
		goto cont;
	}
	server->dev->si_drv1 = server;

cont:
	mtx_lock(&khttpd_lock);
	khttpd_server_status = error;
	khttpd_set_state(error == 0 ? KHTTPD_READY : KHTTPD_FAILED);

	while (khttpd_state != KHTTPD_UNLOADING) {
		if (khttpd_state == KHTTPD_FAILED) {
			mtx_sleep(&khttpd_state, &khttpd_lock, 0,
			    "khttpd-failed", 0);
			continue;
		}

		STAILQ_SWAP(&worklist, &khttpd_command_queue, khttpd_command);
		mtx_unlock(&khttpd_lock);

		while ((command = STAILQ_FIRST(&worklist)) != NULL) {
			STAILQ_REMOVE_HEAD(&worklist, link);
			command->status =
			    command->command(command->argument);
			wakeup(command);
		}

		error = khttpd_kevent_get(khttpd_kqueue, &event);
		if (error != 0)
			TRACE("error kevent_get %d", error);
		if (error == 0)
			((struct khttpd_event_type *)event.udata)->
			    handle_event(&event);

		KASSERT(error == 0 || error == EINTR || error == ETIMEDOUT,
		    ("kevent_get error=%d", error));

		mtx_lock(&khttpd_lock);
	}

	mtx_unlock(&khttpd_lock);

	while ((socket = LIST_FIRST(&khttpd_sockets)) != NULL)
		khttpd_socket_close(socket);

	while ((server = SLIST_FIRST(&khttpd_servers)) != NULL) {
		while ((port = SLIST_FIRST(&server->ports)) != NULL) {
			SLIST_REMOVE_HEAD(&server->ports, link);
			if (port->fd != -1)
				kern_close(td, port->fd);
			free(port, M_KHTTPD);
		}

		SLIST_REMOVE_HEAD(&khttpd_servers, link);
		khttpd_server_free(server);
	}

	if (khttpd_kqueue != -1)
		kern_close(td, khttpd_kqueue);

	khttpd_file_fini();
	khttpd_json_fini();

	mtx_lock(&khttpd_lock);
	khttpd_logger_set_state(KHTTPD_LOGGER_EXITING);
	while (khttpd_logger_state != KHTTPD_LOGGER_EXITED)
		khttpd_logger_wait("khttpd-log-exit");
	mtx_unlock(&khttpd_lock);

	khttpd_log_close(&khttpd_debug_log);

	uma_zdestroy(khttpd_socket_zone);
	uma_zdestroy(khttpd_request_zone);
	uma_zdestroy(khttpd_response_zone);
	uma_zdestroy(khttpd_route_zone);

	kproc_exit(0);
}

/* --------------------------------------------------------- ioctl handlers */

int
khttpd_run_proc(khttpd_command_proc_t proc, void *argument)
{
	struct khttpd_command *command;
	int error;

	command = malloc(sizeof(*command), M_KHTTPD, M_WAITOK);
	command->command = proc;
	command->argument = argument;
	command->status = -1;

	mtx_lock(&khttpd_lock);

	if (STAILQ_EMPTY(&khttpd_command_queue)) {
		PROC_LOCK(khttpd_proc);
		kern_psignal(khttpd_proc, SIGUSR1);
		PROC_UNLOCK(khttpd_proc);
	}

	STAILQ_INSERT_TAIL(&khttpd_command_queue, command, link);

	while ((error = command->status) == -1)
		mtx_sleep(command, &khttpd_lock, 0, "khttpd-cmd", 0);

	mtx_unlock(&khttpd_lock);

	free(command, M_KHTTPD);

	return (error);
}

static int
khttpd_internalize_fd(struct filedesc *fdp, int fd, struct filedescent *ent,
		      int flags, cap_rights_t *rights)
{
	struct filedescent *fdep;
	struct file *fp;
	int error;

	FILEDESC_LOCK_ASSERT(fdp);

	TRACE("enter %d %p", fd, fdp->fd_ofiles[fd].fde_file);

	fdep = &fdp->fd_ofiles[fd];

	if (fd < 0 || fdp->fd_lastfile < fd || (fp = fdep->fde_file) == NULL ||
	    (fp->f_flag & flags) != flags) {
		TRACE("error EBADF");
		return (EBADF);
	}

	error = cap_check(cap_rights_fde(fdep), rights);
	if (error != 0) {
		TRACE("error cap_check %d", error);
		return (error);
	}

	if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
		TRACE("error EOPNOTSUPP");
		return (EOPNOTSUPP);
	}

	fhold(fp);

	bzero(ent, sizeof(*ent));
	ent->fde_file = fp;
	filecaps_copy(&fdep->fde_caps, &ent->fde_caps, TRUE);

	return (0);
}

static void
khttpd_externalize_fd(struct filedesc *fdp, int fd, struct filedescent *ent)
{
	struct filedescent *fdep;

	TRACE("enter %d %p", fd, ent->fde_file);
	FILEDESC_XLOCK_ASSERT(fdp);
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();
	KASSERT(0 <= fd && fd <= fdp->fd_lastfile,
	    ("fd %d is out of range", fd));

	fdep = &fdp->fd_ofiles[fd];
	fdep->fde_file = ent->fde_file;
	ent->fde_file = NULL;
	filecaps_move(&ent->fde_caps, &fdep->fde_caps);
}

static int
khttpd_config_proc(void *argptr)
{
	struct listen_args listen_args;
	struct khttpd_server_port_list ports;	
	struct khttpd_config_proc_args *args;
	struct filedesc *fdp;
	struct file *fp;
	struct khttpd_server_port *port;
	struct khttpd_route *root, *tmproot;
	struct khttpd_mime_type_rule_set *rules;
	struct khttpd_server *server;
	struct thread *td;
	int i, error, *fds, *nextfdp, nfds, nsocks, *sockfds;
	int fd, docroot_fd, access_log_fd, error_log_fd;

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	SLIST_INIT(&ports);
	args = argptr;
	td = curthread;
	fdp = td->td_proc->p_fd;
	server = args->server;

	nfds = 0;
	for (i = 0; i < args->nfdes; ++i)
		if (args->fdes[i].fde_file != NULL)
			++nfds;
	fds = khttpd_malloc(nfds * sizeof(int));

	FILEDESC_XLOCK(fdp);

	error = fdallocn(td, 0, fds, nfds);
	if (error != 0) {
		FILEDESC_XUNLOCK(fdp);
		log(LOG_WARNING,
		    "khttpd: failed to allocate file descriptors: %d", error);
		goto bad1;
	}

	nextfdp = fds;
	sockfds = NULL;
	nsocks = 0;
	docroot_fd = access_log_fd = error_log_fd = -1;
	for (i = 0; i < args->nfdes; ++i) {
		fp = args->fdes[i].fde_file;
		if (fp == NULL)
			fd = -1;
		else {
			fd = *nextfdp++;
			khttpd_externalize_fd(fdp, fd, &args->fdes[i]);
		}

		switch (i) {
		case 0:	/* docroot */
			docroot_fd = fd;
			break;
		case 1: /* access log */
			access_log_fd = fd;
			break;
		case 2:	/* error log */
			error_log_fd = fd;
			break;
		case 3:
			sockfds = nextfdp - 1;
			/* FALLTHROUGH */
		default:
			if (fp != NULL)
				++nsocks;
		}
	}

	FILEDESC_XUNLOCK(fdp);

	for (i = 0; i < nsocks; ++i) {
		port = malloc(sizeof(*port), M_KHTTPD, M_WAITOK);
		port->event_type.handle_event = khttpd_accept_client;
		port->fd = sockfds[i];
		port->server = server;
		SLIST_INSERT_HEAD(&ports, port, link);

		listen_args.s = port->fd;
		listen_args.backlog = khttpd_listen_backlog;
		error = sys_listen(td, &listen_args);
		if (error != 0) {
			log(LOG_WARNING, "khttpd: failed to listen "
			    "on the given sockets: %d", error);
			goto bad2;
		}

		error = khttpd_kevent_add_read(khttpd_kqueue, port->fd,
		    &port->event_type);
		if (error != 0) {
			log(LOG_WARNING, "khttpd: failed to kevent"
			    "(EVFILT_READ) on the given sockets: %d", error);
			goto bad2;
		}
	}

	root = uma_zalloc_arg(khttpd_route_zone, &khttpd_route_type_null,
	    M_WAITOK);

	error = khttpd_route_add(root, "*", &khttpd_route_type_asterisc);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to add route '*': %d",
		    error);
		goto bad3;
	}

	error = khttpd_sysctl_route(root);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to add route for sysctl: %d",
		    error);
		goto bad3;
	}

	if (docroot_fd != -1) {
		rules = khttpd_parse_mime_type_rules
		    (khttpd_default_mime_type_rules);
		error = khttpd_file_mount("/", root, fds[0], rules);
		if (error != 0) {
			log(LOG_WARNING, "khttpd: failed to mount root docs: "
			    "%d", error);
			goto bad4;
		}
	}

	khttpd_log_set_fd(&server->access_log, access_log_fd);
	khttpd_log_set_fd(&server->error_log, error_log_fd);

	SLIST_SWAP(&server->ports, &ports, khttpd_server_port);

	tmproot = server->route_root;
	server->route_root = root;
	khttpd_route_free(tmproot);

	khttpd_free(fds);

	return (0);

bad4:
	khttpd_mime_type_rule_set_free(rules);

bad3:
	khttpd_route_free(root);
bad2:
	while ((port = SLIST_FIRST(&ports)) != NULL) {
		SLIST_REMOVE_HEAD(&ports, link);
		if (port->fd != -1)
			kern_close(td, port->fd);
		free(port, M_KHTTPD);
	}
	kern_close(td, docroot_fd);
	kern_close(td, error_log_fd);
	kern_close(td, access_log_fd);
bad1:
	khttpd_free(fds);

	return (error);
}

static int
khttpd_config(struct khttpd_server *server, struct khttpd_config_args *args)
{
	struct filedesc *fdp;
	struct khttpd_config_proc_args proc_args;
	struct thread *td;
	int *fds, nfds;
	int i, error, flags;
	cap_rights_t rights;

	TRACE("enter");

	td = curthread;
	fdp = td->td_proc->p_fd;
	nfds = args->nfds;

	fds = khttpd_malloc(nfds * sizeof(int));
	error = copyin(args->fds, fds, nfds * sizeof(int));
	if (error != 0)
		goto bad1;

	proc_args.server = server;
	proc_args.fdes = khttpd_malloc(nfds * sizeof(struct filedescent));
	bzero(proc_args.fdes, nfds * sizeof(struct filedescent));
	proc_args.nfdes = nfds;

	FILEDESC_SLOCK(fdp);

	for (i = 0; i < nfds; ++i) {
		if (fds[i] == -1)
			continue;

		switch (i) {
		case 0:
			flags = FEXEC;
			cap_rights_init(&rights, CAP_LOOKUP);
			break;

		case 1:
		case 2:
			flags = FWRITE;
			cap_rights_init(&rights, CAP_WRITE);
			break;

		default:
			flags = FREAD;
			cap_rights_init(&rights, CAP_LISTEN);
		}

		error = khttpd_internalize_fd(fdp, fds[i], &proc_args.fdes[i],
		    flags, &rights);
		if (error != 0) {
			FILEDESC_SUNLOCK(fdp);
			goto bad3;
		}
	}

	FILEDESC_SUNLOCK(fdp);

	error = khttpd_run_proc(khttpd_config_proc, &proc_args);
	if (error != 0)
		goto bad2;

	khttpd_free(proc_args.fdes);
	khttpd_free(fds);

	return (0);

bad3:
	while (0 <= --i)
		if (proc_args.fdes[i].fde_file != NULL) {
			filecaps_free(&proc_args.fdes[i].fde_caps);
			fdrop(proc_args.fdes[i].fde_file, td);
		}
bad2:
	khttpd_free(proc_args.fdes);
bad1:
	khttpd_free(fds);

	return (error);
}

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	switch (cmd) {

	case KHTTPD_IOC_CONFIG:
		error = khttpd_config(dev->si_drv1,
		    (struct khttpd_config_args *)data);
		break;

	default:
		error = ENOIOCTL;
	}

	return (error);
}

static void
khttpd_unload(void)
{
	struct khttpd_command_list worklist;
	struct khttpd_command *command;
	struct proc *proc;

	STAILQ_INIT(&worklist);

	mtx_lock(&khttpd_lock);

	/* khttpd_state is UNLOADING if load has been failed */
	while (khttpd_state != KHTTPD_UNLOADING &&
	    khttpd_state != KHTTPD_READY)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-unload", 0);

	if (khttpd_state == KHTTPD_READY)
		khttpd_set_state(KHTTPD_UNLOADING);

	STAILQ_SWAP(&worklist, &khttpd_command_queue, khttpd_command);
	mtx_unlock(&khttpd_lock);

	while ((command = STAILQ_FIRST(&worklist)) != NULL) {
		STAILQ_REMOVE_HEAD(&worklist, link);
		command->status = ECANCELED;
		wakeup(command);
	}

	while ((proc = pfind(khttpd_pid)) != NULL) {
		PROC_UNLOCK(proc);
		pause("khttpd-exit", hz);
	}

	mtx_destroy(&khttpd_lock);
}

static int
khttpd_load(void)
{
	int error;

	mtx_init(&khttpd_lock, "khttpd", NULL, MTX_DEF);

	khttpd_log_init(&khttpd_debug_log);

	error = kproc_create(khttpd_main, NULL, &khttpd_proc, 0, 0, "khttpd");
	if (error != 0) {
		log(LOG_ERR, "khttpd: failed to fork khttpd: %d", error);
		return (error);
	}

	khttpd_pid = khttpd_proc->p_pid;

	mtx_lock(&khttpd_lock);

	while (khttpd_state == KHTTPD_LOADING)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-load", 0);

	if (khttpd_state == KHTTPD_FAILED) {
		error = khttpd_server_status;
		khttpd_set_state(KHTTPD_UNLOADING);
	}

	mtx_unlock(&khttpd_lock);

	if (error != 0)
		khttpd_unload();

	return (error);
}

static int
khttpd_quiesce_proc(void *args)
{

	TRACE("enter");
	KHTTPD_CURPROC_IS_KHTTPD_ASSERT();

	return (LIST_EMPTY(&khttpd_sockets) ? 0 : EBUSY);
}

static int
khttpd_loader(struct module *m, int what, void *arg)
{
	int error;

	switch (what) {

	case MOD_LOAD:
		return (khttpd_load());

	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		khttpd_unload();
		return (0);

	case MOD_QUIESCE:
		error = khttpd_run_proc(khttpd_quiesce_proc, NULL);
		if (error != 0)
			return (error);
		error = khttpd_sdt_quiesce();
		return (error);

	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(khttpd, khttpd_loader, NULL);
