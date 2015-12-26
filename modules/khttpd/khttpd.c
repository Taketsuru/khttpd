/*-
 * Copyright (c) 2015 Taketsuru <taketsuru11@gmail.com>.
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

#include <vm/uma.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* ------------------------------------------------------- type definitions */

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
	struct khttpd_address_info	addrinfo;
	int		fd;
};

typedef int (*khttpd_receive_t)(struct khttpd_socket *);

struct khttpd_socket {
	/* must be &event_type == &<this struct> */
	struct khttpd_event_type event_type;
	LIST_ENTRY(khttpd_socket) link;
	STAILQ_HEAD(, khttpd_request) xmit_queue;
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
	struct khttpd_mbuf_pos	request_line;
	struct khttpd_mbuf_pos	header;
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

struct khttpd_label {
	const char	*name;
	int		id;
	SLIST_ENTRY(khttpd_label) link;
};

SLIST_HEAD(khttpd_label_list, khttpd_label);

/* -------------------------------------------------- prototype declrations */

static int khttpd_route_compare(struct khttpd_route *x,
    struct khttpd_route *y);

static void khttpd_kevent_nop(struct kevent *event);

static int khttpd_transmit_status_line
    (struct khttpd_socket *socket, struct khttpd_request *request,
	struct khttpd_response *response, struct mbuf **out);
static int khttpd_transmit_body_mbuf(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out);

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

struct khttpd_log_state khttpd_log_state[] = {
	{ /* KHTTPD_LOG_DEBUG */
		.mask = 0,
		.fd = -1
	},
	{ /* KHTTPD_LOG_ERROR */
		.mask = 0,
		.fd = -1
	},
	{ /* KHTTPD_LOG_ACCESS */
		.mask = 0,
		.fd = -1
	},
};

static const u_int khttpd_log_conf_valid_masks[] = {
	KHTTPD_LOG_DEBUG_ALL,	/* KHTTPD_LOG_DEBUG */
	0,			/* KHTTPD_LOG_ERROR */
	0,			/* KHTTPD_LOG_ACCESS */
};

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

/*
 * This value must be larger than the length of the longest name in
 * khttpd_fields.
 */
#define KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH	32

static struct khttpd_route_type khttpd_route_type_null = {
	.name = "<no route>",
	.received_header = khttpd_received_header_null,
};

static struct khttpd_label_list khttpd_method_hash_table[64];
static struct khttpd_label_list khttpd_field_hash_table[16];

static struct mtx khttpd_lock;
static struct cdev *khttpd_dev;
static struct proc *khttpd_proc;
static size_t khttpd_message_size_limit = 16384;
static pid_t khttpd_pid;
static int khttpd_listen_backlog = 128;
static int khttpd_state;
static int khttpd_server_status;
static boolean_t khttpd_log_writing, khttpd_log_waiting;
static char khttpd_log_buffer[1024];

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

struct khttpd_route khttpd_route_root = {
	.children_tree = SPLAY_INITIALIZER(khttpd_route_root.children_tree),
	.children_list =
	    LIST_HEAD_INITIALIZER(khttpd_route_root.children_list),
	.type = &khttpd_route_type_null,
	.parent = NULL,
	.refcount = 1,
};

static struct khttpd_route_type khttpd_route_type_asterisc = {
	.name = "asterisc",
	.received_header = khttpd_asterisc_received_header
};

static SLIST_HEAD(khttpd_server_port_list, khttpd_server_port)
    khttpd_server_ports = SLIST_HEAD_INITIALIZER(khttpd_server_port_list);

static LIST_HEAD(, khttpd_socket) khttpd_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static uma_zone_t khttpd_route_zone;
static uma_zone_t khttpd_socket_zone;
static uma_zone_t khttpd_request_zone;
static uma_zone_t khttpd_response_zone;
static int khttpd_kqueue;

/* --------------------------------------------------- function definitions */

void *khttpd_malloc(size_t size)
{

	return malloc(size, M_KHTTPD, M_WAITOK);
}

void khttpd_free(void *mem)
{

	free(mem, M_KHTTPD);
}

void khttpd_log(int type, const char *fmt, ...)
{
	struct uio auio;
	struct iovec iov[2];
	struct timeval tv;
	va_list vl;
	int len, len2;

	/* 
	 * Currently, khttpd_log can put a log entry only from the khttpd
	 * process.
	 */
	if (curproc != khttpd_proc)
		return;

	mtx_lock(&khttpd_lock);
	while (khttpd_log_writing) {
		khttpd_log_waiting = TRUE;
		mtx_sleep(&khttpd_log_writing, &khttpd_lock, 0, "khttpd-log",
		    0);
	}
	khttpd_log_writing = TRUE;
	mtx_unlock(&khttpd_lock);

	microuptime(&tv);

	va_start(vl, fmt);

	len = type == KHTTPD_LOG_DEBUG ?
	    snprintf(khttpd_log_buffer, sizeof(khttpd_log_buffer),
		"%ld.%06ld %d %s ",
		tv.tv_sec, tv.tv_usec, curthread->td_tid, va_arg(vl, char *)) :
	    snprintf(khttpd_log_buffer, sizeof(khttpd_log_buffer),
		"%ld.%06ld ", tv.tv_sec, tv.tv_usec);
	len = MIN(sizeof(khttpd_log_buffer) - 1, len);

	len2 = vsnprintf((char *)khttpd_log_buffer + len,
	    sizeof(khttpd_log_buffer) - len, fmt, vl);
	len2 = MIN(sizeof(khttpd_log_buffer) - len - 1, len2);

	len += len2;

	va_end(vl);

	iov[0].iov_base = (void *)khttpd_log_buffer;
	iov[0].iov_len = len;

	iov[1].iov_base = (void *)(khttpd_crlf + 1);
	iov[1].iov_len = 1;

	auio.uio_iov = iov;
	auio.uio_iovcnt = 2;
	auio.uio_resid = iov[0].iov_len + iov[1].iov_len;
	auio.uio_segflg = UIO_SYSSPACE;
	kern_writev(curthread, khttpd_log_state[KHTTPD_LOG_DEBUG].fd, &auio);

	mtx_lock(&khttpd_lock);
	khttpd_log_writing = FALSE;
	if (khttpd_log_waiting) {
		khttpd_log_waiting = FALSE;
		wakeup(&khttpd_log_writing);
	}
	mtx_unlock(&khttpd_lock);
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

	TRACE("enter %s", route->path);

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

	KASSERT(curproc == khttpd_proc,
	    ("curproc = %p, khttpd_proc = %p", curproc, khttpd_proc));

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
khttpd_route_add(struct khttpd_route *root, char *path,
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
					    &parent->children_tree, next);
					LIST_REMOVE(ptr, children_link);

					ptr->parent = route;
					ptr->label += len;
					ptr->label_len -= len;

					SPLAY_INSERT(khttpd_route_tree,
					    &route->children_tree, ptr);
					if (prev == NULL)
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
	m_freem(request->request_line.ptr);
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

	va_start(vl, value_fmt);
	khttpd_response_vadd_field(response, field, value_fmt, vl);
	va_end(vl);
}

void khttpd_response_vadd_field(struct khttpd_response *response,
    const char *field, const char *value_fmt, va_list vl)
{
	struct mbuf *m;

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

	KASSERT(response->status == 0, ("status=%d", response->status));
	response->status = status;
}

static void
khttpd_response_set_content_length(struct khttpd_response *response,
    off_t length)
{

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

	if (response->close)
		return;
	khttpd_response_add_field(response, "Connection", "%s", "close");
	response->close = TRUE;
}

void
khttpd_response_set_body_proc(struct khttpd_response *response,
    khttpd_transmit_t proc, off_t content_length)
{

	KASSERT(!response->has_transfer_encoding && 
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	response->transmit_body = proc;
	khttpd_response_set_content_length(response, content_length);
}

void
khttpd_response_set_body_mbuf(struct khttpd_response *response,
    struct mbuf *data)
{
	KASSERT(response->body == NULL,
	    ("response %p has body %p", response, response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	khttpd_response_set_content_length(response, m_length(data, NULL));

	response->transmit_body = khttpd_transmit_body_mbuf;
	response->body = data;
}

void
khttpd_response_set_body_bytes(struct khttpd_response *response,
    void *data, size_t size, void (*free_data)(void *))
{
	struct mbuf *m;

	KASSERT(response->body == NULL,
	    ("response %p has body %p", response, response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("response=%p, transfer_encoding_chunked=%d, "
		"has_content_length=%d",
		response, response->transfer_encoding_chunked,
		response->has_content_length));

	khttpd_response_set_content_length(response, size);

	response->transmit_body = khttpd_transmit_body_mbuf;
	response->body = m = m_gethdr(M_WAITOK, MT_DATA);
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

	socket = mem;

	socket->receive = khttpd_receive_request_line;
	socket->transmit = khttpd_transmit_status_line;

	bzero(&socket->khttpd_socket_zctor_begin,
	    offsetof(struct khttpd_socket, khttpd_socket_zctor_end) - 
	    offsetof(struct khttpd_socket, khttpd_socket_zctor_begin));

	socket->fd = -1;
	socket->refcount = 1;

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_socket *socket;
	struct thread *td;

	TRACE("enter");

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

	++socket->refcount;
}

void
khttpd_socket_free(struct khttpd_socket *socket)
{

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

	shutdown_args.s = socket->fd;
	shutdown_args.how = SHUT_WR;
	sys_shutdown(curthread, &shutdown_args);

	khttpd_socket_drain(socket);
	khttpd_socket_clear_all_requests(socket);
}

static void
khttpd_socket_set_limit(struct khttpd_socket *socket, off_t size)
{

	TRACE("enter %jd", (intmax_t)size);

	socket->recv_limit = size -
	    (m_length(socket->recv_ptr, NULL) - socket->recv_off);
}

static int
khttpd_socket_read(struct khttpd_socket *socket)
{
	struct uio auio;
	struct mbuf *m;
	struct thread *td;
	ssize_t resid;
	int error, flags;

	TRACE("enter");

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

void
khttpd_set_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{

	TRACE("enter");

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

	socket->transmit = khttpd_transmit_status_line;

	return (0);
}

static int
khttpd_transmit_trailer(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m;

	TRACE("enter");

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
	int error;

	TRACE("enter");

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
	khttpd_mbuf_printf(head, "%jx\r\n", m_length(m, NULL));
	m_cat(head, m);
	khttpd_mbuf_printf(head, "\r\n");

	return (0);
}

static int
khttpd_transmit_body_mbuf(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{

	TRACE("enter");

	*out = response->body;
	response->body = NULL;
	socket->transmit = khttpd_transmit_end;

	return (0);
}

static int
khttpd_transmit_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m;

	TRACE("enter");

	*out = m = response->header;
	response->header = NULL;

	if (m == NULL)
		m = m_gethdr(M_WAITOK, MT_DATA);

	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));

	if (response->status == 204 || response->status == 304 ||
	    request->method == KHTTPD_METHOD_HEAD)
		socket->transmit = khttpd_transmit_end;

	else if (response->transfer_encoding_chunked)
		socket->transmit = khttpd_transmit_chunk;

	else if (0 < response->content_length)
		socket->transmit = response->transmit_body;

	else
		socket->transmit = khttpd_transmit_end;

	return (0);
}

static int
khttpd_transmit_status_line(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct mbuf *m;

	TRACE("enter");

	*out = m = m_gethdr(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(m, "HTTP/1.%d %d n/a\r\n", response->version_minor,
	    response->status);
	response->header_closed = TRUE;
	socket->transmit = khttpd_transmit_header;

	return (0);
}

void khttpd_transmit_finished(struct khttpd_socket *socket)
{

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

	khttpd_set_error_response(socket, request, NULL, 431,
	    "Request Header Fields Too Large",
	    "The header fields in the request is too large.", TRUE);
}

void
khttpd_set_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");

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

	if (request->close)
		khttpd_socket_drain(socket);
	request->end_of_message(socket, request);
	socket->recv_request = NULL;
	khttpd_request_free(request);
	socket->receive = khttpd_receive_request_line;
}

static int
khttpd_receive_crlf_following_chunk_data(struct khttpd_socket *socket)
{
	struct khttpd_mbuf_pos pos;
	struct khttpd_request *request;
	int ch, error;

	TRACE("enter");

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
	struct khttpd_mbuf_pos pos, tmppos;
	const char *cp;
	char *end;
	struct khttpd_request *request;
	struct khttpd_route *route;
	int ch, error;

	TRACE("enter");

	/*
	 * Free mbufs preceding the current reading position.
	 */

	if (socket->recv_leftovers != NULL &&
	    socket->recv_leftovers != socket->recv_ptr)
		socket->recv_leftovers = m_free(socket->recv_leftovers);

	/* 
	 * Get a line.
	 */

	khttpd_socket_set_limit(socket, khttpd_message_size_limit);
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
		if (pos.unget == -1 &&
		    (pos.ptr == NULL ||
			(pos.ptr->m_next == NULL && pos.off == pos.ptr->m_len)))
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
	 * Take the ownership of the receiving mbuf chain.
	 */

	khttpd_mbuf_pos_copy(&pos, &request->request_line);
	socket->recv_leftovers = NULL;

	/* 
	 * If the request line is larger than khttpd_message_size_limit, send
	 * 'URI too long' response message.
	 */

	if (error == ENOBUFS) {
		khttpd_set_uri_too_long_response(socket, request);
		return (0);
	}

	/*
	 * If the request line is terminated prematurely, send 'Bad Request'
	 * response message.
	 */

	if (error == ENOENT) {
		khttpd_set_bad_request_response(socket, request);
		return (0);
	}

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

	route = khttpd_route_find(&khttpd_route_root,
	    sbuf_data(&request->target), &request->suffix);
	if (route == NULL) {
		khttpd_set_not_found_response(socket, request, FALSE);
		route = &khttpd_route_root;
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

	td = curthread;
	port = event->udata;

	socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);

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

	td = curthread;
	so = socket->fp->f_data;

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
	struct khttpd_socket *socket;
	struct khttpd_server_port *port;
	struct thread *td;
	size_t longest, len;
	int debug_fd, error, i;

	TRACE("enter %p", arg);

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
		printf("khttpd: failed to open the console: %d\n", error);
		goto cont;
	}
	debug_fd = td->td_retval[0];

	//khttpd_log_state[KHTTPD_LOG_DEBUG].mask = KHTTPD_LOG_DEBUG_ALL;
	khttpd_log_state[KHTTPD_LOG_DEBUG].fd = debug_fd;

	error = kern_dup(td, FDDUP_NORMAL, 0, debug_fd, 0);
	if (error != 0) {
		printf("khttpd: failed to duplicate debug_fd: %d", error);
		goto cont;
	}
	khttpd_log_state[KHTTPD_LOG_ERROR].fd = td->td_retval[0];

	error = kern_dup(td, FDDUP_NORMAL, 0, debug_fd, 0);
	if (error != 0) {
		printf("khttpd: failed to duplicate debug_fd: %d", error);
		goto cont;
	}
	khttpd_log_state[KHTTPD_LOG_ACCESS].fd = td->td_retval[0];

	bzero(&sigact, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	error = kern_sigaction(td, SIGUSR1, &sigact, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigaction(SIGUSR1) failed: %d\n", error);
		goto cont;
	}

	error = kern_sigaction(td, SIGPIPE, &sigact, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigaction(SIGPIPE) failed: %d\n", error);
		goto cont;
	}

	SIGEMPTYSET(sigmask);
	SIGADDSET(sigmask, SIGUSR1);
	error = kern_sigprocmask(td, SIG_UNBLOCK, &sigmask, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigprocmask() failed: %d\n", error);
		goto cont;
	}

	error = sys_kqueue(td, NULL);
	if (error != 0) {
		printf("khttpd: kqueue() failed: %d\n", error);
		goto cont;
	}
	khttpd_kqueue = td->td_retval[0];

	error = khttpd_kevent_add_signal(khttpd_kqueue, SIGUSR1,
	    &khttpd_stop_request_type);
	if (error != 0) {
		printf("khttpd: kevent(EVFILT_SIGNAL, SIGUSR1) failed: %d\n",
		    error);
		goto cont;
	}

	error = khttpd_route_add(&khttpd_route_root, "*",
	    &khttpd_route_type_asterisc);
	if (error != 0) {
		printf("khttpd: failed to add route '*': %d\n", error);
		goto cont;
	}

	error = khttpd_file_init();

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
			command->status = command->command(command->argument);
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

	while ((port = SLIST_FIRST(&khttpd_server_ports)) != NULL) {
		SLIST_REMOVE_HEAD(&khttpd_server_ports, link);
		if (port->fd != -1)
			kern_close(td, port->fd);
		free(port, M_KHTTPD);
	}

	if (khttpd_kqueue != -1)
		kern_close(td, khttpd_kqueue);

	khttpd_route_clear_all(&khttpd_route_root);

	for (i = 0; i < KHTTPD_LOG_END; ++i)
		if (khttpd_log_state[i].fd != -1) {
			kern_close(td, khttpd_log_state[i].fd);
			khttpd_log_state[i].fd = -1;
		}

	khttpd_file_fini();
	khttpd_json_fini();

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
khttpd_open_server_port(void *arg)
{
	struct socket_args socket_args;
	struct listen_args listen_args;
	struct khttpd_server_port *port;
	struct thread *td;
	int error;

	TRACE("enter");

	KASSERT(curproc == khttpd_proc,
	    ("curproc=%p, khttpd_proc=%p", curproc, khttpd_proc));

	port = arg;
	td = curthread;

	KASSERT(port->fd == -1, ("port->fd=%d", port->fd));

	socket_args.domain = port->addrinfo.ai_family;
	socket_args.type = port->addrinfo.ai_socktype;
	socket_args.protocol = port->addrinfo.ai_protocol;
	error = sys_socket(td, &socket_args);
	if (error != 0) {
		TRACE("error socket %d", error);
		return (error);
	}
	port->fd = td->td_retval[0];
	TRACE("fd %d", port->fd);

	error = kern_bindat(td, AT_FDCWD, port->fd,
	    (struct sockaddr *)&port->addrinfo.ai_addr);
	if (error != 0) {
		TRACE("error bind %d", error);
		goto bad;
	}

	listen_args.s = port->fd;
	listen_args.backlog = khttpd_listen_backlog;
	error = sys_listen(td, &listen_args);
	if (error != 0) {
		TRACE("error listen %d", error);
		goto bad;
	}

	error = khttpd_kevent_add_read(khttpd_kqueue, port->fd,
	    &port->event_type);
	if (error != 0) {
		TRACE("error kevent %d", error);
		goto bad;
	}

	SLIST_INSERT_HEAD(&khttpd_server_ports, port, link);

	return (0);

bad:
	kern_close(td, port->fd);
	port->fd = -1;

	return (error);
}

static int
khttpd_add_port(struct khttpd_address_info *ai)
{
	struct khttpd_server_port *port;
	int error;

	port = malloc(sizeof(*port), M_KHTTPD, M_WAITOK);
	port->event_type.handle_event = khttpd_accept_client;
	bcopy(ai, &port->addrinfo, sizeof(port->addrinfo));
	port->fd = -1;

	error = khttpd_run_proc(khttpd_open_server_port, port);

	if (error != 0)
		free(port, M_KHTTPD);

	return (error);
}

static int
khttpd_set_log_conf(void *argument)
{
	struct filedesc *fdp;
	struct filedescent *srcfde, *dstfde;
	struct khttpd_log_conf *conf;
	struct khttpd_log_state *state;
	struct thread *td;
	int error, newfd;

	conf = argument;

	TRACE("enter %d %#x", conf->type, conf->mask);

	KASSERT(curproc == khttpd_proc,
	    ("curproc=%p, khttpd_proc=%p", curproc, khttpd_proc));

	td = curthread;
	fdp = td->td_proc->p_fd;

	FILEDESC_XLOCK(fdp);

	error = fdalloc(td, 0, &newfd);
	if (error != 0) {
		TRACE("error fdalloc %d", error);
		fdrop(conf->fde->fde_file, td);
		FILEDESC_XUNLOCK(fdp);
		return (error);
	}

	srcfde = conf->fde;
	dstfde = &fdp->fd_ofiles[newfd];
	dstfde->fde_file = srcfde->fde_file;
	filecaps_move(&srcfde->fde_caps, &dstfde->fde_caps);

	FILEDESC_XUNLOCK(fdp);

	state = &khttpd_log_state[conf->type];
	if (state->fd != -1)
		kern_close(curthread, state->fd);
	state->mask = conf->mask;
	state->fd = newfd;

	TRACE("fd %d", newfd);

	return (0);
}

static int
khttpd_configure_log(struct khttpd_log_conf *conf)
{
	struct filedesc *fdp;
	struct file *fp;
	struct filedescent fde, *fdep;
	struct thread *td;
	u_int mask;
	int error, fd, type;

	type = conf->type;
	if (type < KHTTPD_LOG_DEBUG || KHTTPD_LOG_ACCESS < type)
		return (EINVAL);

	mask = conf->mask;
	if ((mask & khttpd_log_conf_valid_masks[type]) != mask)
		return (EINVAL);

	td = curthread;
	fd = conf->fd;
	fdp = td->td_proc->p_fd;

	FILEDESC_SLOCK(fdp);

	fdep = &fdp->fd_ofiles[conf->fd];

	if (fd < 0 || fdp->fd_lastfile < fd ||
	    (fp = fdep->fde_file) == NULL) {
		error = EBADF;
		goto out;
	}

	if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
		error = EOPNOTSUPP;
		goto out;
	}

	fhold(fp);

	fde.fde_file = fp;
	filecaps_copy(&fdep->fde_caps, &fde.fde_caps, true);
	FILEDESC_SUNLOCK(fdp);

	conf->fde = &fde;

	return (khttpd_run_proc(khttpd_set_log_conf, conf));

out:
	FILEDESC_SUNLOCK(fdp);

	return (error);
}

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	switch (cmd) {

	case KHTTPD_IOC_CONFIGURE_LOG:
		error = khttpd_configure_log((struct khttpd_log_conf *)data);
		break;

	case KHTTPD_IOC_ADD_PORT:
		error = khttpd_add_port((struct khttpd_address_info *)data);
		break;

	case KHTTPD_IOC_MOUNT:
		error = khttpd_mount((struct khttpd_mount_args *)data);
		break;

	case KHTTPD_IOC_SET_MIME_TYPE_RULES:
		error = khttpd_set_mime_type_rules
		    ((struct khttpd_set_mime_type_rules_args *)data);
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

	if (khttpd_dev != NULL)
		destroy_dev(khttpd_dev);

	khttpd_sdt_unload();
	khttpd_sysctl_unload();

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

	/* khttpd_pid is 0 if fork has been failed. */
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

	error = kproc_create(khttpd_main, NULL, &khttpd_proc, 0, 0, "khttpd");
	if (error != 0) {
		printf("khttpd: failed to fork khttpd: %d\n", error);
		goto bad;
	}

	khttpd_pid = khttpd_proc->p_pid;

	mtx_lock(&khttpd_lock);
	while (khttpd_state == KHTTPD_LOADING)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-load", 0);
	if (khttpd_state == KHTTPD_FAILED) {
		error = khttpd_server_status;
		goto bad;
	}
	mtx_unlock(&khttpd_lock);

	error = khttpd_sysctl_load();
	if (error != 0)
		goto bad;

	error = khttpd_sdt_load();
	if (error != 0)
		goto bad;

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &khttpd_dev,
	    &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "khttpd");
	if (error != 0) {
		printf("khttpd: failed to create /dev/khttpd: %d\n", error);
		goto bad;
	}

	return (0);

bad:
	khttpd_set_state(KHTTPD_UNLOADING);
	mtx_unlock(&khttpd_lock);
	khttpd_unload();

	return (error);
}

static int
khttpd_quiesce_proc(void *args)
{
	int error;

	TRACE("enter");

	error = LIST_EMPTY(&khttpd_sockets) ? 0 : EBUSY;
	if (error != 0)
		printf("khttpd: the server still has a connection.\n");
	return (error);
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
