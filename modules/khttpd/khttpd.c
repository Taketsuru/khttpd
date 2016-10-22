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

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stack.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
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
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/un.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>

#include <vm/uma.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "khttpd.h"
#include "khttpd_private.h"

#ifndef KHTTPD_MAX_PORTS_PER_SERVER
#define KHTTPD_MAX_PORTS_PER_SERVER	4
#endif

#ifndef KHTTPD_MSGBUF_LIMIT
#define KHTTPD_MSGBUF_LIMIT	1024
#endif

#ifndef KHTTPD_LOG_LIMIT
#define KHTTPD_LOG_LIMIT	1024
#endif

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

enum {
	/* triggered when all the worker threads should exit */
	KHTTPD_EVENT_SHUTDOWN_WORKERS,
};

/*
 *	* - read only
 *	0 - only the receiver or the xmitter can access
 *	a - atomic
 *	p - khttpd_lock
 *	s - khttpd_socket lock
 */

struct khttpd_log {
	TAILQ_ENTRY(khttpd_log) link;
	struct mbufq	queue;
	int		fd;
	boolean_t	draining;
	boolean_t	choking;
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
	struct khttpd_event_type	event_type;
	LIST_ENTRY(khttpd_socket) link;
	off_t			recv_limit;
	khttpd_receive_t	receive;
	khttpd_transmit_t	transmit;
	int			fd;
	u_int			refcount;

#define khttpd_socket_zero_begin peer_addr
	struct sockaddr_storage peer_addr;
	struct khttpd_server_port *port;
	struct file		*fp;
	struct mbuf		*recv_leftovers;
	struct mbuf		*recv_ptr;
	struct mbuf		*recv_bol_ptr;
	struct khttpd_request	*recv_request;
	struct mbuf		*recv_tail;
	struct mbuf		*xmit_buf;
	struct khttpd_request	*xmit_request;
	u_int			recv_off;
	u_int			recv_bol_off;
	unsigned		recv_found_bol:1;
	unsigned		recv_eof:1;
	unsigned		recv_drain:1;
	unsigned		xmit_shutdown:1;
	unsigned		xmit_scheduled:1;
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
	struct mbuf		*request_line;
	struct mbuf		*trailer;
	struct khttpd_response	*response;
	struct khttpd_route	*route;
	void		*data;
	const char	*query;
	const char	*suffix;
	u_int		transfer_encoding_count;
	unsigned	method:8;
	unsigned	version_minor:8;
	unsigned	close:1;
	unsigned	continue_response:1;
	unsigned	has_content_length:1;
	unsigned	has_transfer_encoding:1;
	unsigned	has_expect_continue:1;
	unsigned	response_committed:1;
	unsigned	receiving_chunk_and_trailer:1;
	unsigned	transfer_encoding_chunked:1;

#define khttpd_request_zctor_end	ref_count
	u_int		ref_count;
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
	unsigned	status:16;
	unsigned	has_content_length:1;
	unsigned	has_transfer_encoding:1;
	unsigned	transfer_encoding_chunked:1;
	unsigned	header_closed:1;
	unsigned	close:1;

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

struct khttpd_listen_proc_args {
	struct khttpd_server	*server;
	struct filedescent	*fdes;
	int			nfdes;
};

struct khttpd_config_log_proc_args {
	struct khttpd_server *server;
	struct filedescent fde;
	int	log;
};

struct khttpd_worker {
	TAILQ_ENTRY(khttpd_worker) link;
};

TAILQ_HEAD(khttpd_worker_queue, khttpd_worker);

/* -------------------------------------------------- prototype declrations */

static int khttpd_route_compare(struct khttpd_route *x,
    struct khttpd_route *y);

static void khttpd_socket_handle_event(struct kevent *event);

static int khttpd_transmit_status_line_and_header
    (struct khttpd_socket *socket, struct khttpd_request *request,
	struct khttpd_response *response, struct mbuf **out);

static int khttpd_receive_chunk(struct khttpd_socket *receiver);
static int khttpd_receive_body(struct khttpd_socket *receiver);
static int khttpd_receive_header_or_trailer(struct khttpd_socket *receiver);
static int khttpd_receive_request_line(struct khttpd_socket *receiver);

static void khttpd_asterisc_received_header(struct khttpd_socket *receiver,
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

/*
 * This value must be larger than the length of the longest name in
 * khttpd_fields.
 */
#define KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH	32

static struct khttpd_label_list khttpd_method_hash_table[64];
static struct khttpd_label_list khttpd_field_hash_table[16];

static cap_rights_t khttpd_socket_rights;
static struct mtx khttpd_lock;
struct proc *khttpd_proc;
struct thread *khttpd_main_thread;
static TAILQ_HEAD(, khttpd_log) khttpd_busy_logs;
static size_t khttpd_message_size_limit = 16384;
static pid_t khttpd_pid;
int khttpd_debug_mask;
static int khttpd_listen_backlog = 128;
static int khttpd_state;
static int khttpd_server_status;

const char khttpd_crlf[] = { '\r', '\n' };

static struct cdevsw khttpd_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl   = khttpd_ioctl,
	.d_name	   = "khttpd"
};

/*
 * khttpd process-local variables
 */

static struct khttpd_route_type khttpd_route_type_null = {
	.received_header = khttpd_received_header_null,
};

static struct khttpd_route_type khttpd_route_type_asterisc = {
	.received_header = khttpd_asterisc_received_header
};

static struct khttpd_socket_list khttpd_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static struct khttpd_server_list khttpd_servers =
    SLIST_HEAD_INITIALIZER(khttpd_server_list);

static struct khttpd_worker_queue khttpd_waiting_workers =
    TAILQ_HEAD_INITIALIZER(khttpd_waiting_workers);
static uma_zone_t khttpd_route_zone;
static uma_zone_t khttpd_socket_zone;
static uma_zone_t khttpd_request_zone;
static uma_zone_t khttpd_response_zone;
static int khttpd_kqueue;
static int khttpd_worker_count;
static int khttpd_worker_count_max;
static boolean_t khttpd_worker_shutdown;
static boolean_t khttpd_worker_initializing;

static struct sx khttpd_msgbuf_lock;
static struct mbufq khttpd_msgbuf;

/* --------------------------------------------------- function definitions */

/*
 * malloc/free/realloc wrapper functions
 */

void *khttpd_malloc(size_t size)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	void *mem;

	mem = malloc(size, M_KHTTPD, M_WAITOK);

#ifdef KHTTPD_TRACE_MALLOC
	TR2("alloc %p %#lx", mem, size);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 8, 0);
#endif
	return (mem);
}

void khttpd_free(void *mem)
{

	free(mem, M_KHTTPD);

#ifdef KHTTPD_TRACE_MALLOC
	TR1("free %p", mem);
#endif
}

void *khttpd_realloc(void *mem, size_t size)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	void *newmem;

	newmem = realloc(mem, size, M_KHTTPD, M_WAITOK);

#ifdef KHTTPD_TRACE_MALLOC
	TR1("free %p", mem);
	TR2("alloc %p %#lx", newmem, size);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 8, 0);
#endif

	return (newmem);
}

char *khttpd_strdup(const char *str)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	char *newstr;

	newstr = strdup(str, M_KHTTPD);

#ifdef KHTTPD_TRACE_MALLOC
	TR2("alloc %p %#lx", newstr, strlen(newstr) + 1);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 8, 0);
#endif

	return (newstr);
}

/*
 * message buffer
 */

static void khttpd_msgbuf_init(void)
{

	sx_init(&khttpd_msgbuf_lock, "khttpd-msgbuf");
	mbufq_init(&khttpd_msgbuf, KHTTPD_MSGBUF_LIMIT);
}

static void khttpd_msgbuf_fini(void)
{

	sx_destroy(&khttpd_msgbuf_lock);
	mbufq_drain(&khttpd_msgbuf);
}

void khttpd_msgbuf_put(const char *func, const char *fmt, ...)
{
	struct mbuf *m;
	va_list vl;

	va_start(vl, fmt);

	sx_xlock(&khttpd_msgbuf_lock);

	while (mbufq_full(&khttpd_msgbuf))
		m_freem(mbufq_dequeue(&khttpd_msgbuf));

	m = m_get(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(m, "%lld %s ", get_cyclecount(), func);
	khttpd_mbuf_vprintf(m, fmt, vl);
	khttpd_mbuf_append_ch(m, '\n');
	mbufq_enqueue(&khttpd_msgbuf, m);

	sx_xunlock(&khttpd_msgbuf_lock);

	va_end(vl);
}

/*
 * logging
 */

static void
khttpd_log_init(struct khttpd_log *log)
{

	log->fd = -1;
	log->draining = FALSE;
	log->choking = FALSE;
	mbufq_init(&log->queue, KHTTPD_LOG_LIMIT);
}

static void
khttpd_log_choke(struct khttpd_log *log)
{

	mtx_lock(&khttpd_lock);

	log->choking = TRUE;

	if (0 < mbufq_len(&log->queue)) {
		TAILQ_REMOVE(&khttpd_busy_logs, log, link);
		TAILQ_INSERT_HEAD(&khttpd_busy_logs, log, link);

		while (0 < mbufq_len(&log->queue)) {
			log->draining = TRUE;
			mtx_sleep(log, &khttpd_lock, 0, "khttpd-log-drain", 0);
		}
	}

	mtx_unlock(&khttpd_lock);
}

static void
khttpd_log_dechoke(struct khttpd_log *log)
{

	mtx_lock(&khttpd_lock);

	log->choking = FALSE;
	wakeup(&log);

	mtx_unlock(&khttpd_lock);
}

static void
khttpd_log_close(struct khttpd_log *log)
{

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	khttpd_log_choke(log);

	if (log->fd != -1) {
		kern_close(curthread, log->fd);
		log->fd = -1;
	}

	khttpd_log_dechoke(log);
}

static void
khttpd_log_set_fd(struct khttpd_log *log, int fd)
{
	int old_fd;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	khttpd_log_choke(log);

	old_fd = log->fd;
	log->fd = fd;
	if (old_fd != -1)
		kern_close(curthread, old_fd);

	khttpd_log_dechoke(log);
}

static void
khttpd_log_enqueue(struct khttpd_log *log, struct mbuf *m)
{

	mtx_lock(&khttpd_lock);

	while (log->choking || mbufq_full(&log->queue))
		mtx_sleep(log, &khttpd_lock, 0, "khttpd-choke", 0);

	if (log->fd == -1) {
		m_freem(m);

	} else {
		if (mbufq_len(&log->queue) == 0) {
			if (TAILQ_EMPTY(&khttpd_busy_logs))
				wakeup(&khttpd_busy_logs);
			TAILQ_INSERT_HEAD(&khttpd_busy_logs, log, link);
		}

		mbufq_enqueue(&log->queue, m);
	}

	mtx_unlock(&khttpd_lock);
}

static void
khttpd_log_timestamp(struct mbuf *out)
{
	struct timeval tv;

	microtime(&tv);
	khttpd_mbuf_printf(out, "\"timestamp\": %ld.%06ld", tv.tv_sec,
	    tv.tv_usec);
}		

static void
khttpd_log_request_line(struct mbuf *out, struct khttpd_request *request)
{
	const char *begin, *end, *cp;
	struct mbuf *m;

	khttpd_mbuf_printf(out, "\"request\": \"");
	for (m = request->request_line; m != NULL; m = m->m_next) {
		begin = mtod(m, char *);
		end = begin + m->m_len;
		cp = khttpd_find_ch_in(begin, end, '\n');
		if (cp == NULL)
			khttpd_json_mbuf_append_string_wo_quote(out, begin,
			    end);
		else  {
			khttpd_json_mbuf_append_string_wo_quote(out, begin,
			    cp + 1);
			break;
		}
	}
	khttpd_mbuf_append_ch(out, '"');
}

static void
khttpd_log_peer_info(struct mbuf *out, struct khttpd_socket *socket)
{

	switch (socket->peer_addr.ss_family) {

	case AF_INET:
		khttpd_mbuf_printf(out,
		    "\"family\": \"inet\", \"address\": \"");
		khttpd_mbuf_print_sockaddr_in(out,
		    (struct sockaddr_in *)&socket->peer_addr);
		khttpd_mbuf_append_ch(out, '"');
		break;

	case AF_INET6:
		khttpd_mbuf_printf(out,
		    "\", \"family\": \"inet6\", \"address\": \"");
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
}

static void
khttpd_access(struct khttpd_server *server, struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct khttpd_response *response;
	struct mbuf *ent;

	if (server->access_log.fd == -1)
		return;

	ent = m_get(M_WAITOK, MT_DATA);

	khttpd_mbuf_append_ch(ent, '{');
	khttpd_log_timestamp(ent);
	khttpd_mbuf_printf(ent, ", ");
	khttpd_log_request_line(ent, request);
	khttpd_mbuf_printf(ent, ", ");
	khttpd_log_peer_info(ent, socket);

	response = request->response;

	khttpd_mbuf_printf(ent, ", \"status\": %d", response->status);

	if (response->payload_size != 0)
		khttpd_mbuf_printf(ent, ", \"responsePayloadSize\": %jd",
		    (uintmax_t)response->payload_size);

	if (request->payload_size != 0)
		khttpd_mbuf_printf(ent, ", \"requestPayloadSize\": %jd",
		    (uintmax_t)response->payload_size);

	khttpd_mbuf_printf(ent, "}\n");

	khttpd_log_enqueue(&server->access_log, ent);
}

void
khttpd_verror(struct khttpd_server *server, struct khttpd_socket *socket,
    struct khttpd_request *request, const char *fmt, va_list ap)
{
	struct mbuf *ent;
	struct sbuf *sbuf;

	if (server->error_log.fd == -1)
		return;

	ent = m_get(M_WAITOK, MT_DATA);

	khttpd_mbuf_append_ch(ent, '{');
	khttpd_log_timestamp(ent);

	if (socket != NULL) {
		khttpd_mbuf_printf(ent, ", ");
		khttpd_log_peer_info(ent, socket);
	}

	if (request != NULL) {
		khttpd_mbuf_printf(ent, ", ");
		khttpd_log_request_line(ent, request);
	}

	sbuf = sbuf_new_auto();
	sbuf_vprintf(sbuf, fmt, ap);
	sbuf_finish(sbuf);
	khttpd_mbuf_printf(ent, ", ");
	khttpd_json_mbuf_append_string(ent, sbuf_data(sbuf), sbuf_data(sbuf) +
	    sbuf_len(sbuf));
	sbuf_delete(sbuf);

	khttpd_mbuf_printf(ent, "}\n");

	khttpd_log_enqueue(&server->access_log, ent);
}

void
khttpd_error(struct khttpd_server *server, struct khttpd_socket *socket,
    struct khttpd_request *request, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	khttpd_verror(server, socket, request, fmt, ap);
	va_end(ap);
}

static void
khttpd_logger_main(void *arg)
{
	struct iovec iovs[64];
	struct uio auio;
	struct thread *td;
	struct khttpd_log *l;
	struct mbuf *pkt, *m;
	ssize_t resid;
	int error, i, niov;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	td = curthread;
	niov = sizeof(iovs) / sizeof(iovs[0]);
	error = 0;

	mtx_lock(&khttpd_lock);

	for (;;) {

		while (khttpd_state == KHTTPD_READY &&
		    TAILQ_EMPTY(&khttpd_busy_logs))
			mtx_sleep(&khttpd_busy_logs, &khttpd_lock, 0,
			    "khttpd-log", 0);

		l = TAILQ_FIRST(&khttpd_busy_logs);
		if (l == NULL && khttpd_state != KHTTPD_READY)
			break;
		TAILQ_REMOVE(&khttpd_busy_logs, l, link);

		pkt = mbufq_flush(&l->queue);
		if (l->draining) {
			l->draining = FALSE;
			wakeup(l);
		}

		mtx_unlock(&khttpd_lock);

		while (pkt != NULL) {
			m = pkt;

			while (m != NULL && error == 0) {
				resid = 0;
				for (i = 0; i < niov && m != NULL;
				     ++i, m = m->m_next) {
					iovs[i].iov_base = mtod(m, void *);
					iovs[i].iov_len = m->m_len;
					resid += m->m_len;
				}

				auio.uio_iov = iovs;
				auio.uio_iovcnt = i;
				auio.uio_offset = 0;
				auio.uio_resid = resid;
				auio.uio_segflg = UIO_SYSSPACE;
				auio.uio_td = td;
				error = kern_writev(td, l->fd, &auio);

				if (error != 0)
					log(LOG_WARNING, "khttpd: "
					    "write to log faild (error: %d)",
					    error);
			}

			m = pkt;
			pkt = STAILQ_NEXT(pkt, m_stailqpkt);
			m_freem(m);
		}

		mtx_lock(&khttpd_lock);
	}

	KASSERT(TAILQ_EMPTY(khttpd_busy_logs),
	    ("khttpd_busy_logs is not empty"));

	mtx_unlock(&khttpd_lock);

	kthread_exit();
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
khttpd_kevent(int kq, struct kevent *changes, int nchanges,
    struct kevent *eventlist, int nevents, int *nevent_out,
    const struct timespec *timeout)
{
	struct thread *td;
	int error;

	struct khttpd_kevent_args args = {
		.changelist = changes,
		.eventlist  = eventlist
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	td = curthread;
	error = kern_kevent(td, kq, nchanges, nevents, &k_ops, timeout);
	if (nevent_out != NULL)
		*nevent_out = td->td_retval[0];

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
		    (cp + ptr->label_len < end && cp[ptr->label_len] != '/' &&
			strncmp(ptr->label, "/", ptr->label_len) != 0))
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

	/* socket->recv_request and xmit_request */
	refcount_init(&request->ref_count, 2);

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
	khttpd_response_free(request->response);
	khttpd_route_free(request->route);
}

void khttpd_request_hold(struct khttpd_request *request)
{

	refcount_acquire(&request->ref_count);
}

void khttpd_request_free(struct khttpd_request *request)
{

	if (request != NULL && refcount_release(&request->ref_count))
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

	bzero(&response->khttpd_response_zctor_begin,
	    offsetof(struct khttpd_response, khttpd_response_zctor_end) -
	    offsetof(struct khttpd_response, khttpd_response_zctor_begin));
	response->version_minor = 1;

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
			log(LOG_WARNING,
			    "Field %s is added to a closed header.", field);
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

void
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
	    ("transfer_encoding_chunked=%d, has_content_length=%d",
		response->transfer_encoding_chunked,
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

	KASSERT(response->body == NULL, ("response->body=%p", response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("transfer_encoding_chunked=%d, has_content_length=%d",
		response->transfer_encoding_chunked,
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

	KASSERT(response->body == NULL, ("response->body=%p", response->body));
	KASSERT(!response->has_transfer_encoding &&
	    !response->has_content_length,
	    ("transfer_encoding_chunked=%d, has_content_length=%d",
		response->transfer_encoding_chunked,
		response->has_content_length));

	khttpd_response_set_content_length(response, size);

	response->payload_size = size;
	response->body = m = m_get(M_WAITOK, MT_DATA);
	m_extadd(m, data, size, free_data == NULL ?
	    khttpd_response_free_body_extbuf_null :
	    khttpd_response_free_body_extbuf,
	    free_data, data, 0, EXT_EXTREF);
}

/*
 * socket
 */

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;

	socket = mem;
	socket->event_type.handle_event = khttpd_socket_handle_event;
	return (0);
}

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket;

	TRACE("enter");

	socket = mem;
	socket->recv_limit = khttpd_message_size_limit;
	socket->receive = khttpd_receive_request_line;
	socket->transmit = khttpd_transmit_status_line_and_header;
	socket->fd = -1;
	refcount_init(&socket->refcount, 1);

	bzero(&socket->khttpd_socket_zero_begin,
	    sizeof(struct khttpd_socket) -
	    offsetof(struct khttpd_socket, khttpd_socket_zero_begin));

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_socket *socket;
	struct thread *td;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	socket = mem;
	td = curthread;

	KASSERT(socket->recv_request == NULL,
	    ("socket->recv_request=%p", socket->recv_request));
	KASSERT(socket->xmit_request == NULL,
	    ("socket->xmit_request=%p", socket->xmit_request));
	KASSERT(socket->refcount == 0, ("refcount=%d", socket->refcount));

	m_freem(socket->recv_leftovers);
	m_freem(socket->xmit_buf);

	if (socket->fd != -1)
		kern_close(td, socket->fd);

	if (socket->fp != NULL)
		fdrop(socket->fp, td);
}

void
khttpd_socket_hold(struct khttpd_socket *socket)
{

	refcount_acquire(&socket->refcount);
}

void
khttpd_socket_free(struct khttpd_socket *socket)
{

	if (socket != NULL && refcount_release(&socket->refcount))
		uma_zfree(khttpd_socket_zone, socket);
}

int
khttpd_socket_fd(struct khttpd_socket *socket)
{

	return socket->fd;
}

static void
khttpd_socket_close(struct khttpd_socket *socket)
{
	struct thread *td;
	struct khttpd_request *request;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	if ((request = socket->recv_request) != NULL) {
		khttpd_request_free(request);
		socket->recv_request = NULL;
	}

	if ((request = socket->xmit_request) != NULL) {
		khttpd_request_free(request);
		socket->xmit_request = NULL;
	}

	td = curthread;

	if (socket->fd != -1) {
		kern_close(td, socket->fd);
		socket->fd = -1;
	}

	if (socket->fp != NULL) {
		fdrop(socket->fp, td);
		socket->fp = NULL;
	}

	mtx_lock(&khttpd_lock);
	LIST_REMOVE(socket, link);
	mtx_unlock(&khttpd_lock);

	khttpd_socket_free(socket);
}

static void
khttpd_socket_commit_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct socket *so;
	int error, nopush;

	TRACE("enter");

	if (request->response_committed)
		return;

	request->response_committed = TRUE;

	so = socket->fp->f_data;
	nopush = 1;
	error = so_setsockopt(so, IPPROTO_TCP, TCP_NOPUSH, &nopush,
	    sizeof(nopush));
	if (error != 0)
		log(LOG_WARNING, "khttpd: setsockopt(TCP_NOPUSH): %d", error);

	socket->xmit_scheduled = TRUE;
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
khttpd_socket_set_receive_limit(struct khttpd_socket *socket, off_t size)
{
	int len;

	TRACE("enter %jd", (intmax_t)size);

	len = m_length(socket->recv_ptr, NULL) - socket->recv_off;
	socket->recv_limit = size - len;
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
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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
	else
		socket->recv_tail->m_next = m;

	socket->recv_tail = m == NULL ? NULL : m_last(m);

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
		/* Find the first '\n' in the mbuf pointed by ptr. */

		begin = mtod(ptr, char *);
		end = begin + ptr->m_len;
		cp = khttpd_find_ch_in(begin + off, end, '\n');
		if (cp != NULL) {
			socket->recv_ptr = ptr;
			socket->recv_off = cp + 1 - begin;
			khttpd_mbuf_pos_init(bol, socket->recv_bol_ptr,
			    socket->recv_bol_off);
			socket->recv_bol_ptr = NULL;

			return (0);
		}

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
			if (!socket->recv_eof)
				continue;

			khttpd_mbuf_pos_init(bol, socket->recv_bol_ptr,
			    socket->recv_bol_off);
			socket->recv_bol_ptr = NULL;

			return (ENOENT);
		}

		/* Advance to the next mbuf */

		ptr = ptr->m_next;
		off = 0;
	}
}

void
khttpd_set_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{

	TRACE("enter");

	if (response->status == 0 || response->status / 100 == 1) {
		log(LOG_WARNING, "invalid status %d for %p.", response->status,
		    response);
		khttpd_set_bad_request_response(socket, request);
		return;
	}

	if (request->close)
		khttpd_response_set_connection_close(response);

	if (request->response != NULL) {
		if (request->response->status / 100 == 2)
			log(LOG_WARNING,
			    "a successful response(%d) followed by a "
			    "response(%d)", request->response->status,
			    response->status);

		if (response->status / 100 == 2)
			log(LOG_WARNING, "a response(%d) followed by a "
			    "successful response(%d)",
			    request->response->status, response->status);

		if (request->response_committed)
			log(LOG_WARNING, "a non-closing response %p has "
			    "already started sending for request %p",
			    request->response, request);

		if (request->response_committed || !response->close ||
		    request->response->close) {
			khttpd_response_free(response);
			return;
		}

		khttpd_response_free(request->response);
	}
	request->continue_response = FALSE;
	request->response = response;

	if (response->close) {
		khttpd_socket_drain(socket);
		khttpd_socket_commit_response(socket, request);
	}
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

static int
khttpd_socket_receive_null(struct khttpd_socket *socket)
{
	struct uio auio;
	struct socket *so;
	struct thread *td;
	struct mbuf *m;
	int error, flags;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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
khttpd_socket_handle_event(struct kevent *event)
{
	struct kevent change;
	struct khttpd_request *request;
	struct socket *so;
	struct khttpd_socket *socket;
	struct thread *td;
	struct mbuf *m, *end, *head, *prev;
	ssize_t space, len;
	int error, nopush;

	TRACE("enter %td", event->ident);
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	socket = event->udata;
	td = curthread;
	so = socket->fp->f_data;

	for (;;) {
		if (!socket->xmit_scheduled) {
			if (socket->recv_eof) {
				error = 0;
				break;
			}

			error = socket->recv_drain
			    ? khttpd_socket_receive_null(socket)
			    : socket->receive(socket);

			if (error == 0)
				continue;

			if (error != EWOULDBLOCK)
				log(LOG_WARNING, "khttpd: receive error: %d",
				    error);
			break;
		}

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

			if (prev != NULL) {
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
					log(LOG_WARNING,
					    "khttpd: send error: %d", error);
					break;
				}
			}

			if (end != NULL) {
				error = EWOULDBLOCK;
				break;
			}
		}

		request = socket->xmit_request;
		if (request == NULL ||
		    (!request->response_committed &&
			!request->continue_response)) {
			socket->xmit_scheduled = FALSE;
			nopush = 0;
			error = so_setsockopt(so, IPPROTO_TCP, TCP_NOPUSH,
			    &nopush, sizeof(nopush));
			if (error != 0)
				log(LOG_WARNING,
				    "khttpd: setsockopt(!TCP_NOPUSH): %d",
				    error);
			continue;
		}

		if (request->continue_response) {
			socket->xmit_buf = m = m_gethdr(M_WAITOK, MT_DATA);
			khttpd_mbuf_printf(m, "HTTP/1.1 100 Continue\r\n\r\n");
			request->continue_response = FALSE;
			continue;
		}

		error = socket->transmit(socket, request, request->response,
		    &socket->xmit_buf);
		if (error != 0) {
			if (error != EWOULDBLOCK)
				log(LOG_WARNING, "khttpd: transmit error: %d",
				    error);
			break;
		}
	}

	if (error == EWOULDBLOCK) {
		KASSERT(!socket->recv_eof, ("EOF & EWOULDBLOCK"));

		EV_SET(&change, socket->fd,
		    socket->xmit_scheduled ? EVFILT_WRITE : EVFILT_READ,
		    EV_ENABLE, 0, 0, &socket->event_type);
		error = khttpd_kevent(khttpd_kqueue, &change, 1, NULL, 0,
		    NULL, NULL);
		if (error == 0)
			return;

		log(LOG_WARNING, "khttpd: kevent failed: %d", error);
	}

	khttpd_socket_close(socket);
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
	socket->recv_tail = ptr == NULL ? NULL : m_last(ptr);
}

static void
khttpd_finish_receiving_request(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter");

	request->end_of_message(socket, request);
	KASSERT(request->response != NULL, ("not responded"));
	khttpd_socket_commit_response(socket, request);

	KASSERT(request == socket->recv_request,
	    ("request=%p, socket->recv_request=%p", request,
		socket->recv_request));
	khttpd_request_free(request);
	socket->recv_request = NULL;

	socket->receive = khttpd_receive_request_line;
	khttpd_socket_set_receive_limit(socket, khttpd_message_size_limit);
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
			khttpd_set_payload_too_large_response(socket, request);
			return (0);
		}

		len = (len << 4) + nibble;
	}

	khttpd_terminate_received_mbuf_chain(socket);
	m_freem(pos.ptr);

	if (len == 0) {
		socket->receive = khttpd_receive_header_or_trailer;

	} else {
		request->payload_size += len;
		khttpd_socket_set_receive_limit(socket, len);
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
	resid = socket->recv_limit +
	    m_length(socket->recv_leftovers, NULL);
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
		khttpd_socket_set_receive_limit(socket,
		    khttpd_message_size_limit);
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
	if (request->response != NULL)
		khttpd_response_set_connection_close(request->response);
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

	TRACE("enter");

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
		khttpd_socket_set_receive_limit(socket, khttpd_message_size_limit);
		socket->receive = khttpd_receive_chunk;
		return;
	}

	/*
	 * Start receiving the payload of the request message.
	 */

	if (request->has_content_length ? request->content_length == 0 :
	    !request->transfer_encoding_chunked) {
		khttpd_finish_receiving_request(socket, request);
		return;
	}

	request->payload_size = request->content_length;
	khttpd_socket_set_receive_limit(socket, request->content_length);
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
		khttpd_receive_transfer_encoding_field(socket, request,
		    &pos);
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
			sbuf_clear(output);
			*query = NULL;
			return (EBADMSG);

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
	char method_name[24];
	struct mbuf *m;
	struct khttpd_mbuf_pos pos, tmppos;
	const char *cp;
	char *end;
	struct khttpd_request *request;
	struct khttpd_route *route;
	int ch, error;

	TRACE("enter");

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

	socket->xmit_request = socket->recv_request = request =
	    uma_zalloc(khttpd_request_zone, M_WAITOK);

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
	socket->recv_leftovers = NULL;
	while (m != NULL && m != pos.ptr)
		m = m_free(m);

	m = pos.ptr;
	if (pos.off != 0) {
		if (m == socket->recv_ptr)
			socket->recv_off -= pos.off;
		m_adj(m, pos.off);
		pos.off = 0;
		socket->recv_tail = m_last(m);
	}
	request->request_line = m;

	/*
	 * Find the method of this request message.
	 */

	error = khttpd_mbuf_copy_segment(&pos, ' ', method_name,
	    sizeof(method_name) - 1, &end);

	if (error != 0)
		TRACE("error copy_segment(method) %d", error);

	if (error == 0) {
		*end = '\0';
		request->method = khttpd_method_find(method_name, end);

	} else if (error == ENOMEM) {
		request->method = KHTTPD_METHOD_UNKNOWN;
		error = khttpd_mbuf_next_segment(&pos, ' ');
		if (error != 0)
			goto bad;
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

	route = khttpd_route_find(khttpd_server_route_root(socket->port->server),
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

static int
khttpd_transmit_end(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	struct shutdown_args shutdown_args;
	struct thread *td;
	boolean_t close;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	td = curthread;
	close = response->close;
	socket->transmit = khttpd_transmit_status_line_and_header;

	khttpd_access(socket->port->server, socket, request);

	KASSERT(request == socket->xmit_request,
	    ("socket->xmit_request=%p, request=%p", socket->xmit_request,
		request));
	socket->xmit_request = NULL;
	khttpd_request_free(request);

	if (close && !socket->recv_eof) {
		shutdown_args.s = socket->fd;
		shutdown_args.how = SHUT_WR;
		sys_shutdown(curthread, &shutdown_args);
	}

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
	off_t len;
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
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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

	socket->transmit = khttpd_transmit_end;
}

static void
khttpd_accept_client(struct kevent *event)
{
	struct kevent changes[2];
	struct khttpd_kevent_args args = {
		.changelist = changes,
		.eventlist  = NULL
	};
	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};
	struct sockaddr *name;
	struct khttpd_server_port *port;
	struct khttpd_socket *socket;
	struct thread *td;
	socklen_t namelen;
	int error, fd, nodelay;

	TRACE("enter %td", event->ident);
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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

	nodelay = 1;
	error = kern_setsockopt(td, fd, IPPROTO_TCP, TCP_NODELAY, &nodelay,
	    UIO_SYSSPACE, sizeof(nodelay));
	if (error != 0)
		log(LOG_WARNING, "khttpd: setsockopt(NODELAY): %d", error);

	bcopy(name, &socket->peer_addr, name->sa_len);

	TRACE("new_client %d", fd);

	socket->fd = fd;
	error = getsock_cap(td, socket->fd, &khttpd_socket_rights, &socket->fp,
	    NULL);
	if (error != 0) {
		TRACE("error getsock_cap %d", error);
		goto bad;
	}

	EV_SET(&changes[0], fd, EVFILT_READ, EV_ADD|EV_DISPATCH,
	    0, 0, &socket->event_type);
	EV_SET(&changes[1], fd, EVFILT_WRITE, EV_ADD|EV_DISPATCH|EV_DISABLE,
	    0, 0, &socket->event_type);

	error = kern_kevent(curthread, khttpd_kqueue, sizeof(changes) /
	    sizeof(changes[0]), 0, &k_ops, NULL);
	if (error != 0) {
		TRACE("error kevent %d", error);
		goto bad;
	}

	mtx_lock(&khttpd_lock);
	LIST_INSERT_HEAD(&khttpd_sockets, socket, link);
	mtx_unlock(&khttpd_lock);

	return;

bad:
	khttpd_socket_free(socket);
}

/*
 * server
 */

static void
khttpd_server_free(struct khttpd_server *server)
{
	struct thread *td;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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

static struct khttpd_server *
khttpd_server_alloc(const char *name)
{
	struct khttpd_server *result;
	struct khttpd_route *root;
	int error;

	result = khttpd_malloc(sizeof(struct khttpd_server));
	result->name = strdup(name, M_KHTTPD);
	result->dev = NULL;
	result->route_root = root = uma_zalloc_arg(khttpd_route_zone,
	    &khttpd_route_type_null, M_WAITOK);

	error = khttpd_route_add(root, "*", &khttpd_route_type_asterisc);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to add route '*': %d", error);
		khttpd_free(result);
		return (NULL);
	}

	SLIST_INIT(&result->ports);
	khttpd_log_init(&result->access_log);
	khttpd_log_init(&result->error_log);

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &result->dev,
	    &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "khttpd/%s",
	    result->name);
	if (error != 0) {
		log(LOG_ERR, "khttpd: failed to create the device file: %d",
		    error);
		result->dev->si_drv1 = NULL;
		khttpd_server_free(result);
		return (NULL);
	}

	result->dev->si_drv1 = result;

	return (result);
}

struct khttpd_server *
khttpd_server_find(const char *name)
{
	struct khttpd_server *server;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();
 
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

/* --------------------------------------------------------------- asterisc */

static void
khttpd_asterisc_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter %d", socket->fd);
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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

/* --------------------------------------------------------- worker thread */

static void
khttpd_worker_main(void *arg)
{
	struct khttpd_worker entry;
	struct kevent event;
	struct khttpd_worker *head, *next;
	int error, nevent;
	boolean_t need_new_thread, initialized;

	TRACE("enter");

	initialized = FALSE;
	for (;;) {
		mtx_lock(&khttpd_lock);
		if (!initialized) {
			initialized = TRUE;
			khttpd_worker_initializing = FALSE;
		}
		head = TAILQ_FIRST(&khttpd_waiting_workers);
		if (head == NULL)
			TAILQ_INSERT_HEAD(&khttpd_waiting_workers, &entry,
			    link);
		else {
			TAILQ_INSERT_AFTER(&khttpd_waiting_workers, head,
			    &entry, link);
			error = mtx_sleep(&entry, &khttpd_lock, 0,
			    "khttpd-idling", 1 * hz);
			if (error == EWOULDBLOCK &&
			    &entry != TAILQ_FIRST(&khttpd_waiting_workers)) {
				TAILQ_REMOVE(&khttpd_waiting_workers, &entry,
				    link);
				break;
			}
		}
		mtx_unlock(&khttpd_lock);

		TRACE("kevent enter");
		error = khttpd_kevent(khttpd_kqueue, NULL, 0, &event, 1,
		    &nevent, NULL);
		TRACE("kevent leave");
		if (error != 0)
			TRACE("error kevent_get %d", error);

		mtx_lock(&khttpd_lock);

		TAILQ_REMOVE(&khttpd_waiting_workers, &entry, link);
		next = TAILQ_FIRST(&khttpd_waiting_workers);
		need_new_thread = next == NULL &&
		    !khttpd_worker_initializing && !khttpd_worker_shutdown &&
		    khttpd_worker_count < khttpd_worker_count_max;

		if (next != NULL)
			wakeup(next);
		else if (need_new_thread) {
			khttpd_worker_initializing = TRUE;
			++khttpd_worker_count;
		}

		if (khttpd_worker_shutdown)
			break;

		mtx_unlock(&khttpd_lock);

		if (need_new_thread) {
			error = kthread_add(khttpd_worker_main, NULL,
			    khttpd_proc, NULL, 0, 0, "khttpd-worker");
			if (error != 0) {
				mtx_lock(&khttpd_lock);
				--khttpd_worker_count;
				mtx_unlock(&khttpd_lock);

				log(LOG_WARNING, "khttpd: failed to create a "
				    "worker thread: %d", error);
			}
		}

		if (0 < nevent)
			((struct khttpd_event_type *)event.udata)->
			    handle_event(&event);
	}

	if (--khttpd_worker_count == 0)
		wakeup(&khttpd_worker_count);
	mtx_unlock(&khttpd_lock);

	TRACE("leave");

	kthread_exit();
}

/* ---------------------------------------------------------- khttpd daemon */

int
khttpd_run_proc(khttpd_command_proc_t proc, void *argument)
{
	struct khttpd_command command;
	int error;

	command.command = proc;
	command.argument = argument;
	command.status = -1;

	mtx_lock(&khttpd_lock);

	if (STAILQ_EMPTY(&khttpd_command_queue))
		wakeup(&khttpd_command_queue);

	STAILQ_INSERT_TAIL(&khttpd_command_queue, &command, link);

	while ((error = command.status) == -1)
		mtx_sleep(&command, &khttpd_lock, 0, "khttpd-cmd", 0);

	mtx_unlock(&khttpd_lock);

	return (error);
}

static void
khttpd_set_state(int state)
{
	int old_state;

	mtx_assert(&khttpd_lock, MA_OWNED);

	old_state = khttpd_state;
	if (old_state == state)
		return;
	khttpd_state = state;
	wakeup(&khttpd_state);

	if (old_state == KHTTPD_READY && curthread != khttpd_main_thread)
		wakeup(&khttpd_command_queue);
	if (old_state == KHTTPD_READY)
		wakeup(&khttpd_busy_logs);
}

static void
khttpd_main(void *arg)
{
	struct khttpd_command_list worklist;
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
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

#ifdef KHTTPD_KTR_LOGGING
	khttpd_ktr_logging_init();
#endif
	khttpd_msgbuf_init();

	khttpd_main_thread = curthread;
	khttpd_worker_count_max = mp_ncpus * 3;

	cap_rights_init(&khttpd_socket_rights, CAP_EVENT, CAP_RECV, CAP_SEND,
	    CAP_SETSOCKOPT, CAP_SHUTDOWN);

	STAILQ_INIT(&worklist);
	td = curthread;
	error = 0;

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

	khttpd_label_hash_init(khttpd_method_hash_table,
	    sizeof(khttpd_method_hash_table) /
	    sizeof(khttpd_method_hash_table[0]), khttpd_methods,
	    sizeof(khttpd_methods) / sizeof(khttpd_methods[0]), FALSE);

	khttpd_label_hash_init(khttpd_field_hash_table,
	    sizeof(khttpd_field_hash_table) /
	    sizeof(khttpd_field_hash_table[0]), khttpd_fields,
	    sizeof(khttpd_fields) / sizeof(khttpd_fields[0]), TRUE);

	longest = 0;
	for (i = 0; i < sizeof(khttpd_fields) / sizeof(khttpd_fields[0]);
	     ++i) {
		len = strlen(khttpd_fields[i].name) + 1;
		if (longest < len)
			longest = len;
	}
	if (KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH < longest) {
		log(LOG_WARNING, "khttpd: longest known field name "
		    "expected:%zd, actual:%zd", longest,
		    (size_t)KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH);
		error = EDOOFUS;
		goto cont;
	}

	error = khttpd_json_init();
	if (error != 0)
		goto cont;

#ifdef KHTTPD_DEBUG
	khttpd_debug_mask = KHTTPD_DEBUG_ALL;
#endif

	bzero(&sigact, sizeof(sigact));

	error = kern_sigaction(td, SIGPIPE, &sigact, NULL, 0);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: sigaction(SIGPIPE) failed: %d",
		    error);
		goto cont;
	}

	error = sys_kqueue(td, NULL);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: kqueue() failed: %d", error);
		goto cont;
	}
	khttpd_kqueue = td->td_retval[0];

	EV_SET(&event, KHTTPD_EVENT_SHUTDOWN_WORKERS, EVFILT_USER,
	    EV_ADD, 0, 0, NULL);
	error = khttpd_kevent(khttpd_kqueue, &event, 1, NULL, 0, NULL,
	    NULL);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: kevent(EVFILT_USER) failed: %d",
		    error);
		goto cont;
	}

	error = khttpd_file_init();
	if (error != 0)
		goto cont;

	server = khttpd_server_alloc("ctrl");
	if (server == NULL) {
		log(LOG_WARNING, "khttpd: failed to create "
		    "the control server");
		goto cont;
	}
	SLIST_INSERT_HEAD(&khttpd_servers, server, link);

cont:
	mtx_lock(&khttpd_lock);

	khttpd_server_status = error;
	khttpd_set_state(error == 0 ? KHTTPD_READY : KHTTPD_FAILED);

	while (khttpd_state == KHTTPD_FAILED)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0,
		    "khttpd-failed", 0);

	mtx_unlock(&khttpd_lock);

	TAILQ_INIT(&khttpd_busy_logs);
	if (khttpd_state == KHTTPD_READY)
		kthread_add(khttpd_logger_main, NULL, khttpd_proc, NULL, 0, 0,
		    "logger");

	while (khttpd_state == KHTTPD_READY) {
		EV_SET(&event, KHTTPD_EVENT_SHUTDOWN_WORKERS, EVFILT_USER,
		    EV_CLEAR, 0, 0, NULL);
		error = khttpd_kevent(khttpd_kqueue, &event, 1, NULL, 0, NULL,
		    NULL);
		if (error != 0)
			log(LOG_WARNING, "khttpd: failed to clear "
			    "KHTTPD_EVENT_SHUTDOWN_WORKERS: %d", error);

		error = kthread_add(khttpd_worker_main, NULL, khttpd_proc,
		    NULL, 0, 0, "khttpd-worker");
		if (error != 0)
			log(LOG_WARNING, "khttpd: failed to create a "
			    "worker thread: %d", error);

		mtx_lock(&khttpd_lock);

		++khttpd_worker_count;

		while (khttpd_state == KHTTPD_READY &&
		    STAILQ_EMPTY(&khttpd_command_queue))
			mtx_sleep(&khttpd_command_queue, &khttpd_lock, 0,
			    "khttpd-command", 0);

		khttpd_worker_shutdown = TRUE;
		mtx_unlock(&khttpd_lock);

		EV_SET(&event, KHTTPD_EVENT_SHUTDOWN_WORKERS, EVFILT_USER,
		    0, NOTE_TRIGGER, 0, NULL);
		error = khttpd_kevent(khttpd_kqueue, &event, 1, NULL, 0, NULL,
		    NULL);
		if (error != 0)
			log(LOG_WARNING, "khttpd: failed to notify "
			    "KHTTPD_EVENT_SHUTDOWN_WORKERS: %d", error);

		mtx_lock(&khttpd_lock);
		while (0 < khttpd_worker_count)
			mtx_sleep(&khttpd_worker_count, &khttpd_lock, 0,
			    "khttpd-shutdown", 0);

		STAILQ_SWAP(&worklist, &khttpd_command_queue, khttpd_command);
		khttpd_worker_shutdown = FALSE;

		mtx_unlock(&khttpd_lock);

		while ((command = STAILQ_FIRST(&worklist)) != NULL) {
			STAILQ_REMOVE_HEAD(&worklist, link);
			command->status =
			    command->command(command->argument);
			wakeup(command);
		}
	}

	while ((socket = LIST_FIRST(&khttpd_sockets)) != NULL)
		khttpd_socket_close(socket);

	while ((server = SLIST_FIRST(&khttpd_servers)) != NULL) {
		while ((port = SLIST_FIRST(&server->ports)) != NULL) {
			SLIST_REMOVE_HEAD(&server->ports, link);
			if (port->fd != -1)
				kern_close(td, port->fd);
			khttpd_free(port);
		}

		SLIST_REMOVE_HEAD(&khttpd_servers, link);
		khttpd_server_free(server);
	}

	if (khttpd_kqueue != -1)
		kern_close(td, khttpd_kqueue);

	khttpd_file_fini();
	khttpd_json_fini();

	uma_zdestroy(khttpd_socket_zone);
	uma_zdestroy(khttpd_request_zone);
	uma_zdestroy(khttpd_response_zone);
	uma_zdestroy(khttpd_route_zone);

	khttpd_msgbuf_fini();
#ifdef KHTTPD_KTR_LOGGING
	khttpd_ktr_logging_fini();
#endif

	kproc_exit(0);
}

/* --------------------------------------------------------- ioctl handlers */

static int
khttpd_internalize_fd(struct filedesc *fdp, int fd, struct filedescent *ent,
		      int flags, cap_rights_t *rights)
{
	struct filedescent *fdep;
	struct file *fp;
	int error;

	FILEDESC_LOCK_ASSERT(fdp);

	TRACE("enter %d", fd);

	if (fd < 0 || fdp->fd_lastfile < fd) {
		TRACE("error EBADF 1");
		return (EBADF);
	}

	fdep = &fdp->fd_ofiles[fd];

	if ((fp = fdep->fde_file) == NULL || (fp->f_flag & flags) != flags) {
		TRACE("error EBADF 2");
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
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();
	KASSERT(0 <= fd && fd <= fdp->fd_lastfile,
	    ("fd %d is out of range", fd));

	fdep = &fdp->fd_ofiles[fd];
	fdep->fde_file = ent->fde_file;
	ent->fde_file = NULL;
	filecaps_move(&ent->fde_caps, &fdep->fde_caps);
}

static int
khttpd_listen_proc(void *argptr)
{
	struct kevent event;
	struct listen_args listen_args;
	struct khttpd_server_port_list ports;	
	struct khttpd_listen_proc_args *args;
	struct filedesc *fdp;
	struct khttpd_server_port *port;
	struct khttpd_server *server;
	struct thread *td;
	int i, error, fd, *fds, nfds;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	SLIST_INIT(&ports);
	args = argptr;
	td = curthread;
	fdp = td->td_proc->p_fd;
	server = args->server;

	nfds = args->nfdes;
	fds = khttpd_malloc(nfds * sizeof(int));

	FILEDESC_XLOCK(fdp);

	error = fdallocn(td, 0, fds, nfds);
	if (error != 0) {
		FILEDESC_XUNLOCK(fdp);
		log(LOG_WARNING,
		    "khttpd: failed to allocate file descriptors: %d", error);
		goto bad1;
	}

	for (i = 0; i < nfds; ++i)
		khttpd_externalize_fd(fdp, fds[i], &args->fdes[i]);

	FILEDESC_XUNLOCK(fdp);

	for (i = 0; i < nfds; ++i) {
		fd = fds[i];

		port = khttpd_malloc(sizeof(*port));
		port->event_type.handle_event = khttpd_accept_client;
		port->fd = fd;
		port->server = server;
		SLIST_INSERT_HEAD(&ports, port, link);

		listen_args.s = fd;
		listen_args.backlog = khttpd_listen_backlog;
		error = sys_listen(td, &listen_args);
		if (error != 0) {
			log(LOG_WARNING, "khttpd: failed to listen "
			    "on the given sockets: %d", error);
			goto bad2;
		}

		EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0,
		    &port->event_type);
		error = khttpd_kevent(khttpd_kqueue, &event, 1, NULL, 0, NULL,
		    NULL);
		if (error != 0) {
			log(LOG_WARNING, "khttpd: failed to kevent"
			    "(EVFILT_READ) on the given sockets: %d", error);
			goto bad2;
		}
	}

	SLIST_SWAP(&server->ports, &ports, khttpd_server_port);

	khttpd_free(fds);

	return (0);

bad2:
	while ((port = SLIST_FIRST(&ports)) != NULL) {
		SLIST_REMOVE_HEAD(&ports, link);
		kern_close(td, port->fd);
		khttpd_free(port);
	}
bad1:
	khttpd_free(fds);

	return (error);
}

static int
khttpd_listen(struct khttpd_server *server,
    struct khttpd_listen_args *args)
{
	struct filedesc *fdp;
	struct khttpd_listen_proc_args proc_args;
	cap_rights_t rights;
	struct thread *td;
	int i, error, *fds, nfds;

	TRACE("enter");

	td = curthread;
	fdp = td->td_proc->p_fd;
	nfds = args->nfds;

	if (KHTTPD_MAX_PORTS_PER_SERVER < nfds)
		return (EINVAL);

	fds = khttpd_malloc(nfds * sizeof(int));
	error = copyin(args->fds, fds, nfds * sizeof(int));
	if (error != 0)
		goto bad1;

	proc_args.server = server;
	proc_args.fdes = khttpd_malloc(nfds * sizeof(struct filedescent));
	bzero(proc_args.fdes, nfds * sizeof(struct filedescent));
	proc_args.nfdes = nfds;

	cap_rights_init(&rights, CAP_LISTEN);

	FILEDESC_SLOCK(fdp);

	for (i = 0; i < nfds; ++i) {
		error = khttpd_internalize_fd(fdp, fds[i], &proc_args.fdes[i],
		    FREAD, &rights);
		if (error != 0) {
			FILEDESC_SUNLOCK(fdp);
			while (0 <= --i) {
				filecaps_free(&proc_args.fdes[i].fde_caps);
				fdrop(proc_args.fdes[i].fde_file, td);
			}
			goto bad2;
		}
	}

	FILEDESC_SUNLOCK(fdp);

	error = khttpd_run_proc(khttpd_listen_proc, &proc_args);
	if (error != 0)
		goto bad2;

	khttpd_free(proc_args.fdes);
	khttpd_free(fds);

	return (0);

bad2:
	khttpd_free(proc_args.fdes);
bad1:
	khttpd_free(fds);

	return (error);
}

static int
khttpd_config_log_proc(void *argptr)
{
	struct khttpd_config_log_proc_args *args;
	struct filedesc *fdp;
	struct khttpd_server *server;
	struct thread *td;
	int error, fd;

	TRACE("enter");
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	args = argptr;
	td = curthread;
	fdp = td->td_proc->p_fd;
	server = args->server;

	FILEDESC_XLOCK(fdp);
	error = fdalloc(td, 0, &fd);
	if (error != 0) {
		FILEDESC_XUNLOCK(fdp);
		log(LOG_WARNING,
		    "khttpd: failed to allocate file descriptors: %d", error);
		return (error);
	}
	khttpd_externalize_fd(fdp, fd, &args->fde);
	FILEDESC_XUNLOCK(fdp);

	switch (args->log) {

	case KHTTPD_LOG_ACCESS:
		khttpd_log_set_fd(&server->access_log, fd);
		break;

	case KHTTPD_LOG_ERROR:
		khttpd_log_set_fd(&server->error_log, fd);
		break;

	default:
		panic("unknown log type: %d", args->log);
	}

	return (error);
}

static int
khttpd_config_log(struct khttpd_server *server,
    struct khttpd_config_log_args *args)
{
	struct filedesc *fdp;
	struct khttpd_config_log_proc_args proc_args;
	cap_rights_t rights;
	struct thread *td;
	int error;

	TRACE("enter");

	td = curthread;
	fdp = td->td_proc->p_fd;

	if (args->log <= KHTTPD_LOG_UNKNOWN || KHTTPD_LOG_END <= args->log)
		return (EINVAL);

	if (args->flags != 0)
		return (EINVAL);

	proc_args.server = server;
	proc_args.log = args->log;
	cap_rights_init(&rights, CAP_LISTEN);
	FILEDESC_SLOCK(fdp);
	error = khttpd_internalize_fd(fdp, args->fd, &proc_args.fde, FWRITE,
	    &rights);
	FILEDESC_SUNLOCK(fdp);
	if (error != 0)
		return (error);

	error = khttpd_run_proc(khttpd_config_log_proc, &proc_args);

	return (error);
}

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int error;

	switch (cmd) {

	case KHTTPD_IOC_LISTEN:
		error = khttpd_listen(dev->si_drv1,
		    (struct khttpd_listen_args *)data);
		break;

	case KHTTPD_IOC_CONFIG_LOG:
		error = khttpd_config_log(dev->si_drv1,
		    (struct khttpd_config_log_args *)data);
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
	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

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

#ifdef DDB

#include <ddb/ddb.h>

DB_SHOW_COMMAND(khttpd_msgbuf, db_show_khttpd_msgbuf)
{
	struct mbuf *m;

	STAILQ_FOREACH(m, &khttpd_msgbuf.mq_head, m_stailqpkt)
		db_printf("%.*s", m->m_len, mtod(m, char *));
}

#endif

DEV_MODULE(khttpd, khttpd_loader, NULL);
