/*-
 * Copyright (c) 2017 Taketsuru <taketsuru11@gmail.com>.
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

#include "khttpd_port.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/proc.h>
#include <sys/event.h>
#include <sys/fcntl.h>
#include <sys/socket.h>
#include <sys/sockopt.h>
#include <sys/socketvar.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <vm/uma.h>

#include "khttpd_costruct.h"
#include "khttpd_init.h"
#include "khttpd_job.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_problem.h"
#include "khttpd_refcount.h"
#include "khttpd_status_code.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_stream.h"

#ifndef KHTTPD_PORT_MAX_WAIT_TO_STOP
#define KHTTPD_PORT_MAX_WAIT_TO_STOP	60
#endif

struct khttpd_socket {
	LIST_ENTRY(khttpd_socket) link;
	struct mtx		lock;
	struct callout		recv_callout;
	struct callout		xmit_callout;
	struct sockaddr_storage	peer_address;
	struct khttpd_job	*recv_timeout_job;
	struct khttpd_job	*xmit_timeout_job;
	struct khttpd_stream	*stream;

#define khttpd_socket_zero_begin read_event
	struct khttpd_event	*read_event;
	struct khttpd_event	*write_event;
	struct khttpd_port	*port;
	struct file		*fp;
	struct mbuf		*xmit_buf;
	u_int			recv_timeout;
	u_int			xmit_timeout;
	unsigned		is_tcp:1;
	unsigned		recv_scheduled:1;
	unsigned		xmit_scheduled:1;
	unsigned		xmit_flush_scheduled:1;
	unsigned		xmit_close_scheduled:1;
	unsigned		xmit_nopush:1;
	unsigned		xmit_notification_requested:1;
	unsigned		marker:1;
#define khttpd_socket_zero_end fd

	int			fd;
};

LIST_HEAD(khttpd_socket_list, khttpd_socket);

struct khttpd_port {
	struct mtx		lock;
	struct khttpd_socket_list sockets;
	khttpd_event_fn_t	arrival_fn;

#define khttpd_port_zctor_begin	arrival_event
	struct sockaddr_storage	addr;
	struct khttpd_event	*arrival_event;
	unsigned		is_tcp:1;
	unsigned		costructs_ready:1;
#define khttpd_port_zctor_end	refcount

	KHTTPD_REFCOUNT1_MEMBERS;
	int			fd;
};

static void khttpd_port_dtor(struct khttpd_port *port);
static void khttpd_port_fini(struct khttpd_port *port);
static void khttpd_port_handle_arrival_event(void *arg);

static int khttpd_socket_stream_receive(struct khttpd_stream *, ssize_t *,
    struct mbuf **);
static void khttpd_socket_stream_continue_receiving(struct khttpd_stream *);
static void khttpd_socket_stream_shutdown_receiver(struct khttpd_stream *);
static boolean_t khttpd_socket_stream_send(struct khttpd_stream *,
    struct mbuf *, int);
static void khttpd_socket_stream_send_bufstat(struct khttpd_stream *,
    size_t *, size_t *, size_t *);
static void khttpd_socket_stream_notify_of_drain(struct khttpd_stream *);
static void khttpd_socket_stream_destroy(struct khttpd_stream *);

static void khttpd_socket_shutdown(void *);
static void khttpd_socket_handle_timeout(void *);
static void khttpd_socket_handle_read_event(void *);
static void khttpd_socket_handle_write_event(void *);

struct khttpd_stream_down_ops khttpd_socket_ops = {
	.receive = khttpd_socket_stream_receive,
	.continue_receiving = khttpd_socket_stream_continue_receiving,
	.shutdown_receiver = khttpd_socket_stream_shutdown_receiver,
	.send = khttpd_socket_stream_send,
	.send_bufstat = khttpd_socket_stream_send_bufstat,
	.notify_of_drain = khttpd_socket_stream_notify_of_drain,
	.destroy = khttpd_socket_stream_destroy
};

struct khttpd_costruct_info *khttpd_port_costruct_info;

static struct mtx khttpd_port_lock;
static cap_rights_t khttpd_socket_rights;
static sbintime_t khttpd_port_timeout_pr = SBT_1S * 2;
static uma_zone_t khttpd_socket_zone;
static u_int khttpd_port_count;

MTX_SYSINIT(khttpd_port_lock, &khttpd_port_lock, "port", MTX_DEF);

KHTTPD_REFCOUNT1_GENERATE(khttpd_port, khttpd_port, khttpd_port_dtor,
    khttpd_port_fini);

static void
khttpd_port_handle_arrival_event(void *arg)
{
	struct khttpd_port *port;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;
	port->arrival_fn(port);
	khttpd_event_enable(port->arrival_event);
}

int
khttpd_port_new(struct khttpd_port **port_out)
{
	struct khttpd_port *port;
	struct thread *td;
	int error;

	KHTTPD_ENTRY("%s()", __func__);

	td = curthread;

	mtx_lock(&khttpd_port_lock);
	++khttpd_port_count;
	mtx_unlock(&khttpd_port_lock);

	port = khttpd_malloc(khttpd_costruct_instance_size
	    (khttpd_port_costruct_info));

	mtx_init(&port->lock, "port", NULL, MTX_DEF | MTX_NEW);
	LIST_INIT(&port->sockets);
	bzero((char *)port + 
	    offsetof(struct khttpd_port, khttpd_port_zctor_begin),
	    offsetof(struct khttpd_port, khttpd_port_zctor_end) -
	    offsetof(struct khttpd_port, khttpd_port_zctor_begin));
	KHTTPD_REFCOUNT1_INIT(khttpd_port, port);
	port->fd = -1;

	error = khttpd_costruct_call_ctors(khttpd_port_costruct_info, port);
	if (error != 0) {
		khttpd_port_release(port);
		return (error);
	}

	port->costructs_ready = TRUE;
	*port_out = port;

	return (error);
}

static void
khttpd_port_dtor(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	KASSERT(LIST_EMPTY(&port->sockets), ("port->sockets not empty"));

	if (port->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_port_costruct_info, port);

	if (port->fd != -1) {
		khttpd_event_delete(port->arrival_event);
		kern_close(curthread, port->fd);
	}

	mtx_destroy(&port->lock);
}

static void
khttpd_port_fini(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	khttpd_free(port);

	mtx_lock(&khttpd_port_lock);
	if (--khttpd_port_count == 0)
		wakeup(&khttpd_port_count);
	mtx_unlock(&khttpd_port_lock);
}

int
khttpd_port_start(struct khttpd_port *port, struct sockaddr *addr,
    khttpd_event_fn_t accept_handler, const char **detail_out)
{
	struct listen_args listen_args;
	struct socket_args socket_args;
	struct thread *td;
	const char *detail;
	socklen_t sovallen;
	int error, fd, soval, lowat;
	boolean_t is_tcp;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, port, addr, accept_handler);

	fd = -1;
	td = curthread;
	detail = NULL;
	error = 0;

	if (sizeof(port->addr) < addr->sa_len)
		goto invalid_address;

	switch (addr->sa_family) {
	case AF_INET:
		socket_args.domain = PF_INET;
		is_tcp = TRUE;
		break;
	case AF_INET6:
		socket_args.domain = PF_INET6;
		is_tcp = TRUE;
		break;
	case AF_UNIX:
		socket_args.domain = PF_UNIX;
		is_tcp = FALSE;
		break;
	default:
		goto invalid_address;
	}

	socket_args.type = SOCK_STREAM;
	socket_args.protocol = 0;
	error = sys_socket(td, &socket_args);
	if (error != 0) {
		detail = "socket construction failed";
		goto error;
	}
	fd = td->td_retval[0];

	soval = 1;
	error = kern_setsockopt(td, fd, SOL_SOCKET, SO_REUSEADDR, &soval,
	    UIO_SYSSPACE, sizeof(soval));
	if (error != 0) {
		detail = "setsockopt(SO_REUSEADDR) failed";
		goto error;
	}

	sovallen = sizeof(soval);
	error = kern_getsockopt(td, fd, SOL_SOCKET, SO_SNDBUF, &soval,
	    UIO_SYSSPACE, &sovallen);
	if (error != 0) {
		detail = "getsockopt(SO_SNDBUF) failed";
		goto error;
	}
	
	lowat = MAX(PAGE_SIZE, soval / 2);
	error = kern_setsockopt(td, fd, SOL_SOCKET, SO_SNDLOWAT, &lowat,
	    UIO_SYSSPACE, sizeof(lowat));
	if (error != 0) {
		detail = "setsockopt(SO_SNDLOWAT) failed";
		goto error;
	}

	error = kern_bindat(td, AT_FDCWD, fd, addr);
	if (error != 0) {
		detail = "bind failed";
		goto error;
	}

	listen_args.s = fd;
	listen_args.backlog = -1;
	error = sys_listen(td, &listen_args);
	if (error != 0) {
		detail = "listen failed";
		goto error;
	}

	bcopy(addr, &port->addr, addr->sa_len);
	port->arrival_fn = accept_handler;
	port->is_tcp = is_tcp;
	port->fd = fd;
	port->arrival_event = 
	    khttpd_event_new_read(khttpd_port_handle_arrival_event, port, fd,
		TRUE, NULL);

	return (0);

 invalid_address:
	detail = "invalid address";
	error = EINVAL;

 error:
	kern_close(td, fd);
	if (detail_out != NULL)
		*detail_out = detail;

	return (error);
}

void
khttpd_port_stop(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	if (port->fd == -1)
		return;

	khttpd_event_delete(port->arrival_event);
	port->arrival_event = NULL;
	kern_close(curthread, port->fd);
	port->fd = -1;
}

void
khttpd_port_shutdown(struct khttpd_port *port)
{
	struct khttpd_socket marker;
	struct khttpd_socket *socket, *next;

	bzero(&marker, sizeof(marker));
	marker.marker = TRUE;

	mtx_lock(&port->lock);

	for (socket = LIST_FIRST(&port->sockets);
	     socket != NULL; socket = next)
		if (socket->marker)
			next = LIST_NEXT(socket, link);
		else {
			LIST_INSERT_AFTER(socket, &marker, link);
			mtx_unlock(&port->lock);
			khttpd_socket_shutdown(socket);
			mtx_lock(&port->lock);
			next = LIST_NEXT(&marker, link);
			LIST_REMOVE(&marker, link);
			if (next == NULL && LIST_EMPTY(&port->sockets))
				wakeup(&port->sockets);
		}

	while (!LIST_EMPTY(&port->sockets))
		mtx_sleep(&port->sockets, &port->lock, 0, "sockcls", 0);

	mtx_unlock(&port->lock);
}

struct khttpd_socket *
khttpd_socket_new(void)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s()", __func__);

	socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
	bzero(&socket->khttpd_socket_zero_begin,
	    offsetof(struct khttpd_socket, khttpd_socket_zero_end) -
	    offsetof(struct khttpd_socket, khttpd_socket_zero_begin));
	socket->fd = -1;

	return (socket);
}

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;
	mtx_init(&socket->lock, "socket", NULL, MTX_DEF | MTX_NEW);
	callout_init_mtx(&socket->recv_callout, &socket->lock, 0);
	callout_init_mtx(&socket->xmit_callout, &socket->lock, 0);
	socket->recv_timeout_job = 
	    khttpd_job_new(khttpd_socket_shutdown, socket, NULL);
	socket->xmit_timeout_job =
	    khttpd_job_new(khttpd_socket_shutdown, socket, NULL);
	return (0);
}

static void
khttpd_socket_fini(void *mem, int size)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, mem, size);

	socket = mem;
	callout_drain(&socket->recv_callout);
	callout_drain(&socket->xmit_callout);
	khttpd_job_delete(socket->recv_timeout_job);
	khttpd_job_delete(socket->xmit_timeout_job);
	mtx_destroy(&socket->lock);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_port *port;
	struct khttpd_socket *socket;
	struct thread *td;
	struct mbuf *m;
	int fd;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, mem, size, arg);

	td = curthread;
	socket = mem;
	port = socket->port;

	mtx_lock(&socket->lock);

	KASSERT(!socket->xmit_scheduled && !socket->recv_scheduled,
	    ("xmit_scheduled=%d, recv_scheduled=%d",
		socket->xmit_scheduled, socket->recv_scheduled));

	fd = socket->fd;
	socket->fd = -1;

	m = socket->xmit_buf;
	socket->xmit_buf = NULL;

	mtx_unlock(&socket->lock);

	m_freem(m);

	if (fd == -1)
		return;

	callout_drain(&socket->recv_callout);
	callout_drain(&socket->xmit_callout);

	khttpd_event_delete(socket->read_event);
	khttpd_event_delete(socket->write_event);

	if (port != NULL) {
		mtx_lock(&port->lock);
		LIST_REMOVE(socket, link);
		if (LIST_EMPTY(&port->sockets))
			wakeup(&port->sockets);
		mtx_unlock(&port->lock);
	}

	kern_close(td, fd);
	fdrop(socket->fp, td);
}

static void
khttpd_socket_error(struct khttpd_socket *socket, int severity, int error,
    const char *detail)
{
	struct khttpd_mbuf_json entry;

	khttpd_problem_log_new(&entry, severity, "socket_error",
	    "socket I/O error");
	khttpd_problem_set_detail(&entry, detail);
	khttpd_problem_set_errno(&entry, error);
	khttpd_stream_error(socket->stream, &entry);
}

static void
khttpd_socket_schedule_read_event(struct khttpd_socket *socket)
{

	KHTTPD_ENTRY("%s(%p)", __func__, socket);

	mtx_lock(&socket->lock);

	if (socket->recv_scheduled) {
		mtx_unlock(&socket->lock);
		return;
	}

	socket->recv_scheduled = TRUE;

	if (0 < socket->recv_timeout)
		callout_reset_sbt_curcpu(&socket->recv_callout,
		    socket->recv_timeout, khttpd_port_timeout_pr,
		    khttpd_socket_handle_timeout, socket->recv_timeout_job, 0);

	mtx_unlock(&socket->lock);

	khttpd_event_enable(socket->read_event);
}

int
khttpd_socket_start(struct khttpd_socket *socket, struct khttpd_stream *stream,
    struct khttpd_port *port)
{
	struct thread *td;
	struct sockaddr *name;
	struct khttpd_event *read_event;
	const char *detail;
	socklen_t namelen;
	int error, fd, nodelay, nosigpipe;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, socket, stream, port);

	td = curthread;
	detail = NULL;

	error = kern_accept4(td, port->fd, &name, &namelen, SOCK_NONBLOCK, 
	    NULL);
	if (error != 0) {
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "accept failed");
		return (error);
	}
	socket->fd = fd = td->td_retval[0];

	KASSERT(namelen < sizeof(socket->peer_address),
	    ("namelen=%zd, size=%zd",
		namelen, sizeof(socket->peer_address)));
	bcopy(name, &socket->peer_address, namelen);

	error = getsock_cap(td, fd, &khttpd_socket_rights, &socket->fp, NULL,
	    NULL);
	if (error != 0) {
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "getsock_cap failed");
		return (error);
	}

	nosigpipe = 1;
	error = kern_setsockopt(td, fd, SOL_SOCKET, SO_NOSIGPIPE, &nosigpipe,
	    UIO_SYSSPACE, sizeof(nosigpipe));
	if (error != 0) {
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "setsockopt(SO_NOSIGPIPE) failed");
		return (error);
	}

	if (port->is_tcp) {
		socket->is_tcp = TRUE;

		nodelay = 1;
		error = kern_setsockopt(td, fd, IPPROTO_TCP, TCP_NODELAY,
		    &nodelay, UIO_SYSSPACE, sizeof(nodelay));
		if (error != 0) {
			khttpd_socket_error(socket, LOG_WARNING, error,
			    "setsockopt(TCP_NODELAY) failed");
			return (error);
		}
	}

	socket->stream = stream;
	socket->read_event = read_event = khttpd_event_new_read
	    (khttpd_socket_handle_read_event, socket, socket->fd, FALSE, NULL);
	socket->write_event = khttpd_event_new_write
	    (khttpd_socket_handle_write_event, socket, socket->fd, FALSE,
		read_event);

	mtx_lock(&port->lock);
	KASSERT(socket->port == NULL,
	    ("socket=%p, socket->port=%p", socket, socket->port));
	socket->port = port;
	LIST_INSERT_HEAD(&port->sockets, socket, link);
	mtx_unlock(&port->lock);

	khttpd_socket_schedule_read_event(socket);

	return (0);
}

static void
khttpd_socket_nopush(struct khttpd_socket *socket, int nopush)
{
	int error;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, socket, nopush);
	KASSERT(socket->is_tcp, ("socket %p is not a TCP socket", socket));

	error = so_setsockopt(socket->fp->f_data, IPPROTO_TCP, TCP_NOPUSH,
	    &nopush, sizeof(nopush));
	if (error != 0)
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "setsockopt(TCP_NOPUSH) failed");
}

static int
khttpd_socket_stream_receive(struct khttpd_stream *stream, ssize_t *resid,
    struct mbuf **m_out)
{
	struct uio auio;
	struct thread *td;
	struct mbuf *m;
	struct khttpd_socket *socket;
	ssize_t n;
	int error, flags;

	KHTTPD_ENTRY("%s(%p,%zd)", __func__, stream, *resid);

	td = curthread;
	socket = stream->down;

	bzero(&auio, sizeof(auio));
	auio.uio_resid = n = *resid;
	flags = 0;
	error = soreceive(socket->fp->f_data, NULL, &auio, &m, NULL, &flags);
	switch (error) {

	case EWOULDBLOCK:
		break;

	case 0:
		*resid = auio.uio_resid;
		*m_out = m;
		break;

	default:
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "recv() failed");
	}

	return (error);
}

static void
khttpd_socket_stream_continue_receiving(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	khttpd_socket_schedule_read_event(stream->down);
}

static void
khttpd_socket_stream_shutdown_receiver(struct khttpd_stream *stream)
{
	struct socket *so;
	struct khttpd_socket *socket;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;
	so = socket->fp->f_data;
	error = soshutdown(so, SHUT_RD);
	if (error != 0 && error != ENOTCONN)
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "shutdown(SHUT_RD) failed");
}

static boolean_t
khttpd_socket_send(struct khttpd_socket *socket)
{
	struct socket *so;
	struct mbuf *end, *head, *m, *prev;
	struct thread *td;
	ssize_t space, len, endlen;
	int error;
	boolean_t need_nopush, need_flush, need_close;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);
	mtx_assert(&socket->lock, MA_OWNED);

	if (socket->xmit_scheduled || socket->xmit_buf == NULL)
		return (FALSE);

	td = curthread;

	so = socket->fp->f_data;
	SOCKBUF_LOCK(&so->so_snd);
	space = sbspace(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);

	/* 
	 * Find 'end' such that the total length from 'head' to 'end' is
	 * less than the available space in the socket.
	 */

	head = socket->xmit_buf;
	prev = NULL;
	len = 0;
	for (end = head; end != NULL; end = end->m_next) {
		endlen = end->m_len;
		if (space < len + endlen)
			break;
		len += endlen;
		prev = end;
	}

	socket->xmit_buf = end;

	if (prev == NULL)
		head = NULL;
	else
		prev->m_next = NULL;

	need_nopush = need_flush = need_close = FALSE;

	if (end == NULL && socket->xmit_close_scheduled) {
		need_close = TRUE;
		socket->xmit_close_scheduled =
		    socket->xmit_flush_scheduled = FALSE;

	} else if (end == NULL && socket->xmit_flush_scheduled) {
		need_flush = socket->xmit_nopush;
		socket->xmit_flush_scheduled = FALSE;
		socket->xmit_nopush = FALSE;

	} else {
		need_nopush = !socket->xmit_nopush && socket->is_tcp;
		if (need_nopush)
			socket->xmit_nopush = TRUE;
	}

	socket->xmit_scheduled = TRUE;

	mtx_unlock(&socket->lock);

	if (need_nopush)
		khttpd_socket_nopush(socket, TRUE);

	if (head != NULL) {
		/* sosend needs a packet */
		if ((head->m_flags & M_PKTHDR) == 0) {
			m = m_gethdr(M_WAITOK, MT_DATA);
			m->m_next = head;
			head = m;
		}
		head->m_pkthdr.len = len;

		error = sosend(so, NULL, NULL, head, NULL, 0, td);
		if (error != 0 && error != EPIPE)
			khttpd_socket_error(socket, LOG_WARNING, error,
			    "send() failed");
	}

	if (need_close) {
		error = soshutdown(so, SHUT_WR);
		if (error != 0 && error != ENOTCONN)
			khttpd_socket_error(socket, LOG_WARNING, error,
			    "shutdown(SHUT_WR) failed");
	}

	if (need_flush)
		khttpd_socket_nopush(socket, FALSE);

	mtx_lock(&socket->lock);

	if (socket->xmit_buf == NULL && !socket->xmit_notification_requested) {
		socket->xmit_scheduled = FALSE;
		return (FALSE);
	}

	if (0 < socket->xmit_timeout)
		callout_reset_sbt_curcpu(&socket->xmit_callout,
		    socket->xmit_timeout, khttpd_port_timeout_pr,
		    khttpd_socket_handle_timeout,
		    socket->xmit_timeout_job, 0);

	return (TRUE);
}

static boolean_t
khttpd_socket_stream_send(struct khttpd_stream *stream, struct mbuf *m,
    int flags)
{
	struct khttpd_socket *socket;
	boolean_t need_scheduling, result;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, stream, m, flags);

	socket = stream->down;

	mtx_lock(&socket->lock);

	KASSERT(!socket->xmit_close_scheduled, ("socket has been closed"));

	if ((flags & KHTTPD_STREAM_CLOSE) != 0)
		socket->xmit_close_scheduled = TRUE;

	if ((flags & KHTTPD_STREAM_FLUSH) != 0)
		socket->xmit_flush_scheduled = TRUE;

	if (socket->xmit_buf != NULL)
		m_cat(socket->xmit_buf, m);
	else
		socket->xmit_buf = m;

	need_scheduling = khttpd_socket_send(socket);

	result = socket->xmit_buf != NULL;
	mtx_unlock(&socket->lock);

	if (need_scheduling)
		khttpd_event_enable(socket->write_event);

	return (result);
}

static void
khttpd_socket_stream_send_bufstat(struct khttpd_stream *stream, size_t *hiwat,
    size_t *lowat, size_t *space)
{
	struct khttpd_socket *socket;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;
	so = socket->fp->f_data;
	SOCKBUF_LOCK(&so->so_snd);
	if (hiwat != NULL)
		*hiwat = so->so_snd.sb_hiwat;
	if (lowat != NULL)
		*lowat = so->so_snd.sb_lowat;
	if (space != NULL)
		*space = sbspace(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);
}

static void
khttpd_socket_stream_notify_of_drain(struct khttpd_stream *stream)
{
	struct khttpd_socket *socket;
	boolean_t need_scheduling;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;

	mtx_lock(&socket->lock);

	socket->xmit_notification_requested = TRUE;
	need_scheduling = !socket->xmit_scheduled;
	socket->xmit_scheduled = TRUE;

	mtx_unlock(&socket->lock);

	if (need_scheduling)
		khttpd_event_enable(socket->write_event);
}

static void
khttpd_socket_stream_destroy(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	uma_zfree(khttpd_socket_zone, stream->down);
}

static void
khttpd_socket_shutdown(void *arg)
{
	struct linger linger;
	struct socket *so;
	struct khttpd_socket *socket;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	so = socket->fp->f_data;

	linger.l_onoff = 1;
	linger.l_linger = 0;
	error = so_setsockopt(socket->fp->f_data, SOL_SOCKET, SO_LINGER,
	    &linger, sizeof(linger));
	if (error != 0)
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "setsockopt(SOL_SOCKET, SO_LINGER) failed");

	error = soshutdown(so, SHUT_RD);
	if (error != 0 && error != ENOTCONN)
		khttpd_socket_error(socket, LOG_WARNING, error,
		    "shutdown(SHUT_RDWR) failed");
}

static void
khttpd_socket_handle_timeout(void *arg)
{

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	khttpd_job_schedule(arg, KHTTPD_JOB_FLAGS_NOWAIT);
}

static void
khttpd_socket_handle_read_event(void *arg)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;

	mtx_lock(&socket->lock);
	callout_stop(&socket->recv_callout);
	socket->recv_scheduled = FALSE;
	mtx_unlock(&socket->lock);

	khttpd_stream_data_is_available(socket->stream);
}

static void
khttpd_socket_handle_write_event(void *arg)
{
	struct socket *so;
	struct khttpd_socket *socket;
	ssize_t space;
	boolean_t need_scheduling, notify;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;

	mtx_lock(&socket->lock);

	callout_stop(&socket->xmit_callout);
	socket->xmit_scheduled = FALSE;

	if (socket->xmit_buf != NULL) {
		need_scheduling = khttpd_socket_send(socket);
		if (socket->xmit_buf != NULL)
			notify = FALSE;
		else {
			notify = socket->xmit_notification_requested;
			socket->xmit_notification_requested = FALSE;
		}
	} else {
		notify = socket->xmit_notification_requested;
		need_scheduling = FALSE;
		socket->xmit_notification_requested = FALSE;
	}

	mtx_unlock(&socket->lock);

	if (need_scheduling)
		khttpd_event_enable(socket->write_event);

	if (notify) {
		so = socket->fp->f_data;
		SOCKBUF_LOCK(&so->so_snd);
		space = sbspace(&so->so_snd);
		SOCKBUF_UNLOCK(&so->so_snd);

		khttpd_stream_clear_to_send(socket->stream, space);
	}
}

const struct sockaddr *
khttpd_socket_peer_address(struct khttpd_socket *socket)
{

	return ((struct sockaddr *)&socket->peer_address);
}

static void
khttpd_port_sysinit(void)
{

	KHTTPD_ENTRY("%s()", __func__);
	cap_rights_init(&khttpd_socket_rights, CAP_EVENT, CAP_GETPEERNAME,
	    CAP_GETSOCKOPT, CAP_RECV, CAP_SEND, CAP_SETSOCKOPT, CAP_SHUTDOWN);
}

SYSINIT(khttpd_port_sysinit, SI_SUB_CONFIGURE, SI_ORDER_ANY, 
    khttpd_port_sysinit, NULL);

static int
khttpd_port_costruct_init(void)
{

	KHTTPD_ENTRY("khttpd_port_costruct_init()");

	khttpd_costruct_info_new(&khttpd_port_costruct_info, 
	    sizeof(struct khttpd_port));

	return (0);
}

static void
khttpd_port_costruct_fini(void)
{

	KHTTPD_ENTRY("khttpd_port_costruct_fini()");
	khttpd_costruct_info_destroy(khttpd_port_costruct_info);
}

KHTTPD_INIT(, khttpd_port_costruct_init, khttpd_port_costruct_fini,
    KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS - 1);

static int
khttpd_port_run(void)
{

	KHTTPD_ENTRY("khttpd_port_run()");

	khttpd_socket_zone = uma_zcreate("socket",
	    sizeof(struct khttpd_socket), NULL, khttpd_socket_dtor,
	    khttpd_socket_init, khttpd_socket_fini, UMA_ALIGN_PTR, 0);

	return (0);
}

static void
khttpd_port_exit(void)
{

	KHTTPD_ENTRY("khttpd_port_exit()");

	mtx_lock(&khttpd_port_lock);
	while (0 < khttpd_port_count)
		mtx_sleep(&khttpd_port_count, &khttpd_port_lock, 0,
		    "portexit", 0);
	mtx_unlock(&khttpd_port_lock);

	uma_zdestroy(khttpd_socket_zone);
}

KHTTPD_INIT(khttpd_port, khttpd_port_run, khttpd_port_exit,
    KHTTPD_INIT_PHASE_RUN);
