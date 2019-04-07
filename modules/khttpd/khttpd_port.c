/*-
 * Copyright (c) 2018 Taketsuru <taketsuru11@gmail.com>.
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
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/smp.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/uio.h>
#include <sys/protosw.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockopt.h>
#include <sys/syslog.h>
#include <sys/un.h>
#include <net/vnet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <vm/uma.h>
#include <crypto/siphash/siphash.h>

#include "khttpd_costruct.h"
#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_problem.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_status_code.h"
#include "khttpd_stream.h"
#include "khttpd_task.h"

/* 
 * Key of locks
 * 
 * (a) khttpd_port_lock
 *
 * Lock ordering
 *
 * SOCKBUF_LOCK
 * khttpd_port_lock
 * 
 */

struct khttpd_socket {
	LIST_ENTRY(khttpd_socket) liste;  /* (a) */
	struct sockaddr_storage	peeraddr;
	struct callout		rcv_callout;
	struct callout		snd_callout;
	struct khttpd_task	*cnf_task;
	struct khttpd_task	*rcv_task;
	struct khttpd_task	*rst_task;
	struct khttpd_task	*snd_task;
	struct khttpd_task_queue *queue;

#define khttpd_socket_zero_begin port
	struct khttpd_port	*port;
	struct khttpd_stream	*stream;
	struct mbuf		*xmit_buf;
	struct socket		*so;
	const char		*smesg;
	khttpd_socket_config_fn_t config_fn;
	khttpd_socket_error_fn_t error_fn;
	void			*config_arg;
	unsigned		is_tcp:1;
	unsigned		is_client:1;
	unsigned		xmit_flush_scheduled:1;
	unsigned		xmit_close_scheduled:1;
	unsigned		xmit_notification_requested:1;
};

LIST_HEAD(khttpd_socket_list, khttpd_socket);

struct khttpd_port {
	LIST_ENTRY(khttpd_port) liste; /* (a) */
	struct khttpd_task	*arrival_task;
	struct khttpd_task	*stop_task;
	struct khttpd_task_queue *queue;

#define khttpd_port_zctor_begin	addr
	struct sockaddr_storage	addr;
	struct socket		*so;
	khttpd_socket_config_fn_t config_fn;
	void			*config_arg;
	unsigned		costructs_ready:1;
	unsigned		marker:1;

#define khttpd_port_zctor_end	refcount
	KHTTPD_REFCOUNT1_MEMBERS;
};

LIST_HEAD(khttpd_port_list, khttpd_port);

struct khttpd_port_start_args {
	struct sockaddr_storage		sockaddr;
	khttpd_socket_error_fn_t	error_fn;
	khttpd_socket_config_fn_t	config_fn;
	void				*arg;
	struct khttpd_port		*port;
};

static int khttpd_socket_stream_receive(struct khttpd_stream *, ssize_t *,
    struct mbuf **);
static void khttpd_socket_stream_continue_receiving(struct khttpd_stream *,
	sbintime_t);
static bool khttpd_socket_stream_send(struct khttpd_stream *,
    struct mbuf *, int);
static void khttpd_socket_stream_send_bufstat(struct khttpd_stream *,
    u_int *, int *, long *);
static void khttpd_socket_stream_notify_of_drain(struct khttpd_stream *);
static void khttpd_socket_stream_destroy(struct khttpd_stream *);

extern int uma_align_cache;

struct khttpd_costruct_info *khttpd_port_costruct_info;

static struct khttpd_stream_down_ops khttpd_socket_ops = {
	.receive = khttpd_socket_stream_receive,
	.continue_receiving = khttpd_socket_stream_continue_receiving,
	.send = khttpd_socket_stream_send,
	.send_bufstat = khttpd_socket_stream_send_bufstat,
	.notify_of_drain = khttpd_socket_stream_notify_of_drain,
	.destroy = khttpd_socket_stream_destroy
};
static struct mtx khttpd_port_lock;
static struct khttpd_port_list khttpd_ports_running =
    LIST_HEAD_INITIALIZER(khttpd_ports); /* (a) */
static struct khttpd_socket_list khttpd_port_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets); /* (a) */
static eventhandler_tag khttpd_port_shutdown_tag;
static uma_zone_t khttpd_socket_zone;
static const sbintime_t khttpd_port_timeout_pr = SBT_1S * 2;
static bool khttpd_port_ready;		/* (a) */

MTX_SYSINIT(khttpd_port_lock, &khttpd_port_lock, "ports", MTX_DEF);

static void
khttpd_socket_assert_curthread(struct khttpd_socket *socket)
{

	KASSERT(khttpd_task_queue_on_worker_thread(socket->queue),
	    ("not on the worker thread"));
}

static void
khttpd_socket_report_error(struct khttpd_socket *socket, int severity,
    int error, const char *detail)
{
	struct khttpd_mbuf_json entry;

	khttpd_socket_assert_curthread(socket);

	khttpd_problem_log_new(&entry, severity, "socket_error",
	    "socket I/O error");
	khttpd_problem_set_detail(&entry, detail);
	khttpd_problem_set_errno(&entry, error);
	khttpd_stream_error(socket->stream, &entry);
}

static void
khttpd_socket_on_timeout(void *arg)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	socket = arg;
	khttpd_task_schedule(socket->rst_task);
}

static int
khttpd_socket_on_rcv_upcall(struct socket *so, void *arg, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);

	if (soreadable(so)) {
		soupcall_clear(so, SO_RCV);
		socket = arg;
		callout_stop(&socket->rcv_callout);
		khttpd_task_schedule(socket->rcv_task);
	}

	return (SU_OK);
}

static void
khttpd_socket_set_rcv_upcall(struct khttpd_socket *socket, sbintime_t timeout,
	bool on_worker_thread)
{
	struct socket *so;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, socket, timeout);
	KASSERT(socket->so != NULL, ("socket %p, so NULL", socket));

	so = socket->so;

	SOCKBUF_LOCK(&so->so_rcv);
	KASSERT((so->so_rcv.sb_flags & SB_UPCALL) == 0,
	    ("socket %p already set upcall", socket));

	if (soreadable(so)) {
		khttpd_task_schedule(socket->rcv_task);
		SOCKBUF_UNLOCK(&so->so_rcv);

	} else {
		KHTTPD_NOTE("%s soupcall_set %p", __func__, so);
		soupcall_set(so, SO_RCV, khttpd_socket_on_rcv_upcall, socket);

		if (0 < timeout) {
			KHTTPD_NOTE("set timeout %#lx", timeout);
			callout_reset_sbt_curcpu(&socket->rcv_callout,
			    timeout, khttpd_port_timeout_pr,
			    khttpd_socket_on_timeout, socket, 0);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
	}
}

static int
khttpd_socket_on_snd_upcall(struct socket *so, void *arg, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);

	if (sowriteable(so)) {
		soupcall_clear(so, SO_SND);
		socket = arg;
		callout_stop(&socket->snd_callout);
		khttpd_task_schedule(socket->snd_task);
	}

	return (SU_OK);
}

static void
khttpd_socket_set_snd_upcall(struct khttpd_socket *socket, sbintime_t timeout)
{
	struct socket *so;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, socket, timeout);
	KASSERT(socket->so != NULL, ("socket %p, so NULL", socket));

	so = socket->so;

	SOCKBUF_LOCK(&so->so_snd);
	KASSERT((so->so_snd.sb_flags & SB_UPCALL) == 0,
	    ("socket %p already set upcall", socket));

	if (sowriteable(so)) {
		khttpd_task_schedule(socket->snd_task);

	} else {
		KHTTPD_NOTE("%s soupcall_set %p", __func__, so);
		soupcall_set(so, SO_SND, khttpd_socket_on_snd_upcall, socket);

		if (0 < timeout) {
			KHTTPD_NOTE("set timeout %#lx", timeout);
			callout_reset_sbt_curcpu(&socket->snd_callout,
			    timeout, khttpd_port_timeout_pr,
			    khttpd_socket_on_timeout, socket, 0);
		}
	}

	SOCKBUF_UNLOCK(&so->so_snd);
}

static int
khttpd_socket_stream_receive(struct khttpd_stream *stream, ssize_t *resid,
    struct mbuf **m_out)
{
	struct uio auio;
	struct mbuf *m;
	struct khttpd_socket *socket;
	ssize_t reqsize;
	int error, flags;

	KHTTPD_ENTRY("%s(%p,%zd)", __func__, stream, *resid);

	socket = stream->down;
	khttpd_socket_assert_curthread(socket);

	bzero(&auio, sizeof(auio));
	auio.uio_resid = reqsize = *resid;

	flags = 0;
	error = soreceive(socket->so, NULL, &auio, &m, NULL, &flags);
	if (error != 0 && auio.uio_resid != reqsize) {
		error = 0;
	}
	if (error == 0) {
		*resid = auio.uio_resid;
		*m_out = m;
	}

	return (error);
}

static void
khttpd_socket_stream_continue_receiving(struct khttpd_stream *stream,
	sbintime_t timeout)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	socket = stream->down;
	KASSERT(socket != NULL, ("no socket"));
	khttpd_socket_set_rcv_upcall(socket, timeout,
	    khttpd_task_queue_on_worker_thread(socket->queue));
}

static bool
khttpd_socket_send(struct khttpd_socket *socket)
{
	struct socket *so;
	struct mbuf *end, *head, *m, *prev;
	struct thread *td;
	ssize_t space, len, endlen;
	int error, flags;
	bool need_close;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);
	khttpd_socket_assert_curthread(socket);

	if (socket->xmit_buf == NULL) {
		return (false);
	}

	td = curthread;
	so = socket->so;
	SOCKBUF_LOCK(&so->so_snd);
	space = sbspace(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);

	/* 
	 * Find 'end' such that the total length from 'head' to 'end' is less
	 * than the available space in the socket.
	 */

	head = socket->xmit_buf;
	prev = NULL;
	len = 0;
	for (end = head; end != NULL; end = end->m_next) {
		endlen = end->m_len;
		if (space < len + endlen) {
			break;
		}
		len += endlen;
		prev = end;
	}

	socket->xmit_buf = end;

	if (prev == NULL) {
		head = NULL;
	} else {
		prev->m_next = NULL;
	}

	flags = 0;
	if (end != NULL ||
	    (!socket->xmit_close_scheduled && !socket->xmit_flush_scheduled)) {
		flags |= PRUS_MORETOCOME;
	}

	need_close = end == NULL && socket->xmit_close_scheduled;
	if (need_close) {
		socket->xmit_close_scheduled =
		    socket->xmit_flush_scheduled = false;
	} else if (end == NULL && socket->xmit_flush_scheduled) {
		socket->xmit_flush_scheduled = false;
	}

	if (head != NULL) {
		/* sosend needs a packet */
		if ((head->m_flags & M_PKTHDR) == 0) {
			m = m_gethdr(M_WAITOK, MT_DATA);
			m->m_next = head;
			head = m;
		}
		head->m_pkthdr.len = len;

		error = sosend(so, NULL, NULL, head, NULL, flags, td);
		if (error != 0) {
			KHTTPD_NOTE("%s error %d", __func__, error);
			khttpd_socket_report_error(socket, LOG_WARNING, error,
			    "send() failed");
		}
	}

	if (need_close) {
		error = soshutdown(so, SHUT_WR);
		if (error != 0) {
			KHTTPD_NOTE("%s error %d", __func__, error);
			khttpd_socket_report_error(socket, LOG_WARNING, error,
			    "shutdown(SHUT_WR) failed");
		}
	}

	if (end == NULL) {
		return (false);
	}

	khttpd_socket_set_snd_upcall(socket, 0);

	return (true);
}

static bool
khttpd_socket_stream_send(struct khttpd_stream *stream, struct mbuf *m,
    int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, stream, m, flags);

	socket = stream->down;
	khttpd_socket_assert_curthread(socket);
	KASSERT(!socket->xmit_close_scheduled, ("socket has been closed"));

	if ((flags & KHTTPD_STREAM_CLOSE) != 0) {
		socket->xmit_close_scheduled = true;
	}

	if ((flags & KHTTPD_STREAM_FLUSH) != 0) {
		socket->xmit_flush_scheduled = true;
	}

	if (socket->xmit_buf != NULL) {
		m_cat(socket->xmit_buf, m);
		return (true);
	}

	socket->xmit_buf = m;

	return (khttpd_socket_send(socket));
}

static void
khttpd_socket_stream_send_bufstat(struct khttpd_stream *stream, u_int *hiwat,
    int *lowat, long *space)
{
	struct khttpd_socket *socket;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;
	so = socket->so;
	khttpd_socket_assert_curthread(socket);

	SOCKBUF_LOCK(&so->so_snd);
	if (hiwat != NULL) {
		*hiwat = so->so_snd.sb_hiwat;
	}
	if (lowat != NULL) {
		*lowat = so->so_snd.sb_lowat;
	}
	if (space != NULL) {
		*space = sbspace(&so->so_snd);
	}
	SOCKBUF_UNLOCK(&so->so_snd);
}

static void
khttpd_socket_stream_notify_of_drain(struct khttpd_stream *stream)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;
	khttpd_socket_assert_curthread(socket);
	socket->xmit_notification_requested = true;
	if (socket->xmit_buf == NULL) {
		khttpd_socket_set_snd_upcall(socket, 0);
	}
}

static void
khttpd_socket_destroy(struct khttpd_socket *socket)
{
	struct khttpd_stream *stream;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);
	khttpd_socket_assert_curthread(socket);
	KASSERT(socket->so != NULL, ("so is NULL"));

	if ((stream = socket->stream) != NULL) {
		stream->down = NULL;
		socket->stream = NULL;
	}

	mtx_lock(&khttpd_port_lock);
	LIST_REMOVE(socket, liste);
	if (LIST_EMPTY(&khttpd_port_sockets)) {
		wakeup(&khttpd_port_sockets);
	}
	mtx_unlock(&khttpd_port_lock);

	callout_drain(&socket->rcv_callout);
	callout_drain(&socket->snd_callout);

	so = socket->so;

	SOCKBUF_LOCK(&so->so_rcv);
	if ((so->so_rcv.sb_flags & SB_UPCALL) != 0) {
		soupcall_clear(so, SO_RCV);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);

	SOCKBUF_LOCK(&so->so_snd);
	if ((so->so_snd.sb_flags & SB_UPCALL) != 0) {
		soupcall_clear(so, SO_SND);
	}
	SOCKBUF_UNLOCK(&so->so_snd);

	khttpd_task_cancel(socket->rcv_task);
	khttpd_task_cancel(socket->rst_task);
	khttpd_task_cancel(socket->snd_task);

	uma_zfree(khttpd_socket_zone, socket);
}

static void
khttpd_socket_stream_destroy(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	khttpd_socket_destroy(stream->down);
	stream->down = NULL;
}

static bool
khttpd_socket_enter(struct khttpd_socket *socket)
{

	KHTTPD_ENTRY("%s(%p)", __func__, socket);

	mtx_lock(&khttpd_port_lock);

	if (!khttpd_port_ready) {
		mtx_unlock(&khttpd_port_lock);
		return (true);
	}

	LIST_INSERT_HEAD(&khttpd_port_sockets, socket, liste);

	mtx_unlock(&khttpd_port_lock);

	return (false);
}

const struct sockaddr *
khttpd_socket_name(struct khttpd_socket *socket)
{
	struct sockaddr *sa;
	struct socket *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);
	khttpd_socket_assert_curthread(socket);

	so = socket->so;
	sa = NULL;
	CURVNET_SET(so->so_vnet);
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	CURVNET_RESTORE();

	return (error == 0 ? sa : NULL);
}

const struct sockaddr *
khttpd_socket_peer_address(struct khttpd_socket *socket)
{

	return ((struct sockaddr *)&socket->peeraddr);
}

struct khttpd_task_queue *
khttpd_socket_task_queue(struct khttpd_socket *socket)
{

	return (socket->queue);
}

void
khttpd_socket_set_smesg(struct khttpd_socket *sock, const char *smesg)
{

	sock->smesg = smesg;
}

static int
khttpd_socket_did_connected_upcall(struct socket *so, void *arg, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);
	SOCKBUF_LOCK_ASSERT(&so->so_snd);

	socket = arg;

	if (sowriteable(so)) {
		KASSERT((so->so_snd.sb_flags & SB_UPCALL) != 0,
		    ("so_snd.sb_flags %#x", so->so_snd.sb_flags));
		soupcall_clear(so, SO_SND);
		khttpd_task_schedule(socket->cnf_task);
	}

	return (SU_OK);
}

static void
khttpd_socket_do_connect_task(void *arg)
{
	struct khttpd_mbuf_json problem;
	struct khttpd_socket *socket;
	struct socket *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	so = socket->so;

	error = soconnect(so, (struct sockaddr *)&socket->peeraddr, curthread);
	if (error != 0 && error != EINPROGRESS) {
		KHTTPD_NOTE("%s error %d", __func__, error);

		khttpd_mbuf_json_new(&problem);
		khttpd_mbuf_json_object_begin(&problem);
		khttpd_problem_set_errno(&problem, error);
		khttpd_problem_set_detail(&problem,
		    "socket connection failure");
		socket->error_fn(socket->config_arg, &problem);
		khttpd_mbuf_json_delete(&problem);
		khttpd_socket_destroy(socket);
		return;
	}

	SOCKBUF_LOCK(&so->so_snd);

	soupcall_set(so, SO_SND, khttpd_socket_did_connected_upcall, socket);
	khttpd_socket_did_connected_upcall(so, socket, 0);

	SOCKBUF_UNLOCK(&so->so_snd);
}

void
khttpd_socket_connect(struct sockaddr *peeraddr, struct sockaddr *sockaddr,
    khttpd_socket_config_fn_t fn, void *arg, khttpd_socket_error_fn_t error_fn)
{
	struct khttpd_mbuf_json problem;
	struct khttpd_socket *socket;
	struct socket *so;
	struct thread *td;
	const char *detail;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, peeraddr, sockaddr);

	td = curthread;
	detail = NULL;

	if (sizeof(socket->peeraddr) < peeraddr->sa_len ||
	    (sockaddr != NULL && sockaddr->sa_family != peeraddr->sa_family)) {
		KHTTPD_NOTE("%s peeraddr EINVAL", __func__);
		khttpd_mbuf_json_new(&problem);
		khttpd_mbuf_json_object_begin(&problem);
		khttpd_problem_set_detail(&problem, "invalid peer address");
		error_fn(arg, &problem);
		khttpd_mbuf_json_delete(&problem);
		return;
	}

	error = socreate(peeraddr->sa_family, &so, SOCK_STREAM, 0, 
	    td->td_ucred, td);
	if (error != 0) {
		KHTTPD_NOTE("%s socreate error %d", __func__, error);
		khttpd_mbuf_json_new(&problem);
		khttpd_mbuf_json_object_begin(&problem);
		khttpd_problem_set_detail(&problem, "socket creation failure");
		khttpd_problem_set_errno(&problem, error);
		error_fn(arg, &problem);
		khttpd_mbuf_json_delete(&problem);
		return;
	}

	if (sockaddr != NULL) {
		error = sobind(so, sockaddr, td);
		if (error != 0) {
			KHTTPD_NOTE("%s sobind error %d", __func__, error);
			soclose(so);

			khttpd_mbuf_json_new(&problem);
			khttpd_mbuf_json_object_begin(&problem);
			khttpd_problem_set_detail(&problem, 
			    "socket bind failure");
			khttpd_problem_set_errno(&problem, error);
			error_fn(arg, &problem);
			khttpd_mbuf_json_delete(&problem);
			return;
		}
	}

	socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
	socket->so = so;
	socket->config_fn = fn;
	socket->error_fn = error_fn;
	socket->config_arg = arg;
	bcopy(peeraddr, &socket->peeraddr, peeraddr->sa_len);
	socket->is_tcp = peeraddr->sa_family == AF_INET || 
	    peeraddr->sa_family == AF_INET6;
	socket->is_client = true;

	SOCK_LOCK(so);
	so->so_state |= SS_NBIO;
	SOCK_UNLOCK(so);

	if (khttpd_socket_enter(socket)) {
		uma_zfree(khttpd_socket_zone, socket);

		khttpd_mbuf_json_new(&problem);
		khttpd_mbuf_json_object_begin(&problem);
		khttpd_problem_set_detail(&problem,
		    "socket connection aborted");
		error_fn(arg, &problem);
		khttpd_mbuf_json_delete(&problem);
		return;
	}

	khttpd_task_queue_run(socket->queue, 
	    khttpd_socket_do_connect_task, socket);
}

void
khttpd_socket_reset(struct khttpd_socket *socket)
{
	struct linger linger;
	struct sockopt sockopt;
	struct socket *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);
	khttpd_socket_assert_curthread(socket);

	so = socket->so;
	if (so != NULL) {
		sockopt.sopt_dir = SOPT_SET;
		sockopt.sopt_level = SOL_SOCKET;
		sockopt.sopt_name = SO_LINGER;
		sockopt.sopt_val = &linger;
		sockopt.sopt_valsize = sizeof(linger);
		sockopt.sopt_td = NULL;
		linger.l_onoff = 1;
		linger.l_linger = 0;
		error = sosetopt(so, &sockopt);
		if (error != 0) {
			KHTTPD_NOTE("sosetopt error %d", error);
		}

		error = soshutdown(so, SHUT_RDWR);
		if (error != 0) {
			KHTTPD_NOTE("shutdown error %d", error);
			khttpd_socket_report_error(socket, LOG_ERR, error,
			    "shutdown(SHUT_RD) failed");
		}
	}

	if (socket->stream != NULL) {
		khttpd_stream_reset(socket->stream);
	} else {
		khttpd_socket_destroy(socket);
	}
}

static int
khttpd_port_costruct_init(void)
{

	KHTTPD_ENTRY("%s()", __func__);
	khttpd_costruct_info_new(&khttpd_port_costruct_info, 
	    sizeof(struct khttpd_port));
	return (0);
}

static void
khttpd_port_costruct_fini(void)
{

	KHTTPD_ENTRY("%s()", __func__);
	khttpd_costruct_info_destroy(khttpd_port_costruct_info);
}

KHTTPD_INIT(, khttpd_port_costruct_init, khttpd_port_costruct_fini,
    KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS - 1);

static void
khttpd_socket_do_cnf_task(void *arg)
{
	struct khttpd_mbuf_json problem;
	struct khttpd_socket_config conf;
	struct sockopt sockopt;
	struct khttpd_socket *socket;
	struct khttpd_stream *stream;
	struct socket *so;
	int error, soptval;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	socket = arg;
	so = socket->so;

	error = so->so_error;
	if (error != 0) {
		KHTTPD_NOTE("%s so_error %d", __func__, error);
		so->so_error = 0;
		if (socket->error_fn != NULL) {
			khttpd_problem_log_new(&problem, LOG_ERR,
			    "socket_error", "socket error");
			khttpd_problem_set_detail(&problem, "so_error");
			khttpd_problem_set_errno(&problem, error);
			socket->error_fn(arg, &problem);
			khttpd_mbuf_json_delete(&problem);
		}
		goto error;
	}

	so = socket->so;
	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_NOSIGPIPE;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		KHTTPD_NOTE("%s sosetopt(SO_NOSIGPIPE) error %d", error);
		if (socket->error_fn != NULL) {
			khttpd_problem_log_new(&problem, LOG_ERR,
			    "socket_error", "socket error");
			khttpd_problem_set_detail(&problem,
			    "sosetopt(SO_NOSIGPIPE) failed");
			khttpd_problem_set_errno(&problem, error);
			socket->error_fn(arg, &problem);
			khttpd_mbuf_json_delete(&problem);
		}
		goto error;
	}

	if (socket->is_tcp) {
		soptval = 1;
		sockopt.sopt_level = IPPROTO_TCP;
		sockopt.sopt_name = TCP_NODELAY;
		error = sosetopt(so, &sockopt);
		if (error != 0) {
			KHTTPD_NOTE("%s sosetopt(TCP_NODELAY) error %d",
			    error);
			if (socket->error_fn != NULL) {
				khttpd_problem_log_new(&problem, LOG_ERR,
				    "socket_error", "socket error");
				khttpd_problem_set_detail(&problem,
				    "sosetopt(TCP_NODELAY) failed");
				khttpd_problem_set_errno(&problem, error);
				socket->error_fn(arg, &problem);
				khttpd_mbuf_json_delete(&problem);
			}
			goto error;
		}
	}

	bzero(&conf, sizeof(conf));
	error = socket->config_fn(socket, socket->config_arg, &conf);
	if (error != 0) {
		goto error;
	}

	socket->stream = stream = conf.stream;
	stream->down = socket;
	stream->down_ops = &khttpd_socket_ops;
	khttpd_stream_on_configured(stream);

	khttpd_socket_set_rcv_upcall(socket, conf.timeout, true);

	return;

 error:
	khttpd_socket_destroy(socket);
}

static void
khttpd_socket_do_rst_task(void *arg)
{

	khttpd_socket_reset(arg);
}

static void
khttpd_socket_do_rcv_task(void *arg)
{
	struct khttpd_socket *socket;

	socket = arg;
	khttpd_stream_data_is_available(socket->stream);
}

static void
khttpd_socket_do_snd_task(void *arg)
{
	struct khttpd_socket *socket;
	struct socket *so;
	long space;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;

	if (socket->xmit_buf != NULL && khttpd_socket_send(socket)) {
		return;
	}

	if (!socket->xmit_notification_requested) {
		return;
	}

	so = socket->so;
	SOCKBUF_LOCK(&so->so_snd);
	if (!sowriteable(so)) {
		SOCKBUF_UNLOCK(&so->so_snd);
		khttpd_socket_set_snd_upcall(socket, 0);
		return;
	}
	space = sbspace(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);

	socket->xmit_notification_requested = false;
	khttpd_stream_clear_to_send(socket->stream, space);
}

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;
	struct khttpd_task_queue *queue;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;
	queue = khttpd_task_queue_new("sock", socket);

	callout_init(&socket->rcv_callout, 0);
	callout_init(&socket->snd_callout, 0);

	socket->cnf_task = khttpd_task_new(queue,
	    khttpd_socket_do_cnf_task, socket, "cnf");
	socket->rcv_task = khttpd_task_new(queue,
	    khttpd_socket_do_rcv_task, socket, "rcv");
	socket->rst_task = khttpd_task_new(queue,
	    khttpd_socket_do_rst_task, socket, "rst");
	socket->snd_task = khttpd_task_new(queue,
	    khttpd_socket_do_snd_task, socket, "snd");

	socket->queue = queue;

	return (0);
}

static void
khttpd_socket_fini(void *mem, int size)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, mem, size);

	socket = mem;
	khttpd_task_delete(socket->cnf_task);
	khttpd_task_delete(socket->rcv_task);
	khttpd_task_delete(socket->rst_task);
	khttpd_task_delete(socket->snd_task);
	khttpd_task_queue_delete(socket->queue);
}

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;
	khttpd_task_queue_assign_random_worker(socket->queue);
	bzero(&socket->khttpd_socket_zero_begin, sizeof(*socket) -
	    offsetof(struct khttpd_socket, khttpd_socket_zero_begin));

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_socket *socket;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, mem, size, arg);

	socket = mem;
	KASSERT(callout_drain(&socket->rcv_callout) == -1,
	    ("rcv_task callout active"));
	KASSERT(callout_drain(&socket->snd_callout) == -1,
	    ("snd_task callout active"));
	KASSERT(!khttpd_task_queue_is_active(socket->queue),
	    ("queue %p is active", socket->queue));

#ifdef INVARIANTS
	struct khttpd_socket *ptr;
	mtx_lock(&khttpd_port_lock);
	LIST_FOREACH(ptr, &khttpd_port_sockets, liste) {
		KASSERT(ptr != socket, ("in khttpd_port_sockets"));
	}
	mtx_unlock(&khttpd_port_lock);
#endif

	khttpd_port_release(socket->port);
	KASSERT(socket->stream == NULL, ("stream is not destroyed"));

	m_freem(socket->xmit_buf);

	if ((so = socket->so) != NULL) {
		KHTTPD_NOTE("%s soclose", __func__);
		soclose(so);
	}
}

static void
khttpd_port_dtor(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	KASSERT(port->so == NULL, ("port is running"));
	KASSERT(!khttpd_task_queue_is_active(port->queue),
	    ("queue %p is active", port->queue));

	if (port->costructs_ready) {
		khttpd_costruct_call_dtors(khttpd_port_costruct_info, port);
	}
}

static void
khttpd_port_fini(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	khttpd_task_delete(port->arrival_task);
	khttpd_task_delete(port->stop_task);
	khttpd_task_queue_delete(port->queue);
	khttpd_free(port);
}

KHTTPD_REFCOUNT1_GENERATE(khttpd_port, khttpd_port_dtor, khttpd_port_fini);

static void
khttpd_port_do_arrival_task(void *arg)
{
	struct khttpd_port *port;
	struct khttpd_socket *socket;
	struct sockaddr *name;
	struct socket *head, *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;
	head = port->so;

	for (;;) {
		SOLISTEN_LOCK(head);
		error = solisten_dequeue(head, &so, 0);

		if (error != 0) {
			/* XXX what should I do? */
			KHTTPD_NOTE("%s solisten_dequeue %d", __func__, error);
			break;
		}

		error = soaccept(so, &name);
		if (error != 0) {
			KHTTPD_NOTE("%s soaccept %d", __func__, error);
			soclose(so);
			continue;
		}

		socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
		socket->port = khttpd_port_acquire(arg);
		socket->so = so;
		socket->config_fn = port->config_fn;
		socket->config_arg = port->config_arg;
		socket->is_tcp = port->addr.ss_family == AF_INET ||
		    port->addr.ss_family == AF_INET6;
		bcopy(name, &socket->peeraddr,
		    MIN(sizeof(socket->peeraddr), name->sa_len));

		if (khttpd_socket_enter(socket)) {
			uma_zfree(khttpd_socket_zone, socket);
		} else {
			khttpd_task_schedule(socket->cnf_task);
		}
	}
}

static void
khttpd_port_do_stop_task(void *arg)
{
	struct khttpd_port *port;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;

	if ((so = port->so) == NULL) {
		khttpd_port_release(port);
		return;
	}
	port->so = NULL;
	khttpd_port_release(port);

	if (SOLISTENING(so)) {
		SOLISTEN_LOCK(so);
		solisten_upcall_set(so, NULL, NULL);
		SOLISTEN_UNLOCK(so);
	} else {
		SOCKBUF_LOCK(&so->so_rcv);
		if ((so->so_rcv.sb_flags & SB_UPCALL) != 0) {
			soupcall_clear(so, SO_RCV);
		}
		SOCKBUF_UNLOCK(&so->so_rcv);
	}

	soclose(so);

	mtx_lock(&khttpd_port_lock);
	LIST_REMOVE(port, liste);
	if (LIST_EMPTY(&khttpd_ports_running)) {
		wakeup(&khttpd_ports_running);
	}
	mtx_unlock(&khttpd_port_lock);

	khttpd_task_cancel(port->arrival_task);
	if (khttpd_task_cancel(port->stop_task)) {
		khttpd_port_release(port);
	}

	khttpd_port_release(port);
}

int
khttpd_port_new(struct khttpd_port **port_out)
{
	struct khttpd_port *port;
	struct thread *td;
	int error;

	KHTTPD_ENTRY("%s()", __func__);

	td = curthread;

	port = khttpd_malloc(khttpd_costruct_instance_size
	    (khttpd_port_costruct_info));

	port->queue = khttpd_task_queue_new("port%p", port);
	port->arrival_task = khttpd_task_new(port->queue,
	    khttpd_port_do_arrival_task, port, "arrival%p", port->queue);
	port->stop_task = khttpd_task_new(port->queue,
	    khttpd_port_do_stop_task, port, "stop%p", port->queue);

	bzero(&port->khttpd_port_zctor_begin,
	    offsetof(struct khttpd_port, khttpd_port_zctor_end) -
	    offsetof(struct khttpd_port, khttpd_port_zctor_begin));
	KHTTPD_REFCOUNT1_INIT(khttpd_port, port);

	error = khttpd_costruct_call_ctors(khttpd_port_costruct_info, port);
	if (error != 0) {
		khttpd_port_release(port);
		return (error);
	}

	port->costructs_ready = true;
	*port_out = port;

	return (error);
}

const struct sockaddr *
khttpd_port_address(struct khttpd_port *port)
{

	return ((struct sockaddr *)&port->addr);
}

static int
khttpd_port_do_arrival_upcall(struct socket *head, void *arg, int flags)
{
	struct khttpd_port *port;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, head, arg, flags);
	port = arg;
	khttpd_task_schedule(port->arrival_task);
	return (SU_OK);
}

static void
khttpd_port_do_start_task(void *arg)
{
	struct khttpd_mbuf_json problem;
	struct sockopt sockopt;
	struct khttpd_port_start_args *args;
	struct khttpd_port *port;
	struct socket *so;
	struct thread *td;
	int error, soptval;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	args = arg;
	td = curthread;
	port = args->port;
	KASSERT(port->costructs_ready, ("!costructs_ready"));

	if ((so = port->so) != NULL) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem, "port is running");
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	error = socreate(args->sockaddr.ss_family, &so, SOCK_STREAM, 0,
	    td->td_ucred, td);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem,
		    "socket construction failed");
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	port->so = so;
	bcopy(&args->sockaddr, &port->addr, args->sockaddr.ss_len);
	port->config_fn = args->config_fn;
	port->config_arg = args->arg;

	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_REUSEADDR;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem,
		    "setsockopt(SO_REUSEADDR) failed");
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	sockopt.sopt_dir = SOPT_GET;
	sockopt.sopt_name = SO_SNDBUF;
	error = sogetopt(so, &sockopt);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem,
		    "getsockopt(SO_SNDBUF) failed");
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	soptval = MAX(PAGE_SIZE, soptval / 2);
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_name = SO_SNDLOWAT;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem,
		    "setsockopt(SO_SNDLOWAT) failed");
		khttpd_problem_set_errno(&problem, error);
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	error = sobind(so, (struct sockaddr *)&args->sockaddr, td);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem, "bind failed");
		khttpd_problem_set_errno(&problem, error);
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	error = solisten(so, -1, td);
	if (error != 0) {
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem, "listen failed");
		khttpd_problem_set_errno(&problem, error);
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}

	mtx_lock(&khttpd_port_lock);
	if (!khttpd_port_ready) {
		mtx_unlock(&khttpd_port_lock);
		khttpd_problem_log_new(&problem, LOG_ERR, "internal_error",
		    "internal error");
		khttpd_problem_set_detail(&problem, "server down");
		args->error_fn(port, args->arg);
		khttpd_mbuf_json_delete(&problem);
		goto quit;
	}
	LIST_INSERT_HEAD(&khttpd_ports_running, port, liste);
	mtx_unlock(&khttpd_port_lock);

	khttpd_free(arg);

	SOLISTEN_LOCK(so);
	so->so_state |= SS_NBIO;
	solisten_upcall_set(so, khttpd_port_do_arrival_upcall, port);
	SOLISTEN_UNLOCK(so);

	khttpd_port_do_arrival_task(port);
	return;

 quit:
	khttpd_port_release(args->port);
	khttpd_free(arg);
}

void
khttpd_port_start(struct khttpd_port *port, struct sockaddr *addr,
    khttpd_socket_config_fn_t fn, khttpd_socket_error_fn_t error_fn,
    void *arg)
{
	struct khttpd_mbuf_json problem;
	struct khttpd_port_start_args *args;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, port, addr, fn);
	KASSERT(port->costructs_ready, ("!costructs_ready"));

	if (sizeof(args->sockaddr) < addr->sa_len) {
		khttpd_problem_log_new(&problem, LOG_ERR, "invalid_value",
		    "invalid value");
		khttpd_problem_set_detail(&problem, "invalid address");
		error_fn(port, arg);
		khttpd_mbuf_json_delete(&problem);
		return;
	}

	args = khttpd_malloc(sizeof(*args));
	bcopy(addr, &args->sockaddr, addr->sa_len);
	args->config_fn = fn;
	args->error_fn = error_fn;
	args->arg = arg;
	args->port = khttpd_port_acquire(port);

	khttpd_task_queue_run(port->queue, khttpd_port_do_start_task, args);
}

void
khttpd_port_stop(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	KASSERT(port->costructs_ready, ("!costructs_ready"));
	khttpd_port_acquire(port);
	if (khttpd_task_schedule(port->stop_task)) {
		khttpd_port_release(port);
	}
}

static void
khttpd_port_shutdown(void *arg)
{
	struct khttpd_socket *socket;

	mtx_lock(&khttpd_port_lock);

	KASSERT(khttpd_port_ready, ("!ready"));
	khttpd_port_ready = false;

	/* 
	 * khttpd_ctrl has the resposibility to stop all the running ports.
	 */

	while (!LIST_EMPTY(&khttpd_ports_running)) {
		mtx_sleep(&khttpd_ports_running, &khttpd_port_lock, 0,
		    "prtshtdwn", 0);
	}

	LIST_FOREACH(socket, &khttpd_port_sockets, liste) {
		khttpd_task_schedule(socket->rst_task);
	}

	while (!LIST_EMPTY(&khttpd_port_sockets)) {
		mtx_sleep(&khttpd_port_sockets, &khttpd_port_lock, 0,
		    "soshtdwn", 0);
	}

	mtx_unlock(&khttpd_port_lock);
}

static void
khttpd_port_exit(void)
{

	KHTTPD_ENTRY("%s()", __func__);

#ifdef INVARIANTS
	mtx_lock(&khttpd_port_lock);
	KASSERT(!khttpd_port_ready, ("ready"));
	KASSERT(LIST_EMPTY(&khttpd_ports_running),
	    ("!LIST_EMPTY(&khttpd_ports_running)"));
	KASSERT(LIST_EMPTY(&khttpd_port_sockets),
	    ("!LIST_EMPTY(&khttpd_port_sockets)"));
	mtx_unlock(&khttpd_port_lock);
#endif	/* INVARIANTS */

	EVENTHANDLER_DEREGISTER(khttpd_main_shutdown,
	    khttpd_port_shutdown_tag);

	uma_zdestroy(khttpd_socket_zone);
}

static int
khttpd_port_run(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_socket_zone = uma_zcreate("socket", 
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor,
	    khttpd_socket_init, khttpd_socket_fini,
	    UMA_ALIGN_CACHE, 0);

	khttpd_port_shutdown_tag =
	    EVENTHANDLER_REGISTER(khttpd_main_shutdown,
		khttpd_port_shutdown, NULL, EVENTHANDLER_PRI_ANY);

	khttpd_port_ready = true;

	return (0);
}

KHTTPD_INIT(khttpd_port, khttpd_port_run, khttpd_port_exit,
    KHTTPD_INIT_PHASE_RUN, khttpd_task);
