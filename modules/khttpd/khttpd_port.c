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
#include "khttpd_stream.h"

/* 
 * Key of locks
 * 
 * (a) port->lock
 * (b) khttpd_port_lock
 * (c) SOCKBUF_LOCK
 * (d) socket->migration_lock
 * (e) worker->lock
 * (*) no concurrent access
 * (-) changes during initialization and doesn't change until uma_zfree
 * (.) atomic access only
 *
 * Lock ordering
 *
 * port->lock
 * SOCKBUF_LOCK
 * khttpd_port_lock
 * socket->migration_lock
 * worker->lock
 * 
 */

struct khttpd_socket_job {
	STAILQ_ENTRY(khttpd_socket_job) stqe; /* (e) */
	void		(*fn)(void *);	      /* (-) */
	void		*arg;		      /* (-) */
	bool		again;		      /* (e) */
	bool		inqueue;	      /* (e) */
	bool		waiting;	      /* (e) */
	bool		oneoff;		      /* (-) */
	/*
	 * When a stream attached to a socket is destroyed, all the jobs
	 * refering the socket should be destroyed too.  This is
	 * implemented by cancelling all the member jobs of the destroyed
	 * socket.  Don't create an oneoff job that refers to a socket
	 * unless enhancing the destruction code so that such a oneoff job
	 * is also destroyed.
	 */
};

STAILQ_HEAD(khttpd_socket_job_stq, khttpd_socket_job);

struct socket;
SLIST_HEAD(khttpd_socket_slist, khttpd_socket);
LIST_HEAD(khttpd_socket_list, khttpd_socket);

struct khttpd_socket_worker {
	struct khttpd_socket_job_stq queue; /* (e) */
	struct khttpd_socket_slist free;    /* (*) */
	struct mtx	lock;
	struct thread	*thread;	    /* (-) */
};

struct khttpd_sockbuf_job {
	struct khttpd_socket_job job;
	struct callout	timeo_callout;
};

struct khttpd_socket_migration_job {
	struct khttpd_socket_job job;
	struct khttpd_socket_worker *worker; /* (d) */
};

struct khttpd_socket {
	LIST_ENTRY(khttpd_socket) liste;   /* (b) */
	SLIST_ENTRY(khttpd_socket) sliste; /* (*) */
	struct khttpd_sockbuf_job rcv_job;
	struct khttpd_sockbuf_job snd_job;
	struct khttpd_socket_job cnf_job;
	struct khttpd_socket_job ntf_job;
	struct khttpd_socket_job rst_job;
	struct khttpd_socket_migration_job mig_job;
	struct rmlock		migration_lock;
	struct sockaddr_storage	peeraddr;    /* (-) */
	struct khttpd_socket_worker *worker; /* (-) */

#define khttpd_socket_zero_begin port
	struct khttpd_port	*port;	   /* (-) */
	struct khttpd_stream	*stream;   /* (*) */
	struct mbuf		*xmit_buf; /* (*) */
	struct socket		*so;	   /* (a) */
	const char		*smesg;	   		       /* (*) */
	khttpd_socket_config_fn_t config_fn;		       /* (-) */
	khttpd_socket_error_fn_t error_fn;		       /* (-) */
	void			*config_arg;		       /* (-) */
	unsigned		is_tcp:1;		       /* (*) */
	unsigned		xmit_flush_scheduled:1;	       /* (*) */
	unsigned		xmit_close_scheduled:1;	       /* (*) */
	unsigned		xmit_notification_requested:1; /* (*) */
};

struct khttpd_port {
	LIST_ENTRY(khttpd_port) liste; /* (b) */
	struct sx		lock;
	struct khttpd_socket_worker *worker; /* (-) */

#define khttpd_port_zctor_begin	addr
	struct sockaddr_storage	addr;		   /* (*) */
	struct khttpd_socket_job arrival_job;
	struct socket		*so;		   /* (*) */
	khttpd_socket_config_fn_t config_fn;	   /* (*) */
	void			*config_arg;	   /* (*) */
	unsigned		costructs_ready:1; /* (*) */
	unsigned		marker:1;	   /* (*) */

#define khttpd_port_zctor_end	refcount
	KHTTPD_REFCOUNT1_MEMBERS;
};

LIST_HEAD(khttpd_port_list, khttpd_port);

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
static void khttpd_port_dtor(struct khttpd_port *);
static void khttpd_port_fini(struct khttpd_port *);

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
    LIST_HEAD_INITIALIZER(khttpd_ports); /* (b) */
static struct khttpd_socket_list khttpd_port_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets); /* (b) */
static struct khttpd_socket_worker **khttpd_socket_workers; /* (*) */
static volatile uint64_t khttpd_port_siphash_counter; /* (.) */
static eventhandler_tag khttpd_port_shutdown_tag; /* (*) */
static uma_zone_t khttpd_socket_zone;		  /* (*) */
static const sbintime_t khttpd_port_timeout_pr = SBT_1S * 2;
static unsigned khttpd_socket_count; /* (b) */
static unsigned khttpd_socket_worker_count; /* (b) */
static enum {
	KHTTPD_PORT_STATE_READY,
	KHTTPD_PORT_STATE_SHUTDOWN,
	KHTTPD_PORT_STATE_EXITING,
} khttpd_port_state;		/* (b) */
static char khttpd_port_siphash_key[SIPHASH_KEY_LENGTH];

MTX_SYSINIT(khttpd_port_lock, &khttpd_port_lock, "ports", MTX_DEF);

KHTTPD_REFCOUNT1_GENERATE(khttpd_port, khttpd_port, khttpd_port_dtor,
    khttpd_port_fini);

static struct khttpd_socket_worker *
khttpd_socket_worker_find(void)
{
	static SIPHASH_CTX siphash_ctx;
	u_long count, hash;

	KASSERT(0 < khttpd_socket_worker_count,
	    ("khttpd_socket_worker_count %d", khttpd_socket_worker_count));

	count = atomic_fetchadd_long(&khttpd_port_siphash_counter, 1);
	hash = SipHash24(&siphash_ctx, khttpd_port_siphash_key,
	    &count, sizeof(count));
	return (khttpd_socket_workers[hash % khttpd_socket_worker_count]);
}

static void
khttpd_socket_assert_curthread(struct khttpd_socket *socket)
{

	KASSERT(socket->worker == NULL || curthread == socket->worker->thread,
	    ("curthread %p, socket->worker->thread %p", curthread,
		socket->worker->thread));
}

static void
khttpd_socket_job_schedule_locked(struct khttpd_socket_worker *worker,
    struct khttpd_socket_job *job, bool expedited)
{
	struct khttpd_socket_job *first;

	KHTTPD_ENTRY("%s(%p,%p,%d)", __func__, worker, job, expedited);
	KASSERT(khttpd_port_state != KHTTPD_PORT_STATE_EXITING, ("exiting"));

	first = STAILQ_FIRST(&worker->queue);
	if (first == job) {
		KHTTPD_NOTE("%s again", __func__);
		job->again = true;
		return;
	}

	if (job->inqueue) {
		KHTTPD_NOTE("%s inqueue", __func__);
		return;
	}

	job->inqueue = true;

	if (first == NULL) {
		wakeup(&worker->queue);
	}

	if (expedited && first != NULL) {
		STAILQ_INSERT_AFTER(&worker->queue, first, job, stqe);
	} else {
		STAILQ_INSERT_TAIL(&worker->queue, job, stqe);
	}
}

static void
khttpd_socket_job_schedule(struct khttpd_socket_worker *worker,
    struct khttpd_socket_job *job, bool expedited)
{

	KHTTPD_ENTRY("%s(%p,%d)", __func__, job, expedited);
	mtx_lock(&worker->lock);
	khttpd_socket_job_schedule_locked(worker, job, expedited);
	mtx_unlock(&worker->lock);
}

static void
khttpd_socket_job_cancel(struct khttpd_socket *socket,
    struct khttpd_socket_job *job)
{
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, socket, job);
	khttpd_socket_assert_curthread(socket);
	KASSERT(!job->oneoff, ("job %p oneoff", job));

	worker = socket->worker;
	mtx_lock(&worker->lock);

	if (!job->inqueue) {
		KHTTPD_NOTE("%s !inqueue", __func__);

	} else if (STAILQ_FIRST(&worker->queue) != job) {
		KHTTPD_NOTE("%s inqueue", __func__);
		STAILQ_REMOVE(&worker->queue, job, khttpd_socket_job, stqe);
		job->inqueue = false;

	} else {
		KHTTPD_NOTE("%s running", __func__);
		job->again = false;
	}

	mtx_unlock(&worker->lock);
}

static void
khttpd_socket_do_free(struct khttpd_socket_worker *worker)
{
	struct khttpd_socket *socket, *tmpsock;
	unsigned count;

	KHTTPD_ENTRY("%s(%p)", __func__, worker);
	KASSERT(!SLIST_EMPTY(&worker->free), ("empty"));
	KASSERT(worker->thread == curthread,
	    ("worker->thread %p", worker->thread));

	count = 0;
	SLIST_FOREACH_SAFE(socket, &worker->free, sliste, tmpsock) {
		uma_zfree(khttpd_socket_zone, socket);
		++count;
	}

	SLIST_INIT(&worker->free);

	mtx_lock(&khttpd_port_lock);

	if ((khttpd_socket_count -= count) == 0 &&
	    khttpd_port_state != KHTTPD_PORT_STATE_READY) {
		wakeup(&khttpd_socket_count);
	}

	mtx_unlock(&khttpd_port_lock);
}

static void
khttpd_socket_worker_main(void *arg)
{
	struct khttpd_socket_job *job;
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	worker = arg;

	mtx_lock(&worker->lock);
	for (;;) {
		if ((job = STAILQ_FIRST(&worker->queue)) == NULL) {
			if (khttpd_port_state == KHTTPD_PORT_STATE_EXITING) {
				break;
			}
			mtx_sleep(&worker->queue, &worker->lock, 0, "idle", 0);
			continue;
		}

		do {
			job->again = false;
			mtx_unlock(&worker->lock);
			KHTTPD_NOTE("%s start %p", __func__, job);

			job->fn(job->arg);

			KHTTPD_NOTE("%s end %p", __func__, job);
			mtx_lock(&worker->lock);
		} while (job->again);

		job->inqueue = false;
		STAILQ_REMOVE_HEAD(&worker->queue, stqe);

		if (job->waiting) {
			KHTTPD_NOTE("%s wakeup %p", __func__, job);
			job->waiting = false;
			wakeup(job);
		}

		if (job->oneoff) {
			KHTTPD_NOTE("%s oneoff %p", __func__, job);
			mtx_unlock(&worker->lock);
			khttpd_free(job);
			mtx_lock(&worker->lock);
		}

		if (!SLIST_EMPTY(&worker->free)) {
			mtx_unlock(&worker->lock);
			khttpd_socket_do_free(worker);
			mtx_lock(&worker->lock);
		}
	}

	KASSERT(STAILQ_EMPTY(&worker->queue), ("worker->queue not empty"));
	KASSERT(SLIST_EMPTY(&worker->free), ("worker->free not empty"));

	mtx_unlock(&worker->lock);

	mtx_lock(&khttpd_port_lock);
	if (--khttpd_socket_worker_count == 0) {
		wakeup(&khttpd_socket_worker_count);
	}
	mtx_unlock(&khttpd_port_lock);

	kthread_exit();
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
khttpd_socket_schedule_reset(void *arg)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket->worker, &socket->rst_job, false);
	rm_runlock(&socket->migration_lock, &trk);
}

static int
khttpd_socket_on_recv_upcall(struct socket *so, void *arg, int flags)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);

	socket = arg;

	if (!soreadable(so)) {
		return (SU_OK);
	}

	soupcall_clear(so, SO_RCV);
	callout_stop(&socket->rcv_job.timeo_callout);

	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket->worker, &socket->rcv_job.job,
	    false);
	rm_runlock(&socket->migration_lock, &trk);

	return (SU_OK);
}

static int
khttpd_socket_on_xmit_upcall(struct socket *so, void *arg, int flags)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);

	socket = arg;

	if (!sowriteable(so)) {
		return (SU_OK);
	}

	soupcall_clear(so, SO_SND);
	callout_stop(&socket->snd_job.timeo_callout);

	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket->worker, &socket->snd_job.job,
	    false);
	rm_runlock(&socket->migration_lock, &trk);

	return (SU_OK);
}

static void
khttpd_socket_set_upcall(struct khttpd_socket *socket, int side,
    sbintime_t timeout)
{
	struct rm_priotracker trk;
	struct khttpd_socket_worker *worker;
	struct khttpd_sockbuf_job *job;
	struct socket *so;
	struct sockbuf *sb;
	bool kick_callout;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, socket,
	    side == SO_RCV ? "recv" : side == SO_SND ? "send" : "invalid");
	KASSERT(socket->so != NULL, ("socket %p, so NULL", socket));

	so = socket->so;
	if (side == SO_RCV) {
		job = &socket->rcv_job;
		sb = &so->so_rcv;
	} else {
		job = &socket->snd_job;
		sb = &so->so_snd;
	}

	SOCKBUF_LOCK(sb);
	KASSERT((sb->sb_flags & SB_UPCALL) == 0,
	    ("socket %p already set upcall", socket));

	rm_rlock(&socket->migration_lock, &trk);
	worker = socket->worker;
	mtx_lock(&worker->lock);

	kick_callout = false;
	if ((side == SO_RCV ? soreadable(so) : sowriteable(so))) {
		khttpd_socket_job_schedule_locked(worker, &job->job, false);

	} else {
		KHTTPD_NOTE("%s soupcall_set %p", __func__, so);
		soupcall_set(so, side, side == SO_RCV ? 
		    khttpd_socket_on_recv_upcall : 
		    khttpd_socket_on_xmit_upcall, socket);
		kick_callout = true;
	}

	mtx_unlock(&worker->lock);
	rm_runlock(&socket->migration_lock, &trk);
	SOCKBUF_UNLOCK(sb);

	if (kick_callout && 0 < timeout) {
		KHTTPD_NOTE("set timeout %#lx", timeout);
		callout_reset_sbt_curcpu(&job->timeo_callout,
		    timeout, khttpd_port_timeout_pr,
		    khttpd_socket_schedule_reset, socket, 0);
	}
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

	khttpd_socket_set_upcall(socket, SO_RCV, timeout);
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
	 * Find 'end' such that the total length from 'head' to 'end' is
	 * less than the available space in the socket.
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

	flags = MSG_DONTWAIT;
	if (end != NULL ||
	    (!socket->xmit_close_scheduled && !socket->xmit_flush_scheduled)) {
		flags |= MSG_MORETOCOME;
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

	khttpd_socket_set_upcall(socket, SO_SND, 0);

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
		khttpd_socket_set_upcall(socket, SO_SND, 0);
	}
}

static void
khttpd_socket_destroy(struct khttpd_socket *socket)
{
	struct khttpd_socket *ptr;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);

#ifdef INVARIANTS
	mtx_lock(&khttpd_port_lock);
	LIST_FOREACH(ptr, &khttpd_port_sockets, liste) {
		if (ptr == socket) {
			break;
		}
	}
	mtx_unlock(&khttpd_port_lock);
	KASSERT(ptr != NULL, ("not in khttpd_port_sockets"));
#endif

	KASSERT(socket->so != NULL, ("so is NULL"));
	khttpd_socket_assert_curthread(socket);

	mtx_lock(&khttpd_port_lock);
	LIST_REMOVE(socket, liste);
	mtx_unlock(&khttpd_port_lock);

	callout_drain(&socket->rcv_job.timeo_callout);
	callout_drain(&socket->snd_job.timeo_callout);

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

	khttpd_socket_job_cancel(socket, &socket->rcv_job.job);
	khttpd_socket_job_cancel(socket, &socket->snd_job.job);
	khttpd_socket_job_cancel(socket, &socket->cnf_job);
	khttpd_socket_job_cancel(socket, &socket->ntf_job);
	khttpd_socket_job_cancel(socket, &socket->rst_job);
	khttpd_socket_job_cancel(socket, &socket->mig_job.job);

	SLIST_INSERT_HEAD(&socket->worker->free, socket, sliste);
}

static void
khttpd_socket_stream_destroy(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	khttpd_socket_assert_curthread(stream->down);
	khttpd_socket_destroy(stream->down);
}

static void
khttpd_socket_do_config(void *arg)
{
	struct khttpd_socket_config conf;
	struct sockopt sockopt;
	struct khttpd_socket *socket;
	struct khttpd_stream *stream;
	struct socket *so;
	int error, soptval;
	bool is_readable;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	socket = arg;
	khttpd_socket_assert_curthread(socket);

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

	SOCKBUF_LOCK(&so->so_rcv);
	is_readable = soreadable(so);
	SOCKBUF_UNLOCK(&so->so_rcv);

	if (is_readable) {
		khttpd_stream_data_is_available(socket->stream);
	} else {
		khttpd_socket_set_upcall(socket, SO_RCV, conf.timeout);
	}

	return;

 error:
	if (socket->error_fn != NULL) {
		socket->error_fn(socket->config_arg, error);
	}
	khttpd_socket_destroy(socket);
}

static bool
khttpd_socket_enter(struct khttpd_socket *socket)
{

	mtx_lock(&khttpd_port_lock);

	if (khttpd_port_state != KHTTPD_PORT_STATE_READY) {
		mtx_unlock(&khttpd_port_lock);
		return (true);
	}

	LIST_INSERT_HEAD(&khttpd_port_sockets, socket, liste);
	++khttpd_socket_count;

	mtx_unlock(&khttpd_port_lock);

	return (false);
}

static void
khttpd_socket_do_accept_and_config_job(void *arg)
{
	struct khttpd_socket *socket;
	struct sockaddr *name;
	struct socket *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	so = socket->so;
	khttpd_socket_assert_curthread(socket);

	error = so->so_error;
	if (error != 0) {
		KHTTPD_NOTE("%s so_error %d", __func__, error);
		so->so_error = 0;
		goto error;
	}		

	error = soaccept(so, &name);
	if (error != 0) {
		KHTTPD_NOTE("%s soaccept error %d", __func__, error);
		goto error;
	}

	bcopy(name, &socket->peeraddr,
	    MIN(sizeof(socket->peeraddr), name->sa_len));
	socket->is_tcp = name->sa_family == AF_INET ||
	    name->sa_family == AF_INET6;

	khttpd_socket_do_config(socket);
	return;

 error:
	if (socket->error_fn != NULL) {
		socket->error_fn(socket->config_arg, error);
	}
	khttpd_socket_destroy(socket);
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

void
khttpd_socket_set_smesg(struct khttpd_socket *sock, const char *smesg)
{

	sock->smesg = smesg;
}

static int
khttpd_socket_did_connected_upcall(struct socket *so, void *arg, int flags)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);
	SOCKBUF_LOCK_ASSERT(&so->so_snd);

	socket = arg;

	if (!sowriteable(so)) {
		return (SU_OK);
	}

	KASSERT((so->so_snd.sb_flags & SB_UPCALL) != 0,
	    ("so_snd.sb_flags %#x", so->so_snd.sb_flags));
	soupcall_clear(so, SO_SND);

	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket->worker, &socket->cnf_job, false);
	rm_runlock(&socket->migration_lock, &trk);

	return (SU_OK);
}

void
khttpd_socket_connect(struct sockaddr *peeraddr, struct sockaddr *sockaddr,
    khttpd_socket_config_fn_t fn, void *arg, khttpd_socket_error_fn_t error_fn)
{
	struct khttpd_socket *socket;
	struct socket *so;
	struct thread *td;
	const char *detail;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, peeraddr, sockaddr);
	KASSERT(khttpd_port_state != KHTTPD_PORT_STATE_EXITING, ("exiting"));

	td = curthread;
	detail = NULL;

	if (sizeof(socket->peeraddr) < peeraddr->sa_len ||
	    (sockaddr != NULL && sockaddr->sa_family != peeraddr->sa_family)) {
		KHTTPD_NOTE("%s peeraddr EINVAL", __func__);
		error_fn(arg, EINVAL);
		return;
	}

	error = socreate(peeraddr->sa_family, &so, SOCK_STREAM, 0, 
	    td->td_ucred, td);
	if (error != 0) {
		KHTTPD_NOTE("%s socreate error %d", __func__, error);
		error_fn(arg, error);
		return;
	}

	if (sockaddr != NULL) {
		error = sobind(so, sockaddr, td);
		if (error != 0) {
			KHTTPD_NOTE("%s sobind error %d", __func__, error);
			soclose(so);
			error_fn(arg, error);
			return;
		}
	}

	socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
	socket->so = so;
	socket->config_fn = fn;
	socket->error_fn = error_fn;
	socket->config_arg = arg;
	socket->cnf_job.fn = khttpd_socket_do_config;
	bcopy(peeraddr, &socket->peeraddr, peeraddr->sa_len);
	socket->is_tcp = peeraddr->sa_family == AF_INET || 
	    peeraddr->sa_family == AF_INET6;

	SOCK_LOCK(so);
	so->so_state |= SS_NBIO;
	SOCK_UNLOCK(so);

	error = soconnect(so, peeraddr, td);

	SOCKBUF_LOCK(&so->so_snd);

	if ((error != 0 && error != EINPROGRESS) ||
	    (error = khttpd_socket_enter(socket) ? ECONNABORTED : 0) != 0) {
		KHTTPD_NOTE("%s error %d", __func__, error);
		SOCKBUF_UNLOCK(&so->so_snd);
		uma_zfree(khttpd_socket_zone, socket);
		error_fn(arg, error);
		return;
	}

	/*
	 * While the sockbuf lock is held, 'socket' and 'so' is valid even
	 * if khttpd_socket_shutdown() finds 'socket' in
	 * 'khttpd_port_sockets' and resets the socket and a upstream code
	 * may destroy the stream behind us.  It's because
	 * khttpd_socket_destroy needs the sockbuf lock.
	 */

	soupcall_set(so, SO_SND, khttpd_socket_did_connected_upcall, socket);
	khttpd_socket_did_connected_upcall(so, socket, 0);

	SOCKBUF_UNLOCK(&so->so_snd);
}

void
khttpd_socket_reset(struct khttpd_socket *socket)
{
	struct linger linger;
	struct sockopt sockopt;
	struct socket *so;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);

	so = socket->so;
	KASSERT(so != NULL, ("socket %p, no so", socket));
	khttpd_socket_assert_curthread(socket);

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

	if (socket->stream != NULL) {
		khttpd_stream_reset(socket->stream);
	} else {
		khttpd_socket_destroy(socket);
	}
}

void
khttpd_socket_run_later(void (*fn)(void *), void *arg)
{
	struct khttpd_socket_job *job;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, fn, arg);

	job = khttpd_malloc(sizeof(struct khttpd_socket_job));
	bzero(job, sizeof(*job));
	job->fn = fn;
	job->arg = arg;
	job->oneoff = true;
	khttpd_socket_job_schedule(khttpd_socket_worker_find(), job, false);
}

static void
khttpd_socket_migrate(struct khttpd_socket *socket,
    struct khttpd_socket_worker *curwkr, struct khttpd_socket_worker *newwkr,
    bool notify)
{
	struct khttpd_socket_job *jobs[3], **jobp;
	struct khttpd_socket_job *job, *prev;
	int i, njobs;
	bool need_wakeup;

	KHTTPD_ENTRY("%s(%p,%p,%p,%d)",
	    __func__, socket, curwkr, newwkr, notify);
	rm_assert(&socket->migration_lock, RA_WLOCKED);
	mtx_assert(&curwkr->lock, MA_OWNED);
	KASSERT(!socket->cnf_job.inqueue, ("cnf_job.inqueue"));
	KASSERT(STAILQ_FIRST(&curwkr->queue) != &socket->rcv_job.job,
	    ("migrate is called by rcv_job"));
	KASSERT(STAILQ_FIRST(&curwkr->queue) != &socket->snd_job.job,
	    ("migrate is called by snd_job"));
	KASSERT(STAILQ_FIRST(&curwkr->queue) != &socket->rst_job,
	    ("migrate is called by rst_job"));

	jobp = jobs;
	prev = STAILQ_FIRST(&curwkr->queue);
	for (job = STAILQ_NEXT(prev, stqe); job != NULL;
	     job = STAILQ_NEXT(job, stqe)) {
		if (job == &socket->rcv_job.job ||
		    job == &socket->snd_job.job || job == &socket->rst_job) {
			KASSERT(jobp - jobs < nitems(jobs), ("jobs overflow"));
			STAILQ_REMOVE_AFTER(&curwkr->queue, prev, stqe);
			job->inqueue = false;
			*jobp++ = job;
			job = prev;
		}
	}

	mtx_unlock(&curwkr->lock);

	socket->worker = newwkr;

	mtx_lock(&newwkr->lock);

	if (notify) {
		khttpd_socket_job_schedule_locked(newwkr,
		    &socket->ntf_job, true);
	}

	njobs = jobp - jobs;
	need_wakeup = jobp != jobs && STAILQ_EMPTY(&newwkr->queue);
	for (i = 0; i < njobs; ++i) {
		khttpd_socket_job_schedule_locked(newwkr, jobs[i], false);
	}

	if (need_wakeup) {
		wakeup(&newwkr->queue);
	}

	mtx_unlock(&newwkr->lock);
	rm_wunlock(&socket->migration_lock);
}

static void
khttpd_socket_do_migration_job(void *arg)
{
	struct khttpd_socket *socket;
	struct khttpd_socket_worker *curwkr, *newwkr;
	struct thread *td;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	td = curthread;
	socket = arg;
	newwkr = socket->mig_job.worker;

	rm_wlock(&socket->migration_lock);

	curwkr = socket->worker;
	KASSERT(curwkr->thread == td, ("curwkr->thread %p", curwkr->thread));
	KASSERT(newwkr->thread != td, ("newwkr->thread %p", newwkr->thread));

	mtx_lock(&curwkr->lock);
	khttpd_socket_migrate(socket, curwkr, newwkr, true);
}

int
khttpd_socket_set_affinity(struct khttpd_socket *subject, 
    struct khttpd_socket *source, void (*notify)(void *), void *arg)
{
	struct khttpd_socket_job *running;
	struct khttpd_socket_worker *curwkr, *newwkr;
	struct thread *td;
	bool on_newwkr;

	KHTTPD_ENTRY("%s(%p,%p,%p,%p)",
	    __func__, subject, source, notify, arg);

	rm_wlock(&subject->migration_lock);

	KASSERT(!subject->mig_job.job.inqueue, ("mig_job.job.inqueue"));
	KASSERT(!subject->ntf_job.inqueue, ("ntf_job.inqueue"));

	td = curthread;
	curwkr = subject->worker;
	newwkr = source->worker;
	on_newwkr = newwkr->thread == td;

	if (curwkr == newwkr ||
	    (!subject->rcv_job.job.inqueue && !subject->snd_job.job.inqueue &&
	     !subject->cnf_job.inqueue && !subject->rst_job.inqueue)) {
		KHTTPD_NOTE("%s no queued jobs", __func__);

		/*
		 * Member 'inqueue' is set only by
		 * khttpd_socket_job_schedule_locked() and it requires the
		 * caller to lock migration_lock.  Because we have the writer
		 * lock of migration_lock, it's guaranteed that inqueue doesn't
		 * change to true even if we don't have curwkr->lock.
		 */

		subject->worker = newwkr;

		if (on_newwkr) {
			rm_wunlock(&subject->migration_lock);
			notify(arg);
			return (0);
		}

		KHTTPD_NOTE("%s schedule notification", __func__);
		subject->ntf_job.fn = notify;
		subject->ntf_job.arg = arg;
		khttpd_socket_job_schedule(newwkr, &subject->ntf_job, true);

		rm_wunlock(&subject->migration_lock);

		return (EINPROGRESS);
	}

	KHTTPD_NOTE("%s queued jobs", __func__);
	mtx_lock(&curwkr->lock);

	running = STAILQ_FIRST(&curwkr->queue);
	if (running != &subject->rcv_job.job &&
	    running != &subject->snd_job.job &&
	    running != &subject->cnf_job && running != &subject->rst_job) {
		KHTTPD_NOTE("%s migrate immediately", __func__);
		if (on_newwkr) {
			khttpd_socket_migrate(subject, curwkr, newwkr, false);
		} else {
			subject->ntf_job.fn = notify;
			subject->ntf_job.arg = arg;
			khttpd_socket_migrate(subject, curwkr, newwkr, true);
		}
		return (EINPROGRESS);
	}

	KHTTPD_NOTE("%s schedule migration", __func__);

	subject->mig_job.worker = newwkr;
	subject->ntf_job.fn = notify;
	subject->ntf_job.arg = arg;
	khttpd_socket_job_schedule_locked(curwkr, &subject->mig_job.job, true);

	mtx_unlock(&curwkr->lock);
	rm_wunlock(&subject->migration_lock);

	return (EINPROGRESS);
}

static void
khttpd_port_do_arrival_job(void *arg)
{
	struct khttpd_port *port;
	struct khttpd_socket *socket;
	struct khttpd_socket_worker *worker;
	struct socket *head, *so;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;
	head = port->so;

	ACCEPT_LOCK();
	while ((so = TAILQ_FIRST(&head->so_comp)) != NULL) {

		if ((head->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
			KHTTPD_NOTE("%s sb_state %#x", __func__,
			    head->so_rcv.sb_state);
			break;
		}

		if (head->so_error != 0) {
			KHTTPD_NOTE("%s so_error %d",
			    __func__, head->so_error);
			head->so_error = 0;
		}

		KHTTPD_NOTE("%s so %p", __func__, so);
		SOCK_LOCK(so);
		soref(so);

		TAILQ_REMOVE(&head->so_comp, so, so_list);
		--head->so_qlen;
		so->so_state |= SS_NBIO;
		so->so_qstate &= ~SQ_COMP;
		so->so_head = NULL;

		SOCK_UNLOCK(so);
		ACCEPT_UNLOCK();

		socket = uma_zalloc(khttpd_socket_zone, M_WAITOK);
		socket->port = khttpd_port_acquire(arg);
		socket->so = so;
		socket->config_fn = port->config_fn;
		socket->config_arg = port->config_arg;
		socket->cnf_job.fn = khttpd_socket_do_accept_and_config_job;

		/*
		 * Because the pointer to the socket has not escaped,
		 * acquiring the migration lock is not necessary.
		 */
		worker = socket->worker;

		/*
		 * Hold 'worker->lock' while the socket is put into
		 * 'khttpd_port_sockets'.  This makes sure that the config
		 * job runs earlier than reset job enqueued by
		 * khttpd_port_shutdown().
		 */
		mtx_lock(&worker->lock);
		if (khttpd_socket_enter(socket)) {
			mtx_unlock(&worker->lock);
			uma_zfree(khttpd_socket_zone, socket);
		} else {
			khttpd_socket_job_schedule_locked(worker,
			    &socket->cnf_job, false);
			mtx_unlock(&worker->lock);
		}

		ACCEPT_LOCK();
	}
	ACCEPT_UNLOCK();
}

static int
khttpd_port_do_arrival_upcall(struct socket *head, void *arg, int flags)
{
	struct khttpd_port *port;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, head, arg, flags);

	port = arg;
	khttpd_socket_job_schedule(port->worker, &port->arrival_job, false);

	return (SU_OK);
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

	sx_init_flags(&port->lock, "port", SX_NEW);
	WITNESS_DEFINEORDER(&port->lock, &khttpd_port_lock);

	port->worker = khttpd_socket_worker_find();

	bzero(&port->khttpd_port_zctor_begin,
	    offsetof(struct khttpd_port, khttpd_port_zctor_end) -
	    offsetof(struct khttpd_port, khttpd_port_zctor_begin));
	KHTTPD_REFCOUNT1_INIT(khttpd_port, port);

	port->arrival_job.fn = khttpd_port_do_arrival_job;
	port->arrival_job.arg = port;

	error = khttpd_costruct_call_ctors(khttpd_port_costruct_info, port);
	if (error != 0) {
		khttpd_port_release(port);
		return (error);
	}

	port->costructs_ready = true;
	*port_out = port;

	return (error);
}

int
khttpd_port_start(struct khttpd_port *port, struct sockaddr *addr,
    khttpd_socket_config_fn_t fn, void *arg, const char **detail_out)
{
	struct sockopt sockopt;
	struct socket *so;
	struct thread *td;
	const char *detail;
	int error, soptval;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, port, addr, fn);
	KASSERT(port->costructs_ready, ("!costructs_ready"));

	td = curthread;
	so = NULL;
	detail = NULL;
	error = 0;

	if (sizeof(port->addr) < addr->sa_len) {
		detail = "invalid address";
		error = EINVAL;
		goto error;
	}

	error = socreate(addr->sa_family, &so, SOCK_STREAM, 0, td->td_ucred,
	    td);
	if (error != 0) {
		detail = "socket construction failed";
		goto error;
	}

	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_REUSEADDR;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		detail = "setsockopt(SO_REUSEADDR) failed";
		goto error;
	}

	sockopt.sopt_dir = SOPT_GET;
	sockopt.sopt_name = SO_SNDBUF;
	error = sogetopt(so, &sockopt);
	if (error != 0) {
		detail = "getsockopt(SO_SNDBUF) failed";
		goto error;
	}

	soptval = MAX(PAGE_SIZE, soptval / 2);
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_name = SO_SNDLOWAT;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		detail = "setsockopt(SO_SNDLOWAT) failed";
		goto error;
	}

	error = sobind(so, addr, td);
	if (error != 0) {
		detail = "bind failed";
		goto error;
	}

	error = solisten(so, -1, td);
	if (error != 0) {
		detail = "listen failed";
		goto error;
	}

	sx_xlock(&port->lock);

	if (port->so != NULL) {
		sx_xunlock(&port->lock);
		detail = "already started";
		goto error;
	}

	mtx_lock(&khttpd_port_lock);
	if (khttpd_port_state != KHTTPD_PORT_STATE_READY) {
		mtx_unlock(&khttpd_port_lock);
		sx_xunlock(&port->lock);
		detail = "server down";
		error = ECONNABORTED;
		goto error;
	}
	LIST_INSERT_HEAD(&khttpd_ports_running, port, liste);
	mtx_unlock(&khttpd_port_lock);

	bcopy(addr, &port->addr, addr->sa_len);
	port->config_fn = fn;
	port->config_arg = arg;
	port->so = so;

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, khttpd_port_do_arrival_upcall, port);
	SOCKBUF_UNLOCK(&so->so_rcv);

	sx_xunlock(&port->lock);

	khttpd_socket_job_schedule(port->worker, &port->arrival_job, false);

	return (0);

 error:
	soclose(so);
	if (detail_out != NULL) {
		*detail_out = detail;
	}

	return (error);
}

void
khttpd_port_stop(struct khttpd_port *port)
{
	struct khttpd_socket_job *job;
	struct khttpd_socket_worker *worker;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	job = &port->arrival_job;
	worker = port->worker;

	sx_xlock(&port->lock);

	if ((so = port->so) == NULL) {
		sx_xunlock(&port->lock);
		return;
	}
	port->so = NULL;

	SOCKBUF_LOCK(&so->so_rcv);
	if ((so->so_rcv.sb_flags & SB_UPCALL) != 0) {
		soupcall_clear(so, SO_RCV);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);

	mtx_lock(&khttpd_port_lock);
	LIST_REMOVE(port, liste);
	if (LIST_EMPTY(&khttpd_ports_running)) {
		wakeup(&khttpd_ports_running);
	}
	mtx_unlock(&khttpd_port_lock);

	for (;;) {
		mtx_lock(&worker->lock);

		if (!job->inqueue) {
			break;
		}

		if (STAILQ_FIRST(&worker->queue) != job) {
			KHTTPD_NOTE("%s inqueue", __func__);
			STAILQ_REMOVE(&worker->queue, job, khttpd_socket_job,
			    stqe);
			job->inqueue = false;
			break;
		}

		KHTTPD_NOTE("%s running", __func__);
		KASSERT(curthread != worker->thread,
		    ("accept handler calls khttpd_port_drain"));
		job->waiting = true;
		mtx_sleep(job, &worker->lock, PDROP, "portdrain", 0);
	}
	mtx_unlock(&worker->lock);
	sx_xunlock(&port->lock);

	soclose(so);
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
khttpd_port_dtor(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	KASSERT(port->so == NULL, ("port is running"));

	if (port->costructs_ready) {
		khttpd_costruct_call_dtors(khttpd_port_costruct_info, port);
	}

	sx_destroy(&port->lock);
}

static void
khttpd_port_fini(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	khttpd_free(port);
}

static void
khttpd_socket_do_rcv_job(void *arg)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	khttpd_socket_assert_curthread(socket);

	khttpd_stream_data_is_available(socket->stream);
}

static void
khttpd_socket_do_snd_job(void *arg)
{
	struct khttpd_socket *socket;
	struct socket *so;
	long space;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	khttpd_socket_assert_curthread(socket);

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
		khttpd_socket_set_upcall(socket, SO_SND, 0);
		return;
	}
	space = sbspace(&so->so_snd);
	SOCKBUF_UNLOCK(&so->so_snd);

	socket->xmit_notification_requested = false;
	khttpd_stream_clear_to_send(socket->stream, space);
}

static void
khttpd_socket_do_reset_job(void *arg)
{

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	khttpd_socket_assert_curthread(arg);

	khttpd_socket_reset(arg);
}

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;

	bzero(&socket->rcv_job, sizeof(socket->rcv_job));
	socket->rcv_job.job.fn = khttpd_socket_do_rcv_job;
	socket->rcv_job.job.arg = socket;
	callout_init(&socket->rcv_job.timeo_callout, 0);

	bzero(&socket->snd_job, sizeof(socket->snd_job));
	socket->snd_job.job.fn = khttpd_socket_do_snd_job;
	socket->snd_job.job.arg = socket;
	callout_init(&socket->snd_job.timeo_callout, 0);

	bzero(&socket->cnf_job, sizeof(socket->cnf_job));
	socket->cnf_job.arg = socket;

	bzero(&socket->ntf_job, sizeof(socket->ntf_job));
	socket->ntf_job.arg = socket;

	bzero(&socket->rst_job, sizeof(socket->rst_job));
	socket->rst_job.fn = khttpd_socket_do_reset_job;
	socket->rst_job.arg = socket;

	bzero(&socket->mig_job, sizeof(socket->mig_job));
	socket->mig_job.job.fn = khttpd_socket_do_migration_job;
	socket->mig_job.job.arg = socket;

	rm_init_flags(&socket->migration_lock, "sock", RM_RECURSE);

	socket->worker = khttpd_socket_worker_find();

	WITNESS_DEFINEORDER(&khttpd_port_lock, &socket->migration_lock);
	WITNESS_DEFINEORDER(&socket->migration_lock, &socket->worker->lock);

	return (0);
}

static void
khttpd_socket_fini(void *mem, int size)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, mem, size);

	socket = mem;
	rm_destroy(&socket->migration_lock);
}

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;
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

	KASSERT(!socket->rcv_job.job.inqueue, ("rcv_job.job.inqueue"));
	KASSERT(!socket->rcv_job.job.waiting, ("rcv_job.job.waiting"));
	KASSERT(callout_drain(&socket->rcv_job.timeo_callout) == -1,
	    ("rcv_job callout active"));
	KASSERT(!socket->snd_job.job.inqueue, ("snd_job.job.inqueue"));
	KASSERT(!socket->snd_job.job.waiting, ("snd_job.job.waiting"));
	KASSERT(callout_drain(&socket->snd_job.timeo_callout) == -1,
	    ("snd_job callout active"));
	KASSERT(!socket->cnf_job.inqueue, ("cnf_job.inqueue"));
	KASSERT(!socket->cnf_job.waiting, ("cnf_job.waiting"));
	KASSERT(!socket->ntf_job.inqueue, ("ntf_job.inqueue"));
	KASSERT(!socket->ntf_job.waiting, ("ntf_job.waiting"));
	KASSERT(!socket->rst_job.inqueue, ("rst_job.inqueue"));
	KASSERT(!socket->rst_job.waiting, ("rst_job.waiting"));
	KASSERT(!socket->mig_job.job.inqueue, ("mig_job.job.inqueue"));
	KASSERT(!socket->mig_job.job.waiting, ("mig_job.job.waiting"));

#ifdef INVARIANTS
	struct khttpd_socket *ptr;
	mtx_lock(&khttpd_port_lock);
	LIST_FOREACH(ptr, &khttpd_port_sockets, liste) {
		KASSERT(ptr != socket, ("in khttpd_port_sockets"));
	}
	mtx_unlock(&khttpd_port_lock);
#endif

	khttpd_port_release(socket->port);

	m_freem(socket->xmit_buf);

	if ((so = socket->so) != NULL) {
		KHTTPD_NOTE("%s soclose", __func__);
		soclose(so);
	}
}

static void
khttpd_port_shutdown(void *arg)
{
	struct khttpd_port marker;
	struct khttpd_port *port, *nport;
	struct khttpd_socket *socket;

	bzero(&marker, sizeof(marker));
	marker.marker = true;

	mtx_lock(&khttpd_port_lock);

	KASSERT(khttpd_port_state == KHTTPD_PORT_STATE_READY,
	    ("khttpd_port_state %d", khttpd_port_state));
	khttpd_port_state = KHTTPD_PORT_STATE_SHUTDOWN;

	for (port = LIST_FIRST(&khttpd_ports_running); port != NULL; 
	     port = nport) {
		if (port->marker) {
			nport = LIST_NEXT(port, liste);
			continue;
		}

		LIST_INSERT_AFTER(port, &marker, liste);
		khttpd_port_acquire(port);
		mtx_unlock(&khttpd_port_lock);

		khttpd_port_stop(port);

		khttpd_port_release(port);
		mtx_lock(&khttpd_port_lock);
		nport = LIST_NEXT(&marker, liste);
		LIST_REMOVE(&marker, liste);
	}

	while (!LIST_EMPTY(&khttpd_ports_running)) {
		mtx_sleep(&khttpd_ports_running, &khttpd_port_lock, 0,
		    "prtshtdwn", 0);
	}

	for (socket = LIST_FIRST(&khttpd_port_sockets); socket != NULL;
	     socket = LIST_NEXT(socket, liste)) {
		khttpd_socket_schedule_reset(socket);
	}

	while (0 < khttpd_socket_count) {
		mtx_sleep(&khttpd_socket_count, &khttpd_port_lock, 0,
		    "soshtdwn", 0);
	}

	mtx_unlock(&khttpd_port_lock);
}

static void
khttpd_port_exit(void)
{
	struct khttpd_socket_worker *worker;
	int i, n;

	KHTTPD_ENTRY("%s()", __func__);

	EVENTHANDLER_DEREGISTER(khttpd_main_shutdown,
	    khttpd_port_shutdown_tag);

	mtx_lock(&khttpd_port_lock);
	KASSERT(LIST_EMPTY(&khttpd_ports_running),
	    ("!LIST_EMPTY(&khttpd_ports_running)"));
	KASSERT(LIST_EMPTY(&khttpd_port_sockets),
	    ("!LIST_EMPTY(&khttpd_port_sockets)"));

	khttpd_port_state = KHTTPD_PORT_STATE_EXITING;

	n = khttpd_socket_worker_count;
	for (i = 0; i < n; ++i) {
		wakeup(&khttpd_socket_workers[i]->queue);
	}

	while (0 < khttpd_socket_worker_count) {
		mtx_sleep(&khttpd_socket_worker_count, &khttpd_port_lock, 0,
		    "portexit", 0);
	}

	mtx_unlock(&khttpd_port_lock);

	for (i = 0; i < n; ++i) {
		worker = khttpd_socket_workers[i];
		KASSERT(STAILQ_EMPTY(&worker->queue),
		    ("worker %d, queue is not empty", i));
		KASSERT(SLIST_EMPTY(&worker->free),
		    ("worker %d, free is not empty", i));
		mtx_destroy(&worker->lock);
		khttpd_free(worker);
	}

	khttpd_free(khttpd_socket_workers);

	uma_zdestroy(khttpd_socket_zone);
}

static int
khttpd_port_run(void)
{
	struct khttpd_socket_worker *worker;
	size_t worker_size;
	int error, i, n;

	KHTTPD_ENTRY("%s()", __func__);

	arc4rand(khttpd_port_siphash_key, sizeof(khttpd_port_siphash_key),
	    FALSE);

	khttpd_port_state = KHTTPD_PORT_STATE_READY;

	khttpd_socket_zone = uma_zcreate("socket",
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor,
	    khttpd_socket_init, khttpd_socket_fini,
	    UMA_ALIGN_CACHE, 0);

	n = mp_ncpus;
	khttpd_socket_workers =
	    khttpd_malloc(n * sizeof(struct khttpd_socket_worker *));
	worker_size = roundup2(sizeof(struct khttpd_socket_worker),
	    uma_align_cache + 1);

	for (i = 0; i < n; ++i) {
		khttpd_socket_workers[i] = worker = khttpd_malloc(worker_size);
		STAILQ_INIT(&worker->queue);
		SLIST_INIT(&worker->free);
		mtx_init(&worker->lock, "prtwrkr", NULL, MTX_DEF | MTX_NEW);

		error = kthread_add(khttpd_socket_worker_main, worker, curproc,
		    &worker->thread, 0, 0, "prtwrkr%d", i);
		if (error != 0) {
			log(LOG_ERR, "khttpd: kthread_add() failed "
			    "(error: %d, file: %s, line: %u)",
			    error, __FILE__, __LINE__);
			break;
		}
	}

	khttpd_socket_worker_count = i;

	khttpd_port_shutdown_tag =
	    EVENTHANDLER_REGISTER(khttpd_main_shutdown,
		khttpd_port_shutdown, NULL, EVENTHANDLER_PRI_ANY);

	if (error != 0) {
		khttpd_port_exit();
	}

	return (error);
}

KHTTPD_INIT(khttpd_port, khttpd_port_run, khttpd_port_exit,
    KHTTPD_INIT_PHASE_RUN);
