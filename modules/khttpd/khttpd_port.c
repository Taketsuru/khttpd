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

struct khttpd_socket_job {
	STAILQ_ENTRY(khttpd_socket_job) stqe;
	void		(*fn)(void *);
	void		*arg;
	bool		active;
	bool		inqueue;
	bool		again;
	bool		waiting;
	bool		oneoff;
};

STAILQ_HEAD(khttpd_socket_job_stq, khttpd_socket_job);

struct socket;
SLIST_HEAD(khttpd_socket_slist, khttpd_socket);

struct khttpd_socket_worker {
	SLIST_ENTRY(khttpd_socket_worker) sle;
	struct khttpd_socket_job_stq queue;
	struct khttpd_socket_slist free;
	struct mtx	lock;
	struct thread	*thread;
};

SLIST_HEAD(khttpd_socket_worker_slist, khttpd_socket_worker);

struct khttpd_sockbuf_job {
	struct khttpd_socket_job job;
	struct callout	timeo_callout;
	int		timeo;
};

struct khttpd_socket_migration_job {
	struct khttpd_socket_job job;
	struct khttpd_socket *socket;
	struct khttpd_socket_worker *worker;
	struct khttpd_socket_job *succ;
};

struct khttpd_socket {
	LIST_ENTRY(khttpd_socket) link;
	SLIST_ENTRY(khttpd_socket) sliste;
	struct khttpd_sockbuf_job rcv_job;
	struct khttpd_sockbuf_job snd_job;
	struct khttpd_socket_job rst_job;
	struct rmlock		migration_lock;
	struct sockaddr_storage	peeraddr;
	struct khttpd_socket_worker *worker;
	struct khttpd_stream	*stream;

#define khttpd_socket_zero_begin port
	struct khttpd_port	*port;
	struct mbuf		*xmit_buf;
	struct socket		*so;
	unsigned		is_tcp:1;
	unsigned		xmit_flush_scheduled:1;
	unsigned		xmit_close_scheduled:1;
	unsigned		xmit_notification_requested:1;
	unsigned		marker:1;
};

LIST_HEAD(khttpd_socket_list, khttpd_socket);

/* 
 * (a) khttpd_port_lock
 */

struct khttpd_port {
	LIST_ENTRY(khttpd_port)	liste;
	struct mtx		lock;
	struct khttpd_socket_list sockets;
	struct khttpd_socket_worker *worker;

#define khttpd_port_zctor_begin	addr
	struct sockaddr_storage	addr;
	khttpd_port_accept_fn_t	arrival_fn;
	struct khttpd_socket_job arrival_job;
	struct socket		*so;
	unsigned		is_tcp:1;
	unsigned		costructs_ready:1;
	u_int			hold; /* (a) */
	bool			waiting_unhold; /* (a) */

#define khttpd_port_zctor_end	refcount
	KHTTPD_REFCOUNT1_MEMBERS;
};

LIST_HEAD(khttpd_port_list, khttpd_port);

static void khttpd_port_dtor(struct khttpd_port *port);
static void khttpd_port_fini(struct khttpd_port *port);

static int khttpd_socket_stream_receive(struct khttpd_stream *, ssize_t *,
    struct mbuf **);
static void khttpd_socket_stream_continue_receiving(struct khttpd_stream *);
static void khttpd_socket_stream_reset(struct khttpd_stream *);
static bool khttpd_socket_stream_send(struct khttpd_stream *,
    struct mbuf *, int);
static void khttpd_socket_stream_send_bufstat(struct khttpd_stream *,
    u_int *, int *, long *);
static void khttpd_socket_stream_notify_of_drain(struct khttpd_stream *);
static void khttpd_socket_stream_destroy(struct khttpd_stream *);

extern int uma_align_cache;

struct khttpd_stream_down_ops khttpd_socket_ops = {
	.receive = khttpd_socket_stream_receive,
	.continue_receiving = khttpd_socket_stream_continue_receiving,
	.reset = khttpd_socket_stream_reset,
	.send = khttpd_socket_stream_send,
	.send_bufstat = khttpd_socket_stream_send_bufstat,
	.notify_of_drain = khttpd_socket_stream_notify_of_drain,
	.destroy = khttpd_socket_stream_destroy
};

struct khttpd_costruct_info *khttpd_port_costruct_info;

static struct mtx khttpd_port_lock;
static struct khttpd_socket_worker **khttpd_socket_workers;
static struct khttpd_socket_worker_slist *khttpd_socket_worker_table;
static struct khttpd_port_list khttpd_port_ports;
static volatile uint64_t khttpd_port_siphash_counter;
static uma_zone_t khttpd_socket_zone;
static eventhandler_tag khttpd_port_reset_all_tag;
static sbintime_t khttpd_port_timeout_pr = SBT_1S * 2;
static u_int khttpd_socket_worker_table_mask;
static u_int khttpd_socket_worker_count;
static bool khttpd_port_exiting;
static char khttpd_port_siphash_key[SIPHASH_KEY_LENGTH];

MTX_SYSINIT(khttpd_port_lock, &khttpd_port_lock, "port", MTX_DEF);

KHTTPD_REFCOUNT1_GENERATE(khttpd_port, khttpd_port, khttpd_port_dtor,
    khttpd_port_fini);

static u_int
khttpd_socket_worker_hash(struct thread *td)
{

	return (murmur3_32_hash(&td, sizeof(td), 0xdeadbeef) & 
	    khttpd_socket_worker_table_mask);
}

static struct khttpd_socket_worker *
khttpd_socket_current_worker(void)
{
	struct khttpd_socket_worker *worker;
	struct thread *td;

	td = curthread;
	SLIST_FOREACH(worker,
	    &khttpd_socket_worker_table[khttpd_socket_worker_hash(td)], sle) {
		if (worker->thread == td) {
			return (worker);
		}
	}

	return (NULL);
}

static void
khttpd_socket_job_schedule_locked(struct khttpd_socket *socket,
    struct khttpd_socket_worker *worker,
    struct khttpd_socket_job *job)
{
	bool result;

	KHTTPD_ENTRY("%s(%p,%p), inqueue %d, active %d",
	    __func__, socket, job, job->inqueue, job->active);

	if (socket != NULL)
		rm_assert(&socket->migration_lock, RA_LOCKED);

	if (STAILQ_FIRST(&worker->queue) == job) {
		KHTTPD_NOTE("%s again", __func__);
		job->again = true;
		return;
	}

	if ((result = !job->inqueue && job->active)) {
		KHTTPD_NOTE("%s enqueue", __func__);
		job->inqueue = true;
		if (STAILQ_EMPTY(&worker->queue))
			wakeup(&worker->queue);
		STAILQ_INSERT_TAIL(&worker->queue, job, stqe);
	}
}

static void
khttpd_socket_job_schedule(struct khttpd_socket *socket,
    struct khttpd_socket_worker *worker,
    struct khttpd_socket_job *job)
{

	KHTTPD_ENTRY("%s(%p,%p)", __func__, socket, job);
	mtx_lock(&worker->lock);
	khttpd_socket_job_schedule_locked(socket, worker, job);
	mtx_unlock(&worker->lock);
}

static bool
khttpd_port_drain_job(struct khttpd_port *port, struct khttpd_socket_job *job)
{
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, port, job);
	mtx_assert(&port->lock, MA_OWNED);

	worker = port->worker;

	mtx_lock(&worker->lock);

	job->active = false;

	if (!job->inqueue) {

	} else if (STAILQ_FIRST(&worker->queue) != job) {
		KHTTPD_NOTE("%s inqueue", __func__);
		STAILQ_REMOVE(&worker->queue, job, khttpd_socket_job, stqe);
		job->inqueue = false;

	} else if (curthread != worker->thread) {
		KHTTPD_NOTE("%s running", __func__);
		job->again = false;
		job->waiting = true;
		mtx_unlock(&port->lock);
		mtx_sleep(job, &worker->lock, PDROP, "jobdrain", 0);
		return (false);

	} else {
		job->again = false;
	}


	mtx_unlock(&worker->lock);
	return (true);
}

static void
khttpd_port_dtor(struct khttpd_port *port)
{
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	KASSERT(LIST_EMPTY(&port->sockets), ("port->sockets not empty"));

	if (port->costructs_ready) {
		khttpd_costruct_call_dtors(khttpd_port_costruct_info, port);

		mtx_lock(&khttpd_port_lock);
		while (port->hold != 0) {
			port->waiting_unhold = true;
			mtx_sleep(port, &khttpd_port_lock, 0, "porthold", 0);
		}
		LIST_REMOVE(port, liste);
		if (LIST_EMPTY(&khttpd_port_ports))
			wakeup(&khttpd_port_ports);
		mtx_unlock(&khttpd_port_lock);
	}

 again:
	/*
	 * The following lock is necessary to satisfy the mtx_assert in
	 * khttpd_port_drain_job.
	 */
	mtx_lock(&port->lock);
	if ((so = port->so) != NULL) {
		if (!khttpd_port_drain_job(port, &port->arrival_job))
			goto again;
		soclose(so);
	}
	mtx_unlock(&port->lock);

	mtx_destroy(&port->lock);
}

static void
khttpd_port_fini(struct khttpd_port *port)
{

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	khttpd_free(port);
}

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

static int
khttpd_socket_on_recv_upcall(struct socket *so, void *arg, int flags)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, so, arg, flags);

	socket = arg;
	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket, socket->worker,
	    &socket->rcv_job.job);
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
	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket, socket->worker,
	    &socket->snd_job.job);
	rm_runlock(&socket->migration_lock, &trk);

	return (SU_OK);
}

static void
khttpd_socket_schedule_reset(void *arg)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	rm_rlock(&socket->migration_lock, &trk);
	khttpd_socket_job_schedule(socket, socket->worker, &socket->rst_job);
	rm_runlock(&socket->migration_lock, &trk);
}

static bool
khttpd_socket_is_readable(struct socket *so)
{

	KHTTPD_ENTRY("%s(%p)", __func__, so);
	SOCKBUF_LOCK_ASSERT(&so->so_rcv);

	KHTTPD_TR("%s state %#x, sb_state %#x, error %d", __func__,
	    so->so_state, so->so_rcv.sb_state, so->so_error);
	KHTTPD_TR("%s sb_lowat %d, sbavail %d", __func__,
	    so->so_rcv.sb_lowat, sbavail(&so->so_rcv));

	return (so->so_rcv.sb_lowat <= sbavail(&so->so_rcv) ||
	    so->so_error != 0 || so->so_rcv.sb_state & SBS_CANTRCVMORE);
}

static bool
khttpd_socket_is_writeable(struct socket *so)
{

	KHTTPD_ENTRY("%s(%p)", __func__, so);
	SOCKBUF_LOCK_ASSERT(&so->so_snd);

	KHTTPD_TR("%s state %#x, sb_state %#x, error %d", __func__,
	    so->so_state, so->so_snd.sb_state, so->so_error);
	KHTTPD_TR("%s sb_lowat %d, sbspace %d", __func__,
	    so->so_snd.sb_lowat, sbspace(&so->so_snd));

	if ((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0 ||
	    so->so_error != 0) {
		return (true);
	}

	if ((so->so_state & SS_ISCONNECTED) == 0) {
		return (false);
	}

	return (so->so_snd.sb_lowat <= sbspace(&so->so_snd));
}

static void
khttpd_socket_schedule_event(struct khttpd_socket *socket, int side,
    bool enable)
{
	struct rm_priotracker trk;
	struct khttpd_socket_worker *worker;
	struct khttpd_sockbuf_job *job;
	struct socket *so;
	struct sockbuf *sb;
	int timeo;
	bool kick_callout, has_upcall;

	KHTTPD_ENTRY("%s(%p,%s,%d)", __func__, socket,
	    side == SO_RCV ? "recv" : side == SO_SND ? "send" : "invalid",
	    enable);

	if ((so = socket->so) == NULL)
		return;

	job = side == SO_RCV ? &socket->rcv_job : &socket->snd_job;
	sb = side == SO_RCV ? &so->so_rcv : &so->so_snd;
	SOCKBUF_LOCK(sb);

	rm_rlock(&socket->migration_lock, &trk);
	worker = socket->worker;
	mtx_lock(&worker->lock);

	if (job->job.active == enable) {
		mtx_unlock(&worker->lock);
		rm_runlock(&socket->migration_lock, &trk);
		SOCKBUF_UNLOCK(sb);
		return;
	}
	job->job.active = enable;

	has_upcall = (sb->sb_flags & SB_UPCALL) != 0;
	kick_callout = false;
	if (enable && (side == SO_RCV ?
	    khttpd_socket_is_readable(so) : khttpd_socket_is_writeable(so)))
		khttpd_socket_job_schedule_locked(socket, worker, &job->job);
	else if (!enable && has_upcall)
		soupcall_clear(so, side);
	else if (enable && !has_upcall) {
		KHTTPD_BRANCH("%s soupcall_set %p", __func__, so);
		soupcall_set(so, side, side == SO_RCV ? 
		    khttpd_socket_on_recv_upcall : 
		    khttpd_socket_on_xmit_upcall, socket);
		kick_callout = true;
	}

	mtx_unlock(&worker->lock);
	rm_runlock(&socket->migration_lock, &trk);
	SOCKBUF_UNLOCK(sb);

	if (!kick_callout)
		callout_stop(&job->timeo_callout);
	else if (0 < (timeo = job->timeo))
		callout_reset_sbt_curcpu(&job->timeo_callout,
		    timeo, khttpd_port_timeout_pr,
		    khttpd_socket_schedule_reset, socket, 0);
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

	if (socket->snd_job.job.active || socket->xmit_buf == NULL)
		return (false);

	td = curthread;

	so = socket->so;
	KHTTPD_NOTE("%s so %p", __func__, so);
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
		if (error != 0 && error != EPIPE)
			khttpd_socket_report_error(socket, LOG_WARNING, error,
			    "send() failed");
	}

	if (need_close) {
		error = soshutdown(so, SHUT_WR);
		if (error != 0 && error != ENOTCONN)
			khttpd_socket_report_error(socket, LOG_WARNING, error,
			    "shutdown(SHUT_WR) failed");
	}

	return (end != NULL || socket->xmit_notification_requested);
}

static void
khttpd_socket_reset(void *arg)
{
	struct linger linger;
	struct sockopt sockopt;
	struct socket *so;
	struct khttpd_socket *socket;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	so = socket->so;
	if (so == NULL)
		return;

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
	if (error != 0)
		khttpd_socket_report_error(socket, LOG_ERR, error,
		    "setsockopt(SOL_SOCKET, SO_LINGER) failed");

	error = soshutdown(so, SHUT_RDWR);
	if (error != 0 && error != ENOTCONN)
		khttpd_socket_report_error(socket, LOG_ERR, error,
		    "shutdown(SHUT_RD) failed");
}

static void
khttpd_socket_migrate(struct khttpd_socket *socket,
    struct khttpd_socket_worker *curworker,
    struct khttpd_socket_worker *newworker,
    struct khttpd_socket_job *auxjob)
{
	struct khttpd_socket_job *jobs[4], **jobp;
	struct khttpd_socket_job *job, *prev;
	int i, njobs;
	bool need_wakeup;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, socket, curworker, newworker);
	rm_assert(&socket->migration_lock, RA_WLOCKED);
	mtx_assert(&curworker->lock, MA_OWNED);

	jobp = jobs;

	if (auxjob != NULL) {
		*jobp++ = auxjob;
	}

	prev = STAILQ_FIRST(&curworker->queue);
	for (job = STAILQ_NEXT(prev, stqe); job != NULL;
	     job = STAILQ_NEXT(job, stqe)) {
		if (job == &socket->rcv_job.job ||
		    job == &socket->snd_job.job ||
		    job == &socket->rst_job) {
			KASSERT(jobp - jobs < nitems(jobs), ("jobs overflow"));
			STAILQ_REMOVE_AFTER(&curworker->queue, prev, stqe);
			job->inqueue = false;
			*jobp++ = job;
			job = prev;
		}
	}
	mtx_unlock(&curworker->lock);

	socket->worker = newworker;

	mtx_lock(&newworker->lock);
	njobs = jobp - jobs;
	need_wakeup = jobp != jobs && STAILQ_EMPTY(&newworker->queue);
	for (i = 0; i < njobs; ++i) {
		job = jobs[i];
		STAILQ_INSERT_TAIL(&newworker->queue, job, stqe);
		job->inqueue = false;
	}
	if (need_wakeup)
		wakeup(&newworker->queue);
	mtx_unlock(&newworker->lock);

	rm_wunlock(&socket->migration_lock);
}

static void
khttpd_socket_do_migration_job(void *arg)
{
	struct khttpd_socket *socket;
	struct khttpd_socket_migration_job *job;
	struct khttpd_socket_worker *curworker, *newworker;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	job = arg;
	socket = job->socket;
	newworker = job->worker;
	khttpd_socket_assert_curthread(socket);

	rm_wlock(&socket->migration_lock);
	curworker = socket->worker;

	mtx_lock(&curworker->lock);
	khttpd_socket_migrate(socket, curworker, newworker, job->succ);
}

void
khttpd_socket_run_later(struct khttpd_socket *socket, void (*fn)(void *),
    void *arg)
{
	struct rm_priotracker trk;
	struct khttpd_socket_job *job;
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, socket, fn, arg);

	job = khttpd_malloc(sizeof(struct khttpd_socket_job));
	bzero(job, sizeof(*job));
	job->fn = fn;
	job->arg = arg;
	job->oneoff = job->active = true;

	if (socket != NULL) {
		rm_rlock(&socket->migration_lock, &trk);
		khttpd_socket_job_schedule(socket, socket->worker, job);
		rm_runlock(&socket->migration_lock, &trk);

	} else {
		worker = khttpd_socket_worker_find();

		mtx_lock(&worker->lock);
		job->inqueue = true;
		if (STAILQ_EMPTY(&worker->queue))
			wakeup(&worker->queue);
		STAILQ_INSERT_TAIL(&worker->queue, job, stqe);
		mtx_unlock(&worker->lock);
	}
}

int
khttpd_socket_set_affinity(struct khttpd_socket *subject, 
    struct khttpd_socket *source, void (*notify)(void *), void *arg)
{
	struct khttpd_socket_job *running, *job2;
	struct khttpd_socket_migration_job *job1;
	struct khttpd_socket_worker *curworker, *newworker;
	struct thread *td;
	bool on_newworker, need_wakeup;

	KHTTPD_ENTRY("%s(%p,%p,%p,%p)",
	    __func__, subject, source, notify, arg);

	td = curthread;
	job1 = NULL;
	job2 = NULL;
	if (source->worker->thread != td)
		goto alloc_job2;
	for (;;) {
		rm_wlock(&subject->migration_lock);

		curworker = subject->worker;
		newworker = source->worker;
		on_newworker = newworker->thread == td;

		if (__predict_true(curworker == newworker ||
		    (!subject->rcv_job.job.inqueue && 
		     !subject->snd_job.job.inqueue &&
		     !subject->rst_job.inqueue))) {
			/*
			 * Member 'inqueue' is set only by
			 * khttpd_socket_job_schedule_locked() and it requires
			 * the caller to lock migration_lock.  Because we have
			 * the writer lock of migration_lock, it's guaranteed
			 * that inqueue doesn't change to true even if we don't
			 * have curworker->lock.
			 */

			if (__predict_false(!on_newworker && job2 == NULL)) {
				rm_wunlock(&subject->migration_lock);
				goto alloc_job2;
			}

			subject->worker = newworker;

			if (!on_newworker) {
				mtx_lock(&newworker->lock);
				need_wakeup = STAILQ_EMPTY(&newworker->queue);
				STAILQ_INSERT_TAIL(&newworker->queue, job2,
				    stqe);
				job2->inqueue = true;
				if (need_wakeup)
					wakeup(&newworker->queue);
				mtx_unlock(&newworker->lock);
				job2 = NULL;
			}

			rm_wunlock(&subject->migration_lock);
			break;
		}

		mtx_lock(&curworker->lock);

		running = STAILQ_FIRST(&curworker->queue);
		if (running != &subject->rcv_job.job &&
		    running != &subject->snd_job.job &&
		    running != &subject->rst_job) {
			if (on_newworker)
				khttpd_socket_migrate(subject, curworker,
				    newworker, NULL);
			else if (job2 != NULL) {
				khttpd_socket_migrate(subject, curworker,
				    newworker, job2);
				job2 = NULL;
			} else {
				mtx_unlock(&curworker->lock);
				rm_wunlock(&subject->migration_lock);
				goto alloc_job2;
			}
			break;
		}

		if (job1 != NULL && job2 != NULL) {
			job1->worker = newworker;
			STAILQ_INSERT_AFTER(&curworker->queue, running,
			    &job1->job, stqe);
			job1->job.inqueue = true;

			mtx_unlock(&curworker->lock);
			rm_wunlock(&subject->migration_lock);

			return (EINPROGRESS);
		}

		mtx_unlock(&curworker->lock);
		rm_wunlock(&subject->migration_lock);

		if (job1 == NULL) {
			job1 = khttpd_malloc
			    (sizeof(struct khttpd_socket_migration_job));
			bzero(job1, sizeof(*job1));
			job1->job.fn = khttpd_socket_do_migration_job;
			job1->job.arg = job1;
			job1->job.oneoff = job1->job.active = true;
			job1->socket = subject;
		}

		if (job2 == NULL) {
 alloc_job2:
			job2 = khttpd_malloc(sizeof(struct khttpd_socket_job));
			bzero(job2, sizeof(*job2));
			job2->fn = notify;
			job2->arg = arg;
			job2->oneoff = job2->active = true;
		}

		if (job1 != NULL)
			job1->succ = job2;
	}

	khttpd_free(job1);
	khttpd_free(job2);

	if (on_newworker) {
		notify(arg);
		return (0);
	}

	return (EINPROGRESS);
}

static void
khttpd_socket_do_rcv_job(void *arg)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	socket = arg;
	khttpd_socket_assert_curthread(socket);
	khttpd_socket_schedule_event(socket, SO_RCV, false);
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

	khttpd_socket_schedule_event(socket, SO_SND, false);

	if (socket->xmit_buf != NULL && khttpd_socket_send(socket))
		khttpd_socket_schedule_event(socket, SO_SND, true);

	if (socket->xmit_notification_requested &&
	    socket->xmit_buf == NULL) {
		socket->xmit_notification_requested = false;

		so = socket->so;
		SOCKBUF_LOCK(&so->so_snd);
		space = sbspace(&so->so_snd);
		SOCKBUF_UNLOCK(&so->so_snd);

		khttpd_stream_clear_to_send(socket->stream, space);
	}
}

static int
khttpd_socket_init(void *mem, int size, int flags)
{
	struct khttpd_socket *socket;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	socket = mem;

	rm_init_flags(&socket->migration_lock, "sock", RM_RECURSE);

	bzero(&socket->rcv_job, sizeof(socket->rcv_job));
	socket->rcv_job.job.fn = khttpd_socket_do_rcv_job;
	socket->rcv_job.job.arg = socket;
	callout_init(&socket->rcv_job.timeo_callout, 0);

	bzero(&socket->snd_job, sizeof(socket->snd_job));
	socket->snd_job.job.fn = khttpd_socket_do_snd_job;
	socket->snd_job.job.arg = socket;
	callout_init(&socket->snd_job.timeo_callout, 0);

	bzero(&socket->rst_job, sizeof(socket->rst_job));
	socket->rst_job.fn = khttpd_socket_reset;
	socket->rst_job.arg = socket;
	socket->rst_job.active = true;

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
	socket->peeraddr.ss_len = offsetof(struct sockaddr_storage,
	    ss_family) + sizeof(socket->peeraddr.ss_family);
	socket->peeraddr.ss_family = AF_UNSPEC;
	socket->worker = khttpd_socket_current_worker();
	socket->stream = arg;

	socket->rcv_job.job.active = false;
	socket->rcv_job.job.inqueue = socket->rcv_job.job.again = 
	    socket->rcv_job.job.waiting = socket->rcv_job.job.oneoff = false;

	socket->rst_job.active = true;
	socket->rst_job.inqueue = socket->rst_job.again = 
	    socket->rst_job.waiting = socket->rst_job.oneoff = false;

	socket->snd_job.job.active = false;
	socket->snd_job.job.inqueue = socket->snd_job.job.again = 
	    socket->snd_job.job.waiting = socket->snd_job.job.oneoff = false;

	bzero(&socket->khttpd_socket_zero_begin, sizeof(*socket) -
	    offsetof(struct khttpd_socket, khttpd_socket_zero_begin));

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_port *port;
	struct khttpd_socket *socket;
	struct socket *so;
	struct thread *td;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, mem, size, arg);

	td = curthread;
	socket = mem;
	port = socket->port;

	if ((so = socket->so) != NULL) {
		KHTTPD_NOTE("%s soclose", __func__);
		soclose(socket->so);
	}

	m_freem(socket->xmit_buf);

	if (port != NULL) {
		mtx_lock(&port->lock);
		LIST_REMOVE(socket, link);
		if (LIST_EMPTY(&port->sockets))
			wakeup(&port->sockets);
		mtx_unlock(&port->lock);

		khttpd_port_release(port);
	}
}

static void
khttpd_port_reset_all(void *arg)
{
	struct khttpd_port *ptr;

	mtx_lock(&khttpd_port_lock);
	LIST_FOREACH(ptr, &khttpd_port_ports, liste) {
		++ptr->hold;
		mtx_unlock(&khttpd_port_lock);

		khttpd_port_reset(ptr);

		mtx_lock(&khttpd_port_lock);
		if (--ptr->hold == 0 && ptr->waiting_unhold) {
			ptr->waiting_unhold = false;
			wakeup(ptr);
		}
	}
	mtx_unlock(&khttpd_port_lock);

	mtx_lock(&khttpd_port_lock);
	while (!LIST_EMPTY(&khttpd_port_ports))
		mtx_sleep(&khttpd_port_ports, &khttpd_port_lock, 0,
		    "portexit", 0);
	mtx_unlock(&khttpd_port_lock);
}

static void
khttpd_socket_worker_main(void *arg)
{
	struct khttpd_socket *socket, *tmpsock;
	struct khttpd_socket_job *job;
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p), name %s", __func__, arg,
	    khttpd_ktr_printf("%s", curthread->td_name));

	worker = arg;

	mtx_lock(&worker->lock);
	for (;;) {
		if ((job = STAILQ_FIRST(&worker->queue)) == NULL) {
			if (khttpd_port_exiting)
				break;
			mtx_sleep(&worker->queue, &worker->lock, 0,
			    "portidle", 0);
			continue;
		}
again:
		mtx_unlock(&worker->lock);

		KHTTPD_NOTE("%s start %p", __func__, job);
		job->fn(job->arg);
		KHTTPD_NOTE("%s end %p", __func__, job);

		mtx_lock(&worker->lock);

		if (job->again) {
			KHTTPD_NOTE("%s wakeup %p", __func__, job);
			job->again = false;
			goto again;
		}

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
			KHTTPD_NOTE("%s free", __func__);
			mtx_unlock(&worker->lock);
			SLIST_FOREACH_SAFE(socket, &worker->free, sliste,
			    tmpsock)
				uma_zfree(khttpd_socket_zone, socket);
			SLIST_INIT(&worker->free);
			mtx_lock(&worker->lock);
		}
	}
	mtx_unlock(&worker->lock);

	mtx_lock(&khttpd_port_lock);
	KHTTPD_NOTE("%s exiting. count %d",
	    __func__, khttpd_socket_worker_count);
	if (--khttpd_socket_worker_count == 0)
		wakeup(&khttpd_socket_worker_count);
	mtx_unlock(&khttpd_port_lock);

	kthread_exit();
}

static int
khttpd_port_run(void)
{
	struct khttpd_socket_worker **workers, *worker;
	size_t worker_size;
	int error, i, n;

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_port_reset_all_tag =
	    EVENTHANDLER_REGISTER(khttpd_main_shutdown,
		khttpd_port_reset_all, NULL, EVENTHANDLER_PRI_ANY);

	khttpd_socket_zone = uma_zcreate("socket",
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor,
	    khttpd_socket_init, khttpd_socket_fini,
	    UMA_ALIGN_PTR, 0);

	n = mp_ncpus;
	khttpd_socket_workers = workers =
	    khttpd_malloc(n * sizeof(struct khttpd_socket_worker *));
	worker_size = roundup2(sizeof(struct khttpd_socket_worker),
	    uma_align_cache + 1);

	khttpd_socket_worker_table = khttpd_malloc(n *
	    sizeof(struct khttpd_socket_worker_slist));
	khttpd_socket_worker_table_mask = n - 1;
	for (i = 0; i < n; ++i) {
		SLIST_INIT(&khttpd_socket_worker_table[i]);
	}

	khttpd_socket_worker_count = 0;

	for (i = 0; i < n; ++i) {
		workers[i] = worker = khttpd_malloc(worker_size);
		STAILQ_INIT(&worker->queue);
		SLIST_INIT(&worker->free);
		mtx_init(&worker->lock, "prtwrkr", NULL, MTX_DEF | MTX_NEW);
		worker->thread = NULL;

		error = kthread_add(khttpd_socket_worker_main, worker, curproc,
		    &worker->thread, 0, 0, "prtwrkr%d", i);
		if (error != 0) {
			mtx_destroy(&worker->lock);
			khttpd_free(worker);

			log(LOG_ERR, "khttpd: kthread_add() failed "
			    "(error: %d, file: %s, line: %u)",
			    error, __FILE__, __LINE__);

			break;
		}

		SLIST_INSERT_HEAD(&khttpd_socket_worker_table
		    [khttpd_socket_worker_hash(worker->thread)], worker, sle);
	}

	khttpd_socket_worker_count = i;

	return (error);
}

static void
khttpd_port_exit(void)
{
	struct khttpd_socket_worker *worker;
	int i, n;

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_port_exiting = true;

	n = khttpd_socket_worker_count;
	for (i = 0; i < n; ++i)
		wakeup(&khttpd_socket_workers[i]->queue);

	mtx_lock(&khttpd_port_lock);
	while (0 < khttpd_socket_worker_count)
		mtx_sleep(&khttpd_socket_worker_count, &khttpd_port_lock, 0,
		    "portexit", 0);
	mtx_unlock(&khttpd_port_lock);

	for (i = 0; i < n; ++i) {
		worker = khttpd_socket_workers[i];
		mtx_destroy(&worker->lock);
		khttpd_free(khttpd_socket_workers[i]);
	}
	khttpd_free(khttpd_socket_workers);
	khttpd_free(khttpd_socket_worker_table);

	uma_zdestroy(khttpd_socket_zone);

	EVENTHANDLER_DEREGISTER(khttpd_main_shutdown,
	    khttpd_port_reset_all_tag);
}

KHTTPD_INIT(khttpd_port, khttpd_port_run, khttpd_port_exit,
    KHTTPD_INIT_PHASE_RUN);

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
	if (error != 0 && auio.uio_resid != reqsize)
		error = 0;
	if (error == 0) {
		*resid = auio.uio_resid;
		*m_out = m;
	}

	return (error);
}

static void
khttpd_socket_stream_continue_receiving(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	KASSERT(stream->down != NULL, ("no socket"));
	khttpd_socket_schedule_event(stream->down, SO_RCV, true);
}

static void
khttpd_socket_stream_reset(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	khttpd_socket_schedule_reset(stream->down);
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

	if ((flags & KHTTPD_STREAM_CLOSE) != 0)
		socket->xmit_close_scheduled = true;

	if ((flags & KHTTPD_STREAM_FLUSH) != 0)
		socket->xmit_flush_scheduled = true;

	if (socket->xmit_buf != NULL)
		m_cat(socket->xmit_buf, m);
	else
		socket->xmit_buf = m;

	if (khttpd_socket_send(socket))
		khttpd_socket_schedule_event(socket, SO_SND, true);

	return (socket->xmit_buf != NULL);
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

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	socket = stream->down;
	socket->xmit_notification_requested = true;
	khttpd_socket_schedule_event(socket, SO_SND, true);
}

static void
khttpd_socket_drain_job(struct khttpd_socket *socket,
    struct khttpd_socket_job *job)
{
	struct rm_priotracker trk;
	struct khttpd_socket_worker *worker;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, socket, job);

 again:
	rm_rlock(&socket->migration_lock, &trk);
	worker = socket->worker;
	mtx_lock(&worker->lock);

	job->active = false;

	if (!job->inqueue) {

	} else if (STAILQ_FIRST(&worker->queue) != job) {
		KHTTPD_NOTE("%s inqueue", __func__);
		STAILQ_REMOVE(&worker->queue, job, khttpd_socket_job, stqe);
		job->inqueue = false;

	} else if (curthread != worker->thread) {
		KHTTPD_NOTE("%s running", __func__);
		job->again = false;
		job->waiting = true;
		rm_runlock(&socket->migration_lock, &trk);
		mtx_sleep(job, &worker->lock, PDROP, "jobdrain", 0);
		goto again;

	} else {
		job->again = false;
	}

	mtx_unlock(&worker->lock);
	rm_runlock(&socket->migration_lock, &trk);
}

static void
khttpd_socket_stream_destroy(struct khttpd_stream *stream)
{
	struct rm_priotracker trk;
	struct khttpd_socket *socket;
	struct khttpd_socket_worker *worker;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p), so %p",
	    __func__, stream, ((struct khttpd_socket *)stream->down)->so);

	socket = stream->down;
	khttpd_socket_assert_curthread(socket);

	callout_drain(&socket->rcv_job.timeo_callout);
	callout_drain(&socket->snd_job.timeo_callout);

	if ((so = socket->so) == NULL) {
		uma_zfree(khttpd_socket_zone, socket);
		return;
	}

	SOCKBUF_LOCK(&so->so_rcv);
	if ((so->so_rcv.sb_flags & SB_UPCALL) != 0)
		soupcall_clear(so, SO_RCV);
	SOCKBUF_UNLOCK(&so->so_rcv);

	SOCKBUF_LOCK(&so->so_snd);
	if ((so->so_snd.sb_flags & SB_UPCALL) != 0)
		soupcall_clear(so, SO_SND);
	SOCKBUF_UNLOCK(&so->so_snd);

	khttpd_socket_drain_job(socket, &socket->rcv_job.job);
	khttpd_socket_drain_job(socket, &socket->rst_job);
	khttpd_socket_drain_job(socket, &socket->snd_job.job);

	rm_rlock(&socket->migration_lock, &trk);
	worker = socket->worker;
	mtx_lock(&worker->lock);
	SLIST_INSERT_HEAD(&worker->free, socket, sliste);
	mtx_unlock(&worker->lock);
	rm_runlock(&socket->migration_lock, &trk);
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

int
khttpd_port_accept(struct khttpd_port *port, struct khttpd_socket *socket)
{
	struct sockopt sockopt;
	struct thread *td;
	struct sockaddr *name;
	struct socket *head, *so;
	int error, soptval;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, port, socket);

	td = curthread;

#ifdef INVARIANT
	mtx_lock(&port->lock);
	KASSERT(td == port->worker->thread,
	    ("curthread %p, worker %p", td, port->worker->thread));
	KASSERT(socket->port == NULL,
	    ("socket=%p, socket->port=%p", socket, socket->port));
	mtx_unlock(&port->lock);
#endif

	/*
	 * Pointer 'head' is guaranteed not to be changed because all codes
	 * that modifies port->socket make sure that the worker is not
	 * executing concurrently with the modification.
	 */
	head = port->so;
	if (head == NULL) {
		KHTTPD_NOTE("%s EBADF", __func__);
		return (EBADF);
	}

	ACCEPT_LOCK();
	if (TAILQ_EMPTY(&head->so_comp)) {
		ACCEPT_UNLOCK();
		KHTTPD_NOTE("%s EWOULDBLOCK", __func__);
		return (EWOULDBLOCK);
	}

	if (head->so_rcv.sb_state & SBS_CANTRCVMORE) {
		ACCEPT_UNLOCK();
		KHTTPD_NOTE("%s ECONNABORTED", __func__);
		return (ECONNABORTED);
	}

	if (head->so_error != 0) {
		error = head->so_error;
		head->so_error = 0;
		ACCEPT_UNLOCK();
		KHTTPD_NOTE("%s error %d", __func__, error);
		return (error);
	}

	so = TAILQ_FIRST(&head->so_comp);
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

	error = soaccept(so, &name);
	if (error != 0) {
		KHTTPD_NOTE("%s error %d", __func__, error);
		soclose(so);
		return (error);
	}

	bcopy(name, &socket->peeraddr,
	    MIN(sizeof(socket->peeraddr), name->sa_len));

	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_NOSIGPIPE;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		khttpd_socket_report_error(socket, LOG_ERR, error,
		    "setsockopt(SO_NOSIGPIPE) failed");
		soclose(so);
		return (error);
	}

	if (port->is_tcp) {
		socket->is_tcp = true;

		soptval = 1;
		sockopt.sopt_level = IPPROTO_TCP;
		sockopt.sopt_name = TCP_NODELAY;
		error = sosetopt(so, &sockopt);
		if (error != 0) {
			khttpd_socket_report_error(socket, LOG_WARNING, error,
			    "setsockopt(TCP_NODELAY) failed");
			soclose(so);
			return (error);
		}
	}

	mtx_lock(&port->lock);
	KHTTPD_NOTE("%s so %p", __func__, so);
	socket->so = so;
	socket->port = port;
	socket->worker = khttpd_socket_worker_find();
	LIST_INSERT_HEAD(&port->sockets, socket, link);
	khttpd_port_acquire(port);
	mtx_unlock(&port->lock);

	khttpd_socket_schedule_event(socket, SO_RCV, true);

	return (0);
}

const struct sockaddr *
khttpd_port_address(struct khttpd_port *port)
{

	return ((const struct sockaddr *)&port->addr);
}

static void
khttpd_port_handle_arrival_event(void *arg)
{
	struct khttpd_port *port;
	struct socket *head;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;
	head = port->so;

	ACCEPT_LOCK();
	while (!TAILQ_EMPTY(&head->so_comp)) {
		ACCEPT_UNLOCK();
		port->arrival_fn(port);
		ACCEPT_LOCK();
	}
	ACCEPT_UNLOCK();
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

	mtx_init(&port->lock, "port", NULL, MTX_DEF | MTX_NEW);
	LIST_INIT(&port->sockets);
	port->worker = khttpd_socket_worker_find();

	bzero(&port->khttpd_port_zctor_begin,
	    offsetof(struct khttpd_port, khttpd_port_zctor_end) -
	    offsetof(struct khttpd_port, khttpd_port_zctor_begin));
	KHTTPD_REFCOUNT1_INIT(khttpd_port, port);

	port->arrival_job.fn = khttpd_port_handle_arrival_event;
	port->arrival_job.arg = port;

	error = khttpd_costruct_call_ctors(khttpd_port_costruct_info, port);
	if (error != 0) {
		khttpd_port_release(port);
		return (error);
	}

	port->costructs_ready = true;
	*port_out = port;

	mtx_lock(&khttpd_port_lock);
	LIST_INSERT_HEAD(&khttpd_port_ports, port, liste);
	mtx_unlock(&khttpd_port_lock);

	return (error);
}

void
khttpd_port_reset(struct khttpd_port *port)
{
	struct rm_priotracker trk;
	struct khttpd_socket marker;
	struct khttpd_socket *socket, *next;

	KHTTPD_ENTRY("%s(%p)", __func__, port);
	KASSERT(port->costructs_ready, ("!costructs_ready"));

	bzero(&marker, sizeof(marker));
	marker.marker = true;

	mtx_lock(&port->lock);

	for (socket = LIST_FIRST(&port->sockets);
	     socket != NULL; socket = next)
		if (socket->marker) {
			next = LIST_NEXT(socket, link);
		} else {
			LIST_INSERT_AFTER(socket, &marker, link);
			mtx_unlock(&port->lock);

			rm_rlock(&socket->migration_lock, &trk);
			khttpd_socket_job_schedule(socket, socket->worker,
			    &socket->rst_job);
			rm_runlock(&socket->migration_lock, &trk);

			mtx_lock(&port->lock);
			next = LIST_NEXT(&marker, link);
			LIST_REMOVE(&marker, link);
			if (next == NULL && LIST_EMPTY(&port->sockets)) {
				wakeup(&port->sockets);
			}
		}

	while (!LIST_EMPTY(&port->sockets)) {
		KHTTPD_NOTE("%s sockcls begin", __func__);
		LIST_FOREACH(socket, &port->sockets, link) {
			KHTTPD_NOTE("%s sockcls %p", __func__, socket);
		}

		mtx_sleep(&port->sockets, &port->lock, 0, "sockcls", 0);
	}

	mtx_unlock(&port->lock);
}

static int
khttpd_port_do_arrival_upcall(struct socket *head, void *arg, int flags)
{
	struct khttpd_port *port;

	KHTTPD_ENTRY("%s(%p,%p,%#x)", __func__, head, arg, flags);

	port = arg;
	khttpd_socket_job_schedule(NULL, port->worker, &port->arrival_job);

	return (SU_OK);
}

int
khttpd_port_start(struct khttpd_port *port, struct sockaddr *addr,
    khttpd_port_accept_fn_t accept_fn, const char **detail_out)
{
	struct sockopt sockopt;
	struct khttpd_socket_worker *worker;
	struct socket *so;
	struct thread *td;
	const char *detail;
	int dom, error, soptval;
	bool is_tcp;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, port, addr, accept_fn);
	KASSERT(port->costructs_ready, ("!costructs_ready"));

	td = curthread;
	so = NULL;
	detail = NULL;
	error = 0;

	if (sizeof(port->addr) < addr->sa_len)
		goto invalid_address;

	switch (addr->sa_family) {
	case AF_INET:
		dom = PF_INET;
		is_tcp = true;
		break;
	case AF_INET6:
		dom = PF_INET6;
		is_tcp = true;
		break;
	case AF_UNIX:
		dom = PF_UNIX;
		is_tcp = false;
		break;
	default:
		goto invalid_address;
	}

	error = socreate(dom, &so, SOCK_STREAM, 0, td->td_ucred, td);
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

	worker = khttpd_socket_worker_find();

	mtx_lock(&port->lock);

	if (port->so != NULL) {
		mtx_unlock(&port->lock);
		detail = "already started";
		goto error;
	}

	bcopy(addr, &port->addr, addr->sa_len);
	port->arrival_fn = accept_fn;
	port->arrival_job.active = true;
	port->is_tcp = is_tcp;
	port->so = so;
	port->worker = worker;

	mtx_unlock(&port->lock);

	SOCKBUF_LOCK(&so->so_rcv);
	soupcall_set(so, SO_RCV, khttpd_port_do_arrival_upcall, port);
	SOCKBUF_UNLOCK(&so->so_rcv);

	khttpd_port_do_arrival_upcall(so, port, 0);

	return (0);

 invalid_address:
	detail = "invalid address";
	error = EINVAL;

 error:
	soclose(so);
	if (detail_out != NULL)
		*detail_out = detail;

	return (error);
}

void
khttpd_port_stop(struct khttpd_port *port)
{
	struct khttpd_socket_worker *worker;
	struct khttpd_socket_job *job;
	struct socket *so;

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	worker = port->worker;
	job = &port->arrival_job;

 again:
	mtx_lock(&port->lock);
	if ((so = port->so) == NULL) {
		mtx_unlock(&port->lock);
		return;
	}

	SOCKBUF_LOCK(&so->so_rcv);
	if ((so->so_snd.sb_flags & SB_UPCALL) != 0) {
		soupcall_clear(so, SO_RCV);
	}
	SOCKBUF_UNLOCK(&so->so_rcv);

	if (!khttpd_port_drain_job(port, job)) {
		goto again;
	}

	port->so = NULL;
	mtx_unlock(&port->lock);

	soclose(so);
}

struct khttpd_socket *
khttpd_socket_new(struct khttpd_stream *stream)
{

	KHTTPD_ENTRY("%s()", __func__);
	return (uma_zalloc_arg(khttpd_socket_zone, stream, M_WAITOK));
}

const struct sockaddr *
khttpd_socket_peer_address(struct khttpd_socket *socket)
{

	return ((struct sockaddr *)&socket->peeraddr);
}

int
khttpd_socket_connect(struct khttpd_socket *socket, struct sockaddr *peeraddr,
    struct sockaddr *sockaddr)
{
	struct sockopt sockopt;
	struct socket *so;
	struct thread *td;
	const char *detail;
	int dom, error, soptval;
	bool is_tcp;

	KHTTPD_ENTRY("%s(%p)", __func__, socket);

	td = curthread;
	detail = NULL;

	if (socket->so != NULL)
		return (EISCONN);

	if (sizeof(socket->peeraddr) < peeraddr->sa_len ||
	    (sockaddr != NULL && sockaddr->sa_family != peeraddr->sa_family))
		return (EINVAL);

	switch (peeraddr->sa_family) {
	case AF_INET:
		dom = PF_INET;
		is_tcp = true;
		break;
	case AF_INET6:
		dom = PF_INET6;
		is_tcp = true;
		break;
	case AF_UNIX:
		dom = PF_UNIX;
		is_tcp = false;
		break;
	default:
		return (EINVAL);
	}

	error = socreate(dom, &socket->so, SOCK_STREAM, 0, td->td_ucred, td);
	if (error != 0)
		return (error);
	so = socket->so;
	KHTTPD_NOTE("%s so %p", __func__, so);

	SOCK_LOCK(so);
	so->so_state |= SS_NBIO;
	SOCK_UNLOCK(so);

	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_NOSIGPIPE;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		khttpd_socket_report_error(socket, LOG_ERR, error,
		    "setsockopt(SO_NOSIGPIPE) failed");
		return (error);
	}

	if (peeraddr->sa_family == PF_INET || 
	    peeraddr->sa_family == PF_INET6) {
		socket->is_tcp = true;

		soptval = 1;
		sockopt.sopt_level = IPPROTO_TCP;
		sockopt.sopt_name = TCP_NODELAY;
		error = sosetopt(so, &sockopt);
		if (error != 0) {
			khttpd_socket_report_error(socket, LOG_ERR, error,
			    "setsockopt(TCP_NODELAY) failed");
			return (error);
		}
	}

	if (sockaddr != NULL) {
		error = sobind(so, sockaddr, td);
		if (error != 0) {
			khttpd_socket_report_error(socket, LOG_ERR, error,
			    "bind() failed");
			return (error);
		}
	}

	error = soconnect(so, peeraddr, td);
	if (error != 0 && error != EINPROGRESS)
		khttpd_socket_report_error(socket, LOG_WARNING, error,
		    "connect() failed");

	return (error);
}

int
khttpd_socket_error(struct khttpd_socket *socket)
{
	struct socket *so;
	int error;

	so = socket->so;
	SOCK_LOCK(so);
	error = so->so_error;
	so->so_error = 0;
	SOCK_UNLOCK(so);

	return (error);
}

const struct sockaddr *
khttpd_socket_name(struct khttpd_socket *_sock)
{
	struct sockaddr *sa;
	struct socket *so;
	int error;

	so = _sock->so;
	sa = NULL;
	CURVNET_SET(so->so_vnet);
	error = (*so->so_proto->pr_usrreqs->pru_sockaddr)(so, &sa);
	CURVNET_RESTORE();

	return (error == 0 ? sa : NULL);
}

bool
khttpd_socket_on_worker_thread(struct khttpd_socket *socket)
{

	return (socket->worker->thread == curthread);
}

struct khttpd_port *
khttpd_socket_port(struct khttpd_socket *socket)
{

	return (socket->port);
}
