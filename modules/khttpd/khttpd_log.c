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

#include "khttpd_log.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/syslog.h>
#include <vm/vm.h>
#include <vm/vm_object.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "khttpd_job.h"
#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_stream.h"

enum {
	khttpd_log_type_null,
	khttpd_log_type_file,
	khttpd_log_type_fluentd,
	khttpd_log_type_count
};

struct khttpd_log {
	struct mtx	lock;
	struct mbufq	queue;
	struct callout	flush_callout;
	sbintime_t	timeout;
	struct khttpd_job *job;
	union {
		struct {
			struct vnode	*vp;
		} file;
		struct {
			struct socket	*so;
			char		*tag;
		} fluentd;
	};
	int		type;
	unsigned	unbuffered:1;
	unsigned	choking:1;
	unsigned	busy:1;
	unsigned	waiting:1;
};

static struct khttpd_log khttpd_log_states[khttpd_log_chan_count];

static int
khttpd_log_write_to_file(struct vnode *vp, int ioflag, struct iovec *iov,
    int niov, ssize_t resid)
{
	struct uio auio;
	struct thread *td;

	td = curthread;

	auio.uio_rw = UIO_WRITE;
	auio.uio_iov = iov;
	auio.uio_iovcnt = niov;
	auio.uio_offset = 0;
	auio.uio_resid = resid;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_td = curthread;

	return (VOP_WRITE(vp, &auio, ioflag, td->td_ucred));
}

static void
khttpd_log_flush_to_file(struct khttpd_log *subject, struct mbuf *head)
{
	struct iovec iovs[64];
	struct mbuf *m, *pkt;
	struct mount *mp;
	struct thread *td;
	struct vnode *vp;
	ssize_t resid;
	int ioflag, lock_flags;
	int error, i, niov;

	KHTTPD_ENTRY("%s(%p)", __func__, subject);

	td = curthread;
	niov = nitems(iovs);
	vp = subject->file.vp;

	bwillwrite();

	ioflag = IO_APPEND | IO_SEQMAX;
	if (vp->v_mount != NULL &&
	    (vp->v_mount->mnt_flag & MNT_SYNCHRONOUS) != 0) {
		ioflag |= IO_SYNC;
	}

	mp = NULL;
	error = vn_start_write(vp, &mp, V_WAIT);

	if (MNT_SHARED_WRITES(mp) ||
	    (mp == NULL && MNT_SHARED_WRITES(vp->v_mount))) {
		lock_flags = LK_SHARED;
	} else {
		lock_flags = LK_EXCLUSIVE;
	}

	vn_lock(vp, lock_flags | LK_RETRY);

	i = 0;
	resid = 0;
	for (pkt = head; pkt != NULL; pkt = STAILQ_NEXT(pkt, m_stailqpkt)) {
		khttpd_mbuf_append_ch(pkt, '\n');

		for (m = pkt; m != NULL; m = m->m_next) {
			iovs[i].iov_base = mtod(m, void *);
			iovs[i].iov_len = m->m_len;
			resid += m->m_len;
			if (++i == nitems(iovs)) {
				error = khttpd_log_write_to_file(vp, ioflag,
				    iovs, i, resid);
				i = 0;
				resid = 0;
			}
		}
	}

	if (0 < i && error == 0) {
		error = khttpd_log_write_to_file(vp, ioflag, iovs, i, resid);
	}

	for (pkt = head; pkt != NULL; ) {
		m = pkt;
		pkt = STAILQ_NEXT(pkt, m_stailqpkt);
		m_freem(m);
	}

	if (error == 0) {
		if (vp->v_object != NULL) {
			VM_OBJECT_WLOCK(vp->v_object);
			vm_object_page_clean(vp->v_object, 0, 0, 0);
			VM_OBJECT_WUNLOCK(vp->v_object);
		}

		error = VOP_FDATASYNC(vp, td);
	}

	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);

	if (error != 0) {
		log(LOG_WARNING, "khttpd: "
		    "failed to write to a log (error: %d)", error);
	}
}

static void
khttpd_log_flush_to_fluentd(struct khttpd_log *subject, struct mbuf *head)
{
	struct bintime now;
	struct khttpd_mbuf_json dst;
	struct mbuf *m, *npkt, *pkt, *last;
	struct socket *so;
	struct thread *td;
	long endlen, len, space;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, subject);

	td = curthread;
	so = subject->fluentd.so;
	bintime(&now);

	khttpd_mbuf_json_new(&dst);

	for (pkt = head; pkt != NULL; pkt = npkt) {
		npkt = STAILQ_NEXT(pkt, m_stailqpkt);

		khttpd_mbuf_json_array_begin(&dst);
		khttpd_mbuf_json_cstr(&dst, true, subject->fluentd.tag);
		khttpd_mbuf_json_format(&dst, false, "%ld", now.sec);
		khttpd_mbuf_json_mbuf(&dst, false, pkt);
		khttpd_mbuf_json_array_end(&dst);
		khttpd_mbuf_json_new_with_mbuf(&dst,
		    khttpd_mbuf_json_move(&dst));
	}

	for (pkt = khttpd_mbuf_json_move(&dst), error = 0;
	     pkt != NULL && error == 0; pkt = npkt) {
		SOCKBUF_LOCK(&so->so_snd);

		while ((so->so_snd.sb_state & SBS_CANTSENDMORE) == 0 &&
		    (space = sbspace(&so->so_snd)) <
		    MAX(pkt->m_len, so->so_snd.sb_lowat)) {
			sbwait(&so->so_snd);
		}

		if ((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0) {
			SOCKBUF_UNLOCK(&so->so_snd);
			error = EPIPE;
			break;
		}

		SOCKBUF_UNLOCK(&so->so_snd);

		last = NULL;
		len = 0;
		for (npkt = pkt; npkt != NULL; npkt = npkt->m_next) {
			endlen = npkt->m_len;
			if (space < len + endlen) {
				break;
			}
			len += endlen;
			last = npkt;
		}

		if (last != NULL) {
			last->m_next = NULL;
		}

		if ((pkt->m_flags & M_PKTHDR) == 0) {
			m = m_gethdr(M_WAITOK, MT_DATA);
			m->m_next = pkt;
			pkt = m;
		}
		pkt->m_pkthdr.len = len;

		error = sosend(so, NULL, NULL, pkt, NULL,
		    npkt != NULL ? MSG_MORETOCOME : 0, td);
	}

	if (error != 0) {
		log(LOG_WARNING, "send() failed: %d", error);
	}
}

static void
khttpd_log_flush(void *arg)
{
	struct mbuf *pkt;
	struct khttpd_log *subject;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	subject = arg;

	mtx_lock(&subject->lock);
	while ((pkt = mbufq_flush(&subject->queue)) != NULL) {
		mtx_unlock(&subject->lock);

		switch (subject->type) {
		case khttpd_log_type_file:
			khttpd_log_flush_to_file(subject, pkt);
			break;
		case khttpd_log_type_fluentd:
			khttpd_log_flush_to_fluentd(subject, pkt);
			break;
		default:
			break;
		}

		mtx_lock(&subject->lock);
	}

	subject->busy = false;
	if (subject->waiting) {
		subject->waiting = false;
		wakeup(subject);
	}
	mtx_unlock(&subject->lock);
}

static void
khttpd_log_choke(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);

	mtx_lock(&log->lock);

	while (log->choking) {
		log->waiting = true;
		mtx_sleep(log, &log->lock, 0, "logchk", 0);
	}
	log->choking = true;

	while (log->busy || (log->type != khttpd_log_type_null &&
		0 < mbufq_len(&log->queue))) {
		if (log->busy) {
			log->waiting = true;
			mtx_sleep(log, &log->lock, 0, "logbsy", 0);
		} else {
			log->busy = true;
			callout_stop(&log->flush_callout);
			mtx_unlock(&log->lock);
			khttpd_log_flush(log);
			mtx_lock(&log->lock);
		}
	}

	/* The following assumptions are valid while choking is true. */
	KASSERT(!log->busy, ("busy"));
	KASSERT(log->choking, ("!choking"));
	KASSERT(log->type == khttpd_log_type_null ||
	    mbufq_len(&log->queue) == 0, ("non-empty queue"));

	mtx_unlock(&log->lock);
}

static void
khttpd_log_dechoke(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);

	mtx_lock(&log->lock);
	KASSERT(log->choking, ("!choking"));

	if (0 < mbufq_len(&log->queue) && log->type != khttpd_log_type_null) {
		log->busy = true;
		callout_stop(&log->flush_callout);
		mtx_unlock(&log->lock);
		khttpd_job_schedule(log->job, 0);
		mtx_lock(&log->lock);
	}

	log->choking = false;
	if (log->waiting) {
		log->waiting = false;
		wakeup(log);
	}

	mtx_unlock(&log->lock);
}

static void
khttpd_log_close(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);

	switch (log->type) {
	case khttpd_log_type_file:
		vn_close(log->file.vp, FWRITE | O_APPEND | O_CREAT,
		    curthread->td_ucred, false);
		break;

	case khttpd_log_type_fluentd:
		soclose(log->fluentd.so);
		khttpd_free(log->fluentd.tag);
		break;
	}

	log->type = khttpd_log_type_null;
}

void
khttpd_log_set_null(int chan)
{
	struct khttpd_log *log;
	struct thread *td;

	KHTTPD_ENTRY("%s(%d)", __func__, chan);
	KASSERT(0 <= chan && chan < khttpd_log_chan_count, ("chan %d", chan));

	td = curthread;
	log = &khttpd_log_states[chan];

	khttpd_log_choke(log);
	khttpd_log_close(log);
	khttpd_log_dechoke(log);
}

int
khttpd_log_set_file(int chan, const char *path, int mode)
{
	struct nameidata nd;
	struct khttpd_log *log;
	struct thread *td;
	int flags;
	int error;

	KHTTPD_ENTRY("%s(%d,\"%s\",%#o)",
	    __func__, chan, khttpd_ktr_printf("%s", path), mode);
	KASSERT(0 <= chan && chan < khttpd_log_chan_count, ("chan %d", chan));

	td = curthread;
	NDINIT(&nd, CREATE, FOLLOW, UIO_SYSSPACE, path, td);
	flags = FWRITE | O_APPEND | O_CREAT;
	error = vn_open(&nd, &flags, mode, NULL);
	if (error != 0) {
		return (error);
	}
	NDFREE(&nd, NDF_ONLY_PNBUF);

	log = &khttpd_log_states[chan];

	khttpd_log_choke(log);
	khttpd_log_close(log);

	log->type = khttpd_log_type_file;
	log->file.vp = nd.ni_vp;
	VOP_UNLOCK(nd.ni_vp, 0);

	khttpd_log_dechoke(log);

	return (error);
}

int
khttpd_log_set_fluentd(int chan, struct sockaddr *addr, const char *tag)
{
	struct sockopt sockopt;
	struct khttpd_log *subject;
	struct socket *so;
	struct thread *td;
	int soptval;
	int error;

	KHTTPD_ENTRY("%s(%d,\"%s\")", __func__, chan,
	    khttpd_ktr_printf("%s", tag));
	KASSERT(0 <= chan && chan < khttpd_log_chan_count, ("chan %d", chan));

	td = curthread;
	subject = &khttpd_log_states[chan];

	error = socreate(addr->sa_family, &so, SOCK_STREAM, 0,
	    td->td_ucred, td);
	if (error != 0) {
		return (error);
	}

	soptval = 1;
	sockopt.sopt_dir = SOPT_SET;
	sockopt.sopt_level = SOL_SOCKET;
	sockopt.sopt_name = SO_NOSIGPIPE;
	sockopt.sopt_val = &soptval;
	sockopt.sopt_valsize = sizeof(soptval);
	sockopt.sopt_td = NULL;
	error = sosetopt(so, &sockopt);
	if (error != 0) {
		log(LOG_ERR, "setsockopt(SO_NOSIGPIPE) failed: %d", error);
		soclose(so);
		return (error);
	}

	if (addr->sa_family == PF_INET || addr->sa_family == PF_INET6) {
		soptval = 1;
		sockopt.sopt_level = IPPROTO_TCP;
		sockopt.sopt_name = TCP_NODELAY;
		error = sosetopt(so, &sockopt);
		if (error != 0) {
			log(LOG_ERR, "setsockopt(TCP_NODELAY) failed: %d",
			    error);
			soclose(so);
			return (error);
		}
	}

	error = soconnect(so, addr, td);
	if (error != 0) {
		log(LOG_WARNING, "connect() failed: %d", error);
		soclose(so);
		return (error);
	}

	khttpd_log_choke(subject);
	khttpd_log_close(subject);

	subject->type = khttpd_log_type_fluentd;
	subject->fluentd.so = so;
	subject->fluentd.tag = khttpd_strdup(tag);

	khttpd_log_dechoke(subject);

	return (0);
}

static void
khttpd_log_timeout(void *arg)
{
	struct khttpd_log *log;
	boolean_t need_scheduling;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	log = arg;
	mtx_assert(&log->lock, MA_OWNED);

	need_scheduling = !log->busy && 0 < mbufq_len(&log->queue);
	if (need_scheduling) {
		log->busy = true;
	}

	mtx_unlock(&log->lock);

	if (need_scheduling) {
		khttpd_job_schedule(log->job, KHTTPD_JOB_FLAGS_NOWAIT);
	}
}

void
khttpd_log_put(int chan, struct mbuf *m)
{
	struct khttpd_log *log;
	boolean_t need_scheduling;

	KHTTPD_ENTRY("%s(%d,%p)", __func__, chan, m);
	KASSERT(0 <= chan && chan < khttpd_log_chan_count,
	    ("invalid chan %d", chan));

	log = &khttpd_log_states[chan];
	mtx_lock(&log->lock);

	while (log->choking) {
		log->waiting = true;
		mtx_sleep(log, &log->lock, 0, "logput", 0);
	}

	mbufq_enqueue(&log->queue, m);

	need_scheduling = !log->busy && log->unbuffered &&
	    log->type != khttpd_log_type_null;

	if (need_scheduling) {
		log->busy = true;
		callout_stop(&log->flush_callout);

	} else if (log->type != khttpd_log_type_null) {
		callout_reset_sbt(&log->flush_callout, log->timeout,
		    SBT_1S, khttpd_log_timeout, log, 0);

	}

	mtx_unlock(&log->lock);

	if (need_scheduling) {
		khttpd_job_schedule(log->job, 0);
	}
}

static int
khttpd_log_mod_init(void)
{
	struct khttpd_log *subject;
	int i;

	KHTTPD_ENTRY("%s()", __func__);

	for (i = 0; i < nitems(khttpd_log_states); ++i) {
		subject = &khttpd_log_states[i];
		bzero(subject, sizeof(*subject));
		mtx_init(&subject->lock, "log", NULL, MTX_DEF | MTX_NEW);
		mbufq_init(&subject->queue, INT_MAX);
		callout_init_mtx(&subject->flush_callout, &subject->lock,
		    CALLOUT_RETURNUNLOCKED);
		subject->job = khttpd_job_new(khttpd_log_flush, subject, NULL);
		subject->timeout = SBT_1S;
	}

	khttpd_log_states[khttpd_log_chan_error].unbuffered = true;

	return (0);
}

static void
khttpd_log_mod_fini(void)
{
	struct khttpd_log *subject;
	struct mbuf *m, *pkt;
	int i;

	KHTTPD_ENTRY("%s()", __func__);

	for (i = 0; i < nitems(khttpd_log_states); ++i) {
		subject = &khttpd_log_states[i];
		khttpd_log_choke(subject);
		khttpd_log_close(subject);
		khttpd_job_delete(subject->job);
		callout_drain(&subject->flush_callout);
		mtx_destroy(&subject->lock);
		for (pkt = mbufq_flush(&subject->queue); pkt != NULL; ) {
			m = pkt;
			pkt = STAILQ_NEXT(pkt, m_stailqpkt);
			m_freem(m);
		}
	}
}

KHTTPD_INIT(khttpd_log, khttpd_log_mod_init, khttpd_log_mod_fini,
    KHTTPD_INIT_PHASE_REGISTER_EVENTS);
