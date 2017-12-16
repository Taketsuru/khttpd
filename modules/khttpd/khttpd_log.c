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

#include "khttpd_log.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>

#include "khttpd_job.h"
#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"

#ifndef KHTTPD_LOG_LIMIT
#define KHTTPD_LOG_LIMIT	512
#endif

struct khttpd_log {
	struct mtx	lock;
	struct mbufq	queue;
	struct callout	flush_callout;
	sbintime_t	silence_till;
	struct khttpd_job *job;
	char		*name;
	int		fd;
	unsigned	choking:1;
	unsigned	busy:1;
	unsigned	waiting:1;
	unsigned	silence:1;
};

static sbintime_t khttpd_log_silence_time = 10 * SBT_1S;
static sbintime_t khttpd_log_flush_time = SBT_1S;

static void khttpd_log_handle_job(void *arg);

static void
khttpd_log_choke(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	mtx_lock(&log->lock);

	while (log->choking) {
		log->waiting = TRUE;
		mtx_sleep(log, &log->lock, 0, "choke", 0);
	}
	log->choking = TRUE;
	
	while (0 < mbufq_len(&log->queue) || log->busy)
		if (log->busy) {
			log->waiting = TRUE;
			mtx_sleep(log, &log->lock, 0, "drain", 0);
		} else {
			log->busy = TRUE;
			mtx_unlock(&log->lock);
			khttpd_job_schedule(log->job, 0);
			mtx_lock(&log->lock);
		}

	mtx_unlock(&log->lock);
}

static void
khttpd_log_dechoke(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);
	mtx_lock(&log->lock);

	KASSERT(log->choking, ("log(%p)->choking is FALSE", log));
	log->choking = FALSE;
	if (log->waiting) {
		log->waiting = FALSE;
		wakeup(log);
	}

	mtx_unlock(&log->lock);
}

struct khttpd_log *
khttpd_log_new(void)
{
	struct khttpd_log *log;

	KHTTPD_ENTRY("%s()", __func__);
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	log = khttpd_malloc(sizeof(*log));

	mtx_init(&log->lock, "log", NULL, MTX_DEF | MTX_NEW);
	mbufq_init(&log->queue, INT_MAX);
	callout_init_mtx(&log->flush_callout, &log->lock,
	    CALLOUT_RETURNUNLOCKED);
	log->job = khttpd_job_new(khttpd_log_handle_job, log, NULL);
	log->name = NULL;
	log->fd = -1;
	log->choking = log->busy = FALSE;

	return (log);
}

void
khttpd_log_delete(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	if (log == NULL)
		return;

	khttpd_log_close(log);

	/*
	 * Once khttpd_log_close() is called, queue is kept empty.  Because the
	 * queue is empty, the flush job is no longer be busy.  So we can
	 * safely delete the job.
	 */
	KASSERT(mbufq_len(&log->queue) == 0,
	    ("log(%p)->queue is not empty", log));
	KASSERT(!log->busy, ("log(%p)->busy is TRUE", log));
	khttpd_job_delete(log->job);

	/*
	 * The callout must be drained before the destruction of the associated
	 * lock.
	 */
	callout_drain(&log->flush_callout);

	mtx_destroy(&log->lock);

	khttpd_free(log->name);
	khttpd_free(log);
}

/*
 * The ownership of the file descriptor moves to 'log'.
 */

void
khttpd_log_set_fd(struct khttpd_log *log, int fd)
{
	int old_fd;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, log, fd);

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	khttpd_log_choke(log);

	old_fd = log->fd;
	log->fd = fd;

	khttpd_log_dechoke(log);

	if (old_fd != -1)
		kern_close(curthread, old_fd);
}

/*
 * This function sleeps until all the log entries enqueued into 'log' are
 * kern_writev()-ed and released.
 */

void
khttpd_log_close(struct khttpd_log *log)
{

	KHTTPD_ENTRY("%s(%p)", __func__, log);
	khttpd_log_set_fd(log, -1);
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
	if (need_scheduling)
		log->busy = TRUE;
	mtx_unlock(&log->lock);

	if (need_scheduling)
		khttpd_job_schedule(log->job, KHTTPD_JOB_FLAGS_NOWAIT);
}

void
khttpd_log_put(struct khttpd_log *log, struct mbuf *m)
{
	boolean_t need_scheduling;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, log, m);
	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	khttpd_mbuf_append_ch(m, '\n');

	mtx_lock(&log->lock);

	while (log->choking) {
		log->waiting = TRUE;
		mtx_sleep(log, &log->lock, 0, "logput", 0);
	}

	if (log->fd == -1) {
		mtx_unlock(&log->lock);
		m_freem(m);
		return;
	}

	mbufq_enqueue(&log->queue, m);

	need_scheduling = !log->busy && 
	    KHTTPD_LOG_LIMIT <= mbufq_len(&log->queue);
	if (need_scheduling) {
		log->busy = TRUE;
		callout_stop(&log->flush_callout);
	} else
		callout_reset_sbt(&log->flush_callout, khttpd_log_flush_time,
		    SBT_1S, khttpd_log_timeout, log, 0);

	mtx_unlock(&log->lock);

	if (need_scheduling)
		khttpd_job_schedule(log->job, 0);
}

void
khttpd_log_set_name(struct khttpd_log *log, const char *name)
{
	char *old_name, *new_name;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, log, khttpd_ktr_printf("%s", name));

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);
	new_name = khttpd_strdup(name);

	mtx_lock(&log->lock);
	old_name = log->name;
	log->name = new_name;
	mtx_unlock(&log->lock);

	khttpd_free(old_name);
}

const char *
khttpd_log_get_name(struct khttpd_log *log)
{

	return (log->name);
}

static void
khttpd_log_handle_job(void *arg)
{
	char namebuf[64];
	struct iovec iovs[64];
	struct uio auio;
	struct bintime bt;
	struct thread *td;
	struct khttpd_log *subject;
	struct mbuf *pkt, *m;
	sbintime_t current;
	ssize_t resid;
	int error, fd, i, niov;
	boolean_t warn;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	td = curthread;
	niov = nitems(iovs);
	subject = arg;

	mtx_lock(&subject->lock);

	KASSERT(subject->busy, ("log %p is not busy", log));

	/* khttpd_log::fd doesn't change while the log is busy */
	fd = subject->fd;

	while ((pkt = mbufq_flush(&subject->queue)) != NULL) {
		mtx_unlock(&subject->lock);

		error = 0;
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
				error = kern_writev(td, fd, &auio);
			}

			m = pkt;
			pkt = STAILQ_NEXT(pkt, m_stailqpkt);
			m_freem(m);
		}

		if (error != 0) {
			bintime(&bt);
			current = bttosbt(bt);
		}

		mtx_lock(&subject->lock);
	}

	subject->busy = FALSE;
	if (subject->waiting) {
		subject->waiting = FALSE;
		wakeup(subject);
	}

	warn = FALSE;
	if (error == 0)
		subject->silence = FALSE;

	else if (!subject->silence || subject->silence_till <= current) {
		warn = subject->silence = TRUE;
		subject->silence_till = current + khttpd_log_silence_time;
		strlcpy(namebuf, subject->name == NULL ? "<anon>" :
		    subject->name, sizeof(namebuf));
	}

	mtx_unlock(&subject->lock);

	if (error == 0)
		kern_fsync(td, fd, FALSE);

	if (warn)
		log(LOG_WARNING, "khttpd: error on log \"%s\" (error: %d)",
		    namebuf, error);
}
