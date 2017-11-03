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
#include <sys/ctype.h>
#include <sys/refcount.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
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
#define KHTTPD_LOG_LIMIT	1024
#endif

struct khttpd_log {
	struct mtx	lock;
	struct mbufq	queue;
	struct khttpd_job *job;
	u_long		put_count;
	u_long		done_count;
	int		fd;
	unsigned	choking:1;
	unsigned	busy:1;
};

static const char *khttpd_log_severities[] = {
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};

static void khttpd_log_handle_job(void *arg);

static void
khttpd_log_choke(struct khttpd_log *log)
{
	u_long put_count;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	mtx_lock(&log->lock);

	while (log->choking)
		mtx_sleep(log, &log->lock, 0, "choke", 0);

	log->choking = TRUE;
	put_count = log->put_count;

	while (log->done_count < put_count)
		mtx_sleep(log, &log->lock, 0, "drain", 0);

	mtx_unlock(&log->lock);
}

static void
khttpd_log_dechoke(struct khttpd_log *log)
{

	mtx_lock(&log->lock);

	KASSERT(log->choking, ("log(%p)->choking is FALSE"));
	log->choking = FALSE;
	wakeup(log);

	mtx_unlock(&log->lock);
}

static void
khttpd_log_init(struct khttpd_log *log)
{

	mtx_init(&log->lock, "log", NULL, MTX_DEF | MTX_NEW);
	mbufq_init(&log->queue, KHTTPD_LOG_LIMIT);
	log->job = khttpd_job_new(khttpd_log_handle_job, log, NULL);
	log->fd = -1;
	log->put_count = log->done_count = 0;
	log->choking = log->busy = FALSE;
}

static void
khttpd_log_fini(struct khttpd_log *log)
{

	khttpd_log_close(log);
	khttpd_job_delete(log->job);
	kern_close(curthread, log->fd);
	mtx_destroy(&log->lock);
}

struct khttpd_log *
khttpd_log_new(void)
{
	struct khttpd_log *log;

	log = khttpd_malloc(sizeof(*log));
	khttpd_log_init(log);
	return (log);
}

void
khttpd_log_delete(struct khttpd_log *log)
{

	if (log == NULL)
		return;

	khttpd_log_fini(log);
	khttpd_free(log);
}

/*
 * The ownership of the file descriptor moves to 'log'.
 */

void
khttpd_log_set_fd(struct khttpd_log *log, int fd)
{
	int old_fd;

	khttpd_log_choke(log);

	old_fd = log->fd;
	log->fd = fd;
	if (old_fd != -1)
		kern_close(curthread, old_fd);

	khttpd_log_dechoke(log);
}

/*
 * This function sleeps until all the log entries enqueued into 'log' are
 * kern_writev()-ed and released.
 */

void
khttpd_log_close(struct khttpd_log *log)
{

	khttpd_log_choke(log);

	if (log->fd != -1) {
		kern_close(curthread, log->fd);
		log->fd = -1;
	}

	khttpd_log_dechoke(log);
}

void
khttpd_log_put(struct khttpd_log *log, struct mbuf *m)
{
	boolean_t need_kick;

	WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL, "%s is called",
	    __func__);

	khttpd_mbuf_append_ch(m, '\n');

	mtx_lock(&log->lock);

	while (log->choking || mbufq_full(&log->queue))
		mtx_sleep(log, &log->lock, 0, "logput", 0);

	if (log->fd == -1) {
		mtx_unlock(&log->lock);
		m_freem(m);
		return;
	}

	++log->put_count;
	need_kick = mbufq_len(&log->queue) == 0 && !log->busy;
	if (need_kick)
		log->busy = TRUE;
	mbufq_enqueue(&log->queue, m);

	mtx_unlock(&log->lock);

	if (need_kick)
		khttpd_job_schedule(log->job);
}

static void
khttpd_log_handle_job(void *arg)
{
	struct iovec iovs[64];
	struct uio auio;
	struct thread *td;
	struct khttpd_log *l;
	struct mbuf *pkt, *m;
	ssize_t resid;
	u_long put_count;
	int error, fd, i, niov;

	td = curthread;
	niov = sizeof(iovs) / sizeof(iovs[0]);
	l = arg;

	mtx_lock(&l->lock);

	for (;;) {
		if (mbufq_full(&l->queue))
			wakeup(l);

		pkt = mbufq_flush(&l->queue);
		if (pkt == NULL)
			break;

		KASSERT(done_count < put_count,
		    ("log=%p, done_count=%d, put_count=%d", l, l->done_count,
			    l->put_count));

		put_count = l->put_count;
		mtx_unlock(&l->lock);

		fd = l->fd;
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
				if (error != 0)
					log(LOG_WARNING, "khttpd: log failed "
					    "(error: %d)", error);
			}

			m = pkt;
			pkt = STAILQ_NEXT(pkt, m_stailqpkt);
			m_freem(m);
		}

		if (error != 0) {
			l->fd = -1;
			kern_close(td, fd);
		}

		mtx_lock(&l->lock);

		l->done_count = put_count;
		if (l->choking)
			wakeup(l);
	}

	l->busy = FALSE;

	mtx_unlock(&l->lock);
}

const char *
khttpd_log_get_severity_label(int severity)
{

	KASSERT(LOG_EMERG <= severity && severity <= LOG_DEBUG,
	    ("unknown severity: %d", severity));

	return (khttpd_log_severities[severity]);
}

void
khttpd_log_put_timestamp_property(struct khttpd_mbuf_json *entry)
{
	struct timeval tv;

	microtime(&tv);
	khttpd_mbuf_json_property_format(entry, "timestamp",
		FALSE, "%ld.%06ld", tv.tv_sec, tv.tv_usec);
}

void
khttpd_log_put_severity_property(struct khttpd_mbuf_json *entry, int severity)
{

	khttpd_mbuf_json_property_cstr(entry, "severity", TRUE,
		khttpd_log_get_severity_label(severity));
}

void
khttpd_log_put_error_properties(struct khttpd_mbuf_json *entry, int severity,
    const char *description_fmt, ...)
{
	va_list args;

	va_start(args, description_fmt);
	khttpd_log_vput_error_properties(entry, severity, description_fmt,
	    args);
	va_end(args);
}

void
khttpd_log_vput_error_properties(struct khttpd_mbuf_json *entry, int severity,
    const char *description_fmt, va_list args)
{

	khttpd_log_put_timestamp_property(entry);
	khttpd_log_put_severity_property(entry, severity);
	khttpd_mbuf_json_property_format(entry, "description", TRUE,
	    description_fmt, args);
}
