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

#include "khttpd_ktr.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/syslog.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>

#include <machine/stdarg.h>

#include "khttpd_init.h"

#ifndef KHTTPD_KTR_FILE
#define KHTTPD_KTR_FILE "/tmp/ktr.txt"
#endif

#ifndef KHTTPD_KTR_BUF_LEN
#define KHTTPD_KTR_BUF_LEN	(2ul * 1024 * 1024 / MLEN)
#endif

#ifdef KHTTPD_KTR_LOGGING

#ifndef KTR
#error KTR option is disabled
#endif

static struct mtx khttpd_ktr_mtx;
static struct mbuf *khttpd_ktr_usedq_head;
static struct mbuf *khttpd_ktr_usedq_tail;
static struct mbuf *khttpd_ktr_freeq;
static struct thread *khttpd_ktr_thread;
static int khttpd_ktr_idx;
static boolean_t khttpd_ktr_shutdown;

MTX_SYSINIT(khttpd_ktr_lock, &khttpd_ktr_mtx, "ktr", MTX_DEF);

void
khttpd_ktr_lock(void)
{

	mtx_lock(&khttpd_ktr_mtx);
}

void
khttpd_ktr_unlock(void)
{

	mtx_unlock(&khttpd_ktr_mtx);
}

const char *
khttpd_ktr_vprintf(const char *fmt, __va_list ap)
{
	struct mbuf *newent;

	mtx_assert(&khttpd_ktr_mtx, MA_LOCKED);

	newent = khttpd_ktr_freeq;
	if (newent == NULL)
		return ("<empty>");
	khttpd_ktr_freeq = newent->m_next;

	newent->m_len = vsnprintf(mtod(newent, char *), 
	    M_TRAILINGSPACE(newent), fmt, ap);
	newent->m_next = NULL;

	if (khttpd_ktr_usedq_head == NULL)
		khttpd_ktr_usedq_head = newent;
	else
		khttpd_ktr_usedq_tail->m_next = newent;
	khttpd_ktr_usedq_tail = newent;

	return (mtod(newent, char *));
}

const char *
khttpd_ktr_printf(const char *fmt, ...)
{
	const char *result;
	va_list ap;

	va_start(ap, fmt);
	result = khttpd_ktr_vprintf(fmt, ap);
	va_end(ap);

	return (result);
}

static void
khttpd_ktr_flush(struct sbuf *sbuf)
{
	struct uio auio;
	struct iovec aiov;
	struct ktr_entry *ep;
	struct thread *td;
	struct mbuf *head, *tail;
	int error, fd, i, n, end;

	td = curthread;

	error = kern_openat(td, AT_FDCWD, KHTTPD_KTR_FILE, UIO_SYSSPACE,
	    O_WRONLY | O_APPEND, 0644);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: "
		    "open(\"" KHTTPD_KTR_FILE "\") failed (error: %d)", error);
		return;
	}
	fd = td->td_retval[0];

	khttpd_ktr_lock();
	end = ktr_idx;
	head = khttpd_ktr_usedq_head;
	tail = khttpd_ktr_usedq_tail;
	khttpd_ktr_usedq_head = khttpd_ktr_usedq_tail = NULL;
	khttpd_ktr_unlock();

	n = ktr_entries;
	for (i = khttpd_ktr_idx; i != end; i = i == n - 1 ? 0 : i + 1) {
		ep = &ktr_buf[i];

		sbuf_printf(sbuf, "%lld %d %d ", (long long)ep->ktr_timestamp,
		    ep->ktr_thread->td_tid, ep->ktr_cpu);
		sbuf_printf(sbuf, ep->ktr_desc, ep->ktr_parms[0], 
		    ep->ktr_parms[1], ep->ktr_parms[2], ep->ktr_parms[3],
		    ep->ktr_parms[4], ep->ktr_parms[5]);
		sbuf_cat(sbuf, "\n");
	}

	sbuf_finish(sbuf);

	khttpd_ktr_lock();
	if (tail != NULL) {
		tail->m_next = khttpd_ktr_freeq;
		khttpd_ktr_freeq = head;
	}
	khttpd_ktr_unlock();

	khttpd_ktr_idx = i;

	aiov.iov_base = sbuf_data(sbuf);
	aiov.iov_len = sbuf_len(sbuf);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = aiov.iov_len;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_writev(td, fd, &auio);
	if (error != 0)
		log(LOG_WARNING, "khttpd: "
		    "write(\"" KHTTPD_KTR_FILE "\") failed (error: %d)",
		    error);

	sbuf_clear(sbuf);
	kern_close(td, fd);
}

static void
khttpd_ktr_main(void *arg)
{
	struct sbuf sbuf;
	struct thread *td;
	int error;

	td = curthread;

	khttpd_ktr_idx = ktr_idx;

	error = kern_openat(td, AT_FDCWD, KHTTPD_KTR_FILE, UIO_SYSSPACE,
	    O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: "
		    "open(\"" KHTTPD_KTR_FILE "\") failed (error: %d)", error);
		goto quit;
	}
	kern_close(td, td->td_retval[0]);

	sbuf_new(&sbuf, NULL, 1024 * 1024, SBUF_AUTOEXTEND);

	while (!khttpd_ktr_shutdown) {
		khttpd_ktr_flush(&sbuf);
		pause("khttpd-ktr", hz);
	}

	sbuf_delete(&sbuf);

quit:
	khttpd_ktr_thread = NULL;
	kthread_exit();
}

static int
khttpd_ktr_start(void)
{
	struct mbuf *m, *last;
	int error, i;

	last = NULL;
	for (i = 0; i < KHTTPD_KTR_BUF_LEN; ++i) {
		m = m_get(M_WAITOK, MT_DATA);
		m->m_next = last;
		last = m;
	}

	khttpd_ktr_lock();
	khttpd_ktr_freeq = last;
	khttpd_ktr_unlock();

	khttpd_ktr_shutdown = FALSE;

	error = kthread_add(khttpd_ktr_main, NULL, curproc, &khttpd_ktr_thread,
	    0, 0, "ktr");
	if (error != 0) {
		log(LOG_WARNING, "khttpd: "
		    "failed to fork ktr (error: %d)", error);
		return (error);
	}

	return (0);
}

static void
khttpd_ktr_stop(void)
{
	struct mbuf *m1, *m2;
	struct sbuf *sbuf;

	khttpd_ktr_shutdown = TRUE;
	while (khttpd_ktr_thread != NULL)
		pause("ktrstop", hz);

	sbuf = sbuf_new_auto();
	khttpd_ktr_flush(sbuf);
	sbuf_delete(sbuf);

	khttpd_ktr_lock();
	m1 = khttpd_ktr_usedq_head;
	m2 = khttpd_ktr_freeq;
	khttpd_ktr_usedq_head = khttpd_ktr_usedq_tail = 
	    khttpd_ktr_freeq = NULL;
	khttpd_ktr_unlock();

	m_freem(m1);
	m_freem(m2);
}

KHTTPD_INIT(, khttpd_ktr_start, khttpd_ktr_stop, KHTTPD_INIT_PHASE_LOCAL - 1);

#endif	/* ifdef KHTTPD_KTR_LOGGING */
