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

#include "khttpd_ktr.h"

#ifdef KHTTPD_KTR_LOGGING

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

#ifndef KHTTPD_KTR_STRING_SIZE
#define KHTTPD_KTR_STRING_SIZE	256
#endif

#ifndef KHTTPD_KTR_STRING_BUF_COUNT
#define KHTTPD_KTR_STRING_BUF_COUNT	8192
#endif

#ifndef KTR
#error KTR option is disabled
#endif

static char khttpd_ktr_strbuf
    [KHTTPD_KTR_STRING_BUF_COUNT][KHTTPD_KTR_STRING_SIZE];
static struct mtx khttpd_ktr_mtx;
static struct sbuf khttpd_ktr_sbuf;
static struct thread *khttpd_ktr_thread;
static uint64_t khttpd_ktr_load_ts;
static int khttpd_ktr_head;
static int khttpd_ktr_tail;
static int khttpd_ktr_idx;
static int khttpd_ktr_fd;
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

char *
khttpd_ktr_newbuf(int *bufsize)
{
	int i, ni;

	mtx_assert(&khttpd_ktr_mtx, MA_OWNED);

	if (bufsize != NULL)
		*bufsize = KHTTPD_KTR_STRING_SIZE;

	i = khttpd_ktr_head;
	ni = i == KHTTPD_KTR_STRING_BUF_COUNT - 1 ? 0 : i + 1;
	if (ni == khttpd_ktr_head)
		return (NULL);
	khttpd_ktr_head = ni;

	return (khttpd_ktr_strbuf[i]);
}

const char *
khttpd_ktr_vprintf(const char *fmt, __va_list ap)
{
	char *buf;

	mtx_assert(&khttpd_ktr_mtx, MA_OWNED);

	buf = khttpd_ktr_newbuf(NULL);
	if (buf == NULL)
		return ("<buffer full>");

	vsnprintf(buf, KHTTPD_KTR_STRING_SIZE, fmt, ap);

	return (buf);
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

static int
khttpd_ktr_flush(void)
{
	struct uio auio;
	struct iovec aiov;
	uint64_t load_ts;
	struct ktr_entry *ep;
	struct thread *td;
	int error, i, n, end, last;

	td = curthread;

	khttpd_ktr_lock();
	end = ktr_idx;
	last = khttpd_ktr_head;
	khttpd_ktr_unlock();

	n = end < khttpd_ktr_idx ? end + ktr_entries - khttpd_ktr_idx :
	    end - khttpd_ktr_idx;
	if (0 < n) {
		sbuf_printf(&khttpd_ktr_sbuf,
		    "# index: %d, end: %d, entries: %d\n",
		    khttpd_ktr_idx, end, n);
	}

	load_ts = khttpd_ktr_load_ts;
	n = ktr_entries;
	for (i = khttpd_ktr_idx; i != end; i = i == n - 1 ? 0 : i + 1) {
		ep = &ktr_buf[i];
		if (ep->ktr_desc == NULL || ep->ktr_timestamp <= load_ts) {
			continue;
		}

		sbuf_printf(&khttpd_ktr_sbuf, "%lld %d %d ",
		    (long long)ep->ktr_timestamp,
		    ep->ktr_thread == NULL ? 0 : ep->ktr_thread->td_tid,
		    ep->ktr_cpu);
		sbuf_printf(&khttpd_ktr_sbuf, ep->ktr_desc, ep->ktr_parms[0], 
		    ep->ktr_parms[1], ep->ktr_parms[2], ep->ktr_parms[3],
		    ep->ktr_parms[4], ep->ktr_parms[5]);
		sbuf_cat(&khttpd_ktr_sbuf, "\n");
	}

	sbuf_finish(&khttpd_ktr_sbuf);

	khttpd_ktr_lock();
	khttpd_ktr_tail = last;
	khttpd_ktr_unlock();

	khttpd_ktr_idx = i;

	aiov.iov_base = sbuf_data(&khttpd_ktr_sbuf);
	aiov.iov_len = sbuf_len(&khttpd_ktr_sbuf);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = aiov.iov_len;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_writev(td, khttpd_ktr_fd, &auio);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: write(\"" KHTTPD_KTR_FILE
		    "\") failed (error: %d)", error);
	}

	error = kern_fsync(td, khttpd_ktr_fd, FALSE);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: fdatasync(\"" KHTTPD_KTR_FILE
		    "\") failed (error: %d)", error);
	}

	sbuf_clear(&khttpd_ktr_sbuf);

	return (error);
}

static bool
khttpd_ktr_expired(struct bintime *last_flush)
{
	struct bintime exp_time;
	struct bintime cur_time;

	bintime(&cur_time);
	exp_time = *last_flush;
	exp_time.sec += 1;
	return (bintime_cmp(&cur_time, &exp_time, <=));
}

static void
khttpd_ktr_main(void *arg)
{
	int end, n;
	struct bintime last_flush;

	bintime(&last_flush);
	while (!khttpd_ktr_shutdown) {
		end = ktr_idx;
		n = end < khttpd_ktr_idx ? end + ktr_entries - khttpd_ktr_idx :
		    end - khttpd_ktr_idx;
		if (0 == n || (n < (ktr_entries >> 1) &&
		    !khttpd_ktr_expired(&last_flush))) {
			pause("ktrflush", 1);
		} else if (khttpd_ktr_flush() == 0) {
			bintime(&last_flush);
		} else {
			break;
		}
	}

	khttpd_ktr_flush();

	khttpd_ktr_thread = NULL;
	kthread_exit();
}

static int
khttpd_ktr_local_init(void)
{
	struct thread *td;
	int error;

	td = curthread;

	sbuf_new(&khttpd_ktr_sbuf, NULL, 1024ul * 1024, SBUF_AUTOEXTEND);

	error = kern_openat(td, AT_FDCWD, KHTTPD_KTR_FILE, UIO_SYSSPACE,
	    O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: open(\"" KHTTPD_KTR_FILE
		    "\") failed (error: %d)", error);
		goto error;
	}
	khttpd_ktr_fd = td->td_retval[0];

	khttpd_ktr_load_ts = get_cyclecount();
	khttpd_ktr_idx = ktr_idx;
	khttpd_ktr_head = khttpd_ktr_tail = 0;

	khttpd_ktr_shutdown = FALSE;
	error = kthread_add(khttpd_ktr_main, NULL, curproc, &khttpd_ktr_thread,
	    0, 0, "ktr");
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to fork ktr (error: %d)",
		    error);
		goto error;
	}

	return (0);

error:
	sbuf_delete(&khttpd_ktr_sbuf);
	kern_close(td, khttpd_ktr_fd);
	khttpd_ktr_fd = -1;

	return (error);
}

static void
khttpd_ktr_local_fini(void)
{

	khttpd_ktr_shutdown = TRUE;
	while (khttpd_ktr_thread != NULL)
		pause("ktrstop", hz);

	sbuf_delete(&khttpd_ktr_sbuf);
	kern_close(curthread, khttpd_ktr_fd);
	khttpd_ktr_fd = -1;
}

KHTTPD_INIT(khttpd_ktr, khttpd_ktr_local_init, khttpd_ktr_local_fini, 0);

#endif	/* ifdef KHTTPD_KTR_LOGGING */
