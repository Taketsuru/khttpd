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
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/ktr.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/fcntl.h>

#define SYSLOG_NAMES
#include <sys/syslog.h>

#include "khttpd.h"
#include "khttpd_private.h"

#ifndef KHTTPD_KTR_FILE
#define KHTTPD_KTR_FILE "/tmp/ktr.txt"
#endif

#ifdef KTR

static struct thread *khttpd_ktr_logging_thread;
static boolean_t khttpd_ktr_logging_shutdown;
static int khttpd_ktr_logging_idx;

static void
khttpd_ktr_logging(struct sbuf *sbuf)
{
	struct uio auio;
	struct iovec aiov;
	struct ktr_entry *ep;
	struct thread *td;
	int error, fd, i, n;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	td = curthread;

	error = kern_openat(td, AT_FDCWD, KHTTPD_KTR_FILE,
	    UIO_SYSSPACE, O_WRONLY | O_APPEND, 0666);
	if (error != 0) {
		log(LOG_WARNING,
		    "khttpd: failed to open ktr file '%s' (error %d)",
		    KHTTPD_KTR_FILE, error);
		return;
	}
	fd = td->td_retval[0];

	sbuf_clear(sbuf);

	n = ktr_entries;
	for (i = khttpd_ktr_logging_idx; i != ktr_idx;
	     i = i == n - 1 ? 0 : i + 1) {
		ep = &ktr_buf[i];

		sbuf_printf(sbuf, "%lld %p %d ",
		    (long long)ep->ktr_timestamp, ep->ktr_thread,
		    ep->ktr_cpu);
		sbuf_printf(sbuf, ep->ktr_desc, ep->ktr_parms[0],
		    ep->ktr_parms[1], ep->ktr_parms[2],
		    ep->ktr_parms[3], ep->ktr_parms[4],
		    ep->ktr_parms[5]);
		sbuf_cat(sbuf, "\n");
	}

	sbuf_finish(sbuf);

	khttpd_ktr_logging_idx = i;

	aiov.iov_base = sbuf_data(sbuf);
	aiov.iov_len = sbuf_len(sbuf);
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = aiov.iov_len;
	auio.uio_segflg = UIO_SYSSPACE;
	error = kern_writev(td, fd, &auio);
	if (error != 0)
		log(LOG_WARNING, "khttpd: KTR flush failed "
		    "(error: %d)", error);

	kern_close(td, fd);
}

static void
khttpd_ktr_logging_main(void *arg)
{
	struct sbuf *sbuf;
	struct thread *td;
	int error;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	td = curthread;

	khttpd_ktr_logging_idx = ktr_idx;

	error = kern_openat(td, AT_FDCWD, KHTTPD_KTR_FILE, UIO_SYSSPACE,
	    O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to open ktr file '%s' "
		    "(error %d)", KHTTPD_KTR_FILE, error);
		goto quit;
	}
	kern_close(td, td->td_retval[0]);

	sbuf = sbuf_new_auto();

	while (!khttpd_ktr_logging_shutdown) {
		khttpd_ktr_logging(sbuf);
		pause("khttpd-ktr-flush", hz);
	}

	sbuf_delete(sbuf);

quit:
	khttpd_ktr_logging_thread = NULL;
	kthread_exit();
}

int
khttpd_ktr_logging_init(void)
{
	int error;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	khttpd_ktr_logging_shutdown = FALSE;

	error = kthread_add(khttpd_ktr_logging_main, NULL, curproc,
	    &khttpd_ktr_logging_thread, 0, 0, "khttpd-ktr-flush");
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to fork khttpd-ktr-flush: %d",
		    error);
		return (error);
	}

	return (0);
}

void
khttpd_ktr_logging_fini(void)
{
	struct sbuf *sbuf;

	KHTTPD_ASSERT_CURPROC_IS_KHTTPD();

	khttpd_ktr_logging_shutdown = TRUE;
	while (khttpd_ktr_logging_thread != NULL)
		pause("khttpd-ktr-flush-fini", hz);

	sbuf = sbuf_new_auto();
	khttpd_ktr_logging(sbuf);
	sbuf_delete(sbuf);
}

#endif	/* ifdef KTR */
