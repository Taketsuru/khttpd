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
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "khttpd_test.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/ktr.h>
#include <sys/stack.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/syslog.h>
#include <machine/setjmp.h>

#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

struct khttpd_test_frame {
	SLIST_ENTRY(khttpd_test_frame) tf_link;
	struct _jmp_buf	*tf_jmp_buf;
};

SLIST_HEAD(khttpd_test_frame_list, khttpd_test_frame);

struct khttpd_test_thread {
	struct khttpd_test_frame_list tt_frames;
	struct khttpd_test_frame tt_bottom;
	struct khttpd_test_frame *tt_target;
	struct thread	*tt_thread;
};

struct khttpd_test_result {
	struct sbuf	tr_stdout;
	struct sbuf	tr_message;
	struct sbuf	tr_info;
	struct bintime	tr_time;
	struct bintime	tr_timestamp;
	struct khttpd_testcase *tr_testcase;
	int		tr_status;
};

struct khttpd_test_filter {
	STAILQ_ENTRY(khttpd_test_filter) list;
	char		*subject;
	char		*name;
	boolean_t	negative;
};

STAILQ_HEAD(khttpd_test_filter_list, khttpd_test_filter);

enum {
	KHTTPD_TEST_TOKEN_NULL,	      /* '\0' */
	KHTTPD_TEST_TOKEN_COMMA,	      /* ',' */
	KHTTPD_TEST_TOKEN_FULL_STOP,	      /* '.' */
	KHTTPD_TEST_TOKEN_EXCLAMATION_MARK, /* '!' */
	KHTTPD_TEST_TOKEN_ASTERISK,	      /* '*' */
	KHTTPD_TEST_TOKEN_STRING,
};

SET_DECLARE(khttpd_testcase_set, struct khttpd_testcase);

static struct sx khttpd_test_lock;
static struct khttpd_test_result *khttpd_test_results;
static struct khttpd_test_result *khttpd_test_current;
static struct khttpd_test_thread *khttpd_test_threads;
static char *khttpd_test_unget_token_str = NULL;
static size_t khttpd_test_results_count;
static u_int khttpd_test_thr_running;
static u_int khttpd_test_barrier_counter;
static u_int khttpd_test_barrier_generation;
static int khttpd_test_unget_token_code = KHTTPD_TEST_TOKEN_NULL;

SX_SYSINIT(khttpd_test_lock, &khttpd_test_lock, "khttpd-test");

static const char *khttpd_test_result_labels[] = {
	"unspec", "pass", "fail", "error", "skip"
};

#ifdef KTR
static uint64_t khttpd_test_ktr_stime;
static int khttpd_test_ktr_start;
#endif	/* ifdef KTR */

static int
khttpd_testcase_cmp(const void *vx, const void *vy)
{
	const struct khttpd_testcase *x, *y;
	int cmp;

	x = *(struct khttpd_testcase *const *)vx;
	y = *(struct khttpd_testcase *const *)vy;
	cmp = strcmp(x->tc_file, y->tc_file);
	return (cmp != 0 ? cmp :
	    (cmp = strcmp(x->tc_subject, y->tc_subject)) != 0 ? cmp :
	    x->tc_line < y->tc_line ? -1 :
	    x->tc_line > y->tc_line ? 1 : 0);
}

void
khttpd_test_vprintf(const char *fmt, va_list ap)
{

	sx_xlock(&khttpd_test_lock);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
	vprintf(fmt, ap);
	sbuf_vprintf(&khttpd_test_current->tr_stdout, fmt, ap);
#pragma clang diagnostic pop

	sx_xunlock(&khttpd_test_lock);
}

void
khttpd_test_printf(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	khttpd_test_vprintf(fmt, ap);
	va_end(ap);
}

static struct khttpd_test_thread *
khttpd_test_find_thread(struct thread *td)
{
	struct khttpd_test_thread *thr;
	int i, thr_count;

	thr_count = khttpd_test_current->tr_testcase->tc_thr_count;
	if (thr_count == 0)
		thr_count = 1;

	for (i = 0; i < thr_count; ++i) {
		thr = &khttpd_test_threads[i];
		if (thr->tt_thread == td)
			return (thr);
	}

	return (NULL);
}

static struct khttpd_test_thread *
khttpd_test_find_curthread(void)
{

	return (khttpd_test_find_thread(curthread));
}

int
khttpd_test_tid(void)
{

	return (khttpd_test_find_curthread() - khttpd_test_threads);
}

static void
khttpd_test_dump_ktr(void)
{
#ifdef KTR
	struct ktr_entry entry;
	struct khttpd_test_thread *tt;
	int start, end, i, n;

	n = ktr_entries;
	start = i = khttpd_test_ktr_start;
	end = ktr_idx;

	for (i = start; i != end; i = i == n - 1 ? 0 : i + 1) {
		entry = ktr_buf[i];
		if (entry.ktr_desc == NULL)
			break;

		tt = khttpd_test_find_thread(entry.ktr_thread);

		sbuf_printf(&khttpd_test_current->tr_info,
		    "%d %td %d %d %ld ", i,
		    tt == NULL ? -1 : tt - khttpd_test_threads,
		    entry.ktr_thread->td_tid, entry.ktr_cpu,
		    entry.ktr_timestamp);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
		sbuf_printf(&khttpd_test_current->tr_info, 
		    entry.ktr_desc, entry.ktr_parms[0],
		    entry.ktr_parms[1], entry.ktr_parms[2], entry.ktr_parms[3],
		    entry.ktr_parms[4], entry.ktr_parms[5]);
#pragma clang diagnostic pop

		sbuf_putc(&khttpd_test_current->tr_info, '\n');
	}
#endif	/* ifdef KTR */
}

struct khttpd_test_frame *
khttpd_test_current_frame(void)
{
	struct khttpd_test_thread *tt;

	tt = khttpd_test_find_curthread();
	return (SLIST_FIRST(&tt->tt_frames));
}

void
khttpd_test_push_frame(struct _jmp_buf *buf)
{
	struct khttpd_test_frame *frame;

	KHTTPD_ENTRY("%s()", __func__);

	frame = khttpd_malloc(sizeof(struct khttpd_test_frame));
	frame->tf_jmp_buf = buf;
	SLIST_INSERT_HEAD(&khttpd_test_find_curthread()->tt_frames, frame,
	    tf_link);
}

void
khttpd_test_pop_frame(void)
{
	struct khttpd_test_frame *frame;
	struct khttpd_test_thread *tt;

	KHTTPD_ENTRY("%s()", __func__);

	tt = khttpd_test_find_curthread();
	frame = SLIST_FIRST(&tt->tt_frames);

	SLIST_REMOVE_HEAD(&tt->tt_frames, tf_link);

	if (tt->tt_target == frame)
		tt->tt_target = NULL;

	khttpd_free(frame);
}

void
khttpd_test_continue_unwind(void)
{
	struct khttpd_test_thread *tt;

	KHTTPD_ENTRY("%s()", __func__);

	tt = khttpd_test_find_curthread();
	if (tt->tt_target != NULL)
		longjmp(SLIST_FIRST(&tt->tt_frames)->tf_jmp_buf, 1);
}

void 
khttpd_test_stop_unwind(void)
{
	struct khttpd_test_thread *tt;

	KHTTPD_ENTRY("%s()", __func__);
	tt = khttpd_test_find_curthread();
	tt->tt_target = NULL;
}

void
khttpd_test_break(struct khttpd_test_frame *target)
{
	struct khttpd_test_thread *tt;

	KHTTPD_ENTRY("%s(%p)", __func__, target);

	tt = khttpd_test_find_curthread();

	if (tt->tt_target != NULL) {
		target = &tt->tt_bottom;
		log(LOG_WARNING, "khttpd: khttpd_test_break is called while "
		    "unwinding is in progress");
	}

	tt->tt_target = target;

	longjmp(SLIST_FIRST(&tt->tt_frames)->tf_jmp_buf, 1);
}

static void
khttpd_test_set_status(int status)
{

	sx_assert(&khttpd_test_lock, SA_XLOCKED);

	KHTTPD_ENTRY("%s()", __func__);
	khttpd_test_current->tr_status = status;

	khttpd_test_barrier_counter = 0;
	++khttpd_test_barrier_generation;
	wakeup(&khttpd_test_barrier_generation);
}

void
khttpd_test_exit(int result, const char *fmt, ...)
{
	struct khttpd_test_thread *tt;
	struct khttpd_test_result *tr;
	struct stack st;
	va_list ap;
	boolean_t first;

	KHTTPD_ENTRY("%s %s", __func__, khttpd_test_result_labels[result]);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 8, 0);

	tr = khttpd_test_current;
	tt = khttpd_test_find_curthread();

	sx_xlock(&khttpd_test_lock);
	first = tr->tr_status == KHTTPD_TEST_RESULT_UNSPECIFIED;
	if (first)
		khttpd_test_set_status(result);
	sx_xunlock(&khttpd_test_lock);

	if (first) {
		printf("%s\n", khttpd_test_result_labels[result]);

		va_start(ap, fmt);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
		sbuf_vprintf(&tr->tr_message, fmt, ap);
#pragma clang diagnostic pop

		va_end(ap);
	}

	khttpd_test_break(&tt->tt_bottom);
}

static void
khttpd_test_fn(void *data)
{
	struct _jmp_buf jmp_buf;
	struct khttpd_testcase *tc;
	struct khttpd_test_thread *tt;
	boolean_t leader;

	tc = data;
	tt = khttpd_test_find_curthread();
	leader = tt == khttpd_test_threads;

	tt->tt_target = NULL;
	if (setjmp(&jmp_buf) == 0) {
		tt->tt_bottom.tf_jmp_buf = &jmp_buf;
		SLIST_INIT(&tt->tt_frames);
		SLIST_INSERT_HEAD(&tt->tt_frames, &tt->tt_bottom, tf_link);

		/*
		 * The following barrier is necessary to guarantee that
		 * tr_status is unspecified when kthread_add fails.
		 */
		KHTTPD_TEST_BARRIER();

		(tc->tc_fn)();
	}

	if (SLIST_FIRST(&tt->tt_frames) != &tt->tt_bottom &&
	    khttpd_test_current->tr_status == KHTTPD_TEST_RESULT_UNSPECIFIED) {
		sx_xlock(&khttpd_test_lock);
		khttpd_test_set_status(KHTTPD_TEST_RESULT_ERROR);
		sx_xunlock(&khttpd_test_lock);

		printf("%s\n", khttpd_test_result_labels
		    [KHTTPD_TEST_RESULT_ERROR]);

		sbuf_printf(&khttpd_test_current->tr_message,
		    "unwind protect begin/end is not paired");
	}

	if (leader)
		return;

	sx_xlock(&khttpd_test_lock);
	if (--khttpd_test_thr_running == 1)
		wakeup(&khttpd_test_thr_running);
	sx_xunlock(&khttpd_test_lock);

	kthread_exit();
}

static void
khttpd_testcase_run(struct khttpd_test_result *tr, struct khttpd_testcase *tc)
{
	struct proc *p;
	int error, i, nthr;
	boolean_t not_set;

	printf("%s.%s...", tc->tc_subject, tc->tc_name);

	p = curproc;
	nthr = tc->tc_thr_count;
	if (nthr == 0)
		nthr = 1;

	khttpd_test_current = tr;

	khttpd_test_threads = khttpd_malloc(nthr *
	    sizeof(struct khttpd_test_thread));

	bzero(khttpd_test_threads, nthr *
	    sizeof(struct khttpd_test_thread));
	for (i = 0; i < nthr; ++i)
		SLIST_INIT(&khttpd_test_threads[i].tt_frames);

	khttpd_test_threads[0].tt_thread = curthread;

#ifdef KTR
	khttpd_test_ktr_stime = get_cyclecount();
	khttpd_test_ktr_start = ktr_idx;
#endif	/* ifdef KTR */

	bintime(&tr->tr_timestamp);

	error = 0;
	for (i = 1; i < nthr; ++i) {
		sx_xlock(&khttpd_test_lock);
		++khttpd_test_thr_running;
		sx_xunlock(&khttpd_test_lock);

		error = kthread_add(khttpd_test_fn, tc, p,
		    &khttpd_test_threads[i].tt_thread, 0, 0, "test%d", i);
		if (error != 0) {
			sx_xlock(&khttpd_test_lock);
			if (--khttpd_test_thr_running == 1)
				wakeup(&khttpd_test_thr_running);
			sx_xunlock(&khttpd_test_lock);
			break;
		}
	}

	if (error == 0) {
		khttpd_test_fn(tc);

	} else {
		sx_xlock(&khttpd_test_lock);
		khttpd_test_set_status(KHTTPD_TEST_RESULT_ERROR);
		sx_xunlock(&khttpd_test_lock);

		printf("%s\n", khttpd_test_result_labels
		    [KHTTPD_TEST_RESULT_ERROR]);

		sbuf_printf(&tr->tr_message,
		    "failed to fork thread (error: %d)", error);
	}

	sx_xlock(&khttpd_test_lock);

	while (1 < khttpd_test_thr_running)
		sx_sleep(&khttpd_test_thr_running, &khttpd_test_lock, 0,
		    "join", 0);
	khttpd_test_thr_running = 0;

	not_set = tr->tr_status == KHTTPD_TEST_RESULT_UNSPECIFIED;
	if (not_set) {
		khttpd_test_set_status(KHTTPD_TEST_RESULT_PASS);
		printf("%s\n", khttpd_test_result_labels[tr->tr_status]);
	}

	sx_xunlock(&khttpd_test_lock);

	bintime(&tr->tr_time);
	bintime_sub(&tr->tr_time, &tr->tr_timestamp);

	khttpd_test_dump_ktr();

	khttpd_free(khttpd_test_threads);

	sbuf_finish(&tr->tr_stdout);
	sbuf_finish(&tr->tr_message);
	sbuf_finish(&tr->tr_info);

	khttpd_test_current = NULL;
}

void
khttpd_test_barrier(void)
{
	struct khttpd_test_result *tr;
	struct khttpd_testcase *tc;
	int error, generation, counter;
	boolean_t interrupted;

	tr = khttpd_test_current;
	tc = tr->tr_testcase;

	sx_xlock(&khttpd_test_lock);

	if (tr->tr_status != KHTTPD_TEST_RESULT_UNSPECIFIED ||
		tc->tc_thr_count == 0)
		goto quit;

	generation = khttpd_test_barrier_generation;
	counter = khttpd_test_barrier_counter;

	if (tc->tc_thr_count - 1 <= counter) {
		khttpd_test_barrier_counter = 0;
		++khttpd_test_barrier_generation;
		wakeup(&khttpd_test_barrier_generation);
		goto quit;
	}

	khttpd_test_barrier_counter = counter + 1;
	do {
		error = sx_sleep(&khttpd_test_barrier_generation,
		    &khttpd_test_lock, 0, "barrier", 10 * hz);
		if (error != 0) {
			sx_xunlock(&khttpd_test_lock);
			khttpd_test_exit(KHTTPD_TEST_RESULT_ERROR,
			    "barrier timeout");
		}
	} while (generation == khttpd_test_barrier_generation);

quit:
	interrupted = tr->tr_status != KHTTPD_TEST_RESULT_UNSPECIFIED;
	sx_xunlock(&khttpd_test_lock);

	if (interrupted)
		khttpd_test_break(&khttpd_test_find_curthread()->tt_bottom);
}

static int
khttpd_test_get_token(const char **strp, char **token)
{
	const char *cp;
	char *buf;
	int code, n;

	if (khttpd_test_unget_token_code != KHTTPD_TEST_TOKEN_NULL) {
		*token = khttpd_test_unget_token_str;
		code = khttpd_test_unget_token_code;

		khttpd_test_unget_token_str = NULL;
		khttpd_test_unget_token_code = KHTTPD_TEST_TOKEN_NULL;

		return (code);
	}

	cp = *strp;
	switch (*cp) {
	case '\0':
		code = KHTTPD_TEST_TOKEN_NULL;
		break;

	case ',':
		++cp;
		code = KHTTPD_TEST_TOKEN_COMMA;
		break;

	case '.':
		++cp;
		code = KHTTPD_TEST_TOKEN_FULL_STOP;
		break;

	case '!':
		++cp;
		code = KHTTPD_TEST_TOKEN_EXCLAMATION_MARK;
		break;

	case '*':
		++cp;
		code = KHTTPD_TEST_TOKEN_ASTERISK;
		break;

	default:
		code = KHTTPD_TEST_TOKEN_STRING;
		n = strcspn(cp, ",.!*");
		*token = buf = khttpd_malloc(n + 1);
		strlcpy(buf, cp, n + 1);
		cp += n;
	}

	*strp = cp;

	return (code);
}

static void
khttpd_test_unget_token(int code, char *token)
{

	KASSERT(khttpd_test_unget_token_code == KHTTPD_TEST_TOKEN_NULL,
	    ("khttpd_test_unget_token pushes back more than 1 tokens"));

	khttpd_test_unget_token_code = code;
	khttpd_test_unget_token_str = token;
}

static const char *
khttpd_test_display_token(int code, const char *token)
{

	switch (code) {
	case KHTTPD_TEST_TOKEN_NULL:
		return ("<end>");
	case KHTTPD_TEST_TOKEN_COMMA:
		return (",");
	case KHTTPD_TEST_TOKEN_FULL_STOP:
		return (".");
	case KHTTPD_TEST_TOKEN_EXCLAMATION_MARK:
		return ("!");
	case KHTTPD_TEST_TOKEN_ASTERISK:
		return ("*");
	case KHTTPD_TEST_TOKEN_STRING:
		return (token);
	default:
		return ("<unknown>");
	}
}

static void
khttpd_test_unexpected_token(int code, const char *token)
{

	log(LOG_ERR, "khttpd: unexpected token '%s'",
	    khttpd_test_display_token(code, token));
}

static int
khttpd_test_parse_test_id(const char **readp,
    struct khttpd_test_filter_list *list)
{
	struct khttpd_test_filter *elm;
	char *name, *subject, *token;
	int code;

	token = subject = name = NULL;

	/* subject */
	code = khttpd_test_get_token(readp, &token);
	if (code != KHTTPD_TEST_TOKEN_ASTERISK &&
	    code != KHTTPD_TEST_TOKEN_STRING)
		goto error;
	subject = code == KHTTPD_TEST_TOKEN_STRING ? token : NULL;
	token = NULL;

	/* '.' */
	code = khttpd_test_get_token(readp, &token);
	if (code != KHTTPD_TEST_TOKEN_FULL_STOP)
		goto error;

	/* name */
	code = khttpd_test_get_token(readp, &token);
	if (code != KHTTPD_TEST_TOKEN_ASTERISK &&
	    code != KHTTPD_TEST_TOKEN_STRING)
		goto error;
	name = code == KHTTPD_TEST_TOKEN_STRING ? token : NULL;
	token = NULL;

	elm = khttpd_malloc(sizeof(*elm));
	elm->subject = subject;
	elm->name = name;
	elm->negative = FALSE;
	STAILQ_INSERT_TAIL(list, elm, list);

	return (0);

error:
	khttpd_test_unexpected_token(code, token);

	khttpd_free(token);
	khttpd_free(subject);
	khttpd_free(name);

	return (EINVAL);
}

static int
khttpd_test_parse_filter(const char **readp,
    struct khttpd_test_filter_list *list)
{
	struct khttpd_test_filter *elm;
	char *token;
	int code, error;
	boolean_t negative;

	token = NULL;
	code = khttpd_test_get_token(readp, &token);

	negative = code == KHTTPD_TEST_TOKEN_EXCLAMATION_MARK;

	if (code != KHTTPD_TEST_TOKEN_EXCLAMATION_MARK) {
		khttpd_test_unget_token(code, token);
		token = NULL;
	}

	error = khttpd_test_parse_test_id(readp, list);
	if (error != 0)
		goto quit;

	if (negative) {
		elm = STAILQ_LAST(list, khttpd_test_filter, list);
		KASSERT(!elm->negative, ("negative elm %s.%s", elm->subject,
			elm->name));
		elm->negative = TRUE;
	}

 quit:
	khttpd_free(token);

	return (error);
}

static int
khttpd_test_parse_filter_list(const char **readp,
    struct khttpd_test_filter_list *list)
{
	char *token;
	int code, error;

	STAILQ_INIT(list);

	token = NULL;
	code = khttpd_test_get_token(readp, &token);
	if (code == KHTTPD_TEST_TOKEN_NULL)
		return (0);

	khttpd_test_unget_token(code, token);
	token = NULL;
	error = khttpd_test_parse_filter(readp, list);

	while (error == 0) {
		code = khttpd_test_get_token(readp, &token);
		if (code == KHTTPD_TEST_TOKEN_NULL)
			break;

		if (code != KHTTPD_TEST_TOKEN_COMMA) {
			khttpd_test_unexpected_token(code, token);
			error = EINVAL;
			break;
		}

		error = khttpd_test_parse_filter(readp, list);
	}
	
	khttpd_free(token);

	return (error);
}

static boolean_t
khttpd_test_match_filter(struct khttpd_testcase *tc,
    struct khttpd_test_filter *elm)
{

	return (elm->subject == NULL ||
	    strcmp(elm->subject, tc->tc_subject) == 0) &&
	    (elm->name == NULL || strcmp(elm->name, tc->tc_name) == 0);
}

static boolean_t
khttpd_test_match_filter_list(struct khttpd_testcase *tc,
    struct khttpd_test_filter_list *list)
{
	struct khttpd_test_filter *elm;
	boolean_t match;

	match = STAILQ_EMPTY(list) || STAILQ_FIRST(list)->negative;
	STAILQ_FOREACH(elm, list, list)
		if (khttpd_test_match_filter(tc, elm))
			match = !elm->negative;

	return (match);
}

static void
khttpd_test_count(int status, int *total, int *failures, int *errors,
    int *skips)
{

	switch (status) {
	case KHTTPD_TEST_RESULT_UNSPECIFIED:
		return;
	case KHTTPD_TEST_RESULT_PASS:
		break;
	case KHTTPD_TEST_RESULT_FAIL:
		++*failures;
		break;
	case KHTTPD_TEST_RESULT_ERROR:
		++*errors;
		break;
	case KHTTPD_TEST_RESULT_SKIP:
		++*skips;
		break;
	}

	++*total;
}

static void
khttpd_test_report(struct sbuf *report, struct khttpd_test_result *results,
    int n)
{
	struct bintime time;
	struct timeval tv;
	struct khttpd_testcase *tc;
	struct khttpd_test_result *etr, *tr;
	const char *name;
	int tests, failures, errors, skips;
	int i, suites_end, suite_end;
	boolean_t need_testuites_tag;

	sbuf_printf(report, "<?xml version=\"1.0\" ?>\n");

	suites_end = suite_end = 0;
	for (i = 0; i < n; ++i) {
		tr = results + i;
		tc = results[i].tr_testcase;

		if (suites_end <= i) {
			if (0 < suites_end)
				sbuf_printf(report, "</testsuites>\n");

			name = tc->tc_file;
			while (++suites_end < n)
				if (strcmp(results[suites_end].tr_testcase->
					tc_file, name) != 0)
					break;

			need_testuites_tag = i != 0 || suites_end != n;
			if (need_testuites_tag)
				sbuf_printf(report, "<testsuites>\n");
		}

		if (suite_end <= i) {
			if (0 < suite_end)
				sbuf_printf(report, "</testsuite>\n");

			name = tc->tc_subject;
			tests = failures = errors = skips = 0;
			khttpd_test_count(tr->tr_status, &tests, &failures,
			    &errors, &skips);
			time = tr->tr_time;
			while (++suite_end < n) {
				etr = &results[suite_end];
				if (strcmp(etr->tr_testcase->tc_subject, name)
				    != 0)
					break;

				khttpd_test_count(etr->tr_status, &tests,
				    &failures, &errors, &skips);

				bintime_add(&time, &etr->tr_time);
			}
			bintime2timeval(&time, &tv);

			sbuf_printf(report, "<testsuite package=\"%s\" "
			    "name=\"%s\" time=\"%ld.%06ld\" "
			    "tests=\"%d\" failures=\"%d\" errors=\"%d\" "
			    "skipped=\"%d\">\n",
			    tc->tc_file, tc->tc_subject, tv.tv_sec, tv.tv_usec,
			    tests, failures, errors, skips);
		}

		if (tr->tr_status == KHTTPD_TEST_RESULT_UNSPECIFIED)
			continue;

		bintime2timeval(&tr->tr_time, &tv);
		sbuf_printf(report, "<testcase classname=\"%s.%s\" "
		    "name=\"%s\" time=\"%ld.%06ld\">\n", tc->tc_file,
		    tc->tc_subject, tc->tc_name, tv.tv_sec, tv.tv_usec);

		switch (tr->tr_status) {
		case KHTTPD_TEST_RESULT_PASS:
			break;
		case KHTTPD_TEST_RESULT_FAIL:
			sbuf_printf(report,
			    "<failure message=\"%s\">\n%s</failure>\n",
			    sbuf_data(&tr->tr_message),
			    sbuf_data(&tr->tr_info));
			break;
		case KHTTPD_TEST_RESULT_ERROR:
			sbuf_printf(report,
			    "<error message=\"%s\">\n%s</error>\n",
			    sbuf_data(&tr->tr_message),
			    sbuf_data(&tr->tr_info));
			break;
		case KHTTPD_TEST_RESULT_SKIP:
			sbuf_printf(report, "<skipped/>\n");
			break;
		default:
			panic("unknown status: %d", tr->tr_status);
		}
		sbuf_printf(report, "</testcase>\n");
	}

	sbuf_printf(report, "</testsuite>\n");
	if (need_testuites_tag)
		sbuf_printf(report, "</testsuites>\n");
}

int
khttpd_test_run(struct sbuf *report, const char *filter_desc)
{
	struct khttpd_test_filter_list filters;
	struct khttpd_test_filter *elm;
	struct khttpd_test_result *trs, *tr;
	struct khttpd_testcase **tcs;
	struct thread *td;
	size_t tcssize, trssize;
	int tests, failures, errors, skips;
	int error, i, n;

	n = SET_COUNT(khttpd_testcase_set);
	if (n == 0)
		return (0);

	td = curthread;

	tcssize = sizeof(struct khttpd_testcase *) * n;
	tcs = khttpd_malloc(tcssize);
	bcopy(SET_BEGIN(khttpd_testcase_set), tcs, tcssize);
	qsort(tcs, n, sizeof(struct khttpd_testcase *), khttpd_testcase_cmp);

	trssize = sizeof(struct khttpd_test_result) *
	    SET_COUNT(khttpd_testcase_set);
	khttpd_test_results = trs = khttpd_malloc(trssize);
	khttpd_test_results_count = SET_COUNT(khttpd_testcase_set);
	bzero(trs, trssize);
	for (i = 0; i < n; ++i) {
		tr = &trs[i];
		sbuf_new(&tr->tr_stdout, NULL, 0, SBUF_AUTOEXTEND);
		sbuf_new(&tr->tr_message, NULL, 0, SBUF_AUTOEXTEND);
		sbuf_new(&tr->tr_info, NULL, 0, SBUF_AUTOEXTEND);
		tr->tr_testcase = tcs[i];
	}

	error = khttpd_test_parse_filter_list(&filter_desc, &filters);
	if (error != 0)
		goto quit;

	for (i = 0; i < n; ++i)
		if (khttpd_test_match_filter_list(tcs[i], &filters))
			khttpd_testcase_run(&trs[i], tcs[i]);

	tests = failures = errors = skips = 0;
	for (i = 0; i < n; ++i)
		khttpd_test_count(trs[i].tr_status,
		    &tests, &failures, &errors, &skips);
	printf("tests: %d, failures: %d, errors: %d, skipped: %d\n", tests,
	    failures, errors, skips);

	while ((elm = STAILQ_FIRST(&filters)) != NULL) {
		STAILQ_REMOVE_HEAD(&filters, list);
		khttpd_free(elm);
	}

	khttpd_test_report(report, trs, n);

quit:
	for (i = 0; i < n; ++i) {
		tr = &trs[i];
		sbuf_delete(&tr->tr_stdout);
		sbuf_delete(&tr->tr_message);
		sbuf_delete(&tr->tr_info);
	}
	khttpd_free(trs);
	khttpd_test_results = NULL;
	khttpd_test_results_count = 0;
	khttpd_free(tcs);

	return (0);
}

#ifdef DDB

#include <ddb/ddb.h>

static void
khttpd_test_db_print_sbuf(struct sbuf *sbuf)
{
	char *cp, *ncp;

	cp = sbuf_data(sbuf);
	for (;;) {
		ncp = strchr(cp, '\n');
		if (ncp == NULL) {
			db_iprintf("%s\n", cp);
			break;
		}

		db_iprintf("%*s\n", (int)(ncp - cp), cp);
		if (ncp[1] == '\0')
			break;
		cp = ncp + 1;
	}
}

static void
khttpd_test_show_result(struct khttpd_test_result *tr)
{
	struct timeval tv;
	struct khttpd_testcase *tc;
	const char *status_label;
	int status;

	tc = tr->tr_testcase;

	status = tr->tr_status;
	status_label = 0 <= status && status < KHTTPD_TEST_RESULT_END ?
	    khttpd_test_result_labels[status] : "unknown";
	db_iprintf("%s: %s", tc->tc_name, status_label);

	if (tr->tr_status != KHTTPD_TEST_RESULT_UNSPECIFIED) {
		bintime2timeval(&tr->tr_time, &tv);
		db_printf(" %ld.%06ld[sec]", tv.tv_sec, tv.tv_usec);
	}

	if (tr->tr_status == KHTTPD_TEST_RESULT_FAIL ||
	    tr->tr_status == KHTTPD_TEST_RESULT_ERROR) {
		db_printf(" %s\n", sbuf_data(&tr->tr_message));
		db_indent += 2;
		db_iprintf("Info:\n");
		db_indent += 2;
		khttpd_test_db_print_sbuf(&tr->tr_info);
		db_indent -= 4;
	}

	db_indent += 2;
	db_iprintf("Output:\n");
	db_indent += 2;
	khttpd_test_db_print_sbuf(&tr->tr_stdout);
	db_indent -= 4;
}

DB_SHOW_COMMAND(test, khttpd_test_ddb_show_test)
{

	if (khttpd_test_current == NULL)
		return;

	khttpd_test_show_result(khttpd_test_current);
}

DB_SHOW_ALL_COMMAND(test, khttpd_test_ddb_show_all_test)
{
	struct khttpd_testcase *tc;
	struct khttpd_test_result *begin, *end, *suites_end, *suite_end;
	struct khttpd_test_result *tr;
	const char *name;
	int indent;

	if (khttpd_test_results == NULL || khttpd_test_results_count == 0)
		return;

	begin = khttpd_test_results;
	end = begin + khttpd_test_results_count;
	suites_end = suite_end = begin;
	indent = db_indent;
	for (tr = begin; tr < end; ++tr) {
		tc = tr->tr_testcase;

		if (suites_end <= tr) {
			if (begin < suites_end)
				db_indent -= 2;

			name = tc->tc_file;
			while (++suites_end < end &&
			    strcmp(suites_end->tr_testcase->tc_file, name)
			    == 0)
				; /* nothing */
			db_iprintf("%s\n", name);
			db_indent += 2;
		}

		if (suite_end <= tr) {
			if (begin < suite_end)
				db_indent -= 2;

			name = tc->tc_subject;
			while (++suite_end < end &&
			    strcmp(suite_end->tr_testcase->tc_file, name)
			    == 0)
				; /* nothing */

			db_iprintf("%s\n", name);
			db_indent += 2;
		}

		khttpd_test_show_result(tr);

		if (tr->tr_status == KHTTPD_TEST_RESULT_UNSPECIFIED)
			break;
	}

	db_indent = indent;
}

#endif /* ifdef DDB */

#if defined(KHTTPD_TEST_ENABLE) &&  !defined(KHTTPD_TEST_TEST_INCLUDED)
#define KHTTPD_TEST_TEST_INCLUDED
#include "khttpd_test_test.c"
#endif
