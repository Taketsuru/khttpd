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

#pragma once

#ifdef _KERNEL

#include <sys/param.h>
#include <sys/linker_set.h>
#include <machine/stdarg.h>
#include <machine/setjmp.h>

struct sbuf;
struct khttpd_test_frame;

struct khttpd_testcase {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
	void		(*tc_fn)();
#pragma clang diagnostic pop

	const char	*tc_subject;
	const char	*tc_name;
	const char	*tc_file;
	u_int		tc_line;
	u_int		tc_thr_count;
};


#define KHTTPD_TESTCASE(subject, name, ...)				\
	static void __CONCAT(test_, __CONCAT(__FILE__, __LINE__))(void); \
	static struct khttpd_testcase					\
	__CONCAT(tag_, __CONCAT(__FILE__, __LINE__)) = {		\
		.tc_fn = __CONCAT(test_, __CONCAT(__FILE__, __LINE__)), \
		.tc_subject = # subject,				\
		.tc_name = # name,					\
		.tc_file = __FILE__,					\
		.tc_line = __LINE__,					\
		__VA_ARGS__						\
	};								\
	SET_ENTRY(khttpd_testcase_set,					\
	    __CONCAT(testcase_, __CONCAT(__FILE__, __LINE__)));		\
	static void __CONCAT(test_, __CONCAT(__FILE__, __LINE__))(void)	\

#define KHTTPD_TEST_BARRIER()						\
	do {								\
		KHTTPD_TR("%s barrier %d", __func__, khttpd_test_tid()); \
		khttpd_test_barrier();					\
	} while (0)


#define KHTTPD_TEST_FAIL(fmt, ...)	       \
	khttpd_test_fail("%s:%u: error: " fmt, \
	    __FILE__, __LINE__, ##__VA_ARGS__)

#define KHTTPD_TEST_EQUAL(type, fmt, expr1, expr2)			\
	do {								\
		type v1 = (expr1);					\
		type v2 = (expr2);					\
		if (v1 != v2)						\
			KHTTPD_TEST_FAIL("%s(==" fmt ") != %s(==" fmt ")", \
			    #expr1, v1, #expr2, v2);			\
	} while (0)

#define KHTTPD_TEST_EQUAL_NOT(type, fmt, expr1, expr2)			\
	do {								\
		type v1 = (expr1);					\
		type v2 = (expr2);					\
		if (v1 == v2)						\
			KHTTPD_TEST_FAIL("%s(==" fmt ") == %s(==" fmt ")", \
			    #expr1, v1, #expr2, v2);			\
	} while (0)

#define KHTTPD_TEST_EQUAL_INT(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(int, "%d", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_INT(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(int, "%d", expr1, expr2)

#define KHTTPD_TEST_EQUAL_UINT(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(u_int, "%u", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_UINT(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(u_int, "%u", expr1, expr2)

#define KHTTPD_TEST_EQUAL_XINT(expr1, expr2)			\
	KHTTPD_TEST_EQUAL(u_int, "%#x", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_XINT(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(u_int, "%#x", expr1, expr2)

#define KHTTPD_TEST_EQUAL_LONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(long, "%ld", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_LONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(long, "%ld", expr1, expr2)

#define KHTTPD_TEST_EQUAL_ULONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(u_long, "%lu", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_ULONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(u_long, "%lu", expr1, expr2)

#define KHTTPD_TEST_EQUAL_XLONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(u_long, "%#lx", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_XLONG(expr1, expr2)		\
	KHTTPD_TEST_EQUAL_NOT(u_long, "%#lx", expr1, expr2)

#define KHTTPD_TEST_EQUAL_PTR(expr1, expr2)		\
	KHTTPD_TEST_EQUAL(void *, "%p", expr1, expr2)

#define KHTTPD_TEST_NOT_EQUAL_PTR(expr1, expr2)			\
	KHTTPD_TEST_EQUAL_NOT(void *, "%p", expr1, expr2)

#define KHTTPD_TEST_ASSERT(cond)				\
	do {							\
		if (!(cond))					\
			KHTTPD_TEST_FAIL("!(%s)", #cond);	\
	} while (0)

#define KHTTPD_TEST_NEGATE(cond)				\
	do {							\
		if (cond)					\
			KHTTPD_TEST_FAIL("%s", #cond);		\
	} while (0)

#define KHTTPD_TEST_UNWIND_PROTECT_BEGIN \
	do { \
		do {			  \
			struct _jmp_buf _jmp_buf;	     \
			int _thrown;			     \
			_thrown = setjmp(&_jmp_buf);	     \
			if (_thrown != 0)		     \
				break;			     \
			khttpd_test_push_frame(&_jmp_buf);   \

#define KHTTPD_TEST_FINALLY		\
	} while (0);				\
	khttpd_test_pop_frame();

#define KHTTPD_TEST_UNWIND_PROTECT_END \
	khttpd_test_continue_unwind(); \
	} while (0)

void khttpd_test_vprintf(const char *fmt, va_list ap);
void khttpd_test_printf(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
struct khttpd_test_frame *khttpd_test_current_frame(void);
void khttpd_test_break(struct khttpd_test_frame *target)
	__attribute__ ((noreturn));
void khttpd_test_push_frame(struct _jmp_buf *buf);
void khttpd_test_pop_frame(void);
void khttpd_test_continue_unwind(void);
void khttpd_test_exit(int result, const char *fmt, ...)
	__attribute__ ((format(printf, 2, 3), noreturn));
void khttpd_test_barrier(void);
int khttpd_test_tid(void);
int khttpd_test_run(struct sbuf *report, const char *filter);

#endif	/* ifdef _KERNEL */
