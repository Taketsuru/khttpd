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

#ifndef KHTTPD_TEST_TEST_INCLUDED
#define KHTTPD_TEST_TEST_INCLUDED
#include "khttpd_test.c"
#endif

#include "khttpd_init.h"
#include "khttpd_test.h"

static const char *test_init_focus[] = {
	"khttpd_test.c",
};

#define TEST_INIT_NFOCUSES (sizeof(test_init_focus) / sizeof(char *))

KHTTPD_TESTCASE(basic, fail)
{

	KHTTPD_TEST_FAIL("this test signals %s", "'fail'");
}

KHTTPD_TESTCASE(basic, error)
{

	KHTTPD_TEST_ERROR("this test signals %s", "'error'");
}

KHTTPD_TESTCASE(basic, skip)
{

	KHTTPD_TEST_SKIP("this test is %s", "skipped");
}

KHTTPD_TESTCASE(basic, assert_op_pass)
{

	KHTTPD_TEST_ASSERT_OP("%d", 1 - 1, ==, 0);
}

KHTTPD_TESTCASE(basic, assert_op_fail)
{

	KHTTPD_TEST_ASSERT_OP("%d", 1 - 1, ==, 1);
	panic("can't reach here");
}

KHTTPD_TESTCASE(basic, assert_pass)
{

	KHTTPD_TEST_ASSERT(TRUE);
}

KHTTPD_TESTCASE(basic, assert_fail)
{

	KHTTPD_TEST_ASSERT(FALSE);
	panic("can't reach here");
}

KHTTPD_TESTCASE(basic, assume_pass)
{

	KHTTPD_TEST_ASSUME(TRUE);
}

KHTTPD_TESTCASE(basic, assume_error)
{

	KHTTPD_TEST_ASSUME(FALSE);
	panic("can't reach here");
}

KHTTPD_TESTCASE(unwind_protect, break)
{
	struct khttpd_test_frame *frame;

	KHTTPD_TEST_UNWIND_PROTECT_BEGIN {
		frame = khttpd_test_current_frame();
		khttpd_test_break(frame);
		KHTTPD_TEST_FAIL("can not reach here");
	} KHTTPD_TEST_UNWIND_PROTECT_END;
}

KHTTPD_TESTCASE(unwind_protect, break_two_scopes)
{
	struct khttpd_test_frame *frame;
	int reach;

	reach = 0;
	KHTTPD_TEST_UNWIND_PROTECT_BEGIN {
		frame = khttpd_test_current_frame();
		KHTTPD_TEST_UNWIND_PROTECT_BEGIN {
			khttpd_test_break(frame);
			KHTTPD_TEST_FAIL("can't reach here");
		} KHTTPD_TEST_UNWIND_PROTECT_END;

		++reach;
		khttpd_test_continue_unwind();
		KHTTPD_TEST_FAIL("can't reach here");
	} KHTTPD_TEST_UNWIND_PROTECT_END;

	KHTTPD_TEST_ASSERT_OP("%d", reach, ==, 1);
}

static void
test_unwind_protect_break_across_functions_helper
    (struct khttpd_test_frame *frame, int *reach)
{

	KHTTPD_TEST_UNWIND_PROTECT_BEGIN {
		khttpd_test_break(frame);
		KHTTPD_TEST_FAIL("can't reach here");
	} KHTTPD_TEST_UNWIND_PROTECT_END;

	++*reach;
	khttpd_test_continue_unwind();
	KHTTPD_TEST_FAIL("can't reach here");
}

KHTTPD_TESTCASE(unwind_protect, nesting_across_function)
{
	struct khttpd_test_frame *frame;
	int reach;

	reach = 0;

	KHTTPD_TEST_UNWIND_PROTECT_BEGIN {
		frame = khttpd_test_current_frame();
		test_unwind_protect_break_across_functions_helper
		    (frame, &reach);
		KHTTPD_TEST_FAIL("can't reach here");
	} KHTTPD_TEST_UNWIND_PROTECT_END;

	KHTTPD_TEST_ASSERT_OP("%d", reach, ==, 1);
}
