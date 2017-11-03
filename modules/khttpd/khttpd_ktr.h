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

#ifndef _KERNEL
#error This file is not for userland code.
#endif

#include <sys/param.h>
#include <sys/stack.h>

#ifdef KHTTPD_TRACE_FN
#define KHTTPD_ENTRY KHTTPD_TR
#else
#define KHTTPD_ENTRY(...)
#endif

#ifdef KHTTPD_TRACE_BRANCH
#define KHTTPD_BRANCH KHTTPD_TR
#else
#define KHTTPD_BRANCH(...)
#endif

#ifdef KHTTPD_TRACE_NOTE
#define KHTTPD_NOTE KHTTPD_TR
#else
#define KHTTPD_NOTE(...)
#endif

#ifdef KHTTPD_TRACE_MALLOC

#ifndef KHTTPD_TRACE_MALLOC_STACK_DEPTH
#define KHTTPD_TRACE_MALLOC_STACK_DEPTH	12
#endif

#define KHTTPD_TR_ALLOC(mem,size)					\
	do {								\
		struct stack st;					\
		KHTTPD_TR("alloc %p %#lx", (mem), (size));		\
		stack_save(&st);					\
		CTRSTACK(KTR_GEN, &st, KHTTPD_TRACE_MALLOC_STACK_DEPTH, 0); \
	} while (0)

#define KHTTPD_TR_FREE(mem) KHTTPD_TR("free %p", (mem))

#else

#define KHTTPD_TR_ALLOC(mem,size)
#define KHTTPD_TR_FREE(mem)

#endif

#ifdef KHTTPD_KTR_LOGGING

#include <sys/param.h>
#include <sys/ktr.h>

void khttpd_ktr_lock(void);
void khttpd_ktr_unlock(void);
const char *khttpd_ktr_printf(const char *fmt, ...) __printflike(1, 2);
const char *khttpd_ktr_vprintf(const char *fmt, __va_list) __printflike(1, 0);

#define KHTTPD_TR_MACRO(_0, _1, _2, _3, _4, _5, _6, N, ...) TR ## N
#define KHTTPD_TR_(__fmt, __macro, ...) __macro(__fmt, ##__VA_ARGS__)
#define KHTTPD_TR(__fmt, ...)					     \
	do {							     \
		khttpd_ktr_lock();				     \
		KHTTPD_TR_(__fmt,				     \
		    KHTTPD_TR_MACRO(_0, ##__VA_ARGS__, 6, 5, 4, 3, 2, 1, 0), \
		    ##__VA_ARGS__);					\
		khttpd_ktr_unlock();					\
	} while (0)
#else

#define KHTTPD_TR(__fmt, ...)

#endif
