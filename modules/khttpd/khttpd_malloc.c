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

#include "khttpd_malloc.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/stack.h>
#include <sys/ktr.h>
#include <sys/malloc.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_ktr.h"

#ifndef KHTTPD_TRACE_MALLOC_STACK_DEPTH
#define KHTTPD_TRACE_MALLOC_STACK_DEPTH	8
#endif

MALLOC_DEFINE(M_KHTTPD, "khttpd", "khttpd heap");

void *khttpd_malloc(size_t size)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	void *mem;

	mem = malloc(size, M_KHTTPD, M_WAITOK);

#ifdef KHTTPD_TRACE_MALLOC
	KHTTPD_TR("alloc %p %#lx", mem, size);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, KHTTPD_TRACE_MALLOC_STACK_DEPTH, 0);
#endif
	return (mem);
}

void khttpd_free(void *mem)
{

#ifdef KHTTPD_TRACE_MALLOC
	KHTTPD_TR("free %p", mem);
#endif
	free(mem, M_KHTTPD);
}

void *khttpd_realloc(void *mem, size_t size)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	void *newmem;

	newmem = realloc(mem, size, M_KHTTPD, M_WAITOK);

#ifdef KHTTPD_TRACE_MALLOC
	KHTTPD_TR("free %p", mem);
	KHTTPD_TR("alloc %p %#lx", newmem, size);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, KHTTPD_TRACE_MALLOC_STACK_DEPTH, 0);
#endif

	return (newmem);
}

char *khttpd_strdup(const char *str)
{
#ifdef KHTTPD_TRACE_MALLOC
	struct stack st;
#endif
	char *newstr;

	newstr = strdup(str, M_KHTTPD);

#ifdef KHTTPD_TRACE_MALLOC
	KHTTPD_TR("alloc %p %#lx", newstr, strlen(newstr) + 1);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, KHTTPD_TRACE_MALLOC_STACK_DEPTH, 0);
#endif

	return (newstr);
}
