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

#include "khttpd_method.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_init.h"
#include "khttpd_strtab.h"

static struct khttpd_strtab_entry khttpd_methods[] = {
	{ "ACL" },
	{ "BASELINE-CONTROL" },
	{ "BIND" },
	{ "CHECKIN" },
	{ "CHECKOUT" },
	{ "CONNECT" },
	{ "COPY" },
	{ "DELETE" },
	{ "GET" },
	{ "HEAD" },
	{ "LABEL" },
	{ "LINK" },
	{ "LOCK" },
	{ "MERGE" },
	{ "MKACTIVITY" },
	{ "MKCALENDAR" },
	{ "MKCOL" },
	{ "MKREDIRECTREF" },
	{ "MKWORKSPACE" },
	{ "MOVE" },
	{ "OPTIONS" },
	{ "ORDERPATCH" },
	{ "PATCH" },
	{ "POST" },
	{ "PRI" },
	{ "PROPFIND" },
	{ "PROPPATCH" },
	{ "PUT" },
	{ "REBIND" },
	{ "REPORT" },
	{ "SEARCH" },
	{ "TRACE" },
	{ "UNBIND" },
	{ "UNCHECKOUT" },
	{ "UNLINK" },
	{ "UNLOCK" },
	{ "UPDATE" },
	{ "UPDATEREDIRECTREF" },
	{ "VERSION-CONTROL" },
};

CTASSERT(nitems(khttpd_methods) == KHTTPD_METHOD_END);

static struct khttpd_strtab_entry_slist
    khttpd_method_table[KHTTPD_STRTAB_POW2_CEIL(KHTTPD_METHOD_END)];

int
khttpd_method_find(const char *begin, const char *end)
{
	struct khttpd_strtab_entry *entry;

	entry = khttpd_strtab_find(khttpd_method_table,
	    nitems(khttpd_method_table), begin, end, FALSE);

	return (entry == NULL ? KHTTPD_METHOD_UNKNOWN :
	    entry - khttpd_methods);
}

const char *
khttpd_method_name(int method)
{

	if (method < 0 || KHTTPD_METHOD_END <= method)
		return (NULL);
	return (khttpd_methods[method].name);
}

static int
khttpd_method_init(void)
{

	khttpd_strtab_init(khttpd_method_table, nitems(khttpd_method_table),
	    khttpd_methods, nitems(khttpd_methods));

	return (0);
}

KHTTPD_INIT(khttpd_method, khttpd_method_init, NULL, KHTTPD_INIT_PHASE_LOCAL);
