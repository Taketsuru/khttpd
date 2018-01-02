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

static const char *khttpd_methods[] = {
	"ACL",
	"BASELINE-CONTROL",
	"BIND",
	"CHECKIN",
	"CHECKOUT",
	"CONNECT",
	"COPY",
	"DELETE",
	"GET",
	"HEAD",
	"LABEL",
	"LINK",
	"LOCK",
	"MERGE",
	"MKACTIVITY",
	"MKCALENDAR",
	"MKCOL",
	"MKREDIRECTREF",
	"MKWORKSPACE",
	"MOVE",
	"OPTIONS",
	"ORDERPATCH",
	"PATCH",
	"POST",
	"PRI",
	"PROPFIND",
	"PROPPATCH",
	"PUT",
	"REBIND",
	"REPORT",
	"SEARCH",
	"TRACE",
	"UNBIND",
	"UNCHECKOUT",
	"UNLINK",
	"UNLOCK",
	"UPDATE",
	"UPDATEREDIRECTREF",
	"VERSION-CONTROL",
};

CTASSERT(nitems(khttpd_methods) == KHTTPD_METHOD_END);

static struct khttpd_strtab *khttpd_method_strtab;

int
khttpd_method_find(const char *begin, const char *end)
{

	return (khttpd_strtab_find(khttpd_method_strtab, begin, end, FALSE));
}

const char *
khttpd_method_name(int method)
{

	return (method < 0 || KHTTPD_METHOD_END <= method ? NULL :
	    khttpd_methods[method]);
}

static int
khttpd_method_init(void)
{

	khttpd_method_strtab = khttpd_strtab_new(khttpd_methods,
	    nitems(khttpd_methods));

	return (khttpd_method_strtab != NULL ? 0 : ENOMEM);
}

static void
khttpd_method_fini(void)
{

	khttpd_strtab_delete(khttpd_method_strtab);
}

KHTTPD_INIT(khttpd_method, khttpd_method_init, khttpd_method_fini,
    KHTTPD_INIT_PHASE_LOCAL);
