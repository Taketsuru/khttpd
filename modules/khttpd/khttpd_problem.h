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

#include <sys/types.h>
#include <machine/stdarg.h>

struct sbuf;

struct khttpd_json;
struct khttpd_mbuf_json;

struct khttpd_problem_property {
	struct khttpd_problem_property *link;
	const char	*name;
};

void khttpd_problem_property_specifier_to_string(struct sbuf *output,
    struct khttpd_problem_property *prop_spec);

#ifdef KHTTPD_KTR_LOGGING
const char *khttpd_problem_ktr_print_property
    (struct khttpd_problem_property *prop_spec);
#endif

void khttpd_problem_response_begin(struct khttpd_mbuf_json *output, int status,
    const char *type, const char *title);
void khttpd_problem_log_new(struct khttpd_mbuf_json *output, int severity,
    const char *type, const char *title);
void khttpd_problem_set_property(struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *property);
void khttpd_problem_set_detail(struct khttpd_mbuf_json *output,
    const char *fmt, ...);
void khttpd_problem_set_vdetail(struct khttpd_mbuf_json *_output,
    const char *_fmt, va_list _va);
void khttpd_problem_set_errno(struct khttpd_mbuf_json *output,
    int error);
void khttpd_problem_no_value_response_begin(struct khttpd_mbuf_json *);
void khttpd_problem_wrong_type_response_begin(struct khttpd_mbuf_json *);
void khttpd_problem_invalid_value_response_begin(struct khttpd_mbuf_json *);
const char *khttpd_problem_get_severity_label(int severity);
void khttpd_problem_internal_error_log_new(struct khttpd_mbuf_json *output);
