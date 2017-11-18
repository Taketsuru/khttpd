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
#include <netinet/in.h>

struct sbuf;

struct khttpd_json;
struct khttpd_mbuf_json;
struct khttpd_problem_property;

int khttpd_webapi_get_string_property(const char **str_out, const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist);
int khttpd_webapi_get_integer_property(int64_t *value_out, const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist);
int khttpd_webapi_get_object_property(struct khttpd_json **value_out,
    const char *name, 
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist);
int khttpd_webapi_get_sockaddr_properties(struct sockaddr *addr, socklen_t len,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output);
