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

struct khttpd_json;
struct mbuf;

enum {
	KHTTPD_JSON_ARRAY = 1,
	KHTTPD_JSON_OBJECT,
	KHTTPD_JSON_INTEGER,
	KHTTPD_JSON_BOOL,
	KHTTPD_JSON_STRING,
	KHTTPD_JSON_NULL,
};

struct khttpd_json_problem {
	const char	*type;
	const char	*title;
	struct sbuf	*detail; /* NULL or a sbuf allocated by sbuf_auto_new */
	unsigned	line;
	unsigned	column;
};

struct khttpd_json *khttpd_json_null_new(void);
struct khttpd_json *khttpd_json_integer_new(int64_t value);
struct khttpd_json *khttpd_json_boolean_new(boolean_t value);
struct khttpd_json *khttpd_json_string_new(void);
struct khttpd_json *khttpd_json_array_new(void);
struct khttpd_json *khttpd_json_object_new(int size_hint);
void khttpd_json_delete(struct khttpd_json *value);
int khttpd_json_type(struct khttpd_json *value);
int64_t khttpd_json_integer_value(struct khttpd_json *value);
int khttpd_json_string_size(struct khttpd_json *value);
const char *khttpd_json_string_data(struct khttpd_json *value);
void khttpd_json_string_append_char(struct khttpd_json *value, int ch);
void khttpd_json_string_append_utf8(struct khttpd_json *value, int code);
int khttpd_json_array_size(struct khttpd_json *value);
struct khttpd_json *khttpd_json_array_get(struct khttpd_json *value,
    int index);
void khttpd_json_array_add(struct khttpd_json *value,
    struct khttpd_json *elem);
int khttpd_json_object_size(struct khttpd_json *value);
struct khttpd_json *khttpd_json_object_get(struct khttpd_json *value,
    const char *name);
struct khttpd_json *khttpd_json_object_get_at(struct khttpd_json *value,
    int index, struct khttpd_json **name_out);
void khttpd_json_object_add(struct khttpd_json *value,
    struct khttpd_json *name, struct khttpd_json *elem);
boolean_t khttpd_json_parse(struct khttpd_json **result,
    struct khttpd_json_problem *, struct mbuf *input, int depth_limit);
