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

#include <sys/types.h>
#include <machine/stdarg.h>

enum khttpd_mbuf_append_entry_type {
	KHTTPD_MBUF_APPEND_END,
	KHTTPD_MBUF_APPEND_STR,
	KHTTPD_MBUF_APPEND_STR_JSON,
	KHTTPD_MBUF_APPEND_MBUF,
	KHTTPD_MBUF_APPEND_MBUF_JSON,
	KHTTPD_MBUF_APPEND_FMT,
	KHTTPD_MBUF_APPEND_FMT_JSON
};

struct mbuf;
struct sbuf;
struct sockaddr;
struct sockaddr_in;
struct sockaddr_in6;

struct khttpd_mbuf_pos {
	struct mbuf	*ptr;
	int32_t		off;
	int		unget;
};

struct khttpd_mbuf_json {
	struct mbuf *mbuf;
	unsigned is_first:1;
};

int khttpd_mbuf_vprintf(struct mbuf *output, const char *fmt, va_list vl);
int khttpd_mbuf_printf(struct mbuf *output, const char *fmt, ...);
struct mbuf *khttpd_mbuf_append(struct mbuf *output, const char *begin,
    const char *end);
struct mbuf *khttpd_mbuf_append_ch(struct mbuf *output, char ch);
void khttpd_mbuf_pos_init(struct khttpd_mbuf_pos *iter, struct mbuf *ptr,
    int off);
void khttpd_mbuf_pos_copy(struct khttpd_mbuf_pos *x,
    struct khttpd_mbuf_pos *y);
int khttpd_mbuf_getc(struct khttpd_mbuf_pos *iter);
void khttpd_mbuf_ungetc(struct khttpd_mbuf_pos *iter, int ch);
boolean_t khttpd_mbuf_skip_ws(struct khttpd_mbuf_pos *iter);
boolean_t khttpd_mbuf_next_line(struct khttpd_mbuf_pos *iter);
void khttpd_mbuf_get_line_and_column(struct khttpd_mbuf_pos *origin,
    struct khttpd_mbuf_pos *pos, unsigned *line_out, unsigned *column_out);
boolean_t khttpd_mbuf_get_header_field(struct khttpd_mbuf_pos *iter,
    const char *name, struct sbuf *value);
int khttpd_mbuf_next_segment(struct khttpd_mbuf_pos *iter, int term_ch);
int khttpd_mbuf_copy_segment(struct khttpd_mbuf_pos *pos, int term_ch,
    char *buffer, size_t size, char **end_out);
int khttpd_mbuf_parse_digits(struct khttpd_mbuf_pos *pos,
    uintmax_t *value_out);
void khttpd_mbuf_base64_encode(struct mbuf *output, const char *buf,
    size_t size);
int khttpd_mbuf_base64_decode(struct khttpd_mbuf_pos *iter, void **buf_out,
    size_t *size_out);
int khttpd_mbuf_next_list_element(struct khttpd_mbuf_pos *pos,
    struct sbuf *output);
boolean_t khttpd_mbuf_list_contains_token(struct khttpd_mbuf_pos *pos,
    char *token, boolean_t ignore_case);

struct mbuf *khttpd_mbuf_put_json_string_wo_quote_mbuf(struct mbuf *output,
    struct mbuf *source);
struct mbuf *khttpd_mbuf_put_json_string(struct mbuf *output,
    const char *begin, const char *end);
struct mbuf *khttpd_mbuf_put_json_string_cstr(struct mbuf *output,
    const char *str);

void khttpd_mbuf_json_new(struct khttpd_mbuf_json *v);
struct mbuf *khttpd_mbuf_json_data(struct khttpd_mbuf_json *v);
struct mbuf *khttpd_mbuf_json_move(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_copy_to_sbuf(struct khttpd_mbuf_json *, struct sbuf *);
void khttpd_mbuf_json_print(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_delete(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_null(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_boolean(struct khttpd_mbuf_json *v, boolean_t value);
void khttpd_mbuf_json_cstr(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *value);
void khttpd_mbuf_json_mbuf(struct khttpd_mbuf_json *v, boolean_t is_string,
    struct mbuf *m);
void khttpd_mbuf_json_sockaddr(struct khttpd_mbuf_json *v,
    const struct sockaddr *sockaddr);
void khttpd_mbuf_json_format(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *fmt, ...);
void khttpd_mbuf_json_vformat(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *fmt, va_list args);
void khttpd_mbuf_json_object_begin(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_object_end(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_property_null(struct khttpd_mbuf_json *v,
    const char *name);
void khttpd_mbuf_json_property_boolean(struct khttpd_mbuf_json *v,
    const char *name, boolean_t value);
void khttpd_mbuf_json_property_cstr(struct khttpd_mbuf_json *v,
    const char *name, boolean_t is_string, const char *value);
void khttpd_mbuf_json_property_format(struct khttpd_mbuf_json *v,
    const char *name, boolean_t is_string, const char *fmt, ...);
void khttpd_mbuf_json_property_vformat(struct khttpd_mbuf_json *v,
    const char *name, boolean_t is_string, const char *fmt, va_list args);
void khttpd_mbuf_json_property_mbuf(struct khttpd_mbuf_json *v,
    const char *name, boolean_t is_string, struct mbuf *m);
void khttpd_mbuf_json_property_mbuf_1st_line(struct khttpd_mbuf_json *v,
    const char *name, struct mbuf *m);
void khttpd_mbuf_json_property_sockaddr(struct khttpd_mbuf_json *v,
    const char *name, struct sockaddr *addr);
void khttpd_mbuf_json_property_array_begin(struct khttpd_mbuf_json *v,
    const char *name);
void khttpd_mbuf_json_property_object_begin(struct khttpd_mbuf_json *v,
    const char *name);
void khttpd_mbuf_json_array_begin(struct khttpd_mbuf_json *v);
void khttpd_mbuf_json_array_end(struct khttpd_mbuf_json *v);
