/*-
 * Copyright (c) 2018 Taketsuru <taketsuru11@gmail.com>.
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

struct mbuf;
struct sockaddr;

struct khttpd_mbuf_json {
	struct mbuf    *mbuf;
	unsigned	is_first:1;
	unsigned	is_property_value:1;
};

struct mbuf *
	khttpd_mbuf_append_ch(struct mbuf *_dst, char _ch);
struct mbuf *
	khttpd_mbuf_append(struct mbuf *_dst,
	    const char *_begin, const char *_end);
int	khttpd_mbuf_printf(struct mbuf *_dst, const char *_fmt, ...);
int	khttpd_mbuf_vprintf(struct mbuf *_dst, const char *_fmt, va_list _vl);
void	khttpd_mbuf_json_new(struct khttpd_mbuf_json *_dst);
struct mbuf *
	khttpd_mbuf_json_data(struct khttpd_mbuf_json *_dst);
struct mbuf *
	khttpd_mbuf_json_move(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_delete(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_null(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_boolean(struct khttpd_mbuf_json *_dst, bool _val);
void	khttpd_mbuf_json_cstr(struct khttpd_mbuf_json *_dst, bool _is_str,
	    const char *_str);
void	khttpd_mbuf_json_bytes(struct khttpd_mbuf_json *_dst, bool _is_str,
	    const char *_begin, const char *_end);
void	khttpd_mbuf_json_mbuf(struct khttpd_mbuf_json *_dst, bool _is_str,
	    struct mbuf *_mbuf);
void	khttpd_mbuf_json_format(struct khttpd_mbuf_json *_dst, bool _is_str,
	    const char *_fmt, ...);
void	khttpd_mbuf_json_vformat(struct khttpd_mbuf_json *_dst, bool _is_str,
	    const char *_fmt, va_list _args);
void	khttpd_mbuf_json_object_begin(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_object_end(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_array_begin(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_array_end(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_property(struct khttpd_mbuf_json *_dst,
	    const char *_name);
void	khttpd_mbuf_json_now(struct khttpd_mbuf_json *_dst);
void	khttpd_mbuf_json_sockaddr(struct khttpd_mbuf_json *_dst,
	    const struct sockaddr *_sa);
