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
#include <sys/sbuf.h>

struct mbuf;

enum {
	KHTTPD_FIELD_UNKNOWN = -1,

	KHTTPD_FIELD_CONTENT_LENGTH,
	KHTTPD_FIELD_TRANSFER_ENCODING,
	KHTTPD_FIELD_CONNECTION,
	KHTTPD_FIELD_EXPECT,
	KHTTPD_FIELD_HOST,

	KHTTPD_FIELD_CONTENT_TYPE,
	KHTTPD_FIELD_LOCATION,
	KHTTPD_FIELD_STATUS,

	KHTTPD_FIELD_END
};

enum {
	KHTTPD_FIELD_ERROR_LONG_LINE,
	KHTTPD_FIELD_ERROR_FOLD_LINE,
	KHTTPD_FIELD_ERROR_NO_SEPARATOR,
	KHTTPD_FIELD_ERROR_NO_NAME,
	KHTTPD_FIELD_ERROR_WS_FOLLOWING_NAME,
};

struct khttpd_field_parser {
	struct sbuf	line;
	struct mbuf    *ptr;
	struct mbuf    *tail;
	u_int		off;
	u_int		maxlen;
	bool		consume;
	char		buf[512];
};

int	khttpd_field_find(const char *, const char *);
int	khttpd_field_maxlen(void);
const char *
	khttpd_field_name(int);
int	khttpd_field_parse(struct khttpd_field_parser *_parser, void *_arg,
	    int (*_found_fn)(void *_arg, int _field, const char *_name,
		const char *_value),
	    int (*_error_fn)(void *_arg, int _reason, const char *_line));
void	khttpd_field_parse_add_data(struct khttpd_field_parser *_parser,
	    struct mbuf *_data);
void	khttpd_field_parse_destroy(struct khttpd_field_parser *_parser);
void	khttpd_field_parse_init(struct khttpd_field_parser *_parser,
	    u_int _maxlen, bool _consume, struct mbuf *_data, u_int off);
