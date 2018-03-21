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

#include <sys/param.h>
#include <sys/mbuf.h>

struct khttpd_stream;

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

struct khttpd_fields {
	char		*putp;
	char		*begin;
	char		*end;
	int		resid;
};

int	khttpd_field_find(const char *, const char *);
const char *
	khttpd_field_name(int);
int	khttpd_fields_receive(struct khttpd_fields *_fields, struct mbuf **_mb,
	    struct khttpd_stream *_stream);

inline void
khttpd_fields_init(struct khttpd_fields *_fields, char *_begin,
    size_t _bufsize, int _max_input_size)
{

	_fields->putp = _fields->begin = _begin;
	_fields->end = _begin + _bufsize;
	_fields->resid = _max_input_size;
}

inline char *
khttpd_fields_begin(struct khttpd_fields *_fields)
{

	return (_fields->begin);
}

inline char *
khttpd_fields_end(struct khttpd_fields *_fields)
{

	return (_fields->putp);
}

inline void
khttpd_fields_reset(struct khttpd_fields *_fields, int _max_input_size)
{

	_fields->putp = _fields->begin;
	_fields->resid = _max_input_size;
}
