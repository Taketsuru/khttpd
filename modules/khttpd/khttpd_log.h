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

#ifdef _KERNEL

#include <sys/param.h>
#include <machine/stdarg.h>

struct mbuf;
struct khttpd_log;
struct khttpd_mbuf_json;

struct khttpd_log *khttpd_log_new(void);
void khttpd_log_delete(struct khttpd_log *log);
void khttpd_log_set_fd(struct khttpd_log *log, int fd);
void khttpd_log_close(struct khttpd_log *log);
void khttpd_log_put(struct khttpd_log *log, struct mbuf *m);

const char *khttpd_log_get_severity_label(int severity);

void khttpd_log_put_timestamp_property(struct khttpd_mbuf_json *entry);
void khttpd_log_put_severity_property(struct khttpd_mbuf_json *entry,
	int severity);
void khttpd_log_put_error_properties(struct khttpd_mbuf_json *entry,
    int severity, const char *description_fmt, ...);
void khttpd_log_vput_error_properties(struct khttpd_mbuf_json *entry,
    int severity, const char *description_fmt, va_list args);

#endif	/* _KERNEL */
