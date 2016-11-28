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

#include <sys/types.h>
#include <machine/stdarg.h>

#include "khttpd_method.h"
#include "khttpd_refcount.h"

enum khttpd_server_log_id {
	KHTTPD_SERVER_LOG_ERROR,
	KHTTPD_SERVER_LOG_ACCESS,

	KHTTPD_SERVER_LOG_END
};

struct khttpd_costruct_info;
struct khttpd_exchange;
struct khttpd_json;
struct khttpd_location;
struct khttpd_location_ops;
struct khttpd_mbuf_json;
struct khttpd_server;
struct mbuf;
struct sbuf;

typedef void (*khttpd_method_fn_t)(struct khttpd_exchange *);
typedef void (*khttpd_location_fn_t)(struct khttpd_location *);
typedef boolean_t (*khttpd_location_set_error_response_fn_t)
    (struct khttpd_exchange *, int status, struct khttpd_mbuf_json *response);

struct khttpd_location_ops {
	khttpd_location_fn_t dtor;
	khttpd_location_set_error_response_fn_t set_error_response;
	khttpd_method_fn_t method[KHTTPD_METHOD_END];
	khttpd_method_fn_t catch_all;
};

extern struct khttpd_costruct_info *khttpd_server_costruct_info;
extern struct khttpd_costruct_info *khttpd_location_costruct_info;

KHTTPD_REFCOUNT1_PROTOTYPE(khttpd_location, khttpd_location);

struct khttpd_location *khttpd_location_new(int *error_out, 
    struct khttpd_server *server, const char *path,
    struct khttpd_location_ops *ops, void *data);
struct khttpd_location_ops *khttpd_location_get_ops
    (struct khttpd_location *location);
void *khttpd_location_data(struct khttpd_location *location);
void *khttpd_location_set_data(struct khttpd_location *location, void *data);
struct khttpd_log *khttpd_location_get_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id);
void khttpd_location_set_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id, struct khttpd_log *log);
void khttpd_location_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id, struct mbuf *entry);
void khttpd_location_error(struct khttpd_location *location, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, ...);
void khttpd_location_verror(struct khttpd_location *location, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, va_list args);
const char *khttpd_location_get_path(struct khttpd_location *location);
struct khttpd_server * khttpd_location_get_server
    (struct khttpd_location *);
struct khttpd_location *khttpd_location_get_parent(struct khttpd_location *);
void khttpd_location_get_options(struct khttpd_location *,
    struct sbuf *output);
void khttpd_location_hide(struct khttpd_location *);
void khttpd_location_show(struct khttpd_location *);

KHTTPD_REFCOUNT1_PROTOTYPE(khttpd_server, khttpd_server);

struct khttpd_server *khttpd_server_new(int *error_out);
struct khttpd_location *khttpd_server_find_location
    (struct khttpd_server *server,
     const char *begin, const char *end, const char **suffix_out);
struct khttpd_location *khttpd_server_first_location
    (struct khttpd_server *server);
struct khttpd_location *khttpd_server_next_location
    (struct khttpd_server *server, struct khttpd_location *);
void khttpd_server_set_log(struct khttpd_server *server,
    enum khttpd_server_log_id log_id, struct khttpd_log *log);
struct khttpd_log *khttpd_server_get_log(struct khttpd_server *server,
    enum khttpd_server_log_id log_id);
void khttpd_server_error(struct khttpd_server *server, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, ...);
void khttpd_server_verror(struct khttpd_server *server, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, va_list args);

int khttpd_location_check_invariants(struct khttpd_location *location,
    struct khttpd_server *server);
int khttpd_server_check_invariants(struct khttpd_server *server);

#endif	/* _KERNEL */
