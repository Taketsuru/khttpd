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

struct mbuf;
struct sbuf;

struct khttpd_exchange;
struct khttpd_log;
struct khttpd_mbuf_json;
struct khttpd_port;
enum khttpd_server_log_id;
struct khttpd_stream;

enum khttpd_http_log_id {
	KHTTPD_HTTP_LOG_ERROR,
	KHTTPD_HTTP_LOG_ACCESS,

	KHTTPD_HTTP_LOG_END
};

struct khttpd_exchange_ops {
	void (*dtor)(struct khttpd_exchange *, void *);
	int  (*send)(struct khttpd_exchange *, void *, struct khttpd_stream *,
	    size_t *);
	int  (*get)(struct khttpd_exchange *, void *, ssize_t, struct mbuf **,
	    boolean_t *);
	void (*put)(struct khttpd_exchange *, void *, struct mbuf *,
	    boolean_t *);
	void (*end)(struct khttpd_exchange *, void *);
};

void khttpd_http_set_log(enum khttpd_http_log_id, struct khttpd_log *);
struct khttpd_log *khttpd_http_get_log(enum khttpd_http_log_id);

struct khttpd_port *khttpd_exchange_get_port(struct khttpd_exchange *exchange);
void khttpd_exchange_set_ops(struct khttpd_exchange *exchange,
    struct khttpd_exchange_ops *ops, void *arg);
struct khttpd_location *khttpd_exchange_location(struct khttpd_exchange *);
void khttpd_exchange_error(struct khttpd_exchange *, 
    struct khttpd_mbuf_json *);
const char *khttpd_exchange_suffix(struct khttpd_exchange *exchange);
const char *khttpd_exchange_get_target(struct khttpd_exchange *exchange);
int khttpd_exchange_method(struct khttpd_exchange *exchange);
boolean_t khttpd_exchange_get_request_header_field(struct khttpd_exchange *,
    const char *, struct sbuf *);
boolean_t khttpd_exchange_is_request_media_type_json(struct khttpd_exchange *,
	boolean_t);
void khttpd_exchange_enable_chunked_transfer(struct khttpd_exchange *exchange);
void khttpd_exchange_add_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, ...);
void khttpd_exchange_vadd_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, va_list va);
void khttpd_exchange_set_response_content_length
    (struct khttpd_exchange *exchange, off_t length);
void khttpd_exchange_close(struct khttpd_exchange *exchange);
void khttpd_exchange_set_response_body(struct khttpd_exchange *exchange,
    struct mbuf *data);
void khttpd_exchange_set_response_body_json(struct khttpd_exchange *exchange,
    struct khttpd_mbuf_json *response);
boolean_t khttpd_exchange_set_response_body_problem_json
    (struct khttpd_exchange *exchange, int status,
     struct khttpd_mbuf_json *info);
void khttpd_exchange_set_error_response_body(struct khttpd_exchange *exchange,
    int status, struct khttpd_mbuf_json *info);
void khttpd_exchange_respond(struct khttpd_exchange *exchange, int status);
void khttpd_exchange_continue_sending(struct khttpd_exchange *);
void khttpd_exchange_continue_receiving(struct khttpd_exchange *);
struct khttpd_stream *khttpd_exchange_get_stream(struct khttpd_exchange *);

void khttpd_http_accept_http_client(void *port);
void khttpd_http_accept_https_client(void *port);

void khttpd_exchange_check_invariants(struct khttpd_exchange *exchange);

#endif	/* _KERNEL */
