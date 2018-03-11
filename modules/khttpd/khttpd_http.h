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
struct sbuf;

struct khttpd_exchange;
struct khttpd_log;
struct khttpd_location;
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
	int  (*get)(struct khttpd_exchange *, void *, long, struct mbuf **);
	void (*put)(struct khttpd_exchange *, void *, struct mbuf *, bool *);
};

void	khttpd_http_error(struct khttpd_mbuf_json *);

struct khttpd_mbuf_json *
	khttpd_exchange_log_entry(struct khttpd_exchange *);
struct khttpd_socket *
	khttpd_exchange_socket(struct khttpd_exchange *);
const struct sockaddr *
	khttpd_exchange_client_address(struct khttpd_exchange *);
const struct sockaddr *
	khttpd_exchange_server_address(struct khttpd_exchange *);
int	khttpd_exchange_method(struct khttpd_exchange *);
struct khttpd_location *
	khttpd_exchange_location(struct khttpd_exchange *);
const char *
	khttpd_exchange_query(struct khttpd_exchange *);
const char *
	khttpd_exchange_suffix(struct khttpd_exchange *);
const char *
	khttpd_exchange_host(struct khttpd_exchange *);
size_t	khttpd_exchange_host_length(struct khttpd_exchange *);
void   *khttpd_exchange_ops_arg(struct khttpd_exchange *);
void	khttpd_exchange_set_ops(struct khttpd_exchange *, 
	    struct khttpd_exchange_ops *, void *);
const char *
	khttpd_exchange_target(struct khttpd_exchange *);
size_t	khttpd_exchange_target_length(struct khttpd_exchange *);
bool	khttpd_exchange_request_is_chunked(struct khttpd_exchange *);
bool	khttpd_exchange_response_is_chunked(struct khttpd_exchange *);
size_t	khttpd_exchange_request_content_length(struct khttpd_exchange *);
bool	khttpd_exchange_has_request_content_length(struct khttpd_exchange *);
bool	khttpd_exchange_has_response_content_length(struct khttpd_exchange *);
bool	khttpd_exchange_request_content_type(struct khttpd_exchange *_xchg,
	    struct sbuf *_dst);
bool	khttpd_exchange_is_json_request(struct khttpd_exchange *, bool);
const char *
	khttpd_exchange_request_header(struct khttpd_exchange *_exchange,
	    size_t *_size_out);
void	khttpd_exchange_enable_chunked_response(struct khttpd_exchange *);
void	khttpd_exchange_clear_response_header(struct khttpd_exchange *_xchg);
void	khttpd_exchange_add_response_field(struct khttpd_exchange *_xchg,
	    const char *_field, const char *_fmt, ...);
void	khttpd_exchange_add_response_field_line(struct khttpd_exchange *_xchg,
	    const char *_begin, const char *_end);
void	khttpd_exchange_vadd_response_field(struct khttpd_exchange *_xchg,
	    const char *_field, const char *_fmt, va_list _args);
void	khttpd_exchange_set_response_content_length
	    (struct khttpd_exchange *_xchg, off_t _length);
void	khttpd_exchange_close(struct khttpd_exchange *_xchg);
void	khttpd_exchange_set_response_body(struct khttpd_exchange *_xchg,
	    struct mbuf *_data);
void	khttpd_exchange_set_response_body_json(struct khttpd_exchange *_xchg,
	    struct khttpd_mbuf_json *_response);
bool	khttpd_exchange_set_response_body_problem_json
	    (struct khttpd_exchange *_xchg, int _status,
	    struct khttpd_mbuf_json *_info);
void	khttpd_exchange_set_error_response_body(struct khttpd_exchange *, int,
	    struct khttpd_mbuf_json *);
void	khttpd_exchange_respond(struct khttpd_exchange *_xchg, int _status);
void	khttpd_exchange_respond_immediately(struct khttpd_exchange *_xchg,
	    int _status);
void	khttpd_exchange_reject(struct khttpd_exchange *_xchg);
void	khttpd_exchange_reset(struct khttpd_exchange *_xchg);
void	khttpd_exchange_continue_sending(struct khttpd_exchange *);
void	khttpd_exchange_continue_receiving(struct khttpd_exchange *);
void	khttpd_http_accept_http_client(struct khttpd_port *_port);
void	khttpd_http_accept_https_client(struct khttpd_port *_port);
