/*-
 * Copyright (c) 2015 Taketsuru <taketsuru11@gmail.com>.
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
#include <sys/ioccom.h>
#include <sys/socket.h>

struct khttpd_address_info {
	struct sockaddr_storage ai_addr;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
};

enum {
	KHTTPD_LOG_DEBUG,
	KHTTPD_LOG_ERROR,
	KHTTPD_LOG_ACCESS,

	KHTTPD_LOG_COUNT
};

struct khttpd_log_conf {
	int	type;
	u_int	mask;
	char	*path;
};

#define KHTTPD_IOC 'h'

#define KHTTPD_IOC_CONFIGURE_LOG	\
	_IOW(KHTTPD_IOC, 0, struct khttpd_log_conf)
#define KHTTPD_IOC_ADD_SERVER_PORT	\
	_IOW(KHTTPD_IOC, 1, struct khttpd_address_info)

#define KHTTPD_LOG_DEBUG_MESSAGE	0x00000001
#define KHTTPD_LOG_DEBUG_TRACE		0x00000002
#define KHTTPD_LOG_DEBUG_ALL		0x00000003

#ifdef _KERNEL

struct khttpd_mbuf_iter {
	struct mbuf	*ptr;
	int		off;
	int		unget;
};

enum {
	KHTTPD_TRANSFER_CODING_UNKNOWN,

	KHTTPD_TRANSFER_CODING_CHUNKED,
	KHTTPD_TRANSFER_CODING_COMPRESS,
	KHTTPD_TRANSFER_CODING_DEFLATE,
	KHTTPD_TRANSFER_CODING_GZIP,

	KHTTPD_TRANSFER_CODING_COUNT
};

enum {
	KHTTPD_JSON_ARRAY = 1,
	KHTTPD_JSON_OBJECT,
	KHTTPD_JSON_INTEGER,
	KHTTPD_JSON_BOOL,
	KHTTPD_JSON_STRING,
	KHTTPD_JSON_NULL,
};

struct kevent;
struct mbuf;

struct khttpd_json;
struct khttpd_request;
struct khttpd_response;
struct khttpd_route;
struct khttpd_socket;

typedef void (*khttpd_received_header_t)(struct khttpd_socket *,
    struct khttpd_request *);
typedef void (*khttpd_received_body_t)(struct khttpd_socket *,
    struct khttpd_request *, const char *begin, const char *end);
typedef void (*khttpd_end_of_message_t)(struct khttpd_socket *,
    struct khttpd_request *);
typedef int (*khttpd_transmit_body_t)(struct khttpd_socket *,
    struct khttpd_request *, struct khttpd_response *);
typedef void (*khttpd_request_dtor_t)(struct khttpd_request *);
typedef void (*khttpd_response_dtor_t)(struct khttpd_response *);
typedef void (*khttpd_route_dtor_t)(struct khttpd_route *);

void khttpd_mbuf_vprintf(struct mbuf *outbuf, const char *fmt, va_list ap);
void khttpd_mbuf_printf(struct mbuf *outbuf, const char *fmt, ...);
void khttpd_base64_encode_to_mbuf(struct mbuf *output, const char *buf,
    size_t size);
int khttpd_base64_decode_from_mbuf(struct khttpd_mbuf_iter *iter,
    void **buf_out, size_t *size_out);
void khttpd_mbuf_iter_init(struct khttpd_mbuf_iter *iter, struct mbuf *ptr,
    int off);
int khttpd_mbuf_getc(struct khttpd_mbuf_iter *iter);
void khttpd_mbuf_ungetc(struct khttpd_mbuf_iter *iter, int ch);
void khttpd_mbuf_skip_json_ws(struct khttpd_mbuf_iter *iter);

void khttpd_json_hold(struct khttpd_json *value);
void khttpd_json_free(struct khttpd_json *value);
int khttpd_json_type(struct khttpd_json *value);
struct khttpd_json *khttpd_json_integer_new(int64_t value);
int64_t khttpd_json_integer_value(struct khttpd_json *value);
struct khttpd_json *khttpd_json_string_new(void);
const char *khttpd_json_string_data(struct khttpd_json *value);
int khttpd_json_string_size(struct khttpd_json *value);
void khttpd_json_string_append(struct khttpd_json *value, const char *begin,
    const char *end);
void khttpd_json_string_append_char(struct khttpd_json *value, int ch);
void khttpd_json_string_append_utf8(struct khttpd_json *value, int code);
struct khttpd_json *khttpd_json_array_new(void);
int khttpd_json_array_size(struct khttpd_json *value);
void khttpd_json_array_add(struct khttpd_json *value, struct khttpd_json *elem);
struct khttpd_json *khttpd_json_array_get(struct khttpd_json *value, int index);
struct khttpd_json *khttpd_json_object_new(int size_hint);
void khttpd_json_object_add(struct khttpd_json *value, struct khttpd_json *name,
    struct khttpd_json *elem);
struct khttpd_json *khttpd_json_object_get(struct khttpd_json *value,
    const char *name);
struct khttpd_json *khttpd_json_object_get_at(struct khttpd_json *value,
    int index, struct khttpd_json **name_out);
int khttpd_json_object_size(struct khttpd_json *value);
int khttpd_json_parse(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out, int depth_limit);

void khttpd_send_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

void khttpd_socket_acquire(struct khttpd_socket *socket);
void khttpd_socket_release(struct khttpd_socket *socket);

void khttpd_ready_to_send(struct khttpd_socket *socket);

void khttpd_send_continue_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
void khttpd_send_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *content, boolean_t close);
void khttpd_send_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_method_not_allowed_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close,
    const char *allowed_methods);
void khttpd_send_conflict_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods);

int khttpd_enable(void);
void khttpd_disable(void);

#endif
