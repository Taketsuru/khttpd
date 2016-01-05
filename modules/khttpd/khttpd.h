/*-
 * Copyright (c) 2016 Taketsuru <taketsuru11@gmail.com>.
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
#include <sys/sbuf.h>

#include <machine/stdarg.h>

#define KHTTPD_VERSION	1100000

enum {
	KHTTPD_METHOD_UNKNOWN,

	KHTTPD_METHOD_ACL,
	KHTTPD_METHOD_BASELINE_CONTROL,
	KHTTPD_METHOD_BIND,
	KHTTPD_METHOD_CHECKIN,
	KHTTPD_METHOD_CHECKOUT,
	KHTTPD_METHOD_CONNECT,
	KHTTPD_METHOD_COPY,
	KHTTPD_METHOD_DELETE,
	KHTTPD_METHOD_GET,
	KHTTPD_METHOD_HEAD,
	KHTTPD_METHOD_LABEL,
	KHTTPD_METHOD_LINK,
	KHTTPD_METHOD_LOCK,
	KHTTPD_METHOD_MERGE,
	KHTTPD_METHOD_MKACTIVITY,
	KHTTPD_METHOD_MKCALENDAR,
	KHTTPD_METHOD_MKCOL,
	KHTTPD_METHOD_MKREDIRECTREF,
	KHTTPD_METHOD_MKWORKSPACE,
	KHTTPD_METHOD_MOVE,
	KHTTPD_METHOD_OPTIONS,
	KHTTPD_METHOD_ORDERPATCH,
	KHTTPD_METHOD_PATCH,
	KHTTPD_METHOD_POST,
	KHTTPD_METHOD_PRI,
	KHTTPD_METHOD_PROPFIND,
	KHTTPD_METHOD_PROPPATCH,
	KHTTPD_METHOD_PUT,
	KHTTPD_METHOD_REBIND,
	KHTTPD_METHOD_REPORT,
	KHTTPD_METHOD_SEARCH,
	KHTTPD_METHOD_TRACE,
	KHTTPD_METHOD_UNBIND,
	KHTTPD_METHOD_UNCHECKOUT,
	KHTTPD_METHOD_UNLINK,
	KHTTPD_METHOD_UNLOCK,
	KHTTPD_METHOD_UPDATE,
	KHTTPD_METHOD_UPDATEREDIRECTREF,
	KHTTPD_METHOD_VERSION_CONTROL,

	KHTTPD_METHOD_END
};

enum {
	KHTTPD_FIELD_UNKNOWN,

	KHTTPD_FIELD_CONTENT_LENGTH,
	KHTTPD_FIELD_TRANSFER_ENCODING,
	KHTTPD_FIELD_CONNECTION,
	KHTTPD_FIELD_EXPECT,
	KHTTPD_FIELD_COOKIE,
	KHTTPD_FIELD_HOST,
	KHTTPD_FIELD_REFERER,
	KHTTPD_FIELD_UPGRADE,
	KHTTPD_FIELD_USER_AGENT,
	KHTTPD_FIELD_VARY,
	KHTTPD_FIELD_WWW_AUTHENTICATE,
	KHTTPD_FIELD_IF,
	KHTTPD_FIELD_IF_MATCH,
	KHTTPD_FIELD_IF_MODIFIED_SINCE,
	KHTTPD_FIELD_IF_NONE_MATCH,
	KHTTPD_FIELD_IF_RANGE,
	KHTTPD_FIELD_IF_SCHEDULE_TAG_MATCH,
	KHTTPD_FIELD_IF_UNMODIFIED_SINCE,

	KHTTPD_FIELD_END
};

struct khttpd_config_args {
	int	*fds;
	int	nfds;
};

#define KHTTPD_IOC 'h'

#define KHTTPD_IOC_CONFIG				\
	_IOW(KHTTPD_IOC, 0, struct khttpd_config_args)

#ifndef KHTTPD_SYS_PREFIX
#define KHTTPD_SYS_PREFIX "/sys"
#endif

#ifdef _KERNEL

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
struct khttpd_header;
struct khttpd_header_field;

typedef void (*khttpd_received_header_t)(struct khttpd_socket *,
    struct khttpd_request *);
typedef void (*khttpd_received_body_t)(struct khttpd_socket *,
    struct khttpd_request *, struct mbuf *);
typedef void (*khttpd_end_of_message_t)(struct khttpd_socket *,
    struct khttpd_request *);
typedef int (*khttpd_transmit_t)(struct khttpd_socket *,
    struct khttpd_request *, struct khttpd_response *, struct mbuf **);
typedef void (*khttpd_request_dtor_t)(struct khttpd_request *, void *);
typedef void (*khttpd_route_dtor_t)(struct khttpd_route *);
typedef int (*khttpd_command_proc_t)(void *);

struct khttpd_mbuf_pos {
	struct mbuf	*ptr;
	int		off;
	int		unget;
};

struct khttpd_route_type {
	const char		*name;
	khttpd_received_header_t received_header;
};

int khttpd_route_add(struct khttpd_route *root, const char *path,
    struct khttpd_route_type *route_type);
void khttpd_route_remove(struct khttpd_route *route);
struct khttpd_route *khttpd_route_find(struct khttpd_route *root,
    const char *target, const char **suffix);
void khttpd_route_set_data(struct khttpd_route *route, void *data,
    khttpd_route_dtor_t dtor);
void *khttpd_route_data(struct khttpd_route *route);
const char *khttpd_route_path(struct khttpd_route *route);
struct khttpd_route_type *khttpd_route_type(struct khttpd_route *route);

void khttpd_received_header_null(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_end_of_message_null(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_received_body_null(struct khttpd_socket *socket,
    struct khttpd_request *request, struct mbuf *m);
void khttpd_request_dtor_null(struct khttpd_request *request, void *data);

void khttpd_mbuf_vprintf(struct mbuf *outbuf, const char *fmt, va_list ap);
void khttpd_mbuf_printf(struct mbuf *outbuf, const char *fmt, ...);
struct mbuf *khttpd_mbuf_append(struct mbuf *output, const char *begin,
    const char *end);
struct mbuf *khttpd_mbuf_append_ch(struct mbuf *output, char ch);
int khttpd_mbuf_next_segment(struct khttpd_mbuf_pos *iter, int term_ch);
int khttpd_mbuf_copy_segment(struct khttpd_mbuf_pos *pos, int term_ch,
    char *buffer, size_t size, char **end_out);
int khttpd_mbuf_parse_digits(struct khttpd_mbuf_pos *pos, uintmax_t *out);
void khttpd_mbuf_base64_encode(struct mbuf *output, const char *buf,
    size_t size);
int khttpd_mbuf_base64_decode(struct khttpd_mbuf_pos *iter, void **buf_out,
    size_t *size_out);
void khttpd_mbuf_pos_init(struct khttpd_mbuf_pos *iter, struct mbuf *ptr,
    int off);
void khttpd_mbuf_pos_copy(struct khttpd_mbuf_pos *src,
    struct khttpd_mbuf_pos *dst);
int khttpd_mbuf_getc(struct khttpd_mbuf_pos *iter);
void khttpd_mbuf_ungetc(struct khttpd_mbuf_pos *iter, int ch);
char *khttpd_find_ch_in(const char *begin, const char *end, char ch1);
char *khttpd_find_ch_in2(const char *begin, const char *end,
    char ch1, char ch2);

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
void khttpd_json_array_add(struct khttpd_json *value,
    struct khttpd_json *elem);
struct khttpd_json *khttpd_json_array_get(struct khttpd_json *value,
    int index);
struct khttpd_json *khttpd_json_object_new(int size_hint);
void khttpd_json_object_add(struct khttpd_json *value,
    struct khttpd_json *name, struct khttpd_json *elem);
struct khttpd_json *khttpd_json_object_get(struct khttpd_json *value,
    const char *name);
struct khttpd_json *khttpd_json_object_get_at(struct khttpd_json *value,
    int index, struct khttpd_json **name_out);
int khttpd_json_object_size(struct khttpd_json *value);
int khttpd_json_parse(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit);
struct mbuf *khttpd_json_mbuf_append_string_wo_quote(struct mbuf *output,
    const char *begin, const char *end);
struct mbuf *khttpd_json_mbuf_append_string_in_mbuf_wo_quote(struct mbuf *output,
    struct mbuf *source);
struct mbuf *khttpd_json_mbuf_append_string(struct mbuf *output,
    const char *begin, const char *end);
struct mbuf *khttpd_json_mbuf_append_string_in_mbuf(struct mbuf *output,
    struct mbuf *source);
struct mbuf *khttpd_json_mbuf_append_cstring(struct mbuf *output,
    const char *str);
void khttpd_json_mbuf_skip_ws(struct khttpd_mbuf_pos *iter);
int khttpd_mbuf_next_list_element(struct khttpd_mbuf_pos *pos,
    struct sbuf *output);
boolean_t khttpd_mbuf_list_contains_token(struct khttpd_mbuf_pos *pos,
    char *token, boolean_t ignore_case);

void khttpd_request_hold(struct khttpd_request *request);
void khttpd_request_free(struct khttpd_request *request);
const char *khttpd_request_target(struct khttpd_request *request);
const char *khttpd_request_suffix(struct khttpd_request *request);
void khttpd_request_set_body_proc(struct khttpd_request *request,
    khttpd_received_body_t, khttpd_end_of_message_t);
void khttpd_request_set_data(struct khttpd_request *request, void *data,
    khttpd_request_dtor_t dtor);
void* khttpd_request_data(struct khttpd_request *request);
int khttpd_request_method(struct khttpd_request *request);
struct khttpd_route *khttpd_request_route(struct khttpd_request *request);

struct khttpd_response *khttpd_response_alloc(void);
void khttpd_response_free(struct khttpd_response *);
void khttpd_response_set_status(struct khttpd_response *response, int code);
void khttpd_response_set_connection_close(struct khttpd_response *response);
void khttpd_response_set_body_proc(struct khttpd_response *response,
    khttpd_transmit_t proc, off_t content_length);
void khttpd_response_set_body_mbuf(struct khttpd_response *response,
    struct mbuf *data);
void khttpd_response_set_body_bytes(struct khttpd_response *response,
    void *data, size_t size, void (*free)(void *));
void khttpd_response_add_field(struct khttpd_response *response,
    const char *field, const char *value_fmt, ...);
void khttpd_response_vadd_field(struct khttpd_response *response,
    const char *field, const char *value_fmt, va_list va);

void khttpd_socket_hold(struct khttpd_socket *socket);
void khttpd_socket_free(struct khttpd_socket *socket);
int khttpd_socket_fd(struct khttpd_socket *socket);

struct khttpd_server *khttpd_get_admin_server(void);
struct khttpd_route *khttpd_server_route_root(struct khttpd_server *);

void khttpd_set_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

void khttpd_transmit_finished(struct khttpd_socket *socket);
void khttpd_ready_to_send(struct khttpd_socket *socket);

void khttpd_set_continue_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
void khttpd_set_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *content, boolean_t close);
void khttpd_set_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *reason, const char *description, boolean_t close);
void khttpd_set_moved_permanently_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *target);
void khttpd_set_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_set_length_required_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_set_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_set_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_set_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_set_conflict_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_set_uri_too_long_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_set_method_not_allowed_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close, 
    const char *allowed_methods);
void khttpd_set_request_header_field_too_large_response
(struct khttpd_socket *socket, struct khttpd_request *request);
void khttpd_set_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_set_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods);

int khttpd_run_proc(khttpd_command_proc_t proc, void *argument);

extern struct proc *khttpd_proc;

#endif	/* _KERNEL */
