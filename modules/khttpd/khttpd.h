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

#define KHTTPD_VERSION	1100000

enum {
	KHTTPD_LOG_DEBUG,
	KHTTPD_LOG_ERROR,
	KHTTPD_LOG_ACCESS,

	KHTTPD_LOG_END
};

enum {
	KHTTPD_TRANSFER_CODING_CHUNKED,
	KHTTPD_TRANSFER_CODING_COMPRESS,
	KHTTPD_TRANSFER_CODING_DEFLATE,
	KHTTPD_TRANSFER_CODING_GZIP,

	KHTTPD_TRANSFER_CODING_COUNT
};

enum {
	KHTTPD_METHOD_UNKNOWN = -1,
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
	KHTTPD_METHOD_VERSION_CONTROL
};

struct filedescent;
struct khttpd_mime_type_rule_set;

struct khttpd_address_info {
	struct sockaddr_storage ai_addr;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
};

struct khttpd_log_conf {
	int	type;
	u_int	mask;
	union {
		int		fd;
		struct filedescent *fde;
	};
};

struct khttpd_mount_args {
	char	*prefix;
	union {
		int			dirfd;
		struct filedescent	*fde;
	};
};

struct khttpd_set_mime_type_rules_args {
	char	*mount_point;
	size_t	bufsize;
	union {
		char	*buf;
		struct khttpd_mime_type_rule_set *rule_set;
	};
};

#define KHTTPD_IOC 'h'

#define KHTTPD_IOC_CONFIGURE_LOG			\
	_IOW(KHTTPD_IOC, 0, struct khttpd_log_conf)
#define KHTTPD_IOC_ADD_PORT				\
	_IOW(KHTTPD_IOC, 1, struct khttpd_address_info)
#define KHTTPD_IOC_MOUNT				\
	_IOW(KHTTPD_IOC, 2, struct khttpd_mount_args)
#define KHTTPD_IOC_SET_MIME_TYPE_RULES			\
	_IOW(KHTTPD_IOC, 3, struct khttpd_set_mime_type_rules_args)

#define KHTTPD_LOG_DEBUG_MESSAGE	0x00000001
#define KHTTPD_LOG_DEBUG_TRACE		0x00000002
#define KHTTPD_LOG_DEBUG_ALL		0x00000003

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
    struct khttpd_request *, const char *begin, const char *end);
typedef void (*khttpd_end_of_message_t)(struct khttpd_socket *,
    struct khttpd_request *);
typedef int (*khttpd_transmit_body_t)(struct khttpd_socket *,
    struct khttpd_request *, struct khttpd_response *);
typedef void (*khttpd_request_dtor_t)(struct khttpd_request *, void *);
typedef void (*khttpd_response_dtor_t)(struct khttpd_response *, void *);
typedef void (*khttpd_route_dtor_t)(struct khttpd_route *);
typedef int (*khttpd_command_proc_t)(void *);

struct khttpd_mbuf_iter {
	struct mbuf	*ptr;
	int		off;
	int		unget;
};

struct khttpd_route_type {
	const char		*name;
	khttpd_received_header_t received_header_fn;
};

int khttpd_route_add(struct khttpd_route *root, char *path,
    struct khttpd_route_type *route_type);
void khttpd_route_remove(struct khttpd_route *route);
struct khttpd_route *khttpd_route_find(struct khttpd_route *root,
    const char *target, const char **suffix);
void khttpd_route_set_data(struct khttpd_route *route, void *data,
    khttpd_route_dtor_t dtor);
void *khttpd_route_data(struct khttpd_route *route);
const char *khttpd_route_path(struct khttpd_route *route);
struct khttpd_route_type *khttpd_route_type(struct khttpd_route *route);

void khttpd_mbuf_vprintf(struct mbuf *outbuf, const char *fmt, va_list ap);
void khttpd_mbuf_printf(struct mbuf *outbuf, const char *fmt, ...);
struct mbuf *khttpd_mbuf_append(struct mbuf *output, const char *begin,
    const char *end);
struct mbuf *khttpd_mbuf_append_ch(struct mbuf *output, char ch);
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
struct mbuf *khttpd_json_mbuf_append_string(struct mbuf *output,
    const char *begin, const char *end);
void khttpd_json_mbuf_skip_ws(struct khttpd_mbuf_iter *iter);

struct khttpd_header_field *khttpd_header_find(struct khttpd_header *header,
    char *field_name, boolean_t include_trailer);
struct khttpd_header_field *khttpd_header_find_next(struct khttpd_header *header,
    struct khttpd_header_field *current, boolean_t include_trailer);
boolean_t
khttpd_header_value_includes(struct khttpd_header *header,
    char *field_name, char *token, boolean_t include_trailer);
int
khttpd_header_addv(struct khttpd_header *header,
    struct iovec *iov, int iovcnt);
int khttpd_header_add(struct khttpd_header *header, char *field);
void
khttpd_header_add_allow(struct khttpd_header *header,
    const char *allowed_methods);
void
khttpd_header_add_location(struct khttpd_header *header,
    const char *location);
void khttpd_header_add_content_length(struct khttpd_header *header,
    uint64_t size);
int
khttpd_header_list_iter_init(struct khttpd_header *header,
    char *name, struct khttpd_header_field **fp_out, char **cp_out,
    boolean_t include_trailer);
int
khttpd_header_list_iter_next(struct khttpd_header *header,
    struct khttpd_header_field **fp_inout, char **cp_inout,
    char **begin_out, char **end_out, boolean_t include_trailer);
int
khttpd_header_get_uint64(struct khttpd_header *header,
    char *name, uint64_t *value_out, boolean_t include_trailer);

struct khttpd_response *khttpd_response_alloc(void);
void khttpd_response_free(struct khttpd_response *);
void khttpd_response_set_status(struct khttpd_response *response, int code);
void khttpd_response_set_xmit_proc(struct khttpd_response *response,
    khttpd_transmit_body_t proc, void *procdata, khttpd_response_dtor_t dtor);
struct khttpd_header *khttpd_response_header(struct khttpd_response *response);
void khttpd_response_set_xmit_data_mbuf(struct khttpd_response *response,
    struct mbuf *data);

const char *khttpd_request_target(struct khttpd_request *request);
const char *khttpd_request_suffix(struct khttpd_request *request);
void khttpd_request_set_data(struct khttpd_request *request, void *data,
    khttpd_request_dtor_t dtor);
void* khttpd_request_data(struct khttpd_request *request);
void khttpd_request_set_body_receiver(struct khttpd_request *request,
    khttpd_received_body_t recv_proc, khttpd_end_of_message_t eom_proc);
int khttpd_request_method(struct khttpd_request *request);
struct khttpd_route *khttpd_request_route(struct khttpd_request *request);

void khttpd_send_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

void khttpd_socket_hold(struct khttpd_socket *socket);
void khttpd_socket_free(struct khttpd_socket *socket);
int khttpd_socket_fd(struct khttpd_socket *socket);

void khttpd_xmit_finished(struct khttpd_socket *socket);
void khttpd_ready_to_send(struct khttpd_socket *socket);

void khttpd_send_continue_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
void khttpd_send_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *content, boolean_t close);
void khttpd_send_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *reason, const char *description, boolean_t close);
void khttpd_send_moved_permanently_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *target);
void khttpd_send_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_conflict_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close);
void khttpd_send_method_not_allowed_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close,
    const char *allowed_methods);
void khttpd_send_request_header_field_too_large_response
(struct khttpd_socket *socket, struct khttpd_request *request);
void khttpd_send_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_send_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods);

int khttpd_run_proc(khttpd_command_proc_t proc, void *argument);

extern struct khttpd_route khttpd_route_root;
extern const char khttpd_crlf[2];

#endif	/* _KERNEL */
