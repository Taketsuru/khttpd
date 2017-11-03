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
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "khttpd_http.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/stack.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/smp.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/file.h>
#include <sys/sysproto.h>
#include <sys/syslog.h>
#include <sys/syscallsubr.h>
#include <sys/un.h>
#include <vm/uma.h>

#include <netinet/in.h>
#include <netinet/tcp.h>

#include "khttpd_init.h"
#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_refcount.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_stream.h"
#include "khttpd_string.h"
#include "khttpd_strtab.h"
#include "khttpd_vhost.h"
#include "khttpd_webapi.h"

enum {
	KHTTPD_FIELD_UNKNOWN = -1,

	KHTTPD_FIELD_CONTENT_LENGTH,
	KHTTPD_FIELD_TRANSFER_ENCODING,
	KHTTPD_FIELD_CONNECTION,
	KHTTPD_FIELD_EXPECT,
	KHTTPD_FIELD_HOST,

	KHTTPD_FIELD_END
};

struct khttpd_session;

struct khttpd_exchange {
	struct sbuf		target;
	struct khttpd_exchange_ops *ops;
	void			*arg;

	/*
	 * Members from khttpd_exchange_zctor_begin to
	 * khttpd_exchange_zctor_end is cleared by ctor.
	 */
#define khttpd_exchange_zctor_begin	request_content_length
	off_t			request_content_length;
	off_t			request_payload_size;
	off_t			response_content_length;
	off_t			response_payload_size;
	struct khttpd_location	*location;
	const char		*query;
	const char		*suffix;
	struct mbuf		*request_line;
	struct mbuf		*request_trailer;
	struct mbuf		*response_header;
	struct mbuf		*response_trailer;
	struct mbuf		*response_buffer;
	unsigned		close:1;
	unsigned		close_requested:1;
	unsigned		continue_requested:1;
	unsigned		target_includes_nul:1;
	unsigned		request_has_content_length:1;
	unsigned		request_chunked:1;
	unsigned		response_has_content_length:1;
	unsigned		response_chunked:1;
	unsigned		response_header_closed:1;
	unsigned		response_pending:1;
	u_short			status;

#define khttpd_exchange_zctor_end	method
	signed char		method;
	u_char			version_minor;
	char			target_buffer[128];
};

typedef int (*khttpd_session_fn_t)(struct khttpd_session *);

struct khttpd_session {
	/*
	 * khttpd_exchange_get_session assumes member 'exchange' is the first
	 * member of struct khttpd_session.
	 */
	struct khttpd_exchange  exchange;
	/*
	 * The up side of the following stream is khttpd_session.  The down
	 * side is a struct khttpd_tls_context or a struct khttpd_socket.
	 */
	struct khttpd_stream	stream;
	struct sbuf		host;
	struct khttpd_socket	*socket;
	off_t			recv_limit;
	khttpd_session_fn_t	receive;
	uma_zone_t		zone;

#define khttpd_session_zero_begin server
	struct khttpd_server	*server;
	struct khttpd_port	*port;
	struct mbuf		*recv_leftovers;
	struct mbuf		*recv_ptr;
	struct mbuf		*recv_bol_ptr;
	struct mbuf		*recv_tail;
	int32_t			recv_off;
	int32_t			recv_bol_off;
	unsigned		recv_found_bol:1;
	unsigned		recv_in_chunk_or_trailer:1;
	unsigned		recv_paused:1;
	unsigned		xmit_waiting_for_drain:1;
#define khttpd_session_zero_end host_buf

	char			host_buf[32];
};

struct khttpd_http_client {
	struct khttpd_session	session;
};

struct khttpd_https_socket {
	struct khttpd_session	session;
	// struct khttpd_tls_context	tls;
	// stream (socket <-> TLS layer)
	// struct khttpd_stream		stream;
};

static void khttpd_session_transmit_finish(struct khttpd_session *session,
    struct mbuf *m);

static void khttpd_session_terminate_received_mbufs
    (struct khttpd_session *session);
static void khttpd_session_set_receive_limit(struct khttpd_session *session,
    off_t size);
static int khttpd_session_receive_and_ignore(struct khttpd_session *);
static int khttpd_session_receive_body(struct khttpd_session *);
static int khttpd_session_receive_header_or_trailer(struct khttpd_session *);
static int khttpd_session_receive_request_line(struct khttpd_session *);
static void khttpd_session_data_is_available(struct khttpd_stream *);
static void khttpd_session_clear_to_send(struct khttpd_stream *);
static void khttpd_session_transmit(struct khttpd_session *session);

/* --------------------------------------------------- variable definitions */

static struct khttpd_strtab_entry khttpd_fields[] = {
	{ "Content-Length" },
	{ "Transfer-Encoding" },
	{ "Connection" },
	{ "Expect" },
	{ "Host" },
};

CTASSERT(sizeof(khttpd_fields) / sizeof(khttpd_fields[0]) == KHTTPD_FIELD_END);

/*
 * This value must be larger than the length of the longest name in
 * khttpd_fields.
 *
 * When the server finds a field whose name is longer than this value, it
 * respond with KHTTPD_STATUS_HEADER_FIELDS_TOO_LARGE.
 */
#define KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH	32

static const char khttpd_crlf[] = { '\r', '\n' };
static struct khttpd_strtab_entry_slist khttpd_field_hash_table[16];
static size_t khttpd_message_size_limit = 16384;
static uma_zone_t khttpd_http_client_zone;

static struct khttpd_stream_up_ops khttpd_session_ops = {
	.data_is_available = khttpd_session_data_is_available,
	.clear_to_send = khttpd_session_clear_to_send,
};

static struct khttpd_exchange_ops khttpd_exchange_null_ops;

static int
khttpd_field_find(const char *begin, const char *end)
{
	struct khttpd_strtab_entry *entry;

	entry = khttpd_strtab_find(khttpd_field_hash_table,
		sizeof(khttpd_field_hash_table) /
	    sizeof(khttpd_field_hash_table[0]), begin, end, TRUE);

	return (entry == NULL ? KHTTPD_FIELD_UNKNOWN :
	    entry - khttpd_fields);
}

static struct khttpd_session *
khttpd_exchange_get_session(struct khttpd_exchange *exchange)
{

	return ((struct khttpd_session *)exchange);
}

static void
khttpd_exchange_access(struct khttpd_exchange *exchange)
{
	struct khttpd_mbuf_json entry;
	struct khttpd_session *session;
	struct khttpd_location *location;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	session = khttpd_exchange_get_session(exchange);
	location = exchange->location;

	khttpd_mbuf_json_new(&entry);
	khttpd_mbuf_json_object_begin(&entry);

	if (exchange->request_payload_size != 0)
		khttpd_mbuf_json_property_format(&entry, "requestPayloadSize",
		    FALSE, "%ju", (uintmax_t)exchange->request_payload_size);

	if (exchange->response_payload_size != 0)
		khttpd_mbuf_json_property_format(&entry, "responsePayloadSize",
		    FALSE, "%ju", (uintmax_t)exchange->response_payload_size);

	khttpd_mbuf_json_property_format(&entry, "status", FALSE, "%d",
	    exchange->status);
	khttpd_mbuf_json_property_object_begin(&entry, "peer");
	khttpd_mbuf_json_sockaddr(&entry, 
	    khttpd_socket_peer_address(session->socket));
	khttpd_mbuf_json_object_end(&entry);
	khttpd_mbuf_json_property_mbuf_1st_line(&entry, "request",
	    exchange->request_line);

	khttpd_location_log(location, KHTTPD_SERVER_LOG_ACCESS,
	    khttpd_mbuf_json_move(&entry));
}

static void
khttpd_exchange_init(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	sbuf_new(&exchange->target, exchange->target_buffer,
	    sizeof(exchange->target_buffer), SBUF_AUTOEXTEND);

	exchange->ops = &khttpd_exchange_null_ops;

	bzero(&exchange->khttpd_exchange_zctor_begin, 
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_end) -
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_begin));
}

static void
khttpd_exchange_fini(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	sbuf_delete(&exchange->target);
}

static void
khttpd_exchange_clear(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	if (exchange->ops->dtor != NULL)
		exchange->ops->dtor(exchange, exchange->arg);

	sbuf_clear(&exchange->target);
	khttpd_location_release(exchange->location);
	m_freem(exchange->request_line);
	m_freem(exchange->request_trailer);
	m_freem(exchange->response_header);
	m_freem(exchange->response_trailer);
	m_freem(exchange->response_buffer);

	exchange->ops = &khttpd_exchange_null_ops;

	bzero(&exchange->khttpd_exchange_zctor_begin, 
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_end) -
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_begin));
}

void
khttpd_exchange_respond(struct khttpd_exchange *exchange, int status)
{
	struct mbuf *m;
	struct khttpd_session *session;
	boolean_t xmit_completed;

	KHTTPD_ENTRY("%s(%p,%d), close_requested=%d, close=%d", __func__,
	    exchange, status, exchange->close_requested, exchange->close);

	session = khttpd_exchange_get_session(exchange);
	exchange->status = status;

	if (session->receive != NULL) {
		KHTTPD_BRANCH("%s postponed", __func__);
		exchange->response_pending = TRUE;
		return;
	}

	if (exchange->close_requested)
		khttpd_exchange_close(exchange);

	if (exchange->close)
		session->receive = NULL;

	m = m_gethdr(M_WAITOK, MT_DATA);
	status = exchange->status;
	khttpd_mbuf_printf(m, "HTTP/1.%d %d n/a\r\n", exchange->version_minor,
	    status);

	exchange->response_header_closed = TRUE;
	m_cat(m, exchange->response_header);
	exchange->response_header = NULL;

	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));

	if (status == 204 || status == 304 ||
	    exchange->method == KHTTPD_METHOD_HEAD) {
		xmit_completed = TRUE;

	} else if (exchange->response_chunked) {
		xmit_completed = FALSE;

	} else if (0 < exchange->response_content_length) {
		if (exchange->response_buffer != NULL) {
			exchange->response_payload_size = 
			    m_length(exchange->response_buffer, NULL);
			m_cat(m, exchange->response_buffer);
			exchange->response_buffer = NULL;
		}

		xmit_completed = exchange->response_content_length <=
		    exchange->response_payload_size;

	} else {
		xmit_completed = TRUE;
	}

	if (xmit_completed)
		khttpd_session_transmit_finish(session, m);
	else {
		khttpd_stream_send(&session->stream, m, 0);
		khttpd_session_transmit(session);
	}
}

void
khttpd_exchange_continue_sending(struct khttpd_exchange *exchange)
{
	struct khttpd_session *session;

	session = khttpd_exchange_get_session(exchange);
	KASSERT(session->receive == NULL,
	    ("invalid state.  session->receive=%p", session->receive));

	khttpd_session_transmit(khttpd_exchange_get_session(exchange));
}

void
khttpd_exchange_continue_receiving(struct khttpd_exchange *exchange)
{
	struct khttpd_session *session;

	session = khttpd_exchange_get_session(exchange);
	KASSERT(session->receive == khttpd_session_receive_body,
	    ("invalid state.  session->receive=%p", session->receive));

	session->recv_paused = FALSE;
	khttpd_session_data_is_available(&session->stream);
}

static void
khttpd_session_abort(struct khttpd_session *session)
{

	khttpd_session_terminate_received_mbufs(session);
	session->receive = NULL;
	khttpd_exchange_close(&session->exchange);
}

static void
khttpd_exchange_reject(struct khttpd_exchange *exchange)
{
	int status;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	status = KHTTPD_STATUS_BAD_REQUEST;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);

	khttpd_session_abort(khttpd_exchange_get_session(exchange));
	khttpd_exchange_respond(exchange, status);
}

struct khttpd_port *
khttpd_exchange_get_port(struct khttpd_exchange *exchange)
{

	return (khttpd_exchange_get_session(exchange)->port);
}

void
khttpd_exchange_set_ops(struct khttpd_exchange *exchange,
    struct khttpd_exchange_ops *ops, void *arg)
{

	exchange->ops = ops;
	exchange->arg = arg;
}

struct khttpd_location *
khttpd_exchange_location(struct khttpd_exchange *exchange)
{

	return (exchange->location);
}

const char *
khttpd_exchange_suffix(struct khttpd_exchange *exchange)
{

	return (exchange->suffix);
}

const char *
khttpd_exchange_get_target(struct khttpd_exchange *exchange)
{

	return (sbuf_data(&exchange->target));
}

int
khttpd_exchange_method(struct khttpd_exchange *exchange)
{

	return (exchange->method);
}

int
khttpd_exchange_get_request_header_field(struct khttpd_exchange *exchange,
    const char *name, struct sbuf *dst)
{
	struct khttpd_mbuf_pos pos;

	khttpd_mbuf_pos_init(&pos, exchange->request_line, 0);
	return (!khttpd_mbuf_next_line(&pos) ? EINVAL :
	    !khttpd_mbuf_get_header_field(&pos, name, dst) ? ENOENT : 0);
}

boolean_t
khttpd_exchange_is_request_media_type_json(struct khttpd_exchange *exchange,
	boolean_t default_is_json)
{
	char content_type_buf[32];
	struct sbuf content_type;
	boolean_t has_content_type, result;

	sbuf_new(&content_type, content_type_buf, sizeof(content_type_buf),
	    SBUF_AUTOEXTEND);
	has_content_type = khttpd_exchange_get_request_header_field(exchange,
	    "Content-Type", &content_type);
	sbuf_finish(&content_type);

	result = has_content_type ? 
	    khttpd_is_json_media_type(sbuf_data(&content_type)) :
	    default_is_json;

	sbuf_delete(&content_type);

	return (result);
}

void
khttpd_exchange_enable_chunked_transfer(struct khttpd_exchange *exchange)
{

	khttpd_exchange_add_response_field(exchange, "Transfer-Encoding",
	    "chunked");
	exchange->response_chunked = TRUE;
}

void khttpd_exchange_add_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, ...)
{
	va_list vl;

	va_start(vl, value_fmt);
	khttpd_exchange_vadd_response_field(exchange, field, value_fmt, vl);
	va_end(vl);
}

void
khttpd_exchange_vadd_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, va_list vl)
{
	struct mbuf *m;

	if (exchange->response_header_closed) {
		if (!exchange->response_chunked)
			khttpd_exchange_error(exchange, LOG_ERR,
			    "Field %s is added to a response but "
			    "the payload transfer has been started.", field);
		m = exchange->response_trailer;
		if (m == NULL)
			exchange->response_trailer = m = 
			    m_gethdr(M_WAITOK, MT_DATA);
	} else {
		m = exchange->response_header;
		if (m == NULL)
			exchange->response_header = m =
			    m_gethdr(M_WAITOK, MT_DATA);
	}

	khttpd_mbuf_printf(m, "%s: ", field);
	khttpd_mbuf_vprintf(m, value_fmt, vl);
	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));
}

void
khttpd_exchange_set_response_content_length(struct khttpd_exchange *exchange,
    off_t length)
{

	KASSERT(!exchange->response_has_content_length,
	    ("Content-Length has already been set"));

	khttpd_exchange_add_response_field(exchange, "Content-Length", "%jd",
	    (uintmax_t)length);
	exchange->response_has_content_length = TRUE;
	exchange->response_content_length = length;
}

void
khttpd_exchange_close(struct khttpd_exchange *exchange)
{

	if (exchange->close)
		return;

	exchange->close = TRUE;
	khttpd_exchange_add_response_field(exchange, "Connection", "%s",
	    "close");
}

void
khttpd_exchange_set_response_body(struct khttpd_exchange *exchange,
    struct mbuf *data)
{
	off_t len;

	KASSERT(!exchange->response_chunked &&
	    !exchange->response_has_content_length,
	    ("chunked=%d, response_has_content_length=%d",
		exchange->response_chunked,
		exchange->response_has_content_length));

	len = m_length(data, NULL);
	khttpd_exchange_set_response_content_length(exchange, len);
	exchange->response_buffer = data;
}

void
khttpd_exchange_set_response_body_json(struct khttpd_exchange *exchange,
    struct khttpd_mbuf_json *response)
{

	khttpd_exchange_set_response_body(exchange, 
	    khttpd_mbuf_json_move(response));
	khttpd_exchange_add_response_field(exchange, "Content-Type",
	    "application/json");
}

boolean_t
khttpd_exchange_set_response_body_problem_json
    (struct khttpd_exchange *exchange, int status,
     struct khttpd_mbuf_json *response)
{

	khttpd_exchange_set_response_body(exchange, 
	    khttpd_mbuf_json_move(response));
	khttpd_exchange_add_response_field(exchange, "Content-Type",
	    "application/problem+json");

	return (TRUE);
}

void
khttpd_exchange_set_error_response_body(struct khttpd_exchange *exchange,
    int status, struct khttpd_mbuf_json *response)
{
	struct khttpd_location *location;
	struct khttpd_mbuf_json new_resp;
	khttpd_location_set_error_response_fn_t fn;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, exchange, status, response);

	if (response == NULL) {
		response = &new_resp;
		khttpd_mbuf_json_new(response);
		khttpd_mbuf_json_object_begin(response);
		khttpd_webapi_set_problem(response, status, NULL, NULL);
	}

	khttpd_mbuf_json_object_end(response);

	for (location = khttpd_exchange_location(exchange);
	     location != NULL;
	     location = khttpd_location_get_parent(location)) {
		fn = khttpd_location_get_ops(location)->set_error_response;
		if (fn != NULL && fn(exchange, status, response))
			break;
	}
	if (location == NULL)
		khttpd_exchange_set_response_body_problem_json(exchange,
		    status, response);
}

static boolean_t
khttpd_exchange_parse_target_uri(struct khttpd_exchange *exchange, 
    struct khttpd_mbuf_pos *pos)
{
	ssize_t query_off;
	int code, error, i, n;
	char ch;

	error = 0;
	query_off = -1;
	for (;;) {
		ch = khttpd_mbuf_getc(pos);
		switch (ch) {

		case '\n':
			exchange->query = NULL;
			return (TRUE);

		case ' ':
			goto end;

		case '?':
			sbuf_putc(&exchange->target, '\0');
			query_off = sbuf_len(&exchange->target);
			continue;

		case '%':
			code = 0;
			n = 0;
			for (i = 0; i < 2; ++i) {
				code <<= 4;
				ch = khttpd_mbuf_getc(pos);
				if ('0' <= ch && ch <= '9')
					code |= ch - '0';

				else if ('A' <= ch && ch <= 'F')
					code |= ch - 'A' + 10;

				else if ('a' <= ch && ch <= 'f')
					code |= ch - 'a' + 10;

				else
					return (TRUE);
			}

			if (code == 0)
				exchange->target_includes_nul = TRUE;

			sbuf_putc(&exchange->target, code);
			continue;

		case ':': case '@': case '/':
		case '!': case '$': case '&': case '\'':
		case '(': case ')': case '*': case '+':
		case ',': case ';': case '=':
		case '-': case '.': case '_': case '~':
			sbuf_putc(&exchange->target, ch);
			break;

		default:
			if (!isalpha(ch) && !isdigit(ch))
				return (TRUE);
			sbuf_putc(&exchange->target, ch);
		}
	}

end:
	error = sbuf_finish(&exchange->target);

	if (error == 0)
		exchange->query = query_off < 0 ? NULL :
		    sbuf_data(&exchange->target) + query_off;

	return (FALSE);
}

void
khttpd_exchange_error(struct khttpd_exchange *exchange, int severity,
    const char *fmt, ...)
{
	va_list ap;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, exchange, severity);

	va_start(ap, fmt);
	khttpd_exchange_verror(exchange, severity, fmt, ap);
	va_end(ap);
}

void
khttpd_exchange_verror(struct khttpd_exchange *exchange, int severity,
    const char *fmt, va_list ap)
{
	struct khttpd_mbuf_json entry;
	struct khttpd_session *session;
	struct khttpd_location *location;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, exchange, severity);

	session = khttpd_exchange_get_session(exchange);
	location = exchange->location;

	khttpd_mbuf_json_new(&entry);
	khttpd_mbuf_json_object_begin(&entry);
	khttpd_mbuf_json_property_object_begin(&entry, "peer");
	khttpd_mbuf_json_sockaddr(&entry, 
	    khttpd_socket_peer_address(session->socket));
	khttpd_mbuf_json_object_end(&entry);
	khttpd_mbuf_json_property_mbuf_1st_line(&entry, "request",
		exchange->request_line);

	if (location != NULL)
		khttpd_location_verror(location, severity, &entry, fmt, ap);
}

static void
khttpd_exchange_default_options_handler(struct khttpd_exchange *exchange)
{
	char buf[256];
	struct sbuf sbuf;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_location_get_options(khttpd_exchange_location(exchange), &sbuf);
	sbuf_finish(&sbuf);
	khttpd_exchange_set_response_content_length(exchange, 0);
	khttpd_exchange_add_response_field(exchange, "Allow", "%s",
	    sbuf_data(&sbuf));
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
	sbuf_delete(&sbuf);
}

static void
khttpd_exchange_check_leftovers(struct khttpd_exchange *exchange,
    const char *name, struct mbuf *m)
{
	struct mbuf *ptr;

	for (; m != NULL; m = m->m_next)
		for (ptr = khttpd_exchange_get_session(exchange)->recv_leftovers;
		     ptr != NULL; ptr = ptr->m_next)
			if (m == ptr)
				panic("mbuf %p in %s is also in "
				    "session->recv_leftover", m, name);
}

void
khttpd_exchange_check_invariants(struct khttpd_exchange *exchange)
{

	khttpd_exchange_check_leftovers(exchange, "request_line",
	    exchange->request_line);
	khttpd_exchange_check_leftovers(exchange, "request_trailer",
	    exchange->request_trailer);
	khttpd_exchange_check_leftovers(exchange, "response_header",
	    exchange->response_header);
	khttpd_exchange_check_leftovers(exchange, "response_trailer",
	    exchange->response_trailer);
	khttpd_exchange_check_leftovers(exchange, "response_buffer",
	    exchange->response_buffer);
}

static void
khttpd_session_init(struct khttpd_session *session,
    struct khttpd_stream_down_ops *ops, uma_zone_t zone)
{
	struct khttpd_stream *stream;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	khttpd_exchange_init(&session->exchange);

	stream = &session->stream;
	stream->up_ops = &khttpd_session_ops;
	stream->down_ops = ops;
	stream->up = session;

	sbuf_new(&session->host, session->host_buf, sizeof(session->host_buf),
	    SBUF_AUTOEXTEND);

	session->zone = zone;
}

static void
khttpd_session_fini(struct khttpd_session *session)
{

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	sbuf_delete(&session->host);
	khttpd_exchange_fini(&session->exchange);
}

static void
khttpd_session_ctor(struct khttpd_session *session)
{

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	session->recv_limit = khttpd_message_size_limit;
	session->receive = khttpd_session_receive_request_line;
	bzero(&session->khttpd_session_zero_begin,
	    offsetof(struct khttpd_session, khttpd_session_zero_end) -
	    offsetof(struct khttpd_session, khttpd_session_zero_begin));
}

static void
khttpd_session_dtor(struct khttpd_session *session)
{

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	khttpd_exchange_clear(&session->exchange);
	khttpd_stream_destroy(&session->stream);
	m_freem(session->recv_leftovers);
	sbuf_clear(&session->host);
	khttpd_server_release(session->server);
	khttpd_port_release(session->port);
}

static void
khttpd_session_next(struct khttpd_session *session)
{
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	khttpd_session_set_receive_limit(session, khttpd_message_size_limit);
	exchange = &session->exchange;
	session->receive = exchange->close ? khttpd_session_receive_and_ignore :
	    khttpd_session_receive_request_line;
	khttpd_exchange_clear(exchange);
	if (session->recv_paused)
		khttpd_session_data_is_available(&session->stream);
}

static void
khttpd_session_transmit_finish(struct khttpd_session *session, struct mbuf *m)
{
	struct khttpd_exchange *exchange;
	int flags;
	boolean_t full;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, session, m);

	exchange = &session->exchange;
	flags = exchange->close ? KHTTPD_STREAM_CLOSE : KHTTPD_STREAM_FLUSH;
	full = khttpd_stream_send(&session->stream, m, flags);

	khttpd_exchange_access(exchange);

	if (full) {
		session->xmit_waiting_for_drain = TRUE;
		khttpd_stream_notify_of_drain(&session->stream);
	} else
		khttpd_session_next(session);
}

static void
khttpd_session_transmit(struct khttpd_session *session)
{
	struct mbuf *head, *m;
	struct khttpd_exchange *exchange;
	size_t sent;
	int error;
	boolean_t pause;

	exchange = &session->exchange;

	if (exchange->ops->get != NULL) {
		head = NULL;
		error = exchange->ops->get(exchange, exchange->arg, &head,
		    &pause);
		if (error == ENOMSG && exchange->response_chunked) {
			if (pause)
				khttpd_exchange_error(exchange, LOG_ERR, 
				    "exchange_ops::get for \"//%s/%s\" try to "
				    "pause the server but the transfer has "
				    "been completed");

			head = m_gethdr(M_WAITOK, MT_DATA);
			khttpd_mbuf_printf(head, "0\r\n");
			m_cat(head, exchange->response_trailer);
			exchange->response_trailer = NULL;
			khttpd_mbuf_printf(head, "\r\n");
			khttpd_session_transmit_finish(session, head);

			return;
		}

		if (error != 0)
			return;

		sent = m_length(head, NULL);
		exchange->response_payload_size += sent;

		if (exchange->response_chunked) {
			m = m_gethdr(M_WAITOK, MT_DATA);
			khttpd_mbuf_printf(m, "%jx\r\n", (uintmax_t)sent);
			m_cat(m, head);
			khttpd_mbuf_printf(m, "\r\n");
			head = m;
			khttpd_stream_send(&session->stream, head, 0);
			if (!pause)
				khttpd_stream_notify_of_drain(&session->stream);

		} else if (exchange->response_payload_size <
		    exchange->response_content_length) {
			khttpd_stream_send(&session->stream, head, 0);
			if (!pause)
				khttpd_stream_notify_of_drain(&session->stream);

		} else if (pause)
			khttpd_exchange_error(exchange, LOG_ERR, 
			    "exchange_ops::get for \"//%s/%s\" try to pause the "
			    "server but the transfer has been completed");

		else
			khttpd_session_transmit_finish(session, head);

	} else if (exchange->ops->send != NULL) {

		sent = 0;
		error = exchange->ops->send(exchange, exchange->arg,
		    &session->stream, &sent);
		if (error != 0)
			return;

		if (exchange->response_content_length - 
		    exchange->response_payload_size < sent) {
			khttpd_exchange_error(exchange, LOG_ERR, "khttpd: "
			    "exchange_ops->get for \"%s\" has been sent more "
			    "than the residual. "
			    "(sent: %zu, residual: %zu)",
			    sbuf_data(&exchange->target),
			    sent, exchange->response_content_length - 
			    exchange->response_payload_size);
			khttpd_session_abort(session);
			khttpd_session_transmit_finish(session, NULL);
			return;
		}

		exchange->response_payload_size += sent;

		if (exchange->response_content_length <=
		    exchange->response_payload_size)
			khttpd_session_transmit_finish(session, NULL);

	} else {
		log(LOG_ERR, "khttpd: exchange op for target \"%s\""
		    "doesn't have neither get nor send method",
		    sbuf_data(&exchange->target));

		exchange->close = TRUE;
		khttpd_session_transmit_finish(session, NULL);
	}
}

static int
khttpd_session_receive_and_ignore(struct khttpd_session *session)
{
	struct mbuf *m, *next;
	off_t resid;
	int error;

	for (m = session->recv_leftovers; m != NULL; m = next) {
		next = m->m_next;

		if (m == session->recv_ptr) {
			session->recv_ptr = NULL;
			session->recv_off = 0;
		}
	}

	if (session->recv_ptr != NULL) {
		m_freem(session->recv_ptr);
		session->recv_ptr = NULL;
		session->recv_off = 0;
	}

	resid = SSIZE_MAX;
	error = khttpd_stream_receive(&session->stream, &resid, &m);
	if (error != 0)
		return (error);
	if (resid == SSIZE_MAX)
		return (ENOMSG);

	m_freem(m);

	return (0);
}

static void
khttpd_session_receive_finish(struct khttpd_session *session)
{
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, session);

	khttpd_session_terminate_received_mbufs(session);
	session->receive = NULL;

	exchange = &session->exchange;

	if (exchange->ops->end != NULL)
		exchange->ops->end(exchange, exchange->arg);

	if (exchange->response_pending)
		khttpd_exchange_respond(exchange, exchange->status);
}

static void
khttpd_session_set_receive_limit(struct khttpd_session *session,
    off_t size)
{
	int len;

	KHTTPD_ENTRY("%s(%p,%ld)", __func__, session, size);

	len = m_length(session->recv_ptr, NULL) - session->recv_off;
	session->recv_limit = size - len;
}

static int
khttpd_session_read(struct khttpd_session *session)
{
	struct mbuf *m;
	ssize_t n, resid;
	int error;

	KHTTPD_ENTRY("%s(%p) recv_limit=%ld", __func__, session,
	    session->recv_limit);

	n = MIN(SSIZE_MAX, session->recv_limit);
	if (n <= 0) {
		KHTTPD_BRANCH("enobufs");
		return (ENOBUFS);
	}

	resid = n;
	error = khttpd_stream_receive(&session->stream, &resid, &m);
	if (error != 0) {
		KHTTPD_BRANCH("error %d", error);
		return (error);
	}

	if (resid == n)
		return (ENOMSG);

	session->recv_limit -= n - resid;
	if (session->recv_ptr == NULL)
		session->recv_ptr = m;
	else
		session->recv_tail->m_next = m;
	session->recv_tail = m == NULL ? NULL : m_last(m);

	return (0);
}

/*
 * RETURN VALUES
 *
 * If successful, khttpd_session_next_line() returns 0.  They return one of the
 * following values on failure.
 *   
 * [EWOULDBLOCK]	More bytes are necessary.
 * 
 * [ENOMSG]		Reaches the end of the stream before it finds a CRLF.
 *
 * [ENOBUFS]		Have read more than session->recv_limit bytes.
 *
 * Others		Any other return values from soreceive().
 */
static int
khttpd_session_next_line(struct khttpd_session *session, 
    struct khttpd_mbuf_pos *bol)
{
	const char *begin, *cp, *end;
	struct mbuf *ptr;
	int32_t off;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	/*
	 * If there is no receiving mbuf chain, receive from the socket.
	 */

	if (session->recv_ptr == NULL) {
		error = khttpd_session_read(session);

		if (error == ENOMSG)
			khttpd_mbuf_pos_init(bol, NULL, 0);

		if (error != 0)
			return (error);
	}

	ptr = session->recv_ptr;
	off = session->recv_off;

	if (session->recv_bol_ptr == NULL) {
		session->recv_bol_ptr = ptr;
		session->recv_bol_off = off;
	}

	for (;;) {
		/* Find the first '\n' in the mbuf pointed by ptr. */

		begin = mtod(ptr, char *);
		end = begin + ptr->m_len;
		cp = khttpd_find_ch_in(begin + off, end, '\n');
		if (cp != NULL) {
			session->recv_ptr = ptr;
			session->recv_off = cp + 1 - begin;
			khttpd_mbuf_pos_init(bol, session->recv_bol_ptr,
			    session->recv_bol_off);
			session->recv_bol_ptr = NULL;
			return (0);
		}

		if (ptr->m_next != NULL) {
			/* Advance to the next mbuf */
			ptr = ptr->m_next;
			off = 0;

		} else {
			/*
			 * No '\n' found.  Receive further if we reached the
			 * end of the chain.
			 */

			session->recv_ptr = ptr;
			session->recv_off = off = ptr->m_len;
			error = khttpd_session_read(session);

			if (error == ENOMSG) {
				khttpd_mbuf_pos_init(bol,
				    session->recv_bol_ptr, 
				    session->recv_bol_off);
				session->recv_bol_ptr = NULL;
			}

			if (error != 0)
				return (error);
		}
	}
}

static void
khttpd_session_terminate_received_mbufs(struct khttpd_session *session)
{
	struct mbuf *ptr;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	if (session->recv_ptr == NULL)
		return;

	KASSERT(session->recv_leftovers == NULL,
	    ("recv_leftovers=%p(data=%p)", session->recv_leftovers,
		mtod(session->recv_leftovers, char *)));

	ptr = m_split(session->recv_ptr, session->recv_off, M_WAITOK);
	session->recv_ptr = session->recv_leftovers = ptr;
	session->recv_off = 0;
	session->recv_tail = ptr == NULL ? NULL : m_last(ptr);
}

static int
khttpd_session_receive_chunk(struct khttpd_session *session)
{
	struct khttpd_mbuf_pos pos;
	off_t len;
	struct khttpd_exchange *exchange;
	int error, nibble, status;
	char ch;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;

	error = khttpd_session_next_line(session, &pos);
	if (error == EWOULDBLOCK)
		return (error);
	if (error != 0) {
		KHTTPD_BRANCH("%s %p reject %u error %d",
		    __func__, exchange, __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (error);
	}

	len = 0;
	for (;;) {
		ch = khttpd_mbuf_getc(&pos);
		if (!isxdigit(ch)) {
			khttpd_mbuf_ungetc(&pos, ch);
			break;
		}

		nibble = isdigit(ch) ? ch - '0' :
		    'A' <= ch && ch <= 'F' ? ch - 'A' + 10 :
		    ch - 'a' + 10;

		if ((len << 4) < len)
			goto too_large;

		len = (len << 4) + nibble;
	}

	khttpd_session_terminate_received_mbufs(session);
	m_freem(pos.ptr);

	if (len == 0)
		session->receive = khttpd_session_receive_header_or_trailer;

	else if (OFF_MAX - exchange->request_payload_size < len)
		goto too_large;

	else {
		exchange->request_payload_size += len;
		khttpd_session_set_receive_limit(session, len);
		session->receive = khttpd_session_receive_body;
	}

	return (0);

 too_large:
	status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);

	khttpd_session_abort(session);
	khttpd_exchange_respond(exchange, status);

	return (0);
}

static int
khttpd_session_receive_chunk_terminator(struct khttpd_session *session)
{
	struct khttpd_mbuf_pos pos;
	struct khttpd_exchange *exchange;
	int ch, error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;

	error = khttpd_session_next_line(session, &pos);
	if (error == EWOULDBLOCK)
		return (error);
	if (error != 0) {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (error);
	}

	ch = khttpd_mbuf_getc(&pos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&pos);
	if (ch != '\n') {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	session->receive = khttpd_session_receive_chunk;

	return (0);
}

static int
khttpd_session_receive_body(struct khttpd_session *session)
{
	off_t resid;
	struct khttpd_exchange *exchange;
	struct thread *td;
	struct mbuf *m, *tail;
	int error;
	boolean_t pause;

	KHTTPD_ENTRY("%s(%p)", __func__, session);
	KASSERT(session->recv_leftovers == session->recv_ptr &&
	    session->recv_off == 0,
	    ("recv_leftovers=%p, recv_ptr=%p, recv_off=%d",
		session->recv_leftovers, session->recv_ptr, session->recv_off));

	td = curthread;
	exchange = &session->exchange;
	pause = FALSE;

	m = session->recv_ptr;
	if (m != NULL) {
		session->recv_ptr = NULL;
		resid = exchange->request_content_length -
		    exchange->request_payload_size;
		tail = m_split(m, resid, M_WAITOK);
		session->recv_leftovers = session->recv_ptr = tail;
		session->recv_off = 0;
		exchange->request_payload_size += resid;

		if (exchange->ops->put == NULL)
			m_freem(m);
		else
			exchange->ops->put(exchange, exchange->arg, m, &pause);

	}

	session->recv_limit = exchange->request_content_length -
	    exchange->request_payload_size;
	while (0 < session->recv_limit) {
		if (pause)
			return (EBUSY);

		error = khttpd_session_read(session);
		if (error == EWOULDBLOCK)
			return (error);
		if (error != 0) {
			khttpd_exchange_reject(exchange);
			return (error);
		}

		m = session->recv_ptr;
		session->recv_ptr = NULL;
		exchange->request_payload_size =
		    exchange->request_content_length - session->recv_limit;

		if (exchange->ops->put == NULL)
			m_freem(m);
		else
			exchange->ops->put(exchange, exchange->arg, m, &pause);
	}

	if (pause)
		khttpd_exchange_error(exchange, LOG_ERR,
		    "exchange_ops::put for \"//%s/%s\" try to pause but "
		    "the request body has already been transfered "
		    "completely.", sbuf_data(&session->host), 
		    sbuf_data(&exchange->target));

	if (session->recv_in_chunk_or_trailer) {
		khttpd_session_set_receive_limit(session,
		    khttpd_message_size_limit);
		session->receive = khttpd_session_receive_chunk_terminator;
		return (0);
	}

	khttpd_session_receive_finish(session);

	return (0);
}

static void
khttpd_session_end_of_header_or_trailer(struct khttpd_session *session)
{
	khttpd_method_fn_t handler;
	struct khttpd_location_ops *ops;
	struct khttpd_exchange *exchange;
	struct mbuf *m;
	int method, status;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;
	khttpd_session_terminate_received_mbufs(session);

	/*
	 * If this is the end of a trailer, we've done for this request
	 * message.
	 */

	if (session->recv_in_chunk_or_trailer) {
		session->recv_in_chunk_or_trailer = FALSE;
		khttpd_session_receive_finish(session);
		return;
	}

	/*
	 * If the request doesn't have Host field, send a 'bad request'
	 * response.
	 *
	 * The handler of Host: field sets exchange->location.  It's always
	 * non-null because khttpd_server_find_location never returns null.
	 */

	if (exchange->location == NULL) {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return;
	}

	/* 
	 * If the given method is unknown, send response with "Not Implemented"
	 * status.
	 */

	if (exchange->method == KHTTPD_METHOD_UNKNOWN) {
		status = KHTTPD_STATUS_NOT_IMPLEMENTED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);
		goto quit;
	}

	/* 
	 * If the target includes a NUL character, send response with "Not
	 * Found" status.
	 */

	if (exchange->target_includes_nul) {
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);
		goto quit;
	}

	/* Call method handler. */

	ops = khttpd_location_get_ops(exchange->location);
	method = exchange->method;
	handler = ops->method[method];
	if (handler == NULL)
		switch (method) {
		case KHTTPD_METHOD_OPTIONS:
			handler = khttpd_exchange_default_options_handler;
			break;
		case KHTTPD_METHOD_HEAD:
			handler = ops->method[KHTTPD_METHOD_GET];
			break;
		default:
			;	/* nothing */
		}

	if (handler != NULL)
		(*handler)(exchange);

	else {
		status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);
	}

 quit:
	/* exchange_ops::send doesn't support chunked transfer. */

	if (exchange->response_chunked && exchange->ops->get == NULL)
		exchange->response_chunked = FALSE;

	/* Send continue response if it has been requested. */

	if (exchange->status == 0 && exchange->continue_requested &&
	    (0 < exchange->request_content_length || 
		exchange->request_chunked)) {
		m = m_gethdr(M_WAITOK, MT_DATA);
		khttpd_mbuf_printf(m, "HTTP/1.1 100 Continue\r\n\r\n");
		khttpd_stream_send(&session->stream, m, KHTTPD_STREAM_FLUSH);
	}

	/*
	 * Start receiving chunked payload if chunked Transfer-Encoding is
	 * specified.
	 */

	session->recv_in_chunk_or_trailer = exchange->request_chunked;
	if (session->recv_in_chunk_or_trailer) {
		khttpd_session_set_receive_limit(session,
		    khttpd_message_size_limit);
		session->receive = khttpd_session_receive_chunk;
		return;
	}

	/* If the message has no body, finish the processing of the request. */

	if (!exchange->request_has_content_length ||
	    exchange->request_content_length == 0) {
		khttpd_session_receive_finish(session);
		return;
	}

	/* Start receiving the body of the message. */

	khttpd_session_set_receive_limit(session, 
	    exchange->request_content_length);
	session->receive = khttpd_session_receive_body;
}

static void
khttpd_session_receive_host_field(struct khttpd_session *session,
    struct khttpd_mbuf_pos *pos)
{
	char buf[sizeof(session->host_buf)];
	struct sbuf host;
	struct khttpd_exchange *exchange;
	struct khttpd_location *location;
	struct khttpd_server *server;
	const char *target;
	int ch;

	KHTTPD_ENTRY("%s(%p,{%p,%d,%d})", __func__, session, pos->ptr,
	    pos->off, pos->unget);

	exchange = &session->exchange;

	if (exchange->location != NULL) {
		/* there is more than one host fields in a request */
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return;
	}

	sbuf_new(&host, buf, sizeof(buf), SBUF_AUTOEXTEND);

	for (;;) {
		ch = khttpd_mbuf_getc(pos);

		switch (ch) {

		case '\n':
			khttpd_mbuf_ungetc(pos, ch);
			goto out;

		case -1:
		case ':':
			goto out;

		case '\r':
			ch = khttpd_mbuf_getc(pos);
			khttpd_mbuf_ungetc(pos, ch);
			if (ch == '\n')
				goto out;
			/* FALLTHROUGH */

		default:
			sbuf_putc(&host, ch);
			break;
		}
	}
 out:
	sbuf_finish(&host);

	if (sbuf_done(&session->host) &&
	    strcmp(sbuf_data(&session->host), sbuf_data(&host)) == 0) {
		server = session->server;

	} else {
		/* 
		 * Find the server.  If the specified Host doesn't exist, send
		 * a 'bad request' response.
		 */

		server = khttpd_vhost_find_server(session->port,
		    sbuf_data(&host));
		if (server == NULL) {
			KHTTPD_BRANCH("%s %p reject %u", __func__, exchange,
			    __LINE__);
			sbuf_delete(&host);
			khttpd_exchange_reject(exchange);
			return;
		}

		session->server = server;
		sbuf_cpy(&session->host, sbuf_data(&host));
		sbuf_finish(&session->host);
	}

	sbuf_delete(&host);

	/* Find the route corresponds to the request target. */

	target = sbuf_data(&exchange->target);
	exchange->location = location = khttpd_server_find_location(server,
	    target, target + sbuf_len(&exchange->target), &exchange->suffix);
}

static void
khttpd_session_receive_content_length_field(struct khttpd_session *session,
    struct khttpd_mbuf_pos *pos)
{
	struct khttpd_exchange *exchange;
	uintmax_t value;
	int error, status;

	KHTTPD_ENTRY("%s(%p,{%p,%d,%d})", __func__, session, pos->ptr,
	    pos->off, pos->unget);

	exchange = &session->exchange;

	error = khttpd_mbuf_parse_digits(pos, &value);
	if (error == ERANGE || OFF_MAX < value) {
		status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_session_abort(session);
		khttpd_exchange_respond(exchange, status);
		return;
	}

	if (error != 0 || exchange->request_has_content_length) {
		KHTTPD_BRANCH("%s %p reject %u error %d",
		    __func__, exchange, __LINE__, error);
		khttpd_exchange_reject(exchange);
		return;
	}

	exchange->request_has_content_length = TRUE;
	exchange->request_content_length = value;
}

static void
khttpd_session_receive_transfer_encoding_field(struct khttpd_session *session,
    struct khttpd_mbuf_pos *pos)
{
	char token_buffer[8];
	struct khttpd_mbuf_json diag;
	struct khttpd_exchange *exchange;
	struct sbuf token;
	int error, status;

	KHTTPD_ENTRY("%s(%p,{%p,%d,%d})", __func__, session, pos->ptr, pos->off,
	    pos->unget);

	sbuf_new(&token, token_buffer, sizeof(token_buffer), SBUF_FIXEDLEN);

	exchange = &session->exchange;
	for (;;) {
		sbuf_clear(&token);

		error = khttpd_mbuf_next_list_element(pos, &token);
		if (error != 0) {
			if (error != ENOMSG)
				log(LOG_ERR, "khttpd: "
				    "khttpd_mbuf_next_list_element failed "
				    "(error: %d)", error);
			break;
		}

		if (sbuf_len(&token) == 0)
			continue;

		if (exchange->request_chunked ||
		    strcasecmp(sbuf_data(&token), "chunked") != 0) {
			status = KHTTPD_STATUS_NOT_IMPLEMENTED;

			khttpd_mbuf_json_new(&diag);
			khttpd_mbuf_json_object_begin(&diag);
			khttpd_webapi_set_problem(&diag, status, NULL, NULL);
			khttpd_webapi_set_problem_detail(&diag, "transfer "
			    "encoding other than 'chunked' is specified");
			khttpd_exchange_set_error_response_body(exchange,
			    status, &diag);

			khttpd_session_abort(session);
			khttpd_exchange_respond(exchange, status);
			break;
		}

		exchange->request_chunked = TRUE;
	}

	sbuf_delete(&token);
}

static void
khttpd_session_receive_connection_field(struct khttpd_session *session,
    struct khttpd_mbuf_pos *pos)
{

	KHTTPD_ENTRY("%s(%p,{%p,%d,%d})", __func__, session, pos->ptr, pos->off,
	    pos->unget);
	session->exchange.close_requested =
	    khttpd_mbuf_list_contains_token(pos, "close", TRUE);
}

static void
khttpd_session_receive_expect_field(struct khttpd_session *session,
    struct khttpd_mbuf_pos *pos)
{
	char token_buffer[16];
	struct khttpd_exchange *exchange;
	struct sbuf token;
	int error;

	KHTTPD_ENTRY("%s(%p,{%p,%d,%d})", __func__, session, pos->ptr, pos->off,
	    pos->unget);

	exchange = &session->exchange;

	if (exchange->version_minor < 1 || exchange->continue_requested)
		return;

	sbuf_new(&token, token_buffer, sizeof(token_buffer), SBUF_FIXEDLEN);

	for (;;) {
		sbuf_clear(&token);

		error = khttpd_mbuf_next_list_element(pos, &token);
		if (error == ENOMSG)
			break;

		if (error != 0 || sbuf_len(&token) == 0)
			continue;

		if (strcasecmp(sbuf_data(&token), "100-continue") == 0) {
			exchange->continue_requested = TRUE;
			break;
		}
	}

	sbuf_delete(&token);
}

static int
khttpd_session_receive_header_or_trailer(struct khttpd_session *session)
{
	char field[KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH];
	struct khttpd_mbuf_pos pos, tmppos;
	struct khttpd_exchange *exchange;
	char *end;
	int ch, error, field_enum, status;
	boolean_t last_ch_is_ws;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;

	/* Get a line */

	error = khttpd_session_next_line(session, &pos);
	switch (error) {

	case 0:
		break;

	case EWOULDBLOCK:
		return (error);

	case ENOBUFS:
		status = KHTTPD_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_session_abort(session);
		khttpd_exchange_respond(exchange, status);
		return (0);

	default:
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	/*
	 * If it's an empty line, we reached the end of a header or a trailer.
	 */

	khttpd_mbuf_pos_copy(&pos, &tmppos);
	ch = khttpd_mbuf_getc(&tmppos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&tmppos);
	if (ch == '\n') {
		khttpd_session_end_of_header_or_trailer(session);
		return (0);
	}

	/*
	 * If it's the first line of a trailer, take the ownership of the
	 * receiving mbuf chain.
	 */

	if (session->recv_in_chunk_or_trailer &&
	    exchange->request_trailer == NULL) {
		exchange->request_trailer = session->recv_leftovers;
		session->recv_leftovers = NULL;
	}

	/*
	 * Extract the field name from the line.  If the character just before
	 * ':' is a white space, set 'bad request' response.
	 */

	error = khttpd_mbuf_copy_segment(&pos, ':', field, sizeof(field) - 1,
	    &end);
	if (error == ENOMEM) {
		/*
		 * Because this field is longer than any known field names,
		 * looking up the table is not necessary.
		 */

		last_ch_is_ws = end[-1] == ' ';
		for (;;) {
			ch = khttpd_mbuf_getc(&pos);
			if (ch == ':' && !last_ch_is_ws)
				break;
			if (ch == ':' || ch == '\n') {
				KHTTPD_BRANCH("%s %p reject %u ch %c",
				    __func__, exchange, __LINE__, ch);
				khttpd_exchange_reject(exchange);
				break;
			}
			last_ch_is_ws = ch == ' ';
		}

		return (0);
	}
	if (error != 0 || end[-1] == ' ') {
		KHTTPD_BRANCH("%s %p reject %u error %d",
		    __func__, exchange, __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	/* If it's a field in a trailer, done */

	if (session->recv_in_chunk_or_trailer)
		return (0);

	/* If the extracted field name is not a known name, done. */

	*end = '\0';
	field_enum = khttpd_field_find(field, end);
	if (field_enum == KHTTPD_FIELD_UNKNOWN)
		return (0);

	/* Ignore any white spaces preceding the value of the field. */

	while ((ch = khttpd_mbuf_getc(&pos)) == ' ')
		;		/* nothing */
	khttpd_mbuf_ungetc(&pos, ch);

	/* Apply a field handler. */

	switch (field_enum) {

	case KHTTPD_FIELD_HOST:
		khttpd_session_receive_host_field(session, &pos);
		break;

	case KHTTPD_FIELD_CONTENT_LENGTH:
		khttpd_session_receive_content_length_field(session, &pos);
		break;

	case KHTTPD_FIELD_TRANSFER_ENCODING:
		khttpd_session_receive_transfer_encoding_field(session, &pos);
		break;

	case KHTTPD_FIELD_CONNECTION:
		khttpd_session_receive_connection_field(session, &pos);
		break;

	case KHTTPD_FIELD_EXPECT:
		khttpd_session_receive_expect_field(session, &pos);
		break;

	default:
		break;
	}

	return (0);
}

static int
khttpd_session_receive_request_line(struct khttpd_session *session)
{
	static const char version_prefix[] = "HTTP/1.";
	char method_name[24];
	struct mbuf *m;
	struct khttpd_mbuf_pos pos, tmppos;
	const char *cp;
	char *end;
	struct khttpd_exchange *exchange;
	int ch, error;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, session, &session->exchange);

	/* Get a line. */

	error = khttpd_session_next_line(session, &pos);
	switch (error) {

	case 0: /* Ignore a line if it's empty. */
		khttpd_mbuf_pos_copy(&pos, &tmppos);
		ch = khttpd_mbuf_getc(&tmppos);
		if (ch == '\r')
			ch = khttpd_mbuf_getc(&tmppos);
		if (ch == '\n')
			return (0);

		session->receive = khttpd_session_receive_header_or_trailer;
		break;

	case EWOULDBLOCK:
		return (error);

	case ENOMSG:
		/*
		 * If EOF is found at the beginning of the line, return
		 * immediately.
		 */
		if (pos.unget == -1 && (pos.ptr == NULL ||
			(pos.ptr->m_next == NULL && 
			    pos.off == pos.ptr->m_len)))
			return (error);
		break;

	default:
		break;
	}

	exchange = &session->exchange;

	/* 
	 * If the request line is longer than khttpd_message_size_limit
	 * (ENOBUFS case) or is terminated prematurely (ENOMSG case), send 'Bad
	 * Request' response message.
	 */

	if (error != 0) {
		KHTTPD_BRANCH("%s %p reject %u error %d",
		    __func__, exchange, __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (error);
	}

	/* Remove preceding empty lines. */

	m = session->recv_leftovers;
	session->recv_leftovers = NULL;

	while (m != NULL && m != pos.ptr)
		m = m_free(m);
	m = pos.ptr;
	if (pos.off != 0) {
		if (m == session->recv_ptr)
			session->recv_off -= pos.off;
		m_adj(m, pos.off);
		pos.off = 0;
		session->recv_tail = m_last(m);
	}
	exchange->request_line = m;

	/* Find the method of this request message. */

	error = khttpd_mbuf_copy_segment(&pos, ' ', method_name,
	    sizeof(method_name) - 1, &end);

	if (error == 0) {
		*end = '\0';
		exchange->method = khttpd_method_find(method_name, end);

	} else if (error == ENOMEM) {
		exchange->method = KHTTPD_METHOD_UNKNOWN;
		error = khttpd_mbuf_next_segment(&pos, ' ');
	}

	if (error != 0) {
		KHTTPD_BRANCH("%s %p reject %u error %d", __func__, exchange,
		    __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	/* Find the target URI of this request message. */

	if (khttpd_exchange_parse_target_uri(exchange, &pos)) {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	/* Find the protocol version. */

	for (cp = version_prefix; (ch = *cp) != '\0'; ++cp)
		if (khttpd_mbuf_getc(&pos) != ch) {
			KHTTPD_BRANCH("%s %p reject %u", __func__, exchange,
			    __LINE__);
			khttpd_exchange_reject(exchange);
			return (0);
		}

	ch = khttpd_mbuf_getc(&pos);
	if (!isdigit(ch)) {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	exchange->version_minor = ch - '0';

	/* Expect the end of the line. */

	ch = khttpd_mbuf_getc(&pos);
	if (ch == '\r')
		ch = khttpd_mbuf_getc(&pos);
	if (ch != '\n') {
		KHTTPD_BRANCH("%s %p reject %u", __func__, exchange, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	return (0);
}

static void
khttpd_session_data_is_available(struct khttpd_stream *stream)
{
	struct khttpd_session *session;
	khttpd_session_fn_t receive;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	session = stream->up;

	while ((receive = session->receive) != NULL)
		switch ((error = receive(session))) {
		case 0:
			break;

		case EWOULDBLOCK:
			khttpd_stream_continue_receiving(stream);
			return;

		case EBUSY:
			session->recv_paused = TRUE;
			return;
		default:
			KHTTPD_BRANCH("%s error=%d", __func__, error);
			uma_zfree(session->zone, session);
			return;
		}

	session->recv_paused = TRUE;
}

static void
khttpd_session_clear_to_send(struct khttpd_stream *stream)
{
	struct khttpd_session *session;

	session = stream->up;
	if (session->xmit_waiting_for_drain) {
		session->xmit_waiting_for_drain = FALSE;
		khttpd_session_next(session);
	} else
		khttpd_session_transmit(session);
}

static int
khttpd_http_client_init(void *mem, int size, int flags)
{
	struct khttpd_http_client *client;

	KHTTPD_ENTRY("%s(%p,%d,%#x)", __func__, mem, size, flags);

	client = mem;
	khttpd_session_init(&client->session, &khttpd_socket_ops,
	    khttpd_http_client_zone);

	return (0);
}

static void
khttpd_http_client_fini(void *mem, int size)
{
	struct khttpd_http_client *client;

	KHTTPD_ENTRY("%s(%p)", __func__, mem);

	client = mem;
	khttpd_session_fini(&client->session);
}

static int
khttpd_http_client_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_http_client *client;

	KHTTPD_ENTRY("%s(%p,%d,%p,%#x)", __func__, mem, size, arg, flags);

	client = mem;
	khttpd_session_ctor(&client->session);

	return (0);
}

static void
khttpd_http_client_dtor(void *mem, int size, void *arg)
{
	struct khttpd_http_client *client;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, mem, size);

	client = mem;
	khttpd_session_dtor(&client->session);
}

void
khttpd_http_accept_http_client(void *arg)
{
	struct khttpd_http_client *client;
	struct khttpd_socket *socket;
	struct khttpd_stream *stream;
	struct khttpd_port *port;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	port = arg;
	client = uma_zalloc(khttpd_http_client_zone, M_WAITOK);
	client->session.port = khttpd_port_acquire(port);
	stream = &client->session.stream;
	stream->down = client->session.socket = socket = khttpd_socket_new();

	error = khttpd_socket_start(socket, stream, port, NULL);
	if (error != 0)
		uma_zfree(khttpd_http_client_zone, client);
}

void
khttpd_http_accept_https_client(void *arg)
{

	panic("%s: not implemented yet", __func__);
}

static void
khttpd_http_check_field_name_size(void)
{
#ifdef INVARIANTS
	size_t len, longest;
	int i;

	KHTTPD_ENTRY("%s()", __func__);

	longest = 0;
	for (i = 0; i < sizeof(khttpd_fields) / sizeof(khttpd_fields[0]);
	     ++i) {
		len = strlen(khttpd_fields[i].name) + 1;
		if (longest < len)
			longest = len;
	}

	KASSERT(KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH < longest,
	    ("longest known field name expected:%zd, actual:%zd",
		longest, (size_t)KHTTPD_LONGEST_KNOWN_FIELD_NAME_LENGTH));
#endif
}

static int
khttpd_http_local_init(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_http_client_zone = uma_zcreate("http",
	    sizeof(struct khttpd_http_client),
	    khttpd_http_client_ctor, khttpd_http_client_dtor,
	    khttpd_http_client_init, khttpd_http_client_fini, UMA_ALIGN_PTR, 0);

	khttpd_strtab_init(khttpd_field_hash_table,
	    sizeof(khttpd_field_hash_table) /
	    sizeof(khttpd_field_hash_table[0]), khttpd_fields,
	    sizeof(khttpd_fields) / sizeof(khttpd_fields[0]));

	khttpd_http_check_field_name_size();

	return (0);
}

static void
khttpd_http_local_fini(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	uma_zdestroy(khttpd_http_client_zone);
}

KHTTPD_INIT(khttpd_http, khttpd_http_local_init, khttpd_http_local_fini,
    KHTTPD_INIT_PHASE_LOCAL);
