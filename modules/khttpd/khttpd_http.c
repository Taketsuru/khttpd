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

#include "khttpd_field.h"
#include "khttpd_init.h"
#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_malloc.h"
#include "khttpd_method.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_problem.h"
#include "khttpd_refcount.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_stream.h"
#include "khttpd_string.h"
#include "khttpd_strtab.h"
#include "khttpd_vhost.h"

struct khttpd_session;

struct khttpd_exchange {
	struct khttpd_mbuf_json	log_entry;
	struct sbuf		target;
	struct timeval		arrival_time;
	char			*request_header;
	char			*request_header_end;
	struct khttpd_exchange_ops *ops;
	void			*arg;

#define khttpd_exchange_zctor_begin	request_body_resid
	off_t			request_body_resid;
	off_t			request_content_length;
	off_t			request_payload_size;
	off_t			response_content_length;
	off_t			response_payload_size;
	const char		*query;
	const char		*suffix;
	const char		*request_content_type;
	struct khttpd_location	*location;
	struct mbuf		*response_header;
	struct mbuf		*response_trailer;
	struct mbuf		*response_buffer;
	unsigned		request_header_size;
	unsigned		request_content_type_len;
	unsigned		status:16;
	unsigned		version_minor:4;
	unsigned		close:1;
	unsigned		close_requested:1;
	unsigned		continue_requested:1;
	unsigned		request_has_host:1;
	unsigned		request_has_content_range:1;
	unsigned		request_has_content_length:1;
	unsigned		request_chunked:1;
	unsigned		response_has_content_length:1;
	unsigned		response_chunked:1;
	unsigned		responding:1;
	unsigned		response_pending:1;

#define khttpd_exchange_zctor_end	method
	signed char		method;
	char			target_buf[256];
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
	char			*chunkbuf_begin;
	char			*chunkbuf_end;
	khttpd_session_fn_t	receive;
	uma_zone_t		zone;

#define khttpd_session_zero_begin server
	struct khttpd_server	*server;
	struct khttpd_port	*port;
	struct mbuf		*recv_ptr;
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

static void khttpd_session_error(struct khttpd_stream *,
    struct khttpd_mbuf_json *);
static int khttpd_session_receive_body(struct khttpd_session *);
static int khttpd_session_receive_request(struct khttpd_session *);
static void khttpd_session_data_is_available(struct khttpd_stream *);
static void khttpd_session_clear_to_send(struct khttpd_stream *, ssize_t);

static size_t khttpd_header_size_limit = 16384;
static size_t khttpd_chunkbuf_size = 128;
static uma_zone_t khttpd_http_client_zone;
static const char khttpd_crlf[] = { '\r', '\n' };

static struct khttpd_stream_up_ops khttpd_session_ops = {
	.data_is_available = khttpd_session_data_is_available,
	.clear_to_send = khttpd_session_clear_to_send,
	.error = khttpd_session_error,
};

static struct khttpd_exchange_ops khttpd_exchange_null_ops;

static void
khttpd_http_log(int chan, struct khttpd_mbuf_json *entry)
{

	khttpd_mbuf_json_object_end(entry);
	khttpd_log_put(chan, khttpd_mbuf_json_move(entry));
}

static struct khttpd_session *
khttpd_exchange_get_session(struct khttpd_exchange *exchange)
{

	return ((struct khttpd_session *)exchange);
}

static void
khttpd_exchange_clear(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	KASSERT(exchange->log_entry.mbuf == NULL,
	    ("exchange->log_entry.mbuf %p", exchange->log_entry.mbuf));

	if (exchange->ops->dtor != NULL) {
		exchange->ops->dtor(exchange, exchange->arg);
	}

	sbuf_clear(&exchange->target);
	exchange->request_header_end = exchange->request_header;
	exchange->ops = &khttpd_exchange_null_ops;
	khttpd_location_release(exchange->location);
	m_freem(exchange->response_header);
	m_freem(exchange->response_trailer);
	m_freem(exchange->response_buffer);
	bzero(&exchange->khttpd_exchange_zctor_begin, 
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_end) -
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_begin));
	exchange->method = -1;
}

static int
khttpd_session_receive_trash(struct khttpd_session *session)
{
	struct mbuf *m;
	off_t resid;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	m_freem(session->recv_ptr);
	session->recv_ptr = NULL;

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
khttpd_session_next(struct khttpd_session *session)
{
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;
	KASSERT(session->receive == NULL,
	    ("session->receive %p", session->receive));
	session->receive = exchange->close ? khttpd_session_receive_trash :
	    khttpd_session_receive_request;
	khttpd_exchange_clear(exchange);
	if (session->recv_paused) {
		khttpd_session_data_is_available(&session->stream);
	}
}

static void
khttpd_session_transmit_finish(struct khttpd_session *session, struct mbuf *m)
{
	struct khttpd_exchange *exchange;
	int flags;
	bool full;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, session, m);

	exchange = &session->exchange;
	flags = exchange->close ? KHTTPD_STREAM_CLOSE : KHTTPD_STREAM_FLUSH;
	full = khttpd_stream_send(&session->stream, m, flags);

	if (exchange->response_payload_size != 0) {
		khttpd_mbuf_json_property(&exchange->log_entry,
		    "responsePayloadSize");
		khttpd_mbuf_json_format(&exchange->log_entry, false, "%ju",
		    (uintmax_t)exchange->response_payload_size);
	}

	khttpd_mbuf_json_property(&exchange->log_entry, "completionTime");
	khttpd_mbuf_json_now(&exchange->log_entry);

	khttpd_http_log(khttpd_log_chan_access, &exchange->log_entry);

	if (full) {
		session->xmit_waiting_for_drain = true;
		khttpd_stream_notify_of_drain(&session->stream);
	} else {
		khttpd_session_next(session);
	}
}

static void
khttpd_session_transmit(struct khttpd_session *session, ssize_t space)
{
	struct khttpd_mbuf_json logent;
	struct khttpd_exchange *exchange;
	struct mbuf *head, *m;
	off_t resid;
	unsigned sent;
	int error;

	KHTTPD_ENTRY("%s(%p,%#zx)", __func__, session, space);
	exchange = &session->exchange;

again:
	head = NULL;
	error = exchange->ops->get == NULL ? 0 : 
	    exchange->ops->get(exchange, exchange->arg, space, &head);

	if (error == EWOULDBLOCK) {
		KHTTPD_NOTE("%s ewouldblock", __func__);
		if (head != NULL) {
			khttpd_mbuf_json_copy(&logent, &exchange->log_entry);
			khttpd_problem_set_internal_error(&logent);
			khttpd_problem_set_detail(&logent, 
			    "exchange_ops::get sets data "
			    "even though it returns EWOULDBLOCK");
			khttpd_http_error(&logent);
			m_freem(head);
		}
		return;
	}

	if (head == NULL) {
		if (exchange->response_chunked) {
			KHTTPD_NOTE("%s last chunk", __func__);
			head = m_gethdr(M_WAITOK, MT_DATA);
			khttpd_mbuf_printf(head, "0\r\n");
			m_cat(head, exchange->response_trailer);
			exchange->response_trailer = NULL;
			khttpd_mbuf_append(head, khttpd_crlf,
			    khttpd_crlf + sizeof(khttpd_crlf));
			khttpd_session_transmit_finish(session, head);
		} else {
			KHTTPD_NOTE("%s premature eof", __func__);
			khttpd_mbuf_json_copy(&logent, &exchange->log_entry);
			khttpd_problem_set_internal_error(&logent);
			khttpd_problem_set_detail(&logent, "exchange_ops::get "
			    "finishes sending data prematurely");
			khttpd_http_error(&logent);
			khttpd_exchange_reset(exchange);
		}
		return;
	}

	if (error != 0) {
		KHTTPD_NOTE("%s error %d", __func__, error);
		khttpd_exchange_reset(exchange);
		return;
	}

	sent = m_length(head, NULL);
	if (sent == 0) {
		KHTTPD_NOTE("%s empty", __func__);
		goto again;
	}

	if (exchange->response_chunked) {
		KHTTPD_NOTE("%s chunk", __func__);
		exchange->response_payload_size += sent;
		m = m_gethdr(M_WAITOK, MT_DATA);
		khttpd_mbuf_printf(m, "%jx\r\n", (uintmax_t)sent);
		m_cat(m, head);
		khttpd_mbuf_append(m, khttpd_crlf,
		    khttpd_crlf + sizeof(khttpd_crlf));
		head = m;
		khttpd_stream_send(&session->stream, head, 0);
		khttpd_stream_notify_of_drain(&session->stream);

	} else if (sent < (resid = exchange->response_content_length - 
		exchange->response_payload_size)) {
		KHTTPD_NOTE("%s more data", __func__);
		exchange->response_payload_size += sent;
		khttpd_stream_send(&session->stream, head, 0);
		khttpd_stream_notify_of_drain(&session->stream);

	} else {
		KHTTPD_NOTE("%s finish", __func__);
		if (resid < sent) {
			KHTTPD_NOTE("%s too much data", __func__);
			khttpd_mbuf_json_copy(&logent, &exchange->log_entry);
			khttpd_problem_set_internal_error(&logent);
			khttpd_problem_set_detail(&logent, 
			    "exchange_ops::get sends too much data");
			khttpd_http_error(&logent);
			m_freem(m_split(head, resid, M_WAITOK));
		}

		exchange->response_payload_size = 
		    exchange->response_content_length;
		khttpd_session_transmit_finish(session, head);
	}
}

static void
khttpd_exchange_send_response(struct khttpd_exchange *exchange)
{
	struct khttpd_session *session;
	struct mbuf *m;
	long space;
	int status;
	bool finish;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	session = khttpd_exchange_get_session(exchange);
	status = exchange->status;

	if (exchange->close_requested) {
		khttpd_exchange_close(exchange);
	}

	if (exchange->close) {
		KHTTPD_NOTE("close");
		session->receive = NULL;
	}

	m = m_gethdr(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(m, "HTTP/1.1 %d N/A\r\n", status);

	exchange->responding = true;
	m_cat(m, exchange->response_header);
	exchange->response_header = NULL;

	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));

	if (status == KHTTPD_STATUS_NO_CONTENT ||
	    status == KHTTPD_STATUS_NOT_MODIFIED ||
	    exchange->method == KHTTPD_METHOD_HEAD) {
		finish = true;

	} else if (exchange->response_chunked) {
		finish = false;

	} else if (0 < exchange->response_content_length) {
		if (exchange->response_buffer != NULL) {
			exchange->response_payload_size = 
			    m_length(exchange->response_buffer, NULL);
			m_cat(m, exchange->response_buffer);
			exchange->response_buffer = NULL;
		}

		finish = exchange->response_content_length <=
		    exchange->response_payload_size;

	} else {
		finish = true;
	}

	if (finish) {
		khttpd_session_transmit_finish(session, m);
	} else if (!khttpd_stream_send(&session->stream, m, 0)) {
		khttpd_stream_send_bufstat(&session->stream, NULL, NULL,
		    &space);
		khttpd_session_transmit(session, space);
	}
}

static void
khttpd_exchange_bailout(struct khttpd_exchange *exchange, int status)
{
	struct khttpd_session *session;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, exchange, status);

	if (exchange->responding) {
		exchange->close = true;
		session = khttpd_exchange_get_session(exchange);
		khttpd_session_transmit_finish(session, NULL);
		khttpd_stream_reset(&session->stream);
		return;
	}

	if (exchange->status != 0) {
		khttpd_exchange_clear_response_header(exchange);
	}

	khttpd_exchange_close(exchange);
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond_immediately(exchange, status);
}

static void
khttpd_exchange_set_allow_field(struct khttpd_exchange *exchange)
{
	char buf[128];
 	struct sbuf sbuf;
	struct khttpd_location_ops *ops;
	struct khttpd_location *location;
	int i;

 	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	location = exchange->location;
	if (location == NULL) {
		sbuf_printf(&sbuf, "%s", khttpd_method_name(0));
		for (i = 1; i < KHTTPD_METHOD_END; ++i)
			sbuf_printf(&sbuf, ", %s", khttpd_method_name(i));

	} else if ((ops = khttpd_location_get_ops(location))->options != NULL)
		ops->options(exchange, &sbuf);

	else {
		KASSERT(ops->catch_all == NULL,
		    ("ops=%p, ops->catch_all=%p", ops, ops->catch_all));

		sbuf_cpy(&sbuf, "OPTIONS");

		for (i = 0; i < KHTTPD_METHOD_END; ++i)
			if (i != KHTTPD_METHOD_OPTIONS &&
			    ops->method[i] != NULL)
				sbuf_printf(&sbuf, ", %s",
				    khttpd_method_name(i));

		if (ops->method[KHTTPD_METHOD_HEAD] == NULL &&
		    ops->method[KHTTPD_METHOD_GET] != NULL)
			sbuf_cat(&sbuf, ", HEAD");
	}

	sbuf_finish(&sbuf);
	khttpd_exchange_add_response_field(exchange, "Allow", "%s",
	    sbuf_data(&sbuf));

	sbuf_delete(&sbuf);
}

static void
khttpd_exchange_options(struct khttpd_exchange *exchange)
{

 	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	khttpd_exchange_set_response_content_length(exchange, 0);
	khttpd_exchange_set_allow_field(exchange);
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
}

static void
khttpd_exchange_method_not_allowed(struct khttpd_exchange *exchange)
{
	int status;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	khttpd_exchange_set_allow_field(exchange);
	status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_session_receive_finish(struct khttpd_session *session)
{
	struct khttpd_exchange *exchange;
	bool pause;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, session);

	session->receive = NULL;
	exchange = &session->exchange;

	if (exchange->request_payload_size != 0) {
		khttpd_mbuf_json_property(&exchange->log_entry,
		    "requestPayloadSize");
		khttpd_mbuf_json_format(&exchange->log_entry, false, "%ju",
		    (uintmax_t)exchange->request_payload_size);
	}

	if (exchange->ops->put != NULL)
		exchange->ops->put(exchange, exchange->arg, NULL, &pause);

	if (exchange->response_pending)
		khttpd_exchange_send_response(exchange);
}

/*
 * RETURN VALUES
 *
 * If successful, khttpd_session_receive_line() returns 0.  They return one of
 * the following values on failure.
 *   
 * [EWOULDBLOCK]	More bytes are necessary.
 * 
 * [ENOMSG]		Reaches the end of the stream before it finds a CRLF.
 *
 * [ENOBUFS]		Have read more than buffer size
 *
 * Others		Any other return values from soreceive().
 */
static int
khttpd_session_receive_chunk_line(struct khttpd_session *session)
{
	off_t resid;
	struct mbuf *next, *ptr;
	char *begin, *bufend, *bufp, *cp, *end;
	u_int off, len;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	ptr = session->recv_ptr;
	off = 0;
	bufp = session->chunkbuf_end;
	bufend = session->chunkbuf_begin + khttpd_chunkbuf_size;

	for (;;) {
		if (ptr == NULL) {
			session->recv_ptr = NULL;
			session->chunkbuf_end = bufp;

			resid = SSIZE_MAX;
			error = khttpd_stream_receive(&session->stream, &resid,
			    &ptr);
			if (error != 0) {
				KHTTPD_NOTE("error %d", error);
				return (error);
			}
			if (resid == SSIZE_MAX) {
				KHTTPD_NOTE("enomsg");
				return (ENOMSG);
			}

			KASSERT(ptr != NULL, ("ptr is NULL"));
			KASSERT(off == 0, ("off %#x", off));
		}

		begin = mtod(ptr, char *) + off;
		end = mtod(ptr, char *) + ptr->m_len;
		cp = memchr(begin, '\n', end - begin);

		if (cp == begin) {
			if (session->chunkbuf_begin < bufp &&
			    bufp[-1] == '\r') {
				--bufp;
			}
			break;
		}

		if (cp != NULL) {
			if (cp[-1] == '\r') {
				len = cp - begin - 1;
			} else {
				len = cp - begin;
			}

			if (bufend - bufp < len) {
				len = bufend - bufp;
				bcopy(begin, bufp, len);
				bufp += len;
				goto enobufs;
			}

			bcopy(begin, bufp, len);
			bufp += len;

			break;
		}

		if (bufend - bufp < end - begin) {
			len = bufend - bufp;
			bcopy(begin, bufp, len);
			bufp += len;
			goto enobufs;
		}

		len = end - begin;
		bcopy(begin, bufp, len);
		bufp += len;

		next = ptr->m_next;
		m_free(ptr);
		ptr = next;
		off = 0;
	}

	m_adj(ptr, cp - mtod(ptr, char *) + 1);
	session->recv_ptr = ptr;
	session->chunkbuf_end = bufp;

	return (0);

 enobufs:
	m_freem(ptr);
	session->recv_ptr = NULL;
	session->chunkbuf_end = bufp;

	return (ENOBUFS);
}

static int
khttpd_session_receive_header(struct khttpd_session *session)
{
	off_t nread;
	struct khttpd_exchange *exchange;
	struct mbuf *next, *ptr;
	char *begin, *bufend, *bufp, *cp;
	u_int clen, len;
	int resid;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	exchange = &session->exchange;
	ptr = session->recv_ptr;
	bufp = exchange->request_header_end;
	bufend = exchange->request_header + khttpd_header_size_limit;
	resid = khttpd_header_size_limit - exchange->request_header_size;
	error = 0;

	while (0 <= resid) {
		KHTTPD_NOTE("resid %#x, bufspace %#x", resid, bufend - bufp);
		if (ptr == NULL) {
			session->recv_ptr = NULL;
			exchange->request_header_end = bufp;

			nread = SSIZE_MAX;
			error = khttpd_stream_receive(&session->stream, &nread,
			    &ptr);
			if (error != 0) {
				KHTTPD_NOTE("error %d", error);
				break;
			}
			if (nread == SSIZE_MAX) {
				KHTTPD_NOTE("enomsg");
				error = ENOMSG;
				break;
			}

			KASSERT(ptr != NULL, ("ptr is NULL"));
		}

		begin = mtod(ptr, char *);
		len = ptr->m_len;
		cp = memchr(begin, '\n', len);
		if (cp == NULL) {
			resid -= len;

			clen = MIN(bufend - bufp, len);
			bcopy(begin, bufp, clen);
			bufp += clen;

			next = ptr->m_next;
			m_free(ptr);
			ptr = next;

			continue;
		}

		if (cp == begin) {
			if (exchange->request_header < bufp && 
			    bufp[-1] == '\r') {
				--bufp;
			}

		} else  {
			len = cp[-1] == '\r' ? cp - begin - 1 : cp - begin;
			clen = MIN(resid, MIN(bufend - bufp, len));
			bcopy(begin, bufp, clen);
			bufp += clen;
		}

		resid -= cp - begin + 1;

		m_adj(ptr, cp - mtod(ptr, char *) + 1);

		if (0 <= resid && exchange->request_header < bufp) {
			/*
			 * This 'if' is necessary to ignore empty lines
			 * preceding a request.
			 */

			if (bufp[-1] == '\n') {
				break;
			}

			if (bufp < bufend) {
				*bufp++ = '\n';
			}
		}
	}

	exchange->request_header_end = bufp;
	exchange->request_header_size = khttpd_header_size_limit - resid;

	KHTTPD_NOTE("fin resid %#x, bufspace %#x", resid, bufend - bufp);

	if (error == 0 && resid < 0) {
		KHTTPD_NOTE("enobufs");
		m_freem(ptr);
		session->recv_ptr = NULL;
		exchange->request_header_size = khttpd_header_size_limit;

		return (ENOBUFS);
	}

	session->recv_ptr = ptr;

	return (error);
}

static int
khttpd_session_receive_trailer(struct khttpd_session *session)
{
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	error = khttpd_session_receive_header(session);
	if (error != 0 && error != ENOMSG && error != ENOBUFS) {
		KHTTPD_NOTE("error %d", error);
		return (error);
	}
	if (error != 0) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		khttpd_exchange_reject(&session->exchange);
		return (error);
	}

	khttpd_session_receive_finish(session);

	return (0);
}

static int
khttpd_session_receive_chunk(struct khttpd_session *session)
{
	off_t len;
	struct khttpd_exchange *exchange;
	char *cp, *ep;
	int error, nibble, status;
	char ch;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	error = khttpd_session_receive_chunk_line(session);
	if (error != 0 && error != ENOMSG && error != ENOBUFS) {
		return (error);
	}

	exchange = &session->exchange;

	if (error != 0) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (error);
	}

	len = 0;
	ep = session->chunkbuf_end;
	for (cp = session->chunkbuf_begin; cp < ep; ++cp) {
		ch = *cp;
		if (!isxdigit(ch)) {
			break;
		}

		nibble = isdigit(ch) ? ch - '0' :
		    'A' <= ch && ch <= 'F' ? ch - 'A' + 10 :
		    ch - 'a' + 10;

		if ((len << 4) < len) {
			goto too_large;
		}

		len = (len << 4) + nibble;
	}

	if (cp < ep && ch != ';') {
		KHTTPD_NOTE("%s reject %u", __func__, __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	if (len == 0) {
		session->receive = khttpd_session_receive_trailer;

	} else if (OFF_MAX - exchange->request_payload_size < len) {
		goto too_large;

	} else {
		exchange->request_body_resid = len;
		session->receive = khttpd_session_receive_body;
	}

	return (0);

 too_large:
	status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond_immediately(exchange, status);

	return (0);
}

static int
khttpd_session_receive_chunk_terminator(struct khttpd_session *session)
{
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	error = khttpd_session_receive_chunk_line(session);
	if (error != 0 && error != ENOMSG && error != ENOBUFS) {
		return (error);
	}

	if (error != 0 || session->chunkbuf_begin != session->chunkbuf_end) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		khttpd_exchange_reject(&session->exchange);
		return (error);
	}

	session->receive = khttpd_session_receive_chunk;

	return (0);
}

static int
khttpd_session_receive_body(struct khttpd_session *session)
{
	struct khttpd_mbuf_json logent;
	off_t nread, resid;
	struct khttpd_exchange *exchange;
	struct mbuf *m;
	u_int len;
	int error;
	bool pause;

	exchange = &session->exchange;
	resid = exchange->request_body_resid;

	KHTTPD_ENTRY("%s(%p), resid=%#x", __func__, session, resid);

	KASSERT(OFF_MAX - exchange->request_payload_size >=
	    exchange->request_body_resid,
	    ("request_payload_size %#jx, request_body_resid %#jx",
		(uintmax_t)exchange->request_payload_size,
		(uintmax_t)exchange->request_body_resid));

	pause = false;
	while (0 < resid) {
		m = session->recv_ptr;
		if (m == NULL) {
			nread = SSIZE_MAX;
			error = khttpd_stream_receive(&session->stream, &nread,
			    &m);
			if (error != 0) {
				KHTTPD_NOTE("error %d", error);
				return (error);
			}

			if (nread == SSIZE_MAX) {
				KHTTPD_NOTE("reject %u", __LINE__);
				khttpd_exchange_reject(exchange);
				return (ENOMSG);
			}
		}

		session->recv_ptr = m_split(m, resid, M_WAITOK);
		len = m_length(m, NULL);
		exchange->request_body_resid = resid -= len;
		exchange->request_payload_size += len;

		if (exchange->ops->put == NULL)
			m_freem(m);
		else
			exchange->ops->put(exchange, exchange->arg, m, &pause);

		if (pause) {
			if (0 < resid) {
				return (EBUSY);
			}

			khttpd_mbuf_json_copy(&logent, &exchange->log_entry);
			khttpd_problem_set_internal_error(&logent);
			khttpd_problem_set_detail(&logent, "exchange_ops::put "
			    "try to pause but the request body has "
			    "already been transfered completely.");
			khttpd_http_error(&logent);
		}
	}

	if (exchange->request_chunked) {
		session->chunkbuf_end = session->chunkbuf_begin;
		session->receive = khttpd_session_receive_chunk_terminator;
	} else {
		khttpd_session_receive_finish(session);
	}

	return (0);
}

static void
khttpd_session_receive_host_field(struct khttpd_session *session,
    const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;
	struct khttpd_server *server;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);

	exchange = &session->exchange;

	if (exchange->request_has_host) {
		/* there is more than one host fields in a request */
		KHTTPD_NOTE("reject %u", __LINE__);
		khttpd_exchange_reject(exchange);
		return;
	}

	khttpd_mbuf_json_property(&exchange->log_entry, "host");
	khttpd_mbuf_json_bytes(&exchange->log_entry, true, begin, end);

	if (end - begin != sbuf_len(&session->host) ||
	    strncmp(begin, sbuf_data(&session->host), end - begin) != 0) {
		/* 
		 * Find the server.  If the specified Host doesn't exist, send
		 * a 'bad request' response.
		 */

		server = khttpd_vhost_find_server(session->port, begin, end);
		if (server == NULL) {
			KHTTPD_NOTE("reject %u", __LINE__);
			khttpd_exchange_reject(exchange);
			return;
		}

		session->server = server;
		sbuf_bcpy(&session->host, begin, end - begin);
		sbuf_finish(&session->host);
	}

	exchange->request_has_host = true;

	/*
	 * Find location as soon as possible so that location specific
	 * functions become available early.
	 */

	exchange->location =
	    khttpd_server_route(session->server, &exchange->target, exchange,
		&exchange->suffix, NULL);
}

static void
khttpd_session_receive_content_length_field(struct khttpd_session *session,
    const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;
	uintmax_t value;
	int error, status;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);

	exchange = &session->exchange;

	error = khttpd_parse_digits(&value, begin, end);
	if (error == ERANGE || (error == 0 && OFF_MAX < value)) {
		KHTTPD_NOTE("reject %u error %d value %jx",
		    __LINE__, error, value);
		status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond_immediately(exchange, status);
		return;
	}

	if (error != 0 || exchange->request_has_content_length) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		khttpd_exchange_reject(exchange);
		return;
	}

	exchange->request_has_content_length = true;
	exchange->request_content_length = value;
}

static void
khttpd_session_receive_content_type_field(struct khttpd_session *session,
    const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);
	exchange = &session->exchange;
	exchange->request_content_type = begin;
	exchange->request_content_type_len = end - begin;
}

static bool
khttpd_session_found_transfer_encoding_token(void *arg, const char *begin,
    const char *end)
{
	struct khttpd_mbuf_json diag;
	struct khttpd_exchange *exchange;
	struct khttpd_session *session;
	int status;

	KHTTPD_ENTRY("%s(%p,\"%s\")", __func__, arg,
	    khttpd_ktr_printf("%.*s", (int)(end - begin), begin));

	session = arg;
	exchange = &session->exchange;

	if (exchange->request_chunked ||
	    end - begin != sizeof("chunked") - 1 ||
	    strncasecmp(begin, "chunked", end - begin) != 0) {

		status = KHTTPD_STATUS_NOT_IMPLEMENTED;
		khttpd_mbuf_json_new(&diag);
		khttpd_problem_response_begin(&diag, status, NULL, NULL);
		khttpd_problem_set_detail(&diag,
		    "unsupported transfer encoding is specified");
		khttpd_exchange_set_error_response_body(exchange, status,
		    &diag);
		khttpd_exchange_respond_immediately(exchange, status);

		return (false);
	}

	exchange->request_chunked = true;
	return (true);
}

static void
khttpd_session_receive_transfer_encoding_field(struct khttpd_session *session,
    const char *begin, const char *end)
{

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);
	khttpd_string_for_each_token(begin, end,
	    khttpd_session_found_transfer_encoding_token, session);
}

static bool
khttpd_session_found_connection_field_token(void *arg, const char *begin,
    const char *end)
{
	struct khttpd_session *session;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, arg, begin, end);

	if (end - begin == sizeof("close") - 1 &&
	    strncmp(begin, "close", end - begin) == 0) {
		session = arg;
		session->exchange.close_requested = true;
		return (false);
	}

	return (true);
}

static void
khttpd_session_receive_connection_field(struct khttpd_session *session,
    const char *begin, const char *end)
{

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);
	khttpd_string_for_each_token(begin, end,
	    khttpd_session_found_connection_field_token, session);
}

static void
khttpd_session_receive_expect_field(struct khttpd_session *session,
    const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;
	int status;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, session, begin, end);

	exchange = &session->exchange;

	if (exchange->version_minor < 1 || begin == end) {
		return;
	}

	if (end - begin == sizeof("100-continue") - 1 &&
	    strncasecmp(begin, "100-continue", end - begin) == 0) {
		exchange->continue_requested = true;
		return;
	}

	status = KHTTPD_STATUS_EXPECTATION_FAILED;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond_immediately(exchange, status);
}

static void
khttpd_exchange_put_request_line(struct khttpd_mbuf_json *entry,
	struct khttpd_exchange *exchange)
{
	const char *begin, *eolp, *end;

	khttpd_mbuf_json_property(entry, "request");
	begin = exchange->request_header;
	end = exchange->request_header_end;
	eolp = memchr(begin, '\n', end - begin);
	khttpd_mbuf_json_format(entry, true, "%.*s",
	    (int)(eolp != NULL ? eolp - begin : end - begin), begin);
}

static int
khttpd_session_receive_request(struct khttpd_session *session)
{
	static const char version_prefix[] = "HTTP/";
	const char *begin, *end;
	const char *bolp, *eolp;
	const char *cp, *reqend;
	khttpd_method_fn_t handler;
	struct khttpd_exchange *exchange;
	struct khttpd_location *location;
	struct khttpd_location_ops *ops;
	struct mbuf *m;
	int field, method, query_off, minlen;
	int ch, error, status;

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	error = khttpd_session_receive_header(session);
	if (error != 0 && error != ENOMSG && error != ENOBUFS) {
		KHTTPD_NOTE("error %d", error);
		return (error);
	}

	exchange = &session->exchange;
	bolp = exchange->request_header;
	reqend = exchange->request_header_end;
	if (error == ENOMSG && bolp == reqend) {
		KHTTPD_NOTE("enomsg");
		return (ENOMSG);
	}

	microtime(&exchange->arrival_time);

	khttpd_mbuf_json_new(&exchange->log_entry);
	khttpd_mbuf_json_object_begin(&exchange->log_entry);

	khttpd_mbuf_json_property(&exchange->log_entry, "arrivalTime");
	khttpd_mbuf_json_now(&exchange->log_entry);

	khttpd_mbuf_json_property(&exchange->log_entry, "peer");
	khttpd_mbuf_json_sockaddr(&exchange->log_entry, 
	    khttpd_socket_peer_address(session->socket));

	khttpd_exchange_put_request_line(&exchange->log_entry, exchange);

	/* Find the method of this request message. */

	minlen = 1 /* request target */ + 1 /* SP */ +
	    sizeof(version_prefix) - 1 + 3 /* version */ + 1 /* LF */;
	if (reqend - bolp <= minlen ||
	    (cp = memchr(bolp, ' ', reqend - minlen - bolp)) == NULL) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		khttpd_exchange_reject(exchange);
		return (0);
	}
	exchange->method = method = khttpd_method_find(bolp, cp);

	/* Find the target URI of this request message. */

	KASSERT(cp + minlen < reqend,
	    ("bolp %p, cp %p, reqend %p, minlen %d",
		bolp, cp, reqend, minlen));
	if ((ch = cp[1]) != '/') {
		if (ch != '*' || cp[2] != ' ') {
			KHTTPD_NOTE("reject %u", __LINE__);
			khttpd_exchange_reject(exchange);
			return (0);
		}
		sbuf_cpy(&exchange->target, "*");
		query_off = -1;
		cp += 3;
	} else {
		cp = khttpd_string_normalize_request_target(&exchange->target,
		    cp + 1, reqend, &query_off);
		if (reqend <= cp || *cp != ' ') {
			KHTTPD_NOTE("reject %u", __LINE__);
			khttpd_exchange_reject(exchange);
			return (0);
		}
		++cp;
	}
	sbuf_finish(&exchange->target); /* always succeeds */
	exchange->query = query_off == -1 ? NULL :
	    sbuf_data(&exchange->target) + query_off;

	/* Find the protocol version. */

	if (reqend < cp + sizeof(version_prefix) - 1 + 3 + 1 ||
	    memcmp(cp, version_prefix, sizeof(version_prefix) - 1) != 0 ||
	    !isdigit(cp[sizeof(version_prefix) - 1]) ||
	    cp[sizeof(version_prefix) - 1 + 1] != '.' ||
	    !isdigit(cp[sizeof(version_prefix) - 1 + 2]) ||
	    cp[sizeof(version_prefix) - 1 + 3] != '\n') {
		KHTTPD_NOTE("reject %u", __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	if (cp[sizeof(version_prefix) - 1] != '1') {
		KHTTPD_NOTE("reject %u", __LINE__);
		status = KHTTPD_STATUS_HTTP_VERSION_NOT_SUPPORTED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond_immediately(exchange, status);
		return (0);
	}

	ch = cp[sizeof(version_prefix) - 1 + 2];
	if (!isdigit(ch)) {
		KHTTPD_NOTE("reject %u", __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	exchange->version_minor = ch - '0';

	/* 
	 * If receiving of header fields fails because of ENOBUFS, send
	 * 'Request Header Fields Too Large' response message.
	 */

	if (error == ENOBUFS) {
		KHTTPD_NOTE("reject %u error %d", __LINE__, error);
		status = KHTTPD_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE;
		khttpd_exchange_set_error_response_body(exchange, status, 
		    NULL);
		khttpd_exchange_respond_immediately(exchange, status);
		return (0);
	}

	/* Reject an incomplete request header. */

	if (error != 0) {
		KHTTPD_NOTE("reject %u", __LINE__);
		khttpd_exchange_reject(exchange);
		KASSERT(error == ENOMSG, ("error %d", error));
		return (ENOMSG);
	}

	/* Parse each header fields */

	for (bolp = cp + sizeof(version_prefix) - 1 + 4;
	     bolp < reqend; bolp = eolp + 1) {
		/*
		 * Extract the field name from the line.  If there is no ':',
		 * it's at the beginning of the line, or it's preceded by a
		 * white space, send 'Bad Request' response.
		 */

		cp = memchr(bolp, ':', reqend - bolp);
		if (cp == NULL || cp == bolp || cp[-1] == ' ') {
			KHTTPD_NOTE("reject %u", __LINE__);
			khttpd_exchange_reject(exchange);
			return (0);
		}

		KHTTPD_NOTE("field %s", khttpd_ktr_printf("%.*s",
			(int)(cp - bolp), bolp));

		eolp = memchr(cp, '\n', reqend - cp);

		/* If the extracted field name is not a known name, done. */

		field = khttpd_field_find(bolp, cp);
		if (field == KHTTPD_FIELD_UNKNOWN) {
			continue;
		}

		/* Trim whitespaces around the field value. */

		begin = cp + 1;
		end = eolp;
		khttpd_string_trim(&begin, &end);

		KHTTPD_TR("value \"%s\"", khttpd_ktr_printf("%.*s",
			(int)(end - begin), begin));
		
		/* Apply a field handler. */

		switch (field) {

		case KHTTPD_FIELD_HOST:
			khttpd_session_receive_host_field(session, begin, end);
			break;

		case KHTTPD_FIELD_CONTENT_RANGE:
			exchange->request_has_content_range = true;
			break;

		case KHTTPD_FIELD_CONTENT_LENGTH:
			khttpd_session_receive_content_length_field(session,
			    begin, end);
			break;

		case KHTTPD_FIELD_CONTENT_TYPE:
			khttpd_session_receive_content_type_field(session,
			    begin, end);
			break;

		case KHTTPD_FIELD_TRANSFER_ENCODING:
			khttpd_session_receive_transfer_encoding_field(session,
			    begin, end);
			break;

		case KHTTPD_FIELD_CONNECTION:
			khttpd_session_receive_connection_field(session, 
			    begin, end);
			break;

		case KHTTPD_FIELD_EXPECT:
			khttpd_session_receive_expect_field(session,
			    begin, end);
			break;

		default:
			break;
		}

		if (session->receive != khttpd_session_receive_request) {
			KHTTPD_NOTE("bailout");
			return (0);
		}
	}

	/*
	 * If the request doesn't have Host field, send 'Bad Request' response.
	 */

	if (!exchange->close && !exchange->request_has_host) {
		KHTTPD_NOTE("reject %u", __LINE__);
		khttpd_exchange_reject(exchange);
		return (0);
	}

	if (exchange->status != 0) {
		/* already found an error in the request */

	} else if (method == KHTTPD_METHOD_UNKNOWN) {
		status = KHTTPD_STATUS_NOT_IMPLEMENTED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);

	} else if ((location = exchange->location) != NULL) {
		ops = khttpd_location_get_ops(location);

		if ((handler = ops->method[method]) == NULL) {
			switch (method) {
			case KHTTPD_METHOD_OPTIONS:
				handler = khttpd_exchange_options;
				break;
			case KHTTPD_METHOD_HEAD:
				handler = ops->method[KHTTPD_METHOD_GET];
				break;
			default:
				;	/* nothing */
			}
		}

		if (handler == NULL) {
			handler = ops->catch_all;
		}

		if (handler == NULL) {
			khttpd_exchange_method_not_allowed(exchange);

		} else if (exchange->request_has_content_range &&
		    method == KHTTPD_METHOD_PUT) {
			KHTTPD_NOTE("%u bad request", __LINE__);
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_exchange_set_error_response_body(exchange,
			    status, NULL);
			khttpd_exchange_respond(exchange, status);

		} else {
			(*handler)(exchange);
		}

	} else if (exchange->method == KHTTPD_METHOD_OPTIONS &&
	    strcmp(sbuf_data(&exchange->target), "*") == 0) {
		/*
		 * If the request method is OPTIONS and the target is "*", send
		 * OPTIONS response.
		 */
		khttpd_exchange_set_allow_field(exchange);
		khttpd_exchange_set_response_content_length(exchange, 0);
		khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);

	} else {
		/*
		 * If the request doesn't have matching location, send a 'Not
		 * Found' response.
		 */
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_exchange_set_error_response_body(exchange, status, 
		    NULL);
		khttpd_exchange_respond(exchange, status);
	}

	/*
	 * Send a continue response if it has been requested.  Note that the
	 * server sends a response before it receives the whole request body
	 * only when it founds a message framing problem and is going to close
	 * the connection.  Thus 100-continue expectation is pointless for this
	 * server.
	 */

	if (exchange->continue_requested &&
	    (0 < exchange->request_content_length || 
		exchange->request_chunked)) {
		m = m_gethdr(M_WAITOK, MT_DATA);
		khttpd_mbuf_printf(m, "HTTP/1.1 100 Continue\r\n\r\n");
		khttpd_stream_send(&session->stream, m, KHTTPD_STREAM_FLUSH);
	}

	if (exchange->request_chunked) {
		/*
		 * Start receiving chunked payload if chunked Transfer-Encoding
		 * is specified.
		 */
		session->chunkbuf_end = session->chunkbuf_begin;
		session->receive = khttpd_session_receive_chunk;

	} else if (exchange->request_has_content_length &&
	    0 < exchange->request_content_length) {
		/* Start receiving the body of the message. */
		exchange->request_body_resid =
		    exchange->request_content_length;
		session->receive = khttpd_session_receive_body;

	} else {
		/*
		 * If the message has no body, finish the processing of the
		 * request.
		 */
		khttpd_session_receive_finish(session);

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
	session->recv_paused = false;

	while ((receive = session->receive) != NULL) {
		switch ((error = receive(session))) {
		case 0:
			break;

		case EWOULDBLOCK:
			khttpd_stream_continue_receiving(stream);
			return;

		case EBUSY:
			goto pause;

		default:
			KHTTPD_NOTE("%s error=%d", __func__, error);
			uma_zfree(session->zone, session);
			return;
		}
	}

 pause:
	session->recv_paused = true;
}

static void
khttpd_session_clear_to_send(struct khttpd_stream *stream, ssize_t space)
{
	struct khttpd_session *session;

	session = stream->up;
	if (session->xmit_waiting_for_drain) {
		session->xmit_waiting_for_drain = false;
		khttpd_session_next(session);
	} else
		khttpd_session_transmit(session, space);
}

static void
khttpd_session_error(struct khttpd_stream *stream,
    struct khttpd_mbuf_json *entry)
{

	khttpd_http_log(khttpd_log_chan_error, entry);
}

static void
khttpd_exchange_init(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	sbuf_new(&exchange->target, exchange->target_buf,
	    sizeof(exchange->target_buf), SBUF_AUTOEXTEND);
	exchange->request_header = exchange->request_header_end = 
	    khttpd_malloc(khttpd_header_size_limit);
	exchange->ops = &khttpd_exchange_null_ops;
	bzero(&exchange->khttpd_exchange_zctor_begin, 
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_end) -
	    offsetof(struct khttpd_exchange, khttpd_exchange_zctor_begin));
	exchange->method = -1;
}

static void
khttpd_exchange_fini(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);
	sbuf_delete(&exchange->target);
	khttpd_free(exchange->request_header);
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

	session->chunkbuf_begin = khttpd_malloc(khttpd_chunkbuf_size);

	session->zone = zone;
}

static void
khttpd_session_fini(struct khttpd_session *session)
{

	KHTTPD_ENTRY("%s(%p)", __func__, session);
	sbuf_delete(&session->host);
	khttpd_free(session->chunkbuf_begin);
	khttpd_exchange_fini(&session->exchange);
}

static void
khttpd_session_ctor(struct khttpd_session *session)
{

	KHTTPD_ENTRY("%s(%p)", __func__, session);

	session->receive = khttpd_session_receive_request;
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
	sbuf_clear(&session->host);
	khttpd_server_release(session->server);
	khttpd_port_release(session->port);
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

static int
khttpd_http_local_init(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_http_client_zone = uma_zcreate("http",
	    sizeof(struct khttpd_http_client),
	    khttpd_http_client_ctor, khttpd_http_client_dtor,
	    khttpd_http_client_init, khttpd_http_client_fini,
	    UMA_ALIGN_PTR, 0);

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

void
khttpd_http_error(struct khttpd_mbuf_json *entry)
{

	khttpd_http_log(khttpd_log_chan_error, entry);
}

struct khttpd_mbuf_json *
khttpd_exchange_log_entry(struct khttpd_exchange *exchange)
{

	return (&exchange->log_entry);
}

struct khttpd_socket *
khttpd_exchange_socket(struct khttpd_exchange *exchange)
{

	return (khttpd_exchange_get_session(exchange)->socket);
}

const struct sockaddr *
khttpd_exchange_client_address(struct khttpd_exchange *exchange)
{

	return (khttpd_socket_peer_address
	    (khttpd_exchange_get_session(exchange)->socket));
}

const struct sockaddr *
khttpd_exchange_server_address(struct khttpd_exchange *exchange)
{

	return (khttpd_socket_name
	    (khttpd_exchange_get_session(exchange)->socket));
}

int
khttpd_exchange_method(struct khttpd_exchange *exchange)
{

	return (exchange->method);
}

struct khttpd_location *
khttpd_exchange_location(struct khttpd_exchange *exchange)
{

	return (exchange->location);
}

const char *
khttpd_exchange_query(struct khttpd_exchange *exchange)
{

	return (exchange->query);
}

const char *
khttpd_exchange_suffix(struct khttpd_exchange *exchange)
{

	return (exchange->suffix);
}

const char *
khttpd_exchange_host(struct khttpd_exchange *exchange)
{

	return (sbuf_data(&khttpd_exchange_get_session(exchange)->host));
}

size_t
khttpd_exchange_host_length(struct khttpd_exchange *exchange)
{

	return (sbuf_len(&khttpd_exchange_get_session(exchange)->host));
}

void *
khttpd_exchange_ops_arg(struct khttpd_exchange *exchange)
{

	return (exchange->arg);
}

void
khttpd_exchange_set_ops(struct khttpd_exchange *exchange,
    struct khttpd_exchange_ops *ops, void *arg)
{

	exchange->ops = ops;
	exchange->arg = arg;
}

const char *
khttpd_exchange_target(struct khttpd_exchange *exchange)
{

	return (sbuf_data(&exchange->target));
}

size_t
khttpd_exchange_target_length(struct khttpd_exchange *exchange)
{

	return (sbuf_len(&exchange->target));
}

bool
khttpd_exchange_request_is_chunked(struct khttpd_exchange *exchange)
{

	return (exchange->request_chunked);
}

bool
khttpd_exchange_response_is_chunked(struct khttpd_exchange *exchange)
{

	return (exchange->response_chunked);
}

size_t
khttpd_exchange_request_content_length(struct khttpd_exchange *exchange)
{

	return (exchange->request_content_length);
}

bool
khttpd_exchange_has_request_content_length(struct khttpd_exchange *exchange)
{

	return (exchange->request_has_content_length);
}

bool
khttpd_exchange_has_response_content_length(struct khttpd_exchange *exchange)
{

	return (exchange->response_has_content_length);
}

bool
khttpd_exchange_request_content_type(struct khttpd_exchange *exchange,
	struct sbuf *dst)
{

	if (exchange->request_content_type == NULL) {
		return (false);
	}

	sbuf_bcpy(dst, exchange->request_content_type, 
	    exchange->request_content_type_len);

	return (true);
}

bool
khttpd_exchange_is_json_request(struct khttpd_exchange *exchange,
	bool default_is_json)
{
	static const char app_json[] = "application/json";
	const char *type, *cp;
	size_t len;

	if ((type = exchange->request_content_type) == NULL) {
		return (default_is_json);
	}

	len = exchange->request_content_type_len;
	cp = memchr(type, ';', len);
	if (cp != NULL) {
		len = cp - type;
	}

	return (sizeof(app_json) -1 == len &&
	    strncmp(type, app_json, len) == 0);
}

const char *
khttpd_exchange_request_header(struct khttpd_exchange *exchange,
    size_t *size_out)
{

	*size_out = exchange->request_header_end - exchange->request_header;
	return (exchange->request_header);
}

void
khttpd_exchange_enable_chunked_response(struct khttpd_exchange *exchange)
{

	KASSERT(!exchange->response_chunked, ("exchange->response_chunked"));
	khttpd_exchange_add_response_field(exchange, "Transfer-Encoding",
	    "chunked");
	exchange->response_chunked = true;
}

void
khttpd_exchange_clear_response_header(struct khttpd_exchange *exchange)
{

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);
	KASSERT(!exchange->responding,
	    ("exchange %p, response header has already been closed",
		exchange));

	m_freem(exchange->response_header);
	exchange->response_header = NULL;

	exchange->response_content_length =
	    exchange->response_payload_size = 0;

	m_freem(exchange->response_trailer);
	exchange->response_trailer = NULL;

	m_freem(exchange->response_buffer);
	exchange->response_buffer = NULL;

	exchange->close = false;
	exchange->response_has_content_length = false;
	exchange->response_chunked = false;
	exchange->response_pending = false;
	exchange->status = 0;
}

void
khttpd_exchange_add_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, ...)
{
	va_list vl;

	va_start(vl, value_fmt);
	khttpd_exchange_vadd_response_field(exchange, field, value_fmt, vl);
	va_end(vl);
}

void
khttpd_exchange_add_response_field_line(struct khttpd_exchange *exchange,
    const char *begin, const char *end)
{
	struct khttpd_mbuf_json problem;
	struct mbuf *m;

	if (exchange->responding) {
		if (!exchange->response_chunked) {
			khttpd_mbuf_json_copy(&problem, &exchange->log_entry);
			khttpd_problem_set_internal_error(&problem);
			khttpd_problem_set_detail(&problem,
			    "payload transfer has been started");
			khttpd_http_error(&problem);
		}
		m = exchange->response_trailer;
		if (m == NULL) {
			exchange->response_trailer = m = 
			    m_gethdr(M_WAITOK, MT_DATA);
		}
	} else {
		m = exchange->response_header;
		if (m == NULL) {
			exchange->response_header = m =
			    m_gethdr(M_WAITOK, MT_DATA);
		}
	}

	khttpd_mbuf_append(m, begin, end);
	khttpd_mbuf_append(m, khttpd_crlf, khttpd_crlf + sizeof(khttpd_crlf));
}

void
khttpd_exchange_vadd_response_field(struct khttpd_exchange *exchange,
    const char *field, const char *value_fmt, va_list vl)
{
	struct khttpd_mbuf_json problem;
	struct mbuf *m;

	if (exchange->responding) {
		if (!exchange->response_chunked) {
			khttpd_mbuf_json_copy(&problem, &exchange->log_entry);
			khttpd_problem_set_internal_error(&problem);
			khttpd_problem_set_detail(&problem,
			    "Field %s is added to a response but "
			    "the payload transfer has been started.", field);
			khttpd_http_error(&problem);
		}
		m = exchange->response_trailer;
		if (m == NULL) {
			exchange->response_trailer = m = 
			    m_gethdr(M_WAITOK, MT_DATA);
		}
	} else {
		m = exchange->response_header;
		if (m == NULL) {
			exchange->response_header = m =
			    m_gethdr(M_WAITOK, MT_DATA);
		}
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
	exchange->response_has_content_length = true;
	exchange->response_content_length = length;
}

void
khttpd_exchange_close(struct khttpd_exchange *exchange)
{

	if (exchange->close)
		return;

	exchange->close = true;
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
	    "application/json; charset=utf-8");
}

bool
khttpd_exchange_set_response_body_problem_json
    (struct khttpd_exchange *exchange, int status,
     struct khttpd_mbuf_json *response)
{

	khttpd_exchange_set_response_body(exchange, 
	    khttpd_mbuf_json_move(response));
	khttpd_exchange_add_response_field(exchange, "Content-Type",
	    "application/problem+json; charset=utf-8");

	return (true);
}

void
khttpd_exchange_set_error_response_body(struct khttpd_exchange *exchange,
    int status, struct khttpd_mbuf_json *response)
{
	struct khttpd_mbuf_json new_resp;
	khttpd_location_set_error_response_fn_t fn;
	struct khttpd_location *location;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, exchange, status, response);

	if (response == NULL) {
		response = &new_resp;
		khttpd_mbuf_json_new(response);
		khttpd_problem_response_begin(response, status, NULL, NULL);
	}

	khttpd_mbuf_json_object_end(response);

	location = khttpd_exchange_location(exchange);
	fn = location == NULL ? NULL :
	    khttpd_location_get_ops(location)->set_error_response;
	if (fn == NULL || !fn(exchange, status, response))
		khttpd_exchange_set_response_body_problem_json(exchange,
		    status, response);
}

void
khttpd_exchange_respond(struct khttpd_exchange *exchange, int status)
{

	KHTTPD_ENTRY("%s(%p,%d)", __func__, exchange, status);

	KASSERT(exchange->status == 0,
	    ("exchange->status %d", exchange->status));
	exchange->status = status;

	khttpd_mbuf_json_property(&exchange->log_entry, "status");
	khttpd_mbuf_json_format(&exchange->log_entry, false, "%d", status);

	if (khttpd_exchange_get_session(exchange)->receive != NULL) {
		KHTTPD_NOTE("postponed");
		exchange->response_pending = true;
		return;
	}

	khttpd_exchange_send_response(exchange);
}

void
khttpd_exchange_respond_immediately(struct khttpd_exchange *exchange,
    int status)
{
	struct khttpd_session *session;

	khttpd_exchange_close(exchange);

	session = khttpd_exchange_get_session(exchange);
	session->receive = NULL;

	khttpd_exchange_respond(exchange, status);
}

void
khttpd_exchange_reject(struct khttpd_exchange *exchange)
{

	khttpd_exchange_bailout(exchange, KHTTPD_STATUS_BAD_REQUEST);
}

void
khttpd_exchange_reset(struct khttpd_exchange *exchange)
{

	khttpd_exchange_bailout(exchange, KHTTPD_STATUS_INTERNAL_SERVER_ERROR);
}

void
khttpd_exchange_continue_sending(struct khttpd_exchange *exchange)
{
	struct khttpd_session *session;

	session = khttpd_exchange_get_session(exchange);
	khttpd_stream_notify_of_drain(&session->stream);
}

void
khttpd_exchange_continue_receiving(struct khttpd_exchange *exchange)
{
	struct khttpd_session *session;

	session = khttpd_exchange_get_session(exchange);
	khttpd_stream_continue_receiving(&session->stream);
}

void
khttpd_http_accept_http_client(struct khttpd_port *port)
{
	struct khttpd_http_client *client;
	struct khttpd_socket *socket;
	struct khttpd_stream *stream;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, port);

	client = uma_zalloc(khttpd_http_client_zone, M_WAITOK);
	client->session.port = khttpd_port_acquire(port);
	stream = &client->session.stream;
	stream->down = client->session.socket = socket =
	    khttpd_socket_new(stream);

	error = khttpd_port_accept(port, socket);
	if (error != 0)
		uma_zfree(khttpd_http_client_zone, client);
}

void
khttpd_http_accept_https_client(struct khttpd_port *port)
{

	panic("%s: not implemented yet", __func__);
}
