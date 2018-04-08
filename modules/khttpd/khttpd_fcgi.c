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

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscallsubr.h>
#include <sys/random.h>
#include <sys/syslog.h>

#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/uma.h>
#include <vm/vm_pageout.h>

#include "khttpd_ctrl.h"
#include "khttpd_field.h"
#include "khttpd_http.h"
#include "khttpd_init.h"
#include "khttpd_json.h"
#include "khttpd_log.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_problem.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_stream.h"
#include "khttpd_string.h"
#include "khttpd_test.h"
#include "khttpd_webapi.h"

#define KHTTPD_FCGI_LOCATION_TYPE		"khttpd_fastcgi"
#define KHTTPD_FCGI_MAX_FIELD_LEN		16384
#define KHTTPD_FCGI_MAX_RECORD_CONTENT_LENGTH	USHRT_MAX
#define KHTTPD_FCGI_RECORD_ALIGN		8

CTASSERT(KHTTPD_FCGI_RECORD_ALIGN < 0xff);
CTASSERT((KHTTPD_FCGI_RECORD_ALIGN & (KHTTPD_FCGI_RECORD_ALIGN - 1)) == 0);

enum {
	KHTTPD_FCGI_TYPE_BEGIN_REQUEST = 1,
	KHTTPD_FCGI_TYPE_ABORT_REQUEST,
	KHTTPD_FCGI_TYPE_END_REQUEST,
	KHTTPD_FCGI_TYPE_PARAMS,
	KHTTPD_FCGI_TYPE_STDIN,
	KHTTPD_FCGI_TYPE_STDOUT,
	KHTTPD_FCGI_TYPE_STDERR,
	KHTTPD_FCGI_TYPE_DATA,
	KHTTPD_FCGI_TYPE_GET_VALUES,
	KHTTPD_FCGI_TYPE_GET_VALUES_RESULT,
	KHTTPD_FCGI_TYPE_UNKNOWN_TYPE,
};

enum {
	KHTTPD_FCGI_ROLE_RESPONDER = 1,
};

enum {
	KHTTPD_FCGI_FLAGS_KEEP_CONN = 1
};

struct khttpd_fcgi_hdr {
	uint8_t		version;
	uint8_t 	type;
	uint16_t	request_id;
	uint16_t	content_length;
	uint8_t		padding_length;
	uint8_t		reserved;
} __attribute__ ((packed));

CTASSERT(sizeof(struct khttpd_fcgi_hdr) % KHTTPD_FCGI_RECORD_ALIGN == 0);

/*
 * (a) - guarded by khttpd_fcgi_lock
 * (b) - guarded by khttpd_fcgi_location_data->lock
 * (c) - guarded by khttpd_fcgi_location_data->lock while the instance is
 * 	 waiting.  Otherwise, only the socket worker thread access it.
 */

struct khttpd_fcgi_xchg_data {
	STAILQ_ENTRY(khttpd_fcgi_xchg_data) link;
	struct sbuf	path_info;
	struct sbuf	script_name;
	struct khttpd_exchange *exchange;

#define khttpd_fcgi_xchg_data_zctor_begin conn
	struct khttpd_fcgi_conn *conn; /* (c) */
	struct mbuf	*put_buf;
	bool		aborted;
	bool		connected;
	bool		send_eof;
	bool		suspend_get;
	bool		waiting; /* (b) */

#define khttpd_fcgi_xchg_data_zctor_end path_info_buf
	char		path_info_buf[64];
	char		script_name_buf[64];
};

STAILQ_HEAD(khttpd_fcgi_xchg_data_stailq, khttpd_fcgi_xchg_data);

struct khttpd_fcgi_conn {
	LIST_ENTRY(khttpd_fcgi_conn) allliste;
	LIST_ENTRY(khttpd_fcgi_conn) liste;
	LIST_ENTRY(khttpd_fcgi_conn) idleliste;
	struct sbuf	line;
	struct khttpd_stream stream;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_xchg_data *attaching; /* (b) */

#define khttpd_fcgi_conn_zctor_begin recv_buf
	struct mbuf	*recv_buf;
	bool		connecting;
	bool		idle;		/* (b) */
	bool		hold;		/* (a) */
	bool		free_on_unhold;	/* (a) */
#define khttpd_fcgi_conn_zctor_end khttpd_fcgi_conn_xchg_state_begin

#define khttpd_fcgi_conn_xchg_state_begin stdin
	struct mbuf	*stdin;
	struct mbuf	*stdout;
	unsigned	status:16;
	unsigned	send_busy:1;
	unsigned	stdin_send_eof:1;
	unsigned	stdin_end:1;
	unsigned	stdout_end:1;
	unsigned	suspend_put:1;
	unsigned	suspend_get:1;
	unsigned	suspend_recv:1;
	unsigned	recv_eof:1;
	unsigned	active:1;
	unsigned	header_finished:1;
	unsigned	responded:1;
#define khttpd_fcgi_conn_xchg_state_end line_buf

	char		line_buf[256];
};

LIST_HEAD(khttpd_fcgi_conn_list, khttpd_fcgi_conn);

enum {
	KHTTPD_FCGI_UPSTREAM_AVAILABLE,
	KHTTPD_FCGI_UPSTREAM_FULL,
	KHTTPD_FCGI_UPSTREAM_FAIL
};

struct khttpd_fcgi_upstream {
	LIST_ENTRY(khttpd_fcgi_upstream) liste;
	TAILQ_ENTRY(khttpd_fcgi_upstream) tailqe;
	struct sockaddr_storage sockaddr;
	struct khttpd_fcgi_location_data *location_data;

#define khttpd_fcgi_upstream_zctor_begin nconn
	sbintime_t	idle_timeout;
	sbintime_t	busy_timeout;
	int		nconn;	/* (b) */
	int		state;	/* (b) */

#define khttpd_fcgi_upstream_zctor_end max_conns
	int		max_conns;
	int		max_conns_config;
};

TAILQ_HEAD(khttpd_fcgi_upstream_tailq, khttpd_fcgi_upstream);
LIST_HEAD(khttpd_fcgi_upstream_list, khttpd_fcgi_upstream);

struct khttpd_fcgi_location_data {
	LIST_ENTRY(khttpd_fcgi_location_data) liste;	 /* (a) */
	struct mtx	lock;
	struct khttpd_fcgi_conn_list idle_conn;		 /* (b) */
	struct khttpd_fcgi_upstream_list upstreams;	 /* (b) */
	struct khttpd_fcgi_upstream_tailq avl_upstreams; /* (b) */
	struct khttpd_fcgi_xchg_data_stailq queue;	 /* (b) */
	struct khttpd_location *location;		 /* This can be NULL. */

#define khttpd_fcgi_location_data_zctor_begin fs_path
	char		*fs_path;
	char		*script_suffix;
	int		nconnecting;
	int		nwaiting;

#define khttpd_fcgi_location_data_zctor_end fs_path_fd
	int		fs_path_fd;
};

LIST_HEAD(khttpd_fcgi_location_data_list, khttpd_fcgi_location_data);

struct khttpd_fcgi_request_header_context {
	struct sbuf	sbuf;
	struct mbuf	*head;
	struct mbuf	*tail;
	u_int		len;
	char		buf[128];
};

static void khttpd_fcgi_connect(struct khttpd_fcgi_location_data *);
static void khttpd_fcgi_conn_data_is_available(struct khttpd_stream *);
static void khttpd_fcgi_conn_clear_to_send(struct khttpd_stream *, ssize_t);
static void khttpd_fcgi_conn_reset(struct khttpd_stream *);
static void khttpd_fcgi_conn_error(struct khttpd_stream *,
    struct khttpd_mbuf_json *);
static void khttpd_fcgi_conn_on_configured(struct khttpd_stream *);
static void khttpd_fcgi_conn_release_locked
    (struct khttpd_fcgi_location_data *, struct khttpd_fcgi_conn *);
static void khttpd_fcgi_exchange_dtor(struct khttpd_exchange *, void *);
static int  khttpd_fcgi_exchange_get(struct khttpd_exchange *, void *,
    ssize_t, struct mbuf **);
static void khttpd_fcgi_exchange_put(struct khttpd_exchange *, void *, 
    struct mbuf *, bool *);
static void khttpd_fcgi_do_method(struct khttpd_exchange *);
static void khttpd_fcgi_location_dtor(struct khttpd_location *);
static bool khttpd_fcgi_filter(struct khttpd_location *, 
    struct khttpd_exchange *, const char *, struct sbuf *);

static struct khttpd_stream_up_ops khttpd_fcgi_conn_ops = {
	.data_is_available = khttpd_fcgi_conn_data_is_available,
	.clear_to_send = khttpd_fcgi_conn_clear_to_send,
	.reset = khttpd_fcgi_conn_reset,
	.error = khttpd_fcgi_conn_error,
	.on_configured = khttpd_fcgi_conn_on_configured
};

static struct khttpd_exchange_ops khttpd_fcgi_exchange_ops = {
	.dtor = khttpd_fcgi_exchange_dtor,
	.get = khttpd_fcgi_exchange_get,
	.put = khttpd_fcgi_exchange_put
};

static struct khttpd_location_ops khttpd_fcgi_ops = {
	.dtor = khttpd_fcgi_location_dtor,
	.filter = khttpd_fcgi_filter,
	.catch_all = khttpd_fcgi_do_method,
};

static struct mtx khttpd_fcgi_lock;
static struct khttpd_fcgi_conn_list khttpd_fcgi_conns =
    LIST_HEAD_INITIALIZER(khttpd_fcgi_conns); /* (a) */
static struct khttpd_fcgi_location_data_list khttpd_fcgi_locations =
    LIST_HEAD_INITIALIZER(khttpd_fcgi_locations); /* (a) */
static uma_zone_t khttpd_fcgi_xchg_data_zone;
static uma_zone_t khttpd_fcgi_conn_zone;
static int khttpd_fcgi_nconn;		  /* (a) */
static bool khttpd_fcgi_nconn_waiting;	  /* (a) */

MTX_SYSINIT(khttpd_fcgi_lock, &khttpd_fcgi_lock, "fcgi", MTX_DEF);

#define KHTTPD_FCGI_LONGEST_VALUE_NAME \
	(MAX(sizeof(khttpd_fcgi_max_conns), sizeof(khttpd_fcgi_max_reqs)) - 1)

static void
khttpd_fcgi_init_record_header(struct khttpd_fcgi_hdr *header,
    int type, int cntlen)
{

	KHTTPD_ENTRY("%s(%p,%d,%#x,%d)", __func__, header, type, cntlen);

	KASSERT(cntlen <= USHRT_MAX, ("cntlen %d", cntlen));

	header->version = 1;
	header->type = type;

	switch (type) {

	case KHTTPD_FCGI_TYPE_GET_VALUES:
	case KHTTPD_FCGI_TYPE_GET_VALUES_RESULT:
	case KHTTPD_FCGI_TYPE_UNKNOWN_TYPE:
		header->request_id = 0;
		break;

	default:
		header->request_id = htons(1);
	}

	header->content_length = htons(cntlen);
	header->padding_length = (0 - cntlen) & (KHTTPD_FCGI_RECORD_ALIGN - 1);
	header->reserved = 0;
}

static u_int
khttpd_fcgi_add_padding(struct mbuf *m, u_int cntlen)
{
	static const char pad[KHTTPD_FCGI_RECORD_ALIGN];
	u_int padlen;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, cntlen);
	padlen = (0 - cntlen) & (KHTTPD_FCGI_RECORD_ALIGN - 1);
	khttpd_mbuf_append(m, pad, pad + padlen);
	return (padlen);
}

static void
khttpd_fcgi_report_error(struct khttpd_fcgi_upstream *upstream,
    struct khttpd_mbuf_json *entry)
{

	KHTTPD_ENTRY("%s(%p,%p)", __func__, upstream, entry);

	khttpd_mbuf_json_property(entry, "timestamp");
	khttpd_mbuf_json_now(entry);

	khttpd_mbuf_json_property(entry, "upstream");
	khttpd_mbuf_json_sockaddr(entry,
	    (struct sockaddr *)&upstream->sockaddr);

	khttpd_http_error(entry);
}

static void
khttpd_fcgi_report_connection_error(struct khttpd_fcgi_upstream *upstream,
    int error)
{
	struct khttpd_mbuf_json logent;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, upstream, error);

	khttpd_mbuf_json_new(&logent);
	khttpd_mbuf_json_object_begin(&logent);
	khttpd_problem_set(&logent, LOG_ERR, "fcgi-connect-fail",
	    "FCGI connection failure");
	khttpd_problem_set_detail(&logent, 
	    "failed to connect to a FastCGI application");
	khttpd_problem_set_errno(&logent, error);
	khttpd_fcgi_report_error(upstream, &logent);
}

static void
khttpd_fcgi_set_protocol_error(struct khttpd_mbuf_json *entry)
{

	KHTTPD_ENTRY("%s(%p)", __func__, entry);
	khttpd_problem_set(entry, LOG_ERR, "fcgi_protocol_error",
	    "FastCGI protocol error");
}

static void
khttpd_fcgi_protocol_error_new(struct khttpd_mbuf_json *entry)
{

	KHTTPD_ENTRY("%s(%p)", __func__, entry);
	khttpd_mbuf_json_new(entry);
	khttpd_mbuf_json_object_begin(entry);
	khttpd_fcgi_set_protocol_error(entry);
}

static void
khttpd_fcgi_abort_exchange(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	xchg_data = conn->xchg_data;
	exchange = xchg_data->exchange;
	xchg_data->aborted = true;

	if (conn->suspend_put) {
		khttpd_exchange_continue_receiving(exchange);
	} else if (conn->suspend_get) {
		khttpd_exchange_continue_sending(exchange);
	}

	if (conn->responded) {
		khttpd_exchange_reset(exchange);

	} else {
		conn->responded = true;
		khttpd_exchange_clear_response_header(exchange);
		khttpd_exchange_set_error_response_body(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR, NULL);
		khttpd_exchange_respond(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR);
	}
}

static bool
khttpd_fcgi_send_stdout(struct khttpd_fcgi_conn *conn, struct mbuf *data)
{
	struct mbuf *stdout;
	bool suspend_recv;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, conn, data);

	suspend_recv = false;

	if (conn->stdout_end) {
		m_freem(data);
	} else if (data == NULL) {
		conn->stdout_end = true;
	} else if ((stdout = conn->stdout) == NULL) {
		conn->stdout = data;
	} else {
		m_cat(stdout, data);
		conn->suspend_recv = suspend_recv = true;
	}

	if (conn->suspend_get) {
		conn->suspend_get = false;
		khttpd_exchange_continue_sending(conn->xchg_data->exchange);
	}

	return (suspend_recv);
}

static void
khttpd_fcgi_hdr_error(struct khttpd_fcgi_conn *conn,
    const char *detail_fmt, ...)
{
	struct khttpd_mbuf_json logent;
	va_list va;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, conn, detail_fmt);
	KASSERT(sbuf_done(&conn->line),
	    ("sbuf_finish is not called yet for conn->line"));

	khttpd_fcgi_protocol_error_new(&logent);

	if (detail_fmt != NULL) {
		va_start(va, detail_fmt);
		khttpd_problem_set_vdetail(&logent, detail_fmt, va);
		va_end(va);
	}

	khttpd_mbuf_json_property(&logent, "line");
	khttpd_mbuf_json_bytes(&logent, true, sbuf_data(&conn->line),
	    sbuf_data(&conn->line) + sbuf_len(&conn->line));
	khttpd_fcgi_report_error(conn->upstream, &logent);

	khttpd_fcgi_abort_exchange(conn);
}

static bool
khttpd_fcgi_process_content_length_field(struct khttpd_fcgi_conn *conn,
    const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;
	uintmax_t value;
	int error;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, conn, begin, end);

	exchange = conn->xchg_data->exchange;

	if (khttpd_exchange_response_is_chunked(exchange))
		return (false);

	if (begin == end) {
		return (false);
	}

	error = khttpd_parse_digits(&value, begin, end);
	if (error == ERANGE || (error == 0 && OFF_MAX < value)) {
		khttpd_fcgi_hdr_error(conn, "out of range");
		return (false);
	}
	if (error != 0) {
		khttpd_fcgi_hdr_error(conn, "invalid value");
		return (false);
	}

	khttpd_exchange_set_response_content_length(exchange, value);

	return (false);
}

static bool
khttpd_fcgi_process_location_field(struct khttpd_fcgi_conn *conn,
    const char *begin, const char *end)
{

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	if (*begin == '/') {
		
		return (false);
	}

	if (conn->status == 0)
		conn->status = KHTTPD_STATUS_FOUND;

	return (true);
}

static bool
khttpd_fcgi_process_status_field(struct khttpd_fcgi_conn *conn,
    const char *begin, const char *end)
{
	int status;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	if (!isdigit(begin[0]) || !isdigit(begin[1]) || !isdigit(begin[2]) ||
	    begin[3] != ' ') {
		khttpd_fcgi_hdr_error(conn, "malformed status field");
	} else {
		sscanf(begin, "%d", &status);
		conn->status = status;
	}

	return (false);
}

static void
khttpd_fcgi_process_response_header_line(struct khttpd_fcgi_conn *conn)
{
	char *begin, *name_end, *value_begin, *end;
	bool append_header;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	begin = sbuf_data(&conn->line);
	end = begin + sbuf_len(&conn->line);
	if (begin < end && end[-1] == '\r') {
		--end;
	}
	while (begin < end && end[-1] == ' ') {
		--end;
	}

	name_end = memchr(begin, ':', end - begin);
	if (name_end == NULL || name_end[-1] == ' ') {
		khttpd_fcgi_hdr_error(conn, "malformed response field");
		return;
	}

	if (name_end == end - 1) {
		return;
	}

	for (value_begin = name_end + 1; *value_begin == ' '; ++value_begin) {
		KASSERT(value_begin < end, ("empty field"));
	}

	append_header = false;

	switch (khttpd_field_find(begin, name_end)) {

	case KHTTPD_FIELD_CONTENT_LENGTH:
		append_header = khttpd_fcgi_process_content_length_field(conn,
		    value_begin, end);
		break;

	case KHTTPD_FIELD_LOCATION:
		append_header = khttpd_fcgi_process_location_field(conn,
		    value_begin, end);
		break;

	case KHTTPD_FIELD_STATUS:
		khttpd_fcgi_process_status_field(conn, value_begin, end);
		break;

	case KHTTPD_FIELD_CONNECTION:
	case KHTTPD_FIELD_TRANSFER_ENCODING:
	case KHTTPD_FIELD_HOST:
		break;

	default:
		append_header = true;
		break;
	}

	if (append_header) {
		khttpd_exchange_add_response_field_line
		    (conn->xchg_data->exchange, begin, end);
	}
}

static bool
khttpd_fcgi_process_response_header(struct khttpd_fcgi_conn *conn,
    struct mbuf *data)
{
	struct khttpd_mbuf_json logent;
	struct mbuf *ptr, *next;
	char *begin, *cp, *bolp, *eolp;
	u_int len, off;
	int status;
	bool result;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, conn, data);

	if (data == NULL) {
		khttpd_mbuf_json_copy(&logent,
		    khttpd_exchange_log_entry(conn->xchg_data->exchange));
		khttpd_fcgi_set_protocol_error(&logent);
		khttpd_problem_set_detail(&logent,
		    "stdout is closed prematurely");
		khttpd_fcgi_report_error(conn->upstream, &logent);
		khttpd_fcgi_abort_exchange(conn);
		return (false);
	}

	ptr = data;
	off = 0;
	for (;;) {
		/* Find the first NL in the mbuf pointed by ptr. */
		begin = mtod(ptr, char *) + off;
		len = ptr->m_len - off;
		cp = memchr(begin, '\n', len);

		if (cp != NULL) {
			len = cp - begin;
			off += len + 1;
		}

		if (KHTTPD_FCGI_MAX_FIELD_LEN < sbuf_len(&conn->line) + len) {
			goto too_long;
		}
		sbuf_bcat(&conn->line, begin, len);

		if (cp == NULL) {
			if ((next = ptr->m_next) == NULL) {
				break;
			}

			m_free(ptr);
			ptr = next;
			off = 0;
			continue;
		}

		sbuf_finish(&conn->line);

		bolp = sbuf_data(&conn->line);
		eolp = bolp + sbuf_len(&conn->line);
		if (bolp < eolp && eolp[-1] == '\r')
			--eolp;
		if (bolp == eolp) {
			if (!khttpd_exchange_has_response_content_length
			    (conn->xchg_data->exchange)) {
				khttpd_exchange_enable_chunked_response
				    (conn->xchg_data->exchange);
			}

			conn->header_finished = true;

			m_adj(ptr, off);
			result = khttpd_fcgi_send_stdout(conn, ptr);

			status = conn->status;
			if (status == 0)
				status = KHTTPD_STATUS_OK;
			conn->responded = true;
			khttpd_exchange_respond(conn->xchg_data->exchange,
			    status);

			return (result);
		}

		khttpd_fcgi_process_response_header_line(conn);
		sbuf_clear(&conn->line);
	}

	return (false);

too_long:
	sbuf_finish(&conn->line);
	khttpd_fcgi_hdr_error(conn, "response header line too long");
	return (false);
}

static bool
khttpd_fcgi_process_stdout_record(struct khttpd_fcgi_conn *conn,
    struct mbuf *data)
{
	bool suspend_recv;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, conn, data);

	if (conn->xchg_data == NULL) {
		m_freem(data);
		return (false);
	}

	suspend_recv = conn->header_finished ?
	    khttpd_fcgi_send_stdout(conn, data) :
	    khttpd_fcgi_process_response_header(conn, data);

	return (suspend_recv);
}

static void
khttpd_fcgi_send_stdin(struct khttpd_fcgi_conn *conn, long space)
{
	struct khttpd_fcgi_hdr *hdr;
	struct khttpd_stream *stream;
	struct mbuf *head, *m, *stdin, *stdin_tail;
	u_int stdin_len;
	int max_stdin_len;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn, space);
	KASSERT(conn->xchg_data->connected, ("not connected"));
	KASSERT(conn->send_busy, ("send_busy should be set before "
		"khttpd_fcgi_send_stdin is called"));

	stream = &conn->stream;

	KHTTPD_NOTE("%s space %#x, stdin %p(%#x), stdin_send_eof %d",
	    __func__, space, conn->stdin, m_length(conn->stdin, NULL),
	    conn->stdin_send_eof);
	while (sizeof(struct khttpd_fcgi_hdr) < space &&
	    ((stdin = conn->stdin) != NULL || conn->stdin_send_eof)) {
		KASSERT(!conn->stdin_end, ("stdin_end"));

		if (stdin == NULL) {
			stdin_len = 0;
			space -= sizeof(struct khttpd_fcgi_hdr);

		} else {
			stdin_len = m_length(stdin, NULL);
			max_stdin_len = MIN
			    (KHTTPD_FCGI_MAX_RECORD_CONTENT_LENGTH,
			    rounddown2(space - sizeof(struct khttpd_fcgi_hdr),
			    KHTTPD_FCGI_RECORD_ALIGN));

			if (max_stdin_len < stdin_len) {
				stdin_len = rounddown2(max_stdin_len,
				    KHTTPD_FCGI_RECORD_ALIGN);
				conn->stdin = m_split(stdin, stdin_len,
				    M_WAITOK);
			}

			space -= sizeof(struct khttpd_fcgi_hdr) + stdin_len +
			    khttpd_fcgi_add_padding(stdin, stdin_len);
		}

		head = m_gethdr(M_WAITOK, MT_DATA);
		head->m_len = sizeof(struct khttpd_fcgi_hdr);
		hdr = mtod(head, struct khttpd_fcgi_hdr *);
		khttpd_fcgi_init_record_header(hdr, KHTTPD_FCGI_TYPE_STDIN,
		    stdin_len);
		head->m_next = stdin;

		if (conn->stdin_send_eof) {
			conn->stdin_send_eof = false;
			conn->stdin_end = true;
			if (0 < stdin_len) {
				m_length(stdin, &stdin_tail);
				stdin_tail->m_next = m = 
				    m_get(M_WAITOK, MT_DATA);
				m->m_len = sizeof(struct khttpd_fcgi_hdr);
				hdr = mtod(m, struct khttpd_fcgi_hdr *);
				khttpd_fcgi_init_record_header(hdr, 
				    KHTTPD_FCGI_TYPE_STDIN, 0);
				space -= sizeof(struct khttpd_fcgi_hdr);
			}
			khttpd_stream_send(stream, head, KHTTPD_STREAM_FLUSH);
		} else {
			khttpd_stream_send(stream, head, 0);
		}
	}

	if (space < 0 || conn->stdin != NULL || conn->stdin_send_eof) {
		KHTTPD_NOTE("%s full, stdin %p(%#x), stdin_send_eof %d",
		    __func__, space, conn->stdin, m_length(conn->stdin, NULL),
		    conn->stdin_send_eof);
		khttpd_stream_notify_of_drain(stream);
		return;
	}

	KHTTPD_NOTE("%s ready, stdin %p(%#x), stdin_send_eof %d",
	    __func__, space, conn->stdin, m_length(conn->stdin, NULL),
	    conn->stdin_send_eof);

	conn->send_busy = false;

	if (conn->suspend_put) {
		conn->suspend_put = false;
		khttpd_exchange_continue_receiving(conn->xchg_data->exchange);
		KHTTPD_NOTE("%s continue", __func__);
	}
}

static struct mbuf *
khttpd_fcgi_append_param(struct mbuf **head, struct mbuf *tail,
    u_int *len_inout, const char *name, const char *value, size_t vallen)
{
	char buf[8];
	struct khttpd_fcgi_hdr *hdr;
	char *bp;
	size_t namelen, oldlen, newlen, len;

	KHTTPD_ENTRY("%s(%p,%p,%s), *len_inout=%#x", __func__, *head, tail,
	    khttpd_ktr_printf("\"%s\",\"%.*s\"", name, 
		(int)vallen, value), *len_inout);

	bp = buf;

	namelen = strlen(name);
	if (namelen < 0x80)
		*bp++ = namelen;
	else {
		*bp++ = (namelen >> 24) | 0x80;
		*bp++ = (namelen >> 16) & 0xff;
		*bp++ = (namelen >> 8) & 0xff;
		*bp++ = namelen & 0xff;
	}

	if (vallen < 0x80)
		*bp++ = vallen;
	else {
		*bp++ = (vallen >> 24) | 0x80;
		*bp++ = (vallen >> 16) & 0xff;
		*bp++ = (vallen >> 8) & 0xff;
		*bp++ = vallen & 0xff;
	}

	len = (bp - buf) + namelen + vallen;
	oldlen = *len_inout;
	newlen = oldlen + len;
	if (newlen <= KHTTPD_FCGI_MAX_RECORD_CONTENT_LENGTH) {
		*len_inout = newlen;

	} else {
		khttpd_fcgi_add_padding(tail, oldlen);
		if (tail->m_next != NULL) {
			tail = tail->m_next;
		}

		hdr = mtod(*head, struct khttpd_fcgi_hdr *);
		khttpd_fcgi_init_record_header(hdr, KHTTPD_FCGI_TYPE_PARAMS,
		    oldlen);

		tail = tail->m_next = *head = m_get(M_WAITOK, MT_DATA);
		tail->m_len = sizeof(*hdr);
		*len_inout = len;
	}

	tail = khttpd_mbuf_append(tail, buf, bp);
	tail = khttpd_mbuf_append(tail, name, name + namelen);
	tail = khttpd_mbuf_append(tail, value, value + vallen);

	return (tail);
}

static struct mbuf *
khttpd_fcgi_append_sockaddr_param(struct mbuf **head, struct mbuf *out,
    u_int *len_inout, const struct sockaddr *addr,
    struct sbuf *tmp_sbuf, const char *addr_var_name,
    const char *port_var_name)
{
	const struct sockaddr_in *addr_in;
	const struct sockaddr_in6 *addr_in6;
	uint32_t ip_addr;
	uint16_t port;
	bool has_remote_addr;

	KHTTPD_ENTRY("%s()", __func__);

	switch (addr->sa_family) {
	case AF_INET:
		addr_in = (const struct sockaddr_in *)addr;
		ip_addr = ntohl(addr_in->sin_addr.s_addr);
		port = ntohs(addr_in->sin_port);
		sbuf_printf(tmp_sbuf, "%d.%d.%d.%d", (ip_addr >> 24) & 0xff,
		    (ip_addr >> 16) & 0xff, (ip_addr >> 8) & 0xff, 
		    ip_addr & 0xff);
		has_remote_addr = true;
		break;

	case AF_INET6:
		addr_in6 = (const struct sockaddr_in6 *)addr;
		port = ntohs(addr_in6->sin6_port);
		khttpd_print_ipv6_address(tmp_sbuf,
		    addr_in6->sin6_addr.s6_addr8);
		has_remote_addr = true;
		break;

	case AF_UNIX:
		has_remote_addr = false;
		break;
	}

	if (has_remote_addr) {
		sbuf_finish(tmp_sbuf);
		out = khttpd_fcgi_append_param(head, out, len_inout,
		    addr_var_name, sbuf_data(tmp_sbuf), sbuf_len(tmp_sbuf));
		sbuf_clear(tmp_sbuf);
		sbuf_printf(tmp_sbuf, "%d", port);
		sbuf_finish(tmp_sbuf);
		out = khttpd_fcgi_append_param(head, out, len_inout, 
		    port_var_name, sbuf_data(tmp_sbuf), sbuf_len(tmp_sbuf));
		sbuf_clear(tmp_sbuf);
	}

	return (out);
}

static struct mbuf *
khttpd_fcgi_convert_request_header_field(struct khttpd_exchange *exchange,
    struct mbuf **head, struct mbuf *tail, u_int *len, struct sbuf *sbuf)
{
	const char *bolp, *eolp, *hdrend;
	const char *begin, *end;
	const char *sp;
	const char *cp;
	size_t header_size;
	int ch;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	bolp = khttpd_exchange_request_header(exchange, &header_size);
	hdrend = bolp + header_size;
	eolp = memchr(bolp, '\n', header_size);

	for (bolp = eolp + 1; bolp < hdrend; bolp = eolp + 1) {
		sp = memchr(bolp, ':', hdrend - bolp);
		KASSERT(sp != NULL && bolp < sp &&
		    sp[-1] != ' ' && sp[-1] != '\t', ("field format error"));

		eolp = memchr(sp + 1, '\n', hdrend - sp - 1);
		KASSERT(eolp != NULL, ("no LF at the end of the last field"));

		switch (khttpd_field_find(bolp, sp)) {

		case KHTTPD_FIELD_CONTENT_LENGTH:
		case KHTTPD_FIELD_TRANSFER_ENCODING:
		case KHTTPD_FIELD_CONNECTION:
		case KHTTPD_FIELD_EXPECT:
		case KHTTPD_FIELD_CONTENT_TYPE:
			break;

		default:
			begin = sp + 1;
			end = eolp;
			khttpd_string_trim(&begin, &end);

			sbuf_cpy(sbuf, "HTTP_");
			for (cp = bolp; cp < sp; ++cp) {
				ch = *cp;
				if (ch == '-') {
					sbuf_putc(sbuf, '_');
				} else {
					sbuf_putc(sbuf, toupper(ch));
				}
			}
			sbuf_finish(sbuf);

			tail = khttpd_fcgi_append_param(head, tail, len,
			    sbuf_data(sbuf), begin, end - begin);

			sbuf_clear(sbuf);
		}
	}

	return (tail);
}

static void
khttpd_fcgi_append_params(struct khttpd_fcgi_location_data *loc_data,
    struct khttpd_fcgi_xchg_data *xchg_data, struct mbuf *m)
{
	char buf[1024];
	struct sbuf sbuf;
	const char *query, *method_name;
	struct khttpd_exchange *exchange;
	struct khttpd_location *location, *tmploc;
	struct khttpd_server *server;
	struct khttpd_fcgi_hdr *hdr;
	struct mbuf *head, *tail;
	const struct sockaddr *addr;
	int method;
	u_int len;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, xchg_data, m);

	exchange = xchg_data->exchange;
	location = khttpd_exchange_location(exchange);
	query = khttpd_exchange_query(exchange);
	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	head = tail = m_get(M_WAITOK, MT_DATA);
	head->m_len = sizeof(*hdr);
	m->m_next = head;
	len = 0;

	sbuf_cpy(&sbuf, loc_data->fs_path);
	sbuf_cat(&sbuf, sbuf_data(&xchg_data->script_name));
	sbuf_finish(&sbuf);
	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "SCRIPT_FILENAME", sbuf_data(&sbuf), sbuf_len(&sbuf));
	sbuf_clear(&sbuf);

	if (query == NULL) {
		tail = khttpd_fcgi_append_param(&head, tail, &len,
		    "QUERY_STRING", "", 0);
	} else {
		tail = khttpd_fcgi_append_param(&head, tail, &len,
		    "QUERY_STRING", query, strlen(query));
	}

	method = khttpd_exchange_method(exchange);
	method_name = khttpd_method_name(method);
	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "REQUEST_METHOD", method_name, strlen(method_name));

	if (khttpd_exchange_request_content_type(exchange, &sbuf)) {
		KHTTPD_NOTE("%s content-type", __func__);
		sbuf_finish(&sbuf);
		tail = khttpd_fcgi_append_param(&head, tail, &len, 
		    "CONTENT_TYPE", sbuf_data(&sbuf), sbuf_len(&sbuf));
		sbuf_clear(&sbuf);
	}

	if (khttpd_exchange_has_request_content_length(exchange)) {
		KHTTPD_NOTE("%s content-length", __func__);
		sbuf_printf(&sbuf, "%jd", (intmax_t)
		    khttpd_exchange_request_content_length(exchange));
		sbuf_finish(&sbuf);
		tail = khttpd_fcgi_append_param(&head, tail, &len, 
		    "CONTENT_LENGTH", sbuf_data(&sbuf), sbuf_len(&sbuf));
		sbuf_clear(&sbuf);
	}

	sbuf_cpy(&sbuf, khttpd_location_get_path(location));
	sbuf_cat(&sbuf, sbuf_data(&xchg_data->script_name));
	sbuf_finish(&sbuf);
	tail = khttpd_fcgi_append_param(&head, tail, &len, 
	    "SCRIPT_NAME", sbuf_data(&sbuf), sbuf_len(&sbuf));
	sbuf_clear(&sbuf);

	sbuf_cpy(&sbuf, khttpd_exchange_target(exchange));
	if (query != NULL) {
		sbuf_putc(&sbuf, '?');
		sbuf_cat(&sbuf, query);
	}
	sbuf_finish(&sbuf);
	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "REQUEST_URI", sbuf_data(&sbuf), sbuf_len(&sbuf));
	sbuf_clear(&sbuf);

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "DOCUMENT_URI", khttpd_exchange_target(exchange),
		khttpd_exchange_target_length(exchange));

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "SERVER_PROTOCOL", "HTTP/1.1", sizeof("HTTP/1.1") - 1);

	/* no https support yet. */
	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "REQUEST_SCHEME", "http", sizeof("http") - 1);

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "GATEWAY_INTERFACE", "CGI/1.1", sizeof("CGI/1.1") - 1);

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "SERVER_SOFTWARE", "khttpd/0.0", sizeof("khttpd/0.0") - 1);

	addr = khttpd_exchange_client_address(exchange);
	tail = khttpd_fcgi_append_sockaddr_param(&head, tail, &len,
	    addr, &sbuf, "REMOTE_ADDR", "REMOTE_PORT");

	addr = khttpd_exchange_server_address(exchange);
	if (addr != NULL)
		tail = khttpd_fcgi_append_sockaddr_param(&head, tail, &len,
		    addr, &sbuf, "SERVER_ADDR", "SERVER_PORT");

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "SERVER_NAME", khttpd_exchange_host(exchange),
	    khttpd_exchange_host_length(exchange));

	tail = khttpd_fcgi_append_param(&head, tail, &len,
	    "REDIRECT_STATUS", "200", 3);

	if (0 < sbuf_len(&xchg_data->path_info)) {
		tail = khttpd_fcgi_append_param(&head, tail, &len,
		    "PATH_INFO", sbuf_data(&xchg_data->path_info),
		    sbuf_len(&xchg_data->path_info));

		server = khttpd_location_get_server(location);
		tmploc = khttpd_server_route(server, &xchg_data->path_info,
		    NULL, NULL, &sbuf);
		khttpd_location_release(tmploc);
		sbuf_finish(&sbuf);
		tail = khttpd_fcgi_append_param(&head, tail, &len,
		    "PATH_TRANSLATED", sbuf_data(&sbuf), sbuf_len(&sbuf));
		sbuf_clear(&sbuf);
	}

	tail = khttpd_fcgi_append_param(&head, tail, &len, "DOCUMENT_ROOT",
	    loc_data->fs_path, strlen(loc_data->fs_path));

	tail = khttpd_fcgi_convert_request_header_field(exchange, &head, tail,
	    &len, &sbuf);

	khttpd_fcgi_add_padding(tail, len);
	if (tail->m_next != NULL)
		tail = tail->m_next;

	hdr = mtod(head, struct khttpd_fcgi_hdr *);
	khttpd_fcgi_init_record_header(hdr, KHTTPD_FCGI_TYPE_PARAMS, len);

	if (0 < len) {
		tail->m_next = head = m_get(M_WAITOK, MT_DATA);
		head->m_len = sizeof(*hdr);
		hdr = mtod(head, struct khttpd_fcgi_hdr *);
		khttpd_fcgi_init_record_header(hdr, KHTTPD_FCGI_TYPE_PARAMS, 0);
	}
}

static void
khttpd_fcgi_begin_request(struct khttpd_fcgi_location_data *loc_data,
    struct khttpd_fcgi_xchg_data *xchg_data,
    struct khttpd_fcgi_conn *conn, long space)
{
	struct record {
		struct khttpd_fcgi_hdr hdr;
		uint16_t	role;
		uint8_t		flags;
		uint8_t		reserved[5];
	} __attribute__ ((packed)) *record;
	struct mbuf *m;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, xchg_data, conn);
	KASSERT(conn->send_busy, ("send_busy is false"));

	m = m_get(M_WAITOK, MT_DATA);
	m->m_len = sizeof(struct record);
	record = mtod(m, struct record *);

	CTASSERT(sizeof(*record) % KHTTPD_FCGI_RECORD_ALIGN == 0);
	khttpd_fcgi_init_record_header(&record->hdr, 
	    KHTTPD_FCGI_TYPE_BEGIN_REQUEST,
	    sizeof(struct record) - offsetof(struct record, role));

	record->role = htons(KHTTPD_FCGI_ROLE_RESPONDER);
	record->flags = KHTTPD_FCGI_FLAGS_KEEP_CONN;
	bzero(record->reserved, sizeof(record->reserved));

	khttpd_fcgi_append_params(loc_data, xchg_data, m);

	space -= m_length(m, NULL);
	khttpd_stream_send(&conn->stream, m, 0);
	khttpd_fcgi_send_stdin(conn, space);
}

static void
khttpd_fcgi_attach_conn(void *arg)
{
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_xchg_data *xchg_data;
	long space;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);
	conn = arg;

	loc_data = conn->upstream->location_data;

	mtx_lock(&loc_data->lock);
	if ((xchg_data = conn->attaching) == NULL) {
		khttpd_fcgi_conn_release_locked(loc_data, conn);
		return;
	}
	conn->attaching = NULL;
	mtx_unlock(&loc_data->lock);

	sbuf_clear(&conn->line);
	m_freem(conn->stdin);
	m_freem(conn->stdout);
	bzero(&conn->khttpd_fcgi_conn_xchg_state_begin,
	    offsetof(struct khttpd_fcgi_conn,
		khttpd_fcgi_conn_xchg_state_end) -
	    offsetof(struct khttpd_fcgi_conn,
		khttpd_fcgi_conn_xchg_state_begin));

	conn->xchg_data = xchg_data;
	conn->send_busy = conn->active = true;
	conn->suspend_get = xchg_data->suspend_get;
	conn->suspend_put = xchg_data->put_buf != NULL;
	conn->stdin = xchg_data->put_buf;
	conn->stdin_send_eof = xchg_data->send_eof;

	xchg_data->put_buf = NULL;
	xchg_data->suspend_get = false;
	xchg_data->connected = true;

	khttpd_stream_send_bufstat(&conn->stream, NULL, NULL, &space);
	khttpd_fcgi_begin_request(conn->upstream->location_data,
	    xchg_data, conn, space);
}

static void
khttpd_fcgi_conn_release_locked
(struct khttpd_fcgi_location_data *loc_data, struct khttpd_fcgi_conn *conn)
{
	struct khttpd_socket *socket;
	struct khttpd_fcgi_xchg_data *xchg_data;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, loc_data, conn);
	mtx_assert(&loc_data->lock, MA_OWNED);
	KASSERT(conn->attaching == NULL, ("attaching %p", conn->attaching));
	KASSERT(!conn->connecting, ("connecting"));

	if (conn->idle) {
		mtx_unlock(&loc_data->lock);
		return;
	}

	if ((xchg_data = STAILQ_FIRST(&loc_data->queue)) == NULL) {
		conn->xchg_data = NULL;
		conn->idle = true;
		LIST_INSERT_HEAD(&loc_data->idle_conn, conn, idleliste);
		mtx_unlock(&loc_data->lock);
		return;
	}

	STAILQ_REMOVE_HEAD(&loc_data->queue, link);
	--loc_data->nwaiting;

	conn->attaching = xchg_data;
	xchg_data->conn = conn;
	socket = khttpd_exchange_socket(xchg_data->exchange);

	mtx_unlock(&loc_data->lock);

	/*
	 * XXX socket can become invalid between the above unlock and the
	 * khttpd_socket_set_affinity() call below.
	 */
	khttpd_socket_set_affinity(conn->stream.down, socket,
	    khttpd_fcgi_attach_conn, conn);
}

static void
khttpd_fcgi_conn_release(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_location_data *loc_data;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn);

	loc_data = conn->upstream->location_data;
	mtx_lock(&loc_data->lock);
	khttpd_fcgi_conn_release_locked(loc_data, conn);
}

static void
khttpd_fcgi_upstream_fail_locked(struct khttpd_fcgi_upstream *upstream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, upstream);
	if (upstream->state == KHTTPD_FCGI_UPSTREAM_AVAILABLE) {
		TAILQ_REMOVE(&upstream->location_data->avl_upstreams, upstream,
		    tailqe);
	}
	upstream->state = KHTTPD_FCGI_UPSTREAM_FAIL;
}

static void
khttpd_fcgi_upstream_fail(struct khttpd_fcgi_upstream *upstream)
{
	struct khttpd_fcgi_location_data *loc_data;

	loc_data = upstream->location_data;

	KHTTPD_ENTRY("%s(%p)", __func__, upstream);
	mtx_lock(&loc_data->lock);
	khttpd_fcgi_upstream_fail_locked(upstream);
	mtx_unlock(&loc_data->lock);
}

static void
khttpd_fcgi_conn_destroy(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_upstream *upstream;
	bool hold, new_conn;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	upstream = conn->upstream;
	loc_data = upstream->location_data;
	new_conn = false;

	mtx_lock(&loc_data->lock);

	if (conn->connecting)
		--loc_data->nconnecting;

	if (conn->idle) {
		LIST_REMOVE(conn, idleliste);
		conn->idle = false;
	}

	mtx_unlock(&loc_data->lock);

	khttpd_stream_destroy(&conn->stream);

	mtx_lock(&loc_data->lock);

	/*
	 * Don't decrement upstream->nconn before the socket is closed by
	 * khttpd_stream_destroy().
	 */
	if (--upstream->nconn < upstream->max_conns &&
	    upstream->state == KHTTPD_FCGI_UPSTREAM_FULL) {
		TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream,
		    tailqe);
		upstream->state = KHTTPD_FCGI_UPSTREAM_AVAILABLE;
	}

	if (loc_data->nconnecting < loc_data->nwaiting)
		khttpd_fcgi_connect(loc_data);

	mtx_unlock(&loc_data->lock);

	mtx_lock(&khttpd_fcgi_lock);
	if ((hold = conn->hold))
		conn->free_on_unhold = true;
	else
		LIST_REMOVE(conn, allliste);
	mtx_unlock(&khttpd_fcgi_lock);

	if (!hold)
		uma_zfree(khttpd_fcgi_conn_zone, conn);
}

static struct khttpd_socket *
khttpd_fcgi_conn_socket(struct khttpd_fcgi_conn *conn)
{

	return (conn->stream.down);
}

static void
khttpd_fcgi_conn_on_configured(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_fcgi_location_data *loc_data;

	conn = stream->up;
	upstream = conn->upstream;
	loc_data = upstream->location_data;

	conn->connecting = false;

	mtx_lock(&loc_data->lock);
	--loc_data->nconnecting;
	khttpd_fcgi_conn_release_locked(loc_data, conn);
}

static int
khttpd_fcgi_did_connected(struct khttpd_socket *socket, void *arg,
	struct khttpd_socket_config *conf)
{
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_fcgi_location_data *loc_data;

	conn = arg;
	upstream = conn->upstream;
	loc_data = upstream->location_data;

	conf->stream = &conn->stream;
	conf->timeout = upstream->idle_timeout;

	return (0);
}

static int
khttpd_fcgi_conn_new(struct khttpd_fcgi_location_data *loc_data,
    struct khttpd_fcgi_upstream *upstream)
{
	struct khttpd_fcgi_conn *conn;
	int error;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, loc_data, upstream);

	conn = uma_zalloc_arg(khttpd_fcgi_conn_zone, upstream, M_WAITOK);
	conn->stream.up_ops = &khttpd_fcgi_conn_ops;
	conn->connecting = true;

	mtx_lock(&khttpd_fcgi_lock);
	LIST_INSERT_HEAD(&khttpd_fcgi_conns, conn, allliste);
	mtx_unlock(&khttpd_fcgi_lock);

	mtx_lock(&loc_data->lock);
	++loc_data->nconnecting;
	if (upstream->max_conns <= ++upstream->nconn &&
	    upstream->state == KHTTPD_FCGI_UPSTREAM_AVAILABLE) {
		TAILQ_REMOVE(&loc_data->avl_upstreams, upstream, tailqe);
		upstream->state = KHTTPD_FCGI_UPSTREAM_FULL;
	}
	mtx_unlock(&loc_data->lock);

	error = khttpd_socket_connect((struct sockaddr *)&upstream->sockaddr,
	    NULL, khttpd_fcgi_did_connected, conn);
	if (error != 0 && error != EINPROGRESS) {
		KHTTPD_NOTE("%s error %d", __func__, error);
		khttpd_fcgi_upstream_fail(upstream);
		khttpd_fcgi_conn_destroy(conn);
		khttpd_fcgi_report_connection_error(upstream, error);
	}

	return (0);
}

static void
khttpd_fcgi_connect(struct khttpd_fcgi_location_data *loc_data)
{
	struct khttpd_fcgi_upstream *upstream;

	KHTTPD_ENTRY("%s(%p)", __func__, loc_data);
	mtx_assert(&loc_data->lock, MA_OWNED);

	while (loc_data->nconnecting < loc_data->nwaiting &&
	    (upstream = TAILQ_FIRST(&loc_data->avl_upstreams)) != NULL) {
		KASSERT(upstream->nconn < upstream->max_conns,
		    ("upstream %p, nconn %d, max_conns %d", upstream,
			upstream->nconn, upstream->max_conns));

		TAILQ_REMOVE(&loc_data->avl_upstreams, upstream, tailqe);
		TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream,
		    tailqe);
		mtx_unlock(&loc_data->lock);

		khttpd_fcgi_conn_new(loc_data, upstream);

		mtx_lock(&loc_data->lock);
	}
}

static void
khttpd_fcgi_end_request(struct khttpd_fcgi_conn *conn,
    uint32_t app_status, int protocol_status)
{
	static const char *protocol_status_names[] = {
		"FCGI_REQUEST_COMPLETE",
		"FCGI_CANT_MPX_CONN",
		"FCGI_OVERLOADED",
		"FCGI_UNKNOWN_ROLE"
	};

	struct khttpd_mbuf_json logent;
	struct khttpd_exchange *exchange;
	struct khttpd_fcgi_xchg_data *xchg_data;
	long space;
	int status;

	KHTTPD_ENTRY("%s(%p,%#x,%d)", __func__, conn, app_status, 
	    protocol_status);

	if (!conn->active) {
		KHTTPD_NOTE("%s inactive", __func__);
		return;
	}
	conn->active = false;

	if ((xchg_data = conn->xchg_data) == NULL) {
		KHTTPD_NOTE("%s null xchg_data", __func__);
		khttpd_stream_send_bufstat(&conn->stream, NULL, NULL, &space);
		khttpd_fcgi_conn_release(conn);
		return;
	}

	exchange = xchg_data->exchange;
	status = conn->status;

	if (!conn->stdout_end) {
		conn->stdout_end = true;
		if (conn->suspend_get) {
			conn->suspend_get = false;
			khttpd_exchange_continue_sending
			    (conn->xchg_data->exchange);
		}
	}

	if (app_status == 0 && protocol_status == 0) {
		KHTTPD_NOTE("%s success", __func__);
		return;
	}

	KHTTPD_NOTE("app_status %#x, protocol_status %d",
	    app_status, protocol_status);
	khttpd_fcgi_protocol_error_new(&logent);

	if (app_status != 0) {
		khttpd_mbuf_json_property(&logent, "appStatus");
		khttpd_mbuf_json_format(&logent, false, "%u",
		    app_status);
	}

	if (protocol_status != 0) {
		khttpd_mbuf_json_property(&logent, "protocolStatus");
		if (protocol_status < nitems(protocol_status_names))
			khttpd_mbuf_json_format(&logent, true, "%s",
			    protocol_status_names[protocol_status]);
		else
			khttpd_mbuf_json_format(&logent, true, "%d",
			    protocol_status);
	}

	khttpd_fcgi_report_error(conn->upstream, &logent);

	/*
	 * XXX Because we have already sent the stdout data to the client, it's
	 * too late to send an unsuccessful http status code to the client.
	 *
	 * We should buffer all the stdout data until we receives end_request
	 * record, and then send them if both the app_status and
	 * protocol_status is 0.
	 */
}

static void
khttpd_fcgi_found_eof(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_mbuf_json logent;
	struct khttpd_fcgi_xchg_data *xchg_data;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	if ((xchg_data = conn->xchg_data) == NULL) {
		KHTTPD_NOTE("%s no xchg_data", __func__);
		khttpd_fcgi_conn_destroy(conn);
		return;
	}

	KHTTPD_NOTE("%s xchg_data %p", __func__, xchg_data);
	khttpd_fcgi_protocol_error_new(&logent);
	khttpd_problem_set_detail(&logent,
	    "upstream server closed the connection prematurely");
	khttpd_fcgi_report_error(conn->upstream, &logent);

	conn->recv_eof = true;
	khttpd_fcgi_abort_exchange(conn);
}

static void
khttpd_fcgi_conn_data_is_available(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_end_request_body {
		uint32_t	app_status;
		uint8_t		protocol_status;
		uint8_t		reserved[3];
	} __attribute__ ((packed));;

	struct khttpd_mbuf_json logent;
	struct khttpd_fcgi_hdr hdr;
	struct khttpd_fcgi_end_request_body endreq_body;
	struct khttpd_fcgi_conn *conn;
	struct mbuf *m;
	ssize_t resid;
	int mlen, cntlen, padlen, pktlen;
	int error;
	bool suspend_recv;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	conn = stream->up;
	suspend_recv = false;
	resid = SSIZE_MAX;
	error = khttpd_stream_receive(&conn->stream, &resid, &m);
	if (error != 0) {
		KHTTPD_NOTE("%s error %d", __func__, error);

		if (error == EWOULDBLOCK) {
			khttpd_stream_continue_receiving(stream,
			    conn->xchg_data == NULL ? 
			    conn->upstream->idle_timeout :
			    conn->upstream->busy_timeout);
			return;
		}

		khttpd_fcgi_protocol_error_new(&logent);
		khttpd_problem_set_detail(&logent, "receive failure");
		khttpd_problem_set_errno(&logent, error);
		khttpd_fcgi_report_error(conn->upstream, &logent);

		m_freem(conn->recv_buf);
		conn->recv_buf = NULL;

		khttpd_socket_reset(khttpd_fcgi_conn_socket(conn));
		return;
	}

	if (m == NULL) {
		khttpd_fcgi_found_eof(conn);
		return;
	}

	if (conn->recv_buf == NULL) {
		conn->recv_buf = m;
	} else {
		m_cat(conn->recv_buf, m);
		m = conn->recv_buf;
	}
	mlen = m_length(m, NULL);
	KHTTPD_NOTE("%s mlen %d", __func__, mlen);

	for (; sizeof(struct khttpd_fcgi_hdr) <= mlen;
	     m = conn->recv_buf) {
		KHTTPD_NOTE("m_length(%p)=%d", m, m_length(m, NULL));
		
		m_copydata(m, 0, sizeof(hdr), (char *)&hdr);

		if (hdr.version != 1) {
			KHTTPD_NOTE("%s invalid version %d %d %d %d %d %d",
			    __func__, hdr.version, hdr.type,
			    ntohs(hdr.request_id),
			    ntohs(hdr.content_length));
			khttpd_fcgi_protocol_error_new(&logent);
			khttpd_problem_set_detail(&logent,
			    "unknown protocol version \"%d\"", hdr.version);
			khttpd_fcgi_report_error(conn->upstream, &logent);

			conn->recv_buf = NULL;
			m_freem(m);

			khttpd_socket_reset(khttpd_fcgi_conn_socket(conn));
			return;
		}

		cntlen = ntohs(hdr.content_length);
		padlen = hdr.padding_length;
		pktlen = sizeof(hdr) + cntlen + padlen;
		KHTTPD_NOTE("%s cntlen %d, padlen %d, pktlen %d",
		    __func__, cntlen, padlen, pktlen);
		if (mlen < pktlen) {
			break;
		}

		conn->recv_buf = m_split(m, pktlen, M_WAITOK);
		mlen -= pktlen;

		switch (hdr.type) {

		case KHTTPD_FCGI_TYPE_END_REQUEST:
			m_copydata(m, sizeof(hdr), sizeof(endreq_body),
			    (char *)&endreq_body);
			m_freem(m);
			khttpd_fcgi_end_request(conn,
			    ntohl(endreq_body.app_status),
			    endreq_body.protocol_status);
			break;

		case KHTTPD_FCGI_TYPE_STDOUT:
			if (cntlen == 0) {
				m_freem(m);
				m = NULL;
			} else {
				m_adj(m, sizeof(hdr));
				m_adj(m, -padlen);
			}
			if (khttpd_fcgi_process_stdout_record(conn, m))
				suspend_recv = true;
			break;

		case KHTTPD_FCGI_TYPE_STDERR:
			if (hdr.content_length == 0) {
				m_freem(m);
				break;
			}

			m_adj(m, sizeof(hdr));
			m_adj(m, -padlen);
			khttpd_problem_log_new(&logent, LOG_WARNING,
			    "fcgi_stderr", "FastCGI stderr");
			khttpd_mbuf_json_property(&logent, "content");
			khttpd_mbuf_json_mbuf(&logent, true, m);
			khttpd_fcgi_report_error(conn->upstream, &logent);
			break;

		default:
			m_freem(m);

			khttpd_fcgi_protocol_error_new(&logent);
			khttpd_problem_set_detail(&logent,
			    "invalid record type \"%d\"", hdr.type);
			khttpd_fcgi_report_error(conn->upstream, &logent);
		}

		KHTTPD_NOTE("%s continue mlen %d", __func__, mlen);
	}

	if (!suspend_recv) {
		khttpd_stream_continue_receiving(stream,
		    conn->upstream->busy_timeout);
	}
}

static void
khttpd_fcgi_conn_clear_to_send(struct khttpd_stream *stream, long space)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, stream, space);

	conn = stream->up;
	if (conn->active && conn->xchg_data != NULL) {
		khttpd_fcgi_send_stdin(conn, space);
	}
}

static void
khttpd_fcgi_conn_reset(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	conn = stream->up;

	if (conn->suspend_recv) {
		KHTTPD_NOTE("%s suspend_recv", __func__);
		conn->suspend_recv = false;
		khttpd_stream_continue_receiving(&conn->stream, 0);
	}
}

static void
khttpd_fcgi_conn_error(struct khttpd_stream *stream,
    struct khttpd_mbuf_json *entry)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, stream, entry);

	conn = stream->up;
	khttpd_fcgi_report_error(conn->upstream, entry);
}

static void
khttpd_fcgi_upstream_destroy(struct khttpd_fcgi_upstream *upstream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, upstream);
	khttpd_free(upstream);
}

static int
khttpd_fcgi_upstream_new(struct khttpd_fcgi_upstream **upstream_out,
    struct khttpd_fcgi_location_data *loc_data,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_fcgi_upstream *upstream;
	int64_t max_conns;
	int error, status;

	KHTTPD_ENTRY("%s(,%p,...)", __func__, loc_data);

	upstream = khttpd_malloc(sizeof(struct khttpd_fcgi_upstream));
	bzero(&upstream->khttpd_fcgi_upstream_zctor_begin,
	    offsetof(struct khttpd_fcgi_upstream,
		khttpd_fcgi_upstream_zctor_end) -
	    offsetof(struct khttpd_fcgi_upstream,
		khttpd_fcgi_upstream_zctor_begin));
	upstream->location_data = loc_data;
	upstream->max_conns = 1;
	upstream->state = KHTTPD_FCGI_UPSTREAM_AVAILABLE;

	status = khttpd_webapi_get_integer_property(&max_conns, "maxConns",
	    input_prop_spec, input, output, true);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;

	} else if (status == KHTTPD_STATUS_NO_CONTENT) {
		max_conns = INT_MAX;

	} else if (max_conns <= 0 || INT_MAX < max_conns) {
		prop_spec.name = "maxConns";
		prop_spec.link = input_prop_spec;
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto end;
	}
	upstream->max_conns_config = max_conns;

	status = khttpd_webapi_get_sockaddr_property
	    ((struct sockaddr *)&upstream->sockaddr,
		sizeof(upstream->sockaddr), "address",
		input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto end;

	mtx_lock(&loc_data->lock);
	TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream, tailqe);
	mtx_unlock(&loc_data->lock);

	if ((error = khttpd_fcgi_conn_new(loc_data, upstream)) == 0) {
		status = KHTTPD_STATUS_OK;

	} else {
		prop_spec.name = "address";
		prop_spec.link = input_prop_spec;
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_detail(output,
		    "failed to connect to the specified address");
		khttpd_problem_set_property(output, &prop_spec);
		khttpd_problem_set_errno(output, error);

		status = KHTTPD_STATUS_BAD_REQUEST;
	}

 end:
	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		*upstream_out = upstream;
	else
		khttpd_fcgi_upstream_destroy(upstream);

	return (status);
}

static void
khttpd_fcgi_exchange_dtor(struct khttpd_exchange *exchange, void *arg)
{
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_hdr *hdr;
	struct mbuf *m;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, exchange, arg);

	xchg_data = arg;
	loc_data = khttpd_location_data(khttpd_exchange_location(exchange));

	if (!xchg_data->connected) {
		KHTTPD_NOTE("%s !connected", __func__);
		mtx_lock(&loc_data->lock);
		if (xchg_data->waiting) {
			KHTTPD_NOTE("%s waiting", __func__);
			STAILQ_REMOVE(&loc_data->queue, xchg_data,
			    khttpd_fcgi_xchg_data, link);
			--loc_data->nwaiting;
		}

		if ((conn = xchg_data->conn) != NULL) {
			KHTTPD_NOTE("%s conn %p", __func__, conn);
			KASSERT(conn->attaching == NULL ||
			    conn->attaching == xchg_data,
			    ("attaching %p", conn->attaching));
			conn->xchg_data = conn->attaching = NULL;
		}

		mtx_unlock(&loc_data->lock);

		uma_zfree(khttpd_fcgi_xchg_data_zone, arg);
		return;
	}

	conn = xchg_data->conn;
	xchg_data->conn = NULL;
	conn->xchg_data = NULL;

	uma_zfree(khttpd_fcgi_xchg_data_zone, xchg_data);

	if (conn->recv_eof) {
		KHTTPD_NOTE("%s eof", __func__);
		khttpd_fcgi_conn_destroy(conn);

	} else {
		if (conn->suspend_recv) {
			KHTTPD_NOTE("%s suspend_recv", __func__);
			conn->suspend_recv = false;
			khttpd_stream_continue_receiving(&conn->stream,
				conn->upstream->busy_timeout);
		}

		if (!conn->header_finished) {
			KHTTPD_NOTE("%s abort_request", __func__);
			m = m_get(M_WAITOK, MT_DATA);
			m->m_len = sizeof(struct khttpd_fcgi_hdr);
			hdr = mtod(m, struct khttpd_fcgi_hdr *);
			khttpd_fcgi_init_record_header(hdr,
			    KHTTPD_FCGI_TYPE_ABORT_REQUEST, 0);
			khttpd_stream_send(&conn->stream, m,
			    KHTTPD_STREAM_FLUSH);
		}
	}
}

static int
khttpd_fcgi_exchange_get(struct khttpd_exchange *exchange, void *arg,
    long space, struct mbuf **data_out)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_conn *conn;
	struct mbuf *hd;
	bool would_block;

	KHTTPD_ENTRY("%s(%p,%p,%#lx)", __func__, exchange, arg, space);

	xchg_data = arg;
	would_block = false;

	if (xchg_data->aborted) {
		KHTTPD_NOTE("%s aborted", __func__);
		return (ECONNABORTED);
	}

	if (!xchg_data->connected) {
		KHTTPD_NOTE("%s !connected", __func__);
		xchg_data->suspend_get = true;
		return (EWOULDBLOCK);
	}

	conn = xchg_data->conn;

	if ((hd = conn->stdout) == NULL) {
		KHTTPD_NOTE("%s stdout_end %d, recv_eof %d", __func__,
			conn->stdout_end, conn->recv_eof);
		if (!conn->stdout_end && !conn->recv_eof) {
			conn->suspend_get = true;
			return (EWOULDBLOCK);
		}
		*data_out = NULL;
		return (0);
	}

	if ((conn->stdout = m_split(hd, space, M_WAITOK)) == NULL &&
	    conn->suspend_recv) {
		conn->suspend_recv = false;
		khttpd_stream_continue_receiving(&conn->stream,
		    conn->upstream->busy_timeout);
	}

	KHTTPD_NOTE("%s send %#x", __func__, m_length(hd, NULL));
	*data_out = hd;
	return (0);
}

static void
khttpd_fcgi_exchange_put(struct khttpd_exchange *exchange, void *arg,
    struct mbuf *data, bool *pause_out)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_conn *conn;
	long space;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, exchange, arg);

	xchg_data = arg;

	if (xchg_data->aborted) {
		KHTTPD_NOTE("%s aborted", __func__);
		m_freem(data);
		khttpd_exchange_clear_response_header(exchange);
		khttpd_exchange_set_error_response_body(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR, NULL);
		khttpd_exchange_respond(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR);
		return;
	}

	if (!xchg_data->connected) {
		if (data == NULL) {
			xchg_data->send_eof = true;
			return;
		}

		if (xchg_data->put_buf == NULL) {
			xchg_data->put_buf = data;
		} else {
			m_cat(xchg_data->put_buf, data);
		}

		*pause_out = true;
		return;
	}

	conn = xchg_data->conn;

	if (data == NULL) {
		conn->stdin_send_eof = true;
	} else if (conn->stdin == NULL) {
		conn->stdin = data;
	} else {
		m_cat(conn->stdin, data);
	}

	if (conn->send_busy) {
		*pause_out = conn->suspend_put = data != NULL;
	} else {
		conn->send_busy = true;
		khttpd_stream_send_bufstat(&conn->stream, NULL, NULL, &space);
		khttpd_fcgi_send_stdin(conn, space);
	}
}

static bool
khttpd_fcgi_filter(struct khttpd_location *location,
    struct khttpd_exchange *exchange, const char *suffix,
    struct sbuf *translated_path)
{
	struct stat statbuf;
	struct sbuf sbuf;
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_xchg_data *data;
	char oldsep, *segbegin, *segend, *script_suffix;
	const char *cp;
	struct thread *td;
	size_t suffix_len;
	int error, fd;

	KHTTPD_ENTRY("%s(%p,%p,%s)", __func__, location, exchange,
	    khttpd_ktr_printf("%s", suffix));

	td = curthread;
	loc_data = khttpd_location_data(location);

	/* Unescape the suffix */

	sbuf_new(&sbuf, NULL, strlen(suffix) + 1, SBUF_AUTOEXTEND);
	khttpd_unescape_uri(&sbuf, suffix);
	sbuf_finish(&sbuf);

	/* Find the script. */

	if ((script_suffix = loc_data->script_suffix) != NULL) {
		suffix_len = strlen(script_suffix);

		segbegin = sbuf_data(&sbuf);
		segend = strchr(segbegin, '/');
		for (;;) {
			if (segend == NULL)
				segend = sbuf_data(&sbuf) + sbuf_len(&sbuf);

			oldsep = *segend;

			if (suffix_len <= segend - segbegin &&
			    memcmp(segend - suffix_len, script_suffix,
				suffix_len) == 0) {
				*segend = '\0';

				error = kern_statat(td, 0, 
				    loc_data->fs_path_fd, sbuf_data(&sbuf),
				    UIO_SYSSPACE, &statbuf, NULL);
				if (error != 0) {
					KHTTPD_BRANCH
					    ("%s stat error %d \"%s\"",
					     __func__, error,
					     khttpd_ktr_printf("%s",
					     sbuf_data(&sbuf)));
					break;
				}

				*segend = oldsep;

				if (S_ISREG(statbuf.st_mode)) {
					KHTTPD_BRANCH("%s %u positive \"%s\"",
					    __func__, __LINE__,
					    khttpd_ktr_printf("%.*s",
						(int)(segend - segbegin),
						segbegin));
					goto positive;
				}
			}

			if (oldsep == '\0')
				break;

			segbegin = segend + 1;
			segend = strchr(segbegin, '/');
		}

	} else {
		fd = loc_data->fs_path_fd;
		segbegin = sbuf_data(&sbuf);
		segend = strchr(segbegin, '/');
		for (;;) {
			if (segend == NULL)
				segend = sbuf_data(&sbuf) + sbuf_len(&sbuf);

			oldsep = *segend;
			*segend = '\0';

			error = kern_statat(td, 0, fd, segbegin, UIO_SYSSPACE,
			    &statbuf, NULL);
			if (error != 0)
				break;

			if (S_ISREG(statbuf.st_mode)) {
				if (fd != loc_data->fs_path_fd)
					kern_close(td, fd);
				*segend = oldsep;
				KHTTPD_BRANCH("%s %u positive \"%s\"",
				    __func__, __LINE__,
				    khttpd_ktr_printf("%.*s",
					(int)(segend - segbegin), segbegin));
				goto positive;
			}

			if (!S_ISDIR(statbuf.st_mode))
				break;

			error = kern_openat(td, fd, segbegin, UIO_SYSSPACE,
			    O_RDONLY | O_DIRECTORY, 0777);
			if (error != 0)
				break;
			fd = td->td_retval[0];

			*segend = oldsep;

			if (oldsep == '\0')
				break;

			segbegin = segend + 1;
			segend = strchr(segbegin, '/');
		}

		if (fd != loc_data->fs_path_fd)
			kern_close(td, fd);
	}

	KHTTPD_BRANCH("%s negative", __func__);
	sbuf_delete(&sbuf);

	return (false);

 positive:
	data = uma_zalloc_arg(khttpd_fcgi_xchg_data_zone, exchange, M_WAITOK);
	if (exchange != NULL)
		khttpd_exchange_set_ops(exchange, &khttpd_fcgi_exchange_ops,
		    data);

	KASSERT(loc_data->fs_path[strlen(loc_data->fs_path) - 1] == '/',
	    ("fs_path \"%s\" is not slash terminated", loc_data->fs_path));

	cp = sbuf_data(&sbuf);
	sbuf_bcat(&data->script_name, cp, segend - cp);
	sbuf_finish(&data->script_name);

	if (translated_path != NULL)
		sbuf_bcpy(translated_path, sbuf_data(&data->script_name),
		    sbuf_len(&data->script_name));

	sbuf_cpy(&data->path_info, segend);
	sbuf_finish(&data->path_info);

	sbuf_delete(&sbuf);

	if (exchange == NULL)
		uma_zfree(khttpd_fcgi_xchg_data_zone, data);

	return (true);
}

static void
khttpd_fcgi_do_method(struct khttpd_exchange *exchange)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_location *location;
	struct khttpd_fcgi_conn *conn;
	struct thread *td;
	int status;

	KHTTPD_ENTRY("%s(%p=%s)", __func__, exchange,
	    khttpd_ktr_printf("{target: \"%s\", method: \"%s\"}",
		khttpd_exchange_target(exchange),
		khttpd_method_name(khttpd_exchange_method(exchange))));

	td = curthread;
	location = khttpd_exchange_location(exchange);
	loc_data = khttpd_location_data(location);
	xchg_data = khttpd_exchange_ops_arg(exchange);

	if (khttpd_exchange_request_is_chunked(exchange)) {
		status = KHTTPD_STATUS_LENGTH_REQUIRED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);
		return;
	}

 	mtx_lock(&loc_data->lock);
	if ((conn = LIST_FIRST(&loc_data->idle_conn)) == NULL) {
		xchg_data->waiting = true;
		STAILQ_INSERT_TAIL(&loc_data->queue, xchg_data, link);
		++loc_data->nwaiting;
		khttpd_fcgi_connect(loc_data);
		mtx_unlock(&loc_data->lock);
		return;
	}

	LIST_REMOVE(conn, idleliste);
	conn->idle = false;
	conn->attaching = xchg_data;
	xchg_data->conn = conn;
	mtx_unlock(&loc_data->lock);

	khttpd_socket_set_affinity(conn->stream.down,
	    khttpd_exchange_socket(exchange), khttpd_fcgi_attach_conn, conn);
}

static int
khttpd_fcgi_conn_init(void *mem, int size, int flags)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);

	conn = mem;
	sbuf_new(&conn->line, conn->line_buf,
	    sizeof(conn->line_buf), SBUF_AUTOEXTEND);
	conn->stream.up_ops = &khttpd_fcgi_conn_ops;
	conn->stream.up = conn;
	conn->stream.down = NULL;
	conn->xchg_data = NULL;

	return (0);
}

static void
khttpd_fcgi_conn_fini(void *mem, int size)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, mem, size);

	conn = mem;
	sbuf_delete(&conn->line);
}

static int
khttpd_fcgi_conn_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%#x,%p,%#x)", __func__, mem, size, arg, flags);

	mtx_lock(&khttpd_fcgi_lock);
	++khttpd_fcgi_nconn;
	mtx_unlock(&khttpd_fcgi_lock);

	conn = mem;
	conn->upstream = arg;
	bzero(&conn->khttpd_fcgi_conn_zctor_begin,
	    offsetof(struct khttpd_fcgi_conn, khttpd_fcgi_conn_zctor_end) -
	    offsetof(struct khttpd_fcgi_conn, khttpd_fcgi_conn_zctor_begin));

	return (0);
}

static void
khttpd_fcgi_conn_dtor(void *mem, int size, void *arg)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%#x,%p)", __func__, mem, size, arg);

	conn = mem;
	KASSERT(conn->xchg_data == NULL,
	    ("busy. conn %p, xchg_data %p", conn, conn->xchg_data));

	sbuf_clear(&conn->line);
	khttpd_stream_destroy(&conn->stream);
	m_freem(conn->recv_buf);
	m_freem(conn->stdin);
	m_freem(conn->stdout);

	mtx_lock(&khttpd_fcgi_lock);
	if (--khttpd_fcgi_nconn == 0 && khttpd_fcgi_nconn_waiting) {
		khttpd_fcgi_nconn_waiting = false;
		wakeup(&khttpd_fcgi_nconn);
	}
	mtx_unlock(&khttpd_fcgi_lock);
}

static int
khttpd_fcgi_xchg_data_init(void *mem, int size, int flags)
{
	struct khttpd_fcgi_xchg_data *data;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);

	data = mem;
	sbuf_new(&data->path_info, data->path_info_buf,
	    sizeof(data->path_info_buf), SBUF_AUTOEXTEND);
	sbuf_new(&data->script_name, data->script_name_buf,
	    sizeof(data->script_name_buf), SBUF_AUTOEXTEND);

	return (0);
}

static void
khttpd_fcgi_xchg_data_fini(void *mem, int size)
{
	struct khttpd_fcgi_xchg_data *data;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, mem, size);

	data = mem;
	sbuf_delete(&data->path_info);
	sbuf_delete(&data->script_name);
}

static int
khttpd_fcgi_xchg_data_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_fcgi_xchg_data *data;

	KHTTPD_ENTRY("%s(%p,%#x,%p,%#x)", __func__, mem, size, arg, flags);

	data = mem;
	data->exchange = arg;
	bzero(&data->khttpd_fcgi_xchg_data_zctor_begin,
	    offsetof(struct khttpd_fcgi_xchg_data,
		khttpd_fcgi_xchg_data_zctor_end) -
	    offsetof(struct khttpd_fcgi_xchg_data,
		khttpd_fcgi_xchg_data_zctor_begin));

	return (0);
}

static void
khttpd_fcgi_xchg_data_dtor(void *mem, int size, void *arg)
{
	struct khttpd_fcgi_xchg_data *xchg_data;

	KHTTPD_ENTRY("%s(%p,%#x,%p)", __func__, mem, size, arg);

	xchg_data = mem;
	sbuf_clear(&xchg_data->path_info);
	sbuf_clear(&xchg_data->script_name);
	m_freem(xchg_data->put_buf);
}

static int
khttpd_fcgi_run(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_fcgi_xchg_data_zone = uma_zcreate("fcgixchg",
	    sizeof(struct khttpd_fcgi_xchg_data),
	    khttpd_fcgi_xchg_data_ctor, khttpd_fcgi_xchg_data_dtor,
	    khttpd_fcgi_xchg_data_init, khttpd_fcgi_xchg_data_fini,
	    UMA_ALIGN_PTR, 0);
	khttpd_fcgi_conn_zone = uma_zcreate("fcgiconn",
	    sizeof(struct khttpd_fcgi_conn),
	    khttpd_fcgi_conn_ctor, khttpd_fcgi_conn_dtor,
	    khttpd_fcgi_conn_init, khttpd_fcgi_conn_fini,
	    UMA_ALIGN_PTR, 0);

	return (0);
}

static void
khttpd_fcgi_exit(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	/*
	 * Destroying khttpd_fcgi_xchg_data_zone at this point is safe
	 * because khttpd_port guarantees that all the ports and sockets
	 * has been gone, and it implies all the exchanges are destroyed
	 * too.
	 */
	uma_zdestroy(khttpd_fcgi_xchg_data_zone);
	uma_zdestroy(khttpd_fcgi_conn_zone);
}

KHTTPD_INIT(khttpd_fcgi, khttpd_fcgi_run, khttpd_fcgi_exit,
    KHTTPD_INIT_PHASE_RUN, khttpd_ctrl);

static void
khttpd_fcgi_location_data_destroy(struct khttpd_fcgi_location_data *data)
{
	struct khttpd_fcgi_upstream *upstream, *tmpupstream;
	struct thread *td;

	KHTTPD_ENTRY("%s(%p)", __func__, data);
	KASSERT(STAILQ_EMPTY(&data->queue), ("queue is not empty"));

	td = curthread;

	mtx_lock(&khttpd_fcgi_lock);
	LIST_REMOVE(data, liste);
	mtx_unlock(&khttpd_fcgi_lock);

	mtx_destroy(&data->lock);
	LIST_FOREACH_SAFE(upstream, &data->upstreams, liste, tmpupstream)
		khttpd_fcgi_upstream_destroy(upstream);
	khttpd_free(data->fs_path);
	khttpd_free(data->script_suffix);
	if (data->fs_path_fd != -1)
		kern_close(td, data->fs_path_fd);
	khttpd_free(data);
}

static int
khttpd_fcgi_location_data_new
   (struct khttpd_fcgi_location_data **location_data_out,
    struct khttpd_location *location, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	char buf[8];
	struct khttpd_problem_property prop_specs[2];
	struct sbuf sbuf;
	struct khttpd_fcgi_location_data *location_data;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_json *upstreams_j;
	struct thread *td;
	const char *str;
	char *dststr;
	size_t len;
	int error, status;
	int i, n;

	KHTTPD_ENTRY("%s()", __func__);

	td = curthread;
	location_data = NULL;
	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	prop_specs[0].link = input_prop_spec;
	prop_specs[1].link = &prop_specs[0];

	location_data = 
	    khttpd_malloc(sizeof(struct khttpd_fcgi_location_data));
	mtx_init(&location_data->lock, "fcgi", NULL, MTX_DEF | MTX_NEW);
	LIST_INIT(&location_data->idle_conn);
	LIST_INIT(&location_data->upstreams);
	TAILQ_INIT(&location_data->avl_upstreams);
	STAILQ_INIT(&location_data->queue);
	location_data->location = location;
	bzero(&location_data->khttpd_fcgi_location_data_zctor_begin,
	    offsetof(struct khttpd_fcgi_location_data,
		khttpd_fcgi_location_data_zctor_end) -
	    offsetof(struct khttpd_fcgi_location_data,
		khttpd_fcgi_location_data_zctor_begin));
	location_data->fs_path_fd = -1;

	mtx_lock(&khttpd_fcgi_lock);
	LIST_INSERT_HEAD(&khttpd_fcgi_locations, location_data, liste);
	mtx_unlock(&khttpd_fcgi_lock);

	status = khttpd_webapi_get_string_property(&str, 
	    "fsPath", input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto end;

	prop_specs[0].name = "fsPath";

	if (str[0] != '/') {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_detail(output,
		    "relative path name is not acceptable.");
		khttpd_problem_set_property(output, &prop_specs[0]);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto end;
	}

	len = strlen(str);
	location_data->fs_path = dststr =
	    khttpd_malloc(str[len - 1] != '/' ? len + 2 : len + 1);
	bcopy(str, dststr, len);
	if (str[len - 1] != '/') {
		dststr[len] = '/';
		dststr[len + 1] = '\0';
	}

	error = kern_openat(td, AT_FDCWD, (char *)dststr, UIO_SYSSPACE,
	    O_RDONLY | O_DIRECTORY, 0);
	if (error != 0) {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_specs[0]);
		khttpd_problem_set_detail(output,
		    "failed to open directory at 'fsPath'");
		khttpd_problem_set_errno(output, error);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto end;
	}

	location_data->fs_path_fd = td->td_retval[0];

	status = khttpd_webapi_get_string_property(&str, 
	    "scriptSuffix", input_prop_spec, input, output, true);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto end;
	if (str != NULL)
		location_data->script_suffix = khttpd_strdup(str);

	status = khttpd_webapi_get_array_property(&upstreams_j, "upstreams",
	    input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto end;

	prop_specs[0].name = "upstreams";
	n = khttpd_json_array_size(upstreams_j);
	for (i = 0; i < n; ++i) {
		sbuf_printf(&sbuf, "[%d]", i);
		sbuf_finish(&sbuf);
		prop_specs[1].name = sbuf_data(&sbuf);

		status = khttpd_fcgi_upstream_new(&upstream, location_data,
		    &prop_specs[1], khttpd_json_array_get(upstreams_j, i),
		    output);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
			goto end;
		}

		LIST_INSERT_HEAD(&location_data->upstreams, upstream, liste);

		sbuf_clear(&sbuf);
	}
	sbuf_delete(&sbuf);

	*location_data_out = location_data;

	return (KHTTPD_STATUS_OK);

 end:
	khttpd_fcgi_location_data_destroy(location_data);
	sbuf_delete(&sbuf);

	return (status);
}

static void
khttpd_fcgi_location_dtor(struct khttpd_location *location)
{

	KHTTPD_ENTRY("%s(%p)", __func__, location);
	khttpd_fcgi_location_data_destroy(khttpd_location_data(location));
}

static void
khttpd_fcgi_location_get(struct khttpd_location *location,
    struct khttpd_mbuf_json *output)
{
	struct khttpd_fcgi_location_data *location_data;
	struct khttpd_fcgi_upstream *upstream;

	KHTTPD_ENTRY("%s(%p)", __func__, location);

	location_data = khttpd_location_data(location);

	khttpd_mbuf_json_object_begin(output);

	khttpd_mbuf_json_property(output, "fsPath");
	khttpd_mbuf_json_cstr(output, true, location_data->fs_path);

	if (location_data->script_suffix != NULL) {
		khttpd_mbuf_json_property(output, "scriptSuffix");
		khttpd_mbuf_json_cstr(output, true,
		    location_data->script_suffix);
	}

	khttpd_mbuf_json_property(output, "upstreams");
	LIST_FOREACH(upstream, &location_data->upstreams, liste) {
		khttpd_mbuf_json_object_begin(output);
		khttpd_mbuf_json_property(output, "address");
		khttpd_mbuf_json_sockaddr(output, 
		    (struct sockaddr *)&upstream->sockaddr);
		khttpd_mbuf_json_object_end(output);
	}

	khttpd_mbuf_json_object_end(output);
}

static int 
khttpd_fcgi_location_put(struct khttpd_location *location, 
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_fcgi_location_data *location_data;
	int status;

	KHTTPD_ENTRY("%s(%p)", __func__, location);

	status = khttpd_fcgi_location_data_new(&location_data, location,
	    output, input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	location_data = khttpd_location_set_data(location, location_data);
	khttpd_fcgi_location_data_destroy(location_data);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_fcgi_location_create(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_fcgi_location_data *loc_data;
	int status;

	KHTTPD_ENTRY("%s(%p)", __func__, server);

	status = khttpd_fcgi_location_data_new(&loc_data, NULL, output,
	    input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_location_type_create_location(location_out, server,
	    path, output, input_prop_spec, input, &khttpd_fcgi_ops, loc_data);
	if (KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		loc_data->location = *location_out;
	} else {
		khttpd_fcgi_location_data_destroy(loc_data);
	}

	return (status);
}

static int
khttpd_fcgi_register_location_type(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_location_type_register(KHTTPD_FCGI_LOCATION_TYPE,
	    khttpd_fcgi_location_create, NULL,
	    khttpd_fcgi_location_get, khttpd_fcgi_location_put);

	return (0);
}

static void
khttpd_fcgi_deregister_location_type(void)
{

	KHTTPD_ENTRY("%s()", __func__);
	khttpd_location_type_deregister(KHTTPD_FCGI_LOCATION_TYPE);
}

KHTTPD_INIT(khttpd_fcgi, khttpd_fcgi_register_location_type,
    khttpd_fcgi_deregister_location_type,
    KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES);
