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
#include <sys/callout.h>
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
#include "khttpd_task.h"
#include "khttpd_test.h"
#include "khttpd_webapi.h"

/*
 * (a) - guarded by khttpd_fcgi_lock
 * (b) - guarded by khttpd_fcgi_location_data->lock
 * (c) - guarded by khttpd_fcgi_location_data->lock while the instance is
 * 	 not active.  Otherwise, only the worker thread accesses it.
 */

#define KHTTPD_FCGI_LOCATION_TYPE		"khttpd_fastcgi"
#define KHTTPD_FCGI_MAX_FIELD_LEN		16384
#define KHTTPD_FCGI_MAX_RECORD_CONTENT_LENGTH	0xffff
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

struct khttpd_fcgi_begin_request_record {
	struct khttpd_fcgi_hdr hdr;
	uint16_t	role;
	uint8_t		flags;
	uint8_t		reserved[5];
} __attribute__ ((packed));

struct khttpd_fcgi_end_request_body {
	uint32_t	app_status;
	uint8_t		protocol_status;
	uint8_t		reserved[3];
} __attribute__ ((packed));

/*
 * State of khttpd_fcgi_xchg_data
 * 
 * dormant
 *	xchg_data->conn is NULL
 *	xchg_data->active is false
 *	xchg_data->waiting is false
 *	not in location_data->queue
 * waiting
 *	xchg_data->conn is NULL
 *	xchg_data->active is false
 *	xchg_data->waiting is true
 *	in location_data->queue
 * attaching
 *	xchg_data->conn is not NULL
 *	xchg_data->active is false
 *	xchg_data->waiting is false
 *	not in location_data->queue
 * active
 *	xchg_data->conn is not NULL
 *	xchg_data->active is true
 *	xchg_data->waiting is false
 *	not in location_data->queue
 */

struct khttpd_fcgi_xchg_data {
	STAILQ_ENTRY(khttpd_fcgi_xchg_data) link;
	struct sbuf	path_info;
	struct sbuf	script_name;
	struct sbuf	line;
	struct sbuf	location;
	struct khttpd_exchange *exchange;

#define khttpd_fcgi_xchg_data_zctor_begin conn
	struct khttpd_fcgi_conn *conn; /* (c) */
	struct mbuf	*put_buf;
	struct mbuf	*get_buf;
	unsigned	status:16;
	unsigned	waiting:1;
	unsigned	active:1;
	unsigned	aborted:1;
	unsigned	responded:1;
	unsigned	header_finished:1;
	unsigned	put_busy:1;
	unsigned	put_eof:1;
	unsigned	put_suspended:1;
	unsigned	put_finished:1;
	unsigned	get_suspended:1;
	unsigned	get_finished:1;

#define khttpd_fcgi_xchg_data_zctor_end path_info_buf
	char		path_info_buf[64];
	char		script_name_buf[64];
	char		line_buf[256];
	char		location_buf[256];
};

STAILQ_HEAD(khttpd_fcgi_xchg_data_stailq, khttpd_fcgi_xchg_data);

/*
 * State of khttpd_fcgi_conn
 *
 * connecting
 *	conn->xchg_data is NULL
 *	conn->active is false
 *	conn->waiting_end is false
 *	conn is not in loc_data->idle_conn
 *	transit to idle by 'on_configured' callback
 *	may be destructed by 'khttpd_fcgi_handle_connection_failure'
 * idle
 *	conn->xchg_data is NULL
 *	conn->active is false
 *	conn->waiting_end is false
 *	conn is in loc_data->idle_conn
 *	transit asynchronously to 'attaching' when it's chosen
 *	    by exchange handling thread
 * attaching
 *	conn->xchg_data is not NULL
 *	conn->active is false
 *	conn->waiting_end is false
 *	transit to 'active' when attach task runs and it have not seen EOF
 * active
 *	conn->xchg_data is not NULL
 *	conn->active is true
 *	conn->waiting_end is false
 *	transit to 'waiting_end' when khttpd_fcgi_detach_conn is called.
 *	may be destructed by 'data_is_available' callback
 * waiting_end
 *	conn->xchg_data is NULL
 *	conn->active is false
 *	conn->waiting_end is true
 *	transit to 'idle' when timeout period has passed or end_request is
 *	    received.
 *	may be destructed by 'data_is_available' callback
 */

struct khttpd_fcgi_conn {
	LIST_ENTRY(khttpd_fcgi_conn) idleliste;
	struct khttpd_stream	stream;
	struct callout		end_request_co;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_fcgi_xchg_data *xchg_data; /* (c) */
	struct khttpd_task	*attach_task;
	struct khttpd_task	*release_task;
	struct khttpd_task	*abort_req_task;

#define khttpd_fcgi_conn_zctor_begin recv_buf
	struct mbuf		*recv_buf;
	unsigned		active:1;
	unsigned		waiting_end:1;
	unsigned		recv_suspended:1;
	unsigned		recv_eof:1;
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

	/* goal: minimize nconnecting satisfying nwaiting <= nconnecting */

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
static void khttpd_fcgi_conn_release(struct khttpd_fcgi_conn *);
static void khttpd_fcgi_exchange_dtor(struct khttpd_exchange *, void *);
static int  khttpd_fcgi_exchange_get(struct khttpd_exchange *, void *,
    ssize_t, struct mbuf **);
static void khttpd_fcgi_exchange_put(struct khttpd_exchange *, void *, 
    struct mbuf *, bool *);
static void khttpd_fcgi_choose_conn(struct khttpd_exchange *);
static bool khttpd_fcgi_filter(struct khttpd_location *, 
    struct khttpd_exchange *, const char *, struct sbuf *);
static void khttpd_fcgi_do_method(struct khttpd_exchange *);
static void khttpd_fcgi_location_dtor(struct khttpd_location *);

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
static uma_zone_t khttpd_fcgi_xchg_data_zone;
static uma_zone_t khttpd_fcgi_conn_zone;
static eventhandler_tag khttpd_fcgi_shutdown_tag;
static unsigned khttpd_fcgi_conn_count; /* (a) */

MTX_SYSINIT(khttpd_fcgi_lock, &khttpd_fcgi_lock, "fcgi", MTX_DEF);

#define KHTTPD_FCGI_LONGEST_VALUE_NAME \
	(MAX(sizeof(khttpd_fcgi_max_conns), sizeof(khttpd_fcgi_max_reqs)) - 1)

static bool
khttpd_fcgi_conn_on_worker_thread(struct khttpd_fcgi_conn *conn)
{

	return (conn->stream.down == NULL ||
	    khttpd_task_queue_on_worker_thread
	    (khttpd_socket_task_queue(conn->stream.down)));
}

static bool
khttpd_fcgi_xchg_data_on_worker_thread(struct khttpd_fcgi_xchg_data *xchg_data)
{

	return (khttpd_exchange_on_worker_thread(xchg_data->exchange));
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
khttpd_fcgi_init_record_header(struct khttpd_fcgi_hdr *header, int type,
    int cntlen)
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
	KASSERT(khttpd_exchange_on_worker_thread(exchange), ("wrong thread"));

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
khttpd_fcgi_append_params(struct khttpd_fcgi_xchg_data *xchg_data,
    struct mbuf *m)
{
	char buf[1024];
	struct sbuf sbuf;
	const char *query, *method_name;
	struct khttpd_exchange *exchange = xchg_data->exchange;
	struct khttpd_location *location, *tmploc;
	struct khttpd_server *server;
	struct khttpd_fcgi_hdr *hdr;
	struct khttpd_fcgi_location_data *loc_data;
	struct mbuf *head, *tail;
	const struct sockaddr *addr;
	int method;
	u_int len;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, xchg_data, m);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));
	KASSERT(xchg_data->active, ("!active"));

	location = khttpd_exchange_location(exchange);
	loc_data = khttpd_location_data(location);
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
		khttpd_fcgi_init_record_header(hdr,
		    KHTTPD_FCGI_TYPE_PARAMS, 0);
	}
}

static void
khttpd_fcgi_send_stdin(struct khttpd_fcgi_xchg_data *xchg_data, long space)
{
	struct khttpd_fcgi_conn *conn = xchg_data->conn;
	struct khttpd_fcgi_hdr *hdr;
	struct khttpd_stream *stream = &conn->stream;
	struct mbuf *head, *m, *stdin, *stdin_tail;
	u_int stdin_len;
	int max_stdin_len;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, xchg_data, space);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));
	KASSERT(xchg_data->active, ("!active"));
	KASSERT(xchg_data->put_busy, ("!put_busy"));

	while (sizeof(struct khttpd_fcgi_hdr) < space &&
	    ((stdin = xchg_data->put_buf) != NULL || xchg_data->put_eof)) {

		if (stdin == NULL) {
			stdin_len = 0;
			space -= sizeof(struct khttpd_fcgi_hdr);

		} else {
			stdin_len = m_length(stdin, NULL);
			max_stdin_len =
			    MIN(KHTTPD_FCGI_MAX_RECORD_CONTENT_LENGTH,
			    rounddown2(space - sizeof(struct khttpd_fcgi_hdr),
			    KHTTPD_FCGI_RECORD_ALIGN));

			if (stdin_len <= max_stdin_len) {
				xchg_data->put_buf = NULL;

			} else {
				stdin_len = rounddown2(max_stdin_len,
				    KHTTPD_FCGI_RECORD_ALIGN);
				xchg_data->put_buf = m_split(stdin, stdin_len,
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

		if (xchg_data->put_buf != NULL || !xchg_data->put_eof) {
			khttpd_stream_send(stream, head, 0);

		} else {
			if (0 < stdin_len) {
				stdin_tail = m_last(stdin);
				stdin_tail->m_next = m = 
				    m_get(M_WAITOK, MT_DATA);
				m->m_len = sizeof(struct khttpd_fcgi_hdr);
				hdr = mtod(m, struct khttpd_fcgi_hdr *);
				khttpd_fcgi_init_record_header(hdr, 
				    KHTTPD_FCGI_TYPE_STDIN, 0);
				space -= sizeof(struct khttpd_fcgi_hdr);
			}
			khttpd_stream_send(stream, head, KHTTPD_STREAM_FLUSH);
			xchg_data->put_eof = false;
		}
	}

	if (space < 0 || xchg_data->put_buf != NULL || xchg_data->put_eof) {
		khttpd_stream_notify_of_drain(stream);
		return;
	}

	xchg_data->put_busy = false;

	if (xchg_data->put_suspended) {
		xchg_data->put_suspended = false;
		khttpd_exchange_continue_receiving(xchg_data->exchange);
	}
}

static void
khttpd_fcgi_conn_destroy_locked(struct khttpd_fcgi_conn *conn,
    struct khttpd_fcgi_upstream *upstream,
    struct khttpd_fcgi_location_data *loc_data)
{

	KHTTPD_ENTRY("%s(%p)", __func__, conn);
	KASSERT(conn->xchg_data == NULL,
	    ("conn->xchg_data %p", conn->xchg_data));
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn),
	    ("not on the worker thread"));

	mtx_unlock(&loc_data->lock);

	khttpd_stream_destroy(&conn->stream);

	mtx_lock(&loc_data->lock);

	if (--upstream->nconn < upstream->max_conns &&
	    upstream->state == KHTTPD_FCGI_UPSTREAM_FULL) {
		TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream, tailqe);
		upstream->state = KHTTPD_FCGI_UPSTREAM_AVAILABLE;
		khttpd_fcgi_connect(loc_data);
	}

	mtx_unlock(&loc_data->lock);

	uma_zfree(khttpd_fcgi_conn_zone, conn);

	mtx_lock(&khttpd_fcgi_lock);
	if (--khttpd_fcgi_conn_count == 0) {
		wakeup(&khttpd_fcgi_conn_count);
	}
	mtx_unlock(&khttpd_fcgi_lock);
}

static void
khttpd_fcgi_conn_destroy(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_upstream *upstream;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);

	callout_drain(&conn->end_request_co);
	khttpd_task_cancel(conn->abort_req_task);

	upstream = conn->upstream;
	loc_data = upstream->location_data;
	mtx_lock(&loc_data->lock);
	khttpd_fcgi_conn_destroy_locked(conn, upstream, loc_data);
}

static void
khttpd_fcgi_attach_conn(void *arg)
{
	struct khttpd_fcgi_begin_request_record *record;
	struct khttpd_fcgi_conn *conn = arg;
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct mbuf *m;
	long space;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);
	KASSERT(!conn->active, ("active"));
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn),
	    ("conn wrong thread"));

	if ((xchg_data = conn->xchg_data) == NULL) {
		/* exchange has gone */
		KHTTPD_NOTE("%s exchange has gone", __func__);
		khttpd_task_schedule(conn->release_task);
		return;
	}

	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("xchg_data wrong thread"));

	if (conn->recv_eof) {
		KHTTPD_NOTE("%s eof", __func__);
		conn->xchg_data = NULL;
		xchg_data->conn = NULL;
		khttpd_task_schedule(conn->release_task);
		khttpd_fcgi_choose_conn(xchg_data->exchange);
		return;
	}

	xchg_data->active = conn->active = true;

	m = m_get(M_WAITOK, MT_DATA);
	m->m_len = sizeof(*record);
	record = mtod(m, struct khttpd_fcgi_begin_request_record *);

	CTASSERT(sizeof(*record) % KHTTPD_FCGI_RECORD_ALIGN == 0);
	khttpd_fcgi_init_record_header(&record->hdr, 
	    KHTTPD_FCGI_TYPE_BEGIN_REQUEST,
	    sizeof(struct khttpd_fcgi_begin_request_record) -
	    offsetof(struct khttpd_fcgi_begin_request_record, role));
	record->role = htons(KHTTPD_FCGI_ROLE_RESPONDER);
	record->flags = KHTTPD_FCGI_FLAGS_KEEP_CONN;
	bzero(record->reserved, sizeof(record->reserved));

	khttpd_fcgi_append_params(xchg_data, m);

	khttpd_stream_send_bufstat(&conn->stream, NULL, NULL, &space);
	space -= m_length(m, NULL);
	khttpd_stream_send(&conn->stream, m, 0);

	xchg_data->put_busy = true;
	khttpd_fcgi_send_stdin(xchg_data, space);
}

static void
khttpd_fcgi_conn_release_locked
(struct khttpd_fcgi_location_data *loc_data, struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_xchg_data *xchg_data;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, loc_data, conn);
	mtx_assert(&loc_data->lock, MA_OWNED);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));
	KASSERT(!conn->active, ("active"));
	KASSERT(!conn->waiting_end, ("waiting_end"));
	KASSERT(!conn->recv_eof, ("recv_eof"));
	KASSERT(conn->xchg_data == NULL, ("xchg_data %p", conn->xchg_data));

	if (conn->recv_suspended) {
		KHTTPD_NOTE("%s recv_suspended %p", __func__);
		conn->recv_suspended = false;
		khttpd_stream_continue_receiving(&conn->stream,
		    conn->upstream->idle_timeout);
	}

	if ((xchg_data = STAILQ_FIRST(&loc_data->queue)) == NULL) {
		LIST_INSERT_HEAD(&loc_data->idle_conn, conn, idleliste);
		mtx_unlock(&loc_data->lock);
		return;
	}

	KASSERT(xchg_data->waiting, ("!waiting"));
	xchg_data->waiting = false;

	STAILQ_REMOVE_HEAD(&loc_data->queue, link);
	--loc_data->nwaiting;

	conn->xchg_data = xchg_data;
	xchg_data->conn = conn;

	khttpd_task_queue_hand_over
	    (khttpd_socket_task_queue(conn->stream.down),
	     khttpd_socket_task_queue
		(khttpd_exchange_socket(xchg_data->exchange)));

	khttpd_task_schedule(conn->attach_task);

	mtx_unlock(&loc_data->lock);
}

static void
khttpd_fcgi_conn_release(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_fcgi_location_data *loc_data;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn);

	callout_drain(&conn->end_request_co);
	khttpd_task_cancel(conn->abort_req_task);

	loc_data = conn->upstream->location_data;
	mtx_lock(&loc_data->lock);
	khttpd_fcgi_conn_release_locked(loc_data, conn);
}

static void
khttpd_fcgi_do_conn_release(void *arg)
{
	struct khttpd_fcgi_conn *conn = arg;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn);

	if (conn->recv_eof) {
		khttpd_fcgi_conn_destroy(conn);
	} else {
		khttpd_fcgi_conn_release(conn);
	}
}

static void
khttpd_fcgi_conn_do_abort_request(void *arg)
{
	struct khttpd_fcgi_conn *conn = arg;
	struct khttpd_fcgi_hdr *hdr;
	struct mbuf *m;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn);
	KASSERT(conn->waiting_end, ("!waiting_end"));

	m = m_get(M_WAITOK, MT_DATA);
	m->m_len = sizeof(struct khttpd_fcgi_hdr);
	hdr = mtod(m, struct khttpd_fcgi_hdr *);
	khttpd_fcgi_init_record_header(hdr, KHTTPD_FCGI_TYPE_ABORT_REQUEST, 0);
	khttpd_stream_send(&conn->stream, m, KHTTPD_STREAM_FLUSH);

	conn->waiting_end = false;

	khttpd_fcgi_conn_release(conn);
}

static void
khttpd_fcgi_end_request_timeout_expired(void *arg)
{
	struct khttpd_fcgi_conn *conn = arg;

	KHTTPD_ENTRY("%s(%p,%#lx)", __func__, conn);
	khttpd_task_schedule(conn->abort_req_task);
}

static void
khttpd_fcgi_detach_conn(struct khttpd_fcgi_xchg_data *xchg_data,
    bool wait_for_end_request)
{
	struct khttpd_fcgi_conn *conn = xchg_data->conn;

	KHTTPD_ENTRY("%s(%p)", __func__, xchg_data);
	KASSERT(xchg_data->active, ("!active"));
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	xchg_data->conn = NULL;
	xchg_data->active = false;

	conn->xchg_data = NULL;
	conn->active = false;

	if (conn->recv_eof) {
		khttpd_task_schedule(conn->release_task);
		return;
	}

	if (wait_for_end_request) {
		KHTTPD_NOTE("%s wait for end_request", __func__);
		conn->waiting_end = true;
		callout_reset_sbt_curcpu(&conn->end_request_co, SBT_1S,
		    SBT_1S, khttpd_fcgi_end_request_timeout_expired, conn, 0);
	}

	khttpd_task_schedule(conn->release_task);
}

static void
khttpd_fcgi_abort_exchange(struct khttpd_fcgi_xchg_data *xchg_data)
{
	struct khttpd_exchange *exchange;

	KHTTPD_ENTRY("%s(%p)", __func__, xchg_data);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	khttpd_fcgi_detach_conn(xchg_data, true);

	xchg_data->aborted = true;
	exchange = xchg_data->exchange;

	if (!xchg_data->responded) {
		xchg_data->responded = true;
		khttpd_exchange_clear_response_header(exchange);
		khttpd_exchange_set_error_response_body(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR, NULL);
		khttpd_exchange_respond(exchange,
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR);
	}
}

static bool
khttpd_fcgi_append_response_body(struct khttpd_fcgi_xchg_data *xchg_data,
    struct mbuf *data)
{
	struct mbuf *buf;
	bool recv_suspended;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, xchg_data, data);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	recv_suspended = false;

	if (xchg_data->get_finished) {
		m_freem(data);

	} else if (data == NULL) {
		xchg_data->get_finished = true;

	} else if ((buf = xchg_data->get_buf) == NULL) {
		xchg_data->get_buf = data;

	} else {
		m_cat(buf, data);
		recv_suspended = true;
	}

	if (xchg_data->get_suspended) {
		xchg_data->get_suspended = false;
		khttpd_exchange_continue_sending(xchg_data->exchange);
	}

	return (recv_suspended);
}

static void
khttpd_fcgi_hdr_error(struct khttpd_fcgi_xchg_data *xchg_data,
    const char *detail_fmt, ...)
{
	struct khttpd_mbuf_json logent;
	va_list va;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, xchg_data, detail_fmt);
	KASSERT(sbuf_done(&xchg_data->line), ("!sbuf_done(&xchg_data->line)"));
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	khttpd_fcgi_protocol_error_new(&logent);

	if (detail_fmt != NULL) {
		va_start(va, detail_fmt);
		khttpd_problem_set_vdetail(&logent, detail_fmt, va);
		va_end(va);
	}

	khttpd_mbuf_json_property(&logent, "line");
	khttpd_mbuf_json_bytes(&logent, true, sbuf_data(&xchg_data->line),
	    sbuf_data(&xchg_data->line) + sbuf_len(&xchg_data->line));
	khttpd_fcgi_report_error(xchg_data->conn->upstream, &logent);

	khttpd_fcgi_abort_exchange(xchg_data);
}

static bool
khttpd_fcgi_process_content_length_field
(struct khttpd_fcgi_xchg_data *xchg_data, const char *begin, const char *end)
{
	struct khttpd_exchange *exchange;
	uintmax_t value;
	int error;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, xchg_data,
	    khttpd_ktr_printf("%.*s", (int)(end - begin), begin));
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	exchange = xchg_data->exchange;

	if (khttpd_exchange_response_is_chunked(exchange)) {
		return (false);
	}

	if (begin == end) {
		return (false);
	}

	error = khttpd_parse_digits(&value, begin, end);
	if (error == ERANGE || (error == 0 && OFF_MAX < value)) {
		khttpd_fcgi_hdr_error(xchg_data, "out of range");
		return (false);
	}
	if (error != 0) {
		khttpd_fcgi_hdr_error(xchg_data, "invalid value");
		return (false);
	}

	khttpd_exchange_set_response_content_length(exchange, value);

	return (false);
}

static bool
khttpd_fcgi_process_location_field(struct khttpd_fcgi_xchg_data *xchg_data,
    const char *begin, const char *end)
{
	
	KHTTPD_ENTRY("%s(%p,%s)", __func__, xchg_data,
	    khttpd_ktr_printf("%.*s", (int)(end - begin), begin));
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	if (begin < end && *begin == '/') {
		if (sbuf_done(&xchg_data->location)) {
			khttpd_fcgi_hdr_error(xchg_data,
			    "duplicated Location: field");
			return (false);
		}
		sbuf_bcpy(&xchg_data->location, begin, end - begin);
		sbuf_finish(&xchg_data->location);
		return (false);
	}

	if (xchg_data->status == 0) {
		xchg_data->status = KHTTPD_STATUS_FOUND;
	}

	return (true);
}

static bool
khttpd_fcgi_process_status_field(struct khttpd_fcgi_xchg_data *xchg_data,
    const char *begin, const char *end)
{
	int status;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, xchg_data,
	    khttpd_ktr_printf("%.*s", (int)(end - begin), begin));
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	if (!isdigit(begin[0]) || !isdigit(begin[1]) || !isdigit(begin[2]) ||
	    begin[3] != ' ') {
		khttpd_fcgi_hdr_error(xchg_data, "malformed status field");
	} else {
		sscanf(begin, "%d", &status);
		xchg_data->status = status;
	}

	return (false);
}

static void
khttpd_fcgi_process_response_header_line
(struct khttpd_fcgi_xchg_data *xchg_data)
{
	char *begin, *name_end, *value_begin, *end;
	bool append_header;

	KHTTPD_ENTRY("%s(%p)", __func__, xchg_data);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	begin = sbuf_data(&xchg_data->line);
	end = begin + sbuf_len(&xchg_data->line);
	if (begin < end && end[-1] == '\r') {
		--end;
	}
	while (begin < end && end[-1] == ' ') {
		--end;
	}

	name_end = memchr(begin, ':', end - begin);
	if (name_end == NULL || name_end[-1] == ' ') {
		khttpd_fcgi_hdr_error(xchg_data, "malformed response field");
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
		append_header = khttpd_fcgi_process_content_length_field
		    (xchg_data, value_begin, end);
		break;

	case KHTTPD_FIELD_LOCATION:
		append_header = khttpd_fcgi_process_location_field(xchg_data,
		    value_begin, end);
		break;

	case KHTTPD_FIELD_STATUS:
		khttpd_fcgi_process_status_field(xchg_data, value_begin, end);
		break;

	case KHTTPD_FIELD_CONNECTION:
	case KHTTPD_FIELD_TRANSFER_ENCODING:
	case KHTTPD_FIELD_HOST:
		break;

	default:
		append_header = true;
		break;
	}

	if (append_header && !sbuf_done(&xchg_data->location)) {
		khttpd_exchange_add_response_field_line(xchg_data->exchange,
		    begin, end);
	}
}

static bool
khttpd_fcgi_process_response_header(struct khttpd_fcgi_xchg_data *xchg_data,
    struct mbuf *data)
{
	struct khttpd_exchange *exchange;
	struct khttpd_mbuf_json logent;
	struct mbuf *ptr, *next;
	char *begin, *cp, *bolp, *eolp;
	u_int len, off;
	int status;
	bool result;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, xchg_data, data);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	if (data == NULL) {
		khttpd_mbuf_json_copy(&logent,
		    khttpd_exchange_log_entry(xchg_data->exchange));
		khttpd_fcgi_set_protocol_error(&logent);
		khttpd_problem_set_detail(&logent,
		    "stdout is closed prematurely");
		khttpd_fcgi_report_error(xchg_data->conn->upstream, &logent);
		khttpd_fcgi_abort_exchange(xchg_data);
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

		if (KHTTPD_FCGI_MAX_FIELD_LEN <
		    sbuf_len(&xchg_data->line) + len) {
			goto too_long;
		}
		sbuf_bcat(&xchg_data->line, begin, len);

		if (cp == NULL) {
			if ((next = ptr->m_next) == NULL) {
				break;
			}

			m_free(ptr);
			ptr = next;
			off = 0;
			continue;
		}

		sbuf_finish(&xchg_data->line);

		bolp = sbuf_data(&xchg_data->line);
		eolp = bolp + sbuf_len(&xchg_data->line);
		if (bolp < eolp && eolp[-1] == '\r')
			--eolp;
		if (bolp == eolp) {
			exchange = xchg_data->exchange;

			if (!khttpd_exchange_has_response_content_length
			    (exchange)) {
				khttpd_exchange_enable_chunked_response
				    (exchange);
			}

			xchg_data->header_finished = true;

			if (sbuf_done(&xchg_data->location)) {
				/* It was a local redirect response. */
				khttpd_fcgi_detach_conn(xchg_data, true);
				khttpd_exchange_redirect(exchange,
				    sbuf_data(&xchg_data->location),
				    sbuf_len(&xchg_data->location));
				return (false);
			}

			m_adj(ptr, off);
			result = 
			    khttpd_fcgi_append_response_body(xchg_data, ptr);

			status = xchg_data->status;
			if (status == 0) {
				status = KHTTPD_STATUS_OK;
			}
			xchg_data->responded = true;
			khttpd_exchange_respond(xchg_data->exchange, status);

			return (result);
		}

		khttpd_fcgi_process_response_header_line(xchg_data);
		sbuf_clear(&xchg_data->line);
	}

	return (false);

too_long:
	sbuf_finish(&xchg_data->line);
	khttpd_fcgi_hdr_error(xchg_data, "response header line too long");
	return (false);
}

static bool
khttpd_fcgi_process_stdout_record(struct khttpd_fcgi_conn *conn,
    struct mbuf *data)
{
	struct khttpd_fcgi_xchg_data *xchg_data;
	bool recv_suspended;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, conn, data);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	if (!conn->active) {
		m_freem(data);
		return (false);
	}

	xchg_data = conn->xchg_data;
	recv_suspended = xchg_data->header_finished ?
	    khttpd_fcgi_append_response_body(xchg_data, data) :
	    khttpd_fcgi_process_response_header(xchg_data, data);

	return (recv_suspended);
}

static void
khttpd_fcgi_upstream_fail_locked(struct khttpd_fcgi_upstream *upstream)
{

	KHTTPD_ENTRY("%s(%p)", __func__, upstream);
	mtx_assert(&upstream->location_data->lock, MA_OWNED);

	if (upstream->state == KHTTPD_FCGI_UPSTREAM_AVAILABLE) {
		TAILQ_REMOVE(&upstream->location_data->avl_upstreams, upstream,
		    tailqe);
	}
	upstream->state = KHTTPD_FCGI_UPSTREAM_FAIL;
}

static void
khttpd_fcgi_upstream_fail(struct khttpd_fcgi_upstream *upstream)
{
	struct khttpd_fcgi_location_data *loc_data = upstream->location_data;

	KHTTPD_ENTRY("%s(%p)", __func__, upstream);

	mtx_lock(&loc_data->lock);
	khttpd_fcgi_upstream_fail_locked(upstream);
	mtx_unlock(&loc_data->lock);
}

static struct khttpd_socket *
khttpd_fcgi_conn_socket(struct khttpd_fcgi_conn *conn)
{

	return (conn->stream.down);
}

static void
khttpd_fcgi_conn_on_configured(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_conn *conn = stream->up;
	struct khttpd_fcgi_upstream *upstream = conn->upstream;
	struct khttpd_fcgi_location_data *loc_data = upstream->location_data;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	mtx_lock(&loc_data->lock);
	--loc_data->nconnecting;
	khttpd_fcgi_conn_release_locked(loc_data, conn);
}

static int
khttpd_fcgi_did_connected(struct khttpd_socket *socket, void *arg,
	struct khttpd_socket_config *conf)
{
	struct khttpd_fcgi_conn *conn = arg;
	struct khttpd_task_queue *tq;

	KHTTPD_ENTRY("%s(%p,%p,%p)", __func__, socket, arg, conf);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	tq = khttpd_socket_task_queue(socket);
	khttpd_task_set_queue(conn->attach_task, tq);
	khttpd_task_set_queue(conn->release_task, tq);
	khttpd_task_set_queue(conn->abort_req_task, tq);

	conf->stream = &conn->stream;
	conf->timeout = conn->upstream->idle_timeout;

	return (0);
}

static void
khttpd_fcgi_handle_connection_failure(void *arg,
    struct khttpd_mbuf_json *error)
{
	struct khttpd_fcgi_conn *conn = arg;
	struct khttpd_fcgi_upstream *upstream = conn->upstream;
	struct khttpd_fcgi_location_data *loc_data = upstream->location_data;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, conn, error);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	khttpd_fcgi_upstream_fail(upstream);
	khttpd_fcgi_conn_destroy(conn);

	mtx_lock(&loc_data->lock);
	--loc_data->nconnecting;
	khttpd_fcgi_connect(loc_data);
	mtx_unlock(&loc_data->lock);

	khttpd_fcgi_report_error(upstream, error);
}

static void
khttpd_fcgi_conn_new(struct khttpd_fcgi_location_data *loc_data,
    struct khttpd_fcgi_upstream *upstream)
{
	struct khttpd_fcgi_conn *conn;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, loc_data, upstream);

	mtx_lock(&khttpd_fcgi_lock);
	++khttpd_fcgi_conn_count;
	mtx_unlock(&khttpd_fcgi_lock);

	conn = uma_zalloc_arg(khttpd_fcgi_conn_zone, upstream, M_WAITOK);

	mtx_lock(&loc_data->lock);
	if (upstream->state != KHTTPD_FCGI_UPSTREAM_AVAILABLE) {
		mtx_unlock(&loc_data->lock);

		uma_zfree(khttpd_fcgi_conn_zone, conn);

		mtx_lock(&khttpd_fcgi_lock);
		if (--khttpd_fcgi_conn_count == 0) {
			wakeup(&khttpd_fcgi_conn_count);
		}
		mtx_unlock(&khttpd_fcgi_lock);

		return;
	}

	if (upstream->max_conns == ++upstream->nconn) {
		upstream->state = KHTTPD_FCGI_UPSTREAM_FULL;
		TAILQ_REMOVE(&loc_data->avl_upstreams, upstream, tailqe);
	}

	++loc_data->nconnecting;

	mtx_unlock(&loc_data->lock);

	khttpd_socket_connect((struct sockaddr *)&upstream->sockaddr,
	    NULL, khttpd_fcgi_did_connected, conn,
	    khttpd_fcgi_handle_connection_failure);
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
		TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream, tailqe);
		mtx_unlock(&loc_data->lock);

		khttpd_fcgi_conn_new(loc_data, upstream);

		mtx_lock(&loc_data->lock);
	}
}

static void
khttpd_fcgi_choose_conn(struct khttpd_exchange *exchange)
{
	struct khttpd_location *location;
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_xchg_data *xchg_data;
	struct khttpd_fcgi_location_data *loc_data;

	KHTTPD_ENTRY("%s(%p)", __func__, exchange);

	location = khttpd_exchange_location(exchange);
	loc_data = khttpd_location_data(location);
	xchg_data = khttpd_exchange_ops_arg(exchange);

	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

 	mtx_lock(&loc_data->lock);
	if ((conn = LIST_FIRST(&loc_data->idle_conn)) == NULL) {
		KASSERT(!xchg_data->waiting, ("waiting"));
		xchg_data->waiting = true;
		STAILQ_INSERT_TAIL(&loc_data->queue, xchg_data, link);
		++loc_data->nwaiting;
		khttpd_fcgi_connect(loc_data);
		mtx_unlock(&loc_data->lock);
		return;
	}

	LIST_REMOVE(conn, idleliste);
	conn->xchg_data = xchg_data;
	xchg_data->conn = conn;
	mtx_unlock(&loc_data->lock);

	khttpd_task_queue_take_over
	    (khttpd_socket_task_queue(conn->stream.down),
	    khttpd_fcgi_attach_conn, conn);
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
	int status;

	KHTTPD_ENTRY("%s(%p,%#x,%d)", __func__, conn, app_status, 
	    protocol_status);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	if (!conn->active) {
		KHTTPD_NOTE("%s !active", __func__);
		return;
	}

	xchg_data = conn->xchg_data;
	khttpd_fcgi_detach_conn(xchg_data, false);

	exchange = xchg_data->exchange;
	status = xchg_data->status;

	if (!xchg_data->get_finished) {
		xchg_data->get_finished = true;
		if (xchg_data->get_suspended) {
			xchg_data->get_suspended = false;
			khttpd_exchange_continue_sending(exchange);
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
		khttpd_mbuf_json_format(&logent, false, "%u", app_status);
	}

	if (protocol_status != 0) {
		khttpd_mbuf_json_property(&logent, "protocolStatus");
		if (protocol_status < nitems(protocol_status_names)) {
			khttpd_mbuf_json_format(&logent, true, "%s",
			    protocol_status_names[protocol_status]);
		} else {
			khttpd_mbuf_json_format(&logent, true, "%d",
			    protocol_status);
		}
	}

	khttpd_fcgi_report_error(conn->upstream, &logent);
}

static void
khttpd_fcgi_found_eof(struct khttpd_fcgi_conn *conn)
{
	struct khttpd_mbuf_json logent;
	struct khttpd_fcgi_upstream *upstream;
	struct khttpd_fcgi_location_data *loc_data;

	KHTTPD_ENTRY("%s(%p)", __func__, conn);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	if (conn->active) {
		KHTTPD_NOTE("%s active", __func__);
		khttpd_fcgi_protocol_error_new(&logent);
		khttpd_problem_set_detail(&logent,
		    "upstream server closed the connection prematurely");
		khttpd_fcgi_report_error(conn->upstream, &logent);

		conn->recv_eof = true;
		khttpd_fcgi_abort_exchange(conn->xchg_data);

		return;
	}

	callout_drain(&conn->end_request_co);
	khttpd_task_cancel(conn->abort_req_task);

	upstream = conn->upstream;
	loc_data = upstream->location_data;
	mtx_lock(&loc_data->lock);

	if (conn->xchg_data != NULL) {
		/* attaching */
		conn->recv_eof = true;
		mtx_unlock(&loc_data->lock);
	} else {
		/* idle */
		LIST_REMOVE(conn, idleliste);
		khttpd_fcgi_conn_destroy_locked(conn, upstream, loc_data);
	}
}

static void
khttpd_fcgi_conn_data_is_available(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_end_request_body endreq_body;
	struct khttpd_fcgi_hdr hdr;
	struct khttpd_mbuf_json logent;
	struct khttpd_fcgi_conn *conn = stream->up;
	struct mbuf *m;
	ssize_t resid;
	int mlen, cntlen, padlen, pktlen;
	int error;
	bool recv_suspended;

	KHTTPD_ENTRY("%s(%p)", __func__, stream);

	recv_suspended = false;
	do {
		resid = SSIZE_MAX;
		error = khttpd_stream_receive(&conn->stream, &resid, &m);

		if (error == EWOULDBLOCK) {
			khttpd_stream_continue_receiving(stream,
			    conn->xchg_data == NULL ? 
			    conn->upstream->idle_timeout :
			    conn->upstream->busy_timeout);
			return;
		}

		if (error != 0) {
			KHTTPD_NOTE("%s error %d", __func__, error);

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

		for (; sizeof(struct khttpd_fcgi_hdr) <= mlen;
		     m = conn->recv_buf) {
			m_copydata(m, 0, sizeof(hdr), (char *)&hdr);

			if (hdr.version != 1) {
				khttpd_fcgi_protocol_error_new(&logent);
				khttpd_problem_set_detail(&logent,
				    "unknown protocol version \"%d\"",
				    hdr.version);
				khttpd_fcgi_report_error(conn->upstream,
				    &logent);

				conn->recv_buf = NULL;
				m_freem(m);

				khttpd_socket_reset
				    (khttpd_fcgi_conn_socket(conn));
				return;
			}

			cntlen = ntohs(hdr.content_length);
			padlen = hdr.padding_length;
			pktlen = sizeof(hdr) + cntlen + padlen;
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
				if (khttpd_fcgi_process_stdout_record
				    (conn, m)) {
					recv_suspended = true;
				}
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
				khttpd_fcgi_report_error(conn->upstream,
				    &logent);
				break;

			default:
				m_freem(m);

				khttpd_fcgi_protocol_error_new(&logent);
				khttpd_problem_set_detail(&logent,
				    "invalid record type \"%d\"", hdr.type);
				khttpd_fcgi_report_error(conn->upstream,
				    &logent);
			}
		}
	} while (!recv_suspended);

	conn->recv_suspended = true;
}

static void
khttpd_fcgi_conn_clear_to_send(struct khttpd_stream *stream, long space)
{
	struct khttpd_fcgi_conn *conn = stream->up;

	KHTTPD_ENTRY("%s(conn %p,%#x)", __func__, conn, space);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	if (conn->active) {
		khttpd_fcgi_send_stdin(conn->xchg_data, space);
	}
}

static void
khttpd_fcgi_conn_reset(struct khttpd_stream *stream)
{
	struct khttpd_fcgi_conn *conn = stream->up;

	KHTTPD_ENTRY("%s(conn %p)", __func__, conn);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

	if (conn->recv_suspended) {
		conn->recv_suspended = false;
		khttpd_stream_continue_receiving(&conn->stream, 0);
	}
}

static void
khttpd_fcgi_conn_error(struct khttpd_stream *stream,
    struct khttpd_mbuf_json *entry)
{
	struct khttpd_fcgi_conn *conn = stream->up;

	KHTTPD_ENTRY("%s(conn %p,%p)", __func__, conn, entry);
	KASSERT(khttpd_fcgi_conn_on_worker_thread(conn), ("wrong thread"));

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
	int64_t intval;
	int status;

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

	prop_spec.name = "idleTimeout";
	status = khttpd_webapi_get_integer_property(&intval, prop_spec.name,
	    input_prop_spec, input, output, true);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;

	} else if (status == KHTTPD_STATUS_NO_CONTENT) {
		upstream->idle_timeout = 0;

	} else if (intval < 0 || SBT_MAX >> 32 < intval) {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto end;

	} else {
		upstream->idle_timeout = intval << 32;
	}

	prop_spec.name = "busyTimeout";
	status = khttpd_webapi_get_integer_property(&intval, prop_spec.name,
	    input_prop_spec, input, output, true);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		return (status);

	} else if (status == KHTTPD_STATUS_NO_CONTENT) {
		upstream->busy_timeout = 0;

	} else if (intval < 0 || SBT_MAX >> 32 < intval) {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto end;

	} else {
		upstream->busy_timeout = intval << 32;
	}

	status = khttpd_webapi_get_sockaddr_property
	    ((struct sockaddr *)&upstream->sockaddr,
		sizeof(upstream->sockaddr), "address",
		input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;
	}

	mtx_lock(&loc_data->lock);
	TAILQ_INSERT_TAIL(&loc_data->avl_upstreams, upstream, tailqe);
	mtx_unlock(&loc_data->lock);

	khttpd_fcgi_conn_new(loc_data, upstream);
	status = KHTTPD_STATUS_OK;

 end:
	if (KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		*upstream_out = upstream;
	} else {
		khttpd_fcgi_upstream_destroy(upstream);
	}

	return (status);
}

static void
khttpd_fcgi_exchange_dtor(struct khttpd_exchange *exchange, void *arg)
{
	struct khttpd_fcgi_conn *conn;
	struct khttpd_fcgi_location_data *loc_data;
	struct khttpd_fcgi_xchg_data *xchg_data = arg;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, exchange, arg);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	if (xchg_data->active) {
		KHTTPD_NOTE("%s active", __func__);
		khttpd_fcgi_detach_conn(xchg_data, true);

	} else {
		loc_data = 
		    khttpd_location_data(khttpd_exchange_location(exchange));
		mtx_lock(&loc_data->lock);

		if ((conn = xchg_data->conn) != NULL) {
			KHTTPD_NOTE("%s attaching", __func__);
			conn->xchg_data = NULL;

		} else if (xchg_data->waiting) {
			KHTTPD_NOTE("%s waiting", __func__);
			STAILQ_REMOVE(&loc_data->queue, xchg_data,
			    khttpd_fcgi_xchg_data, link);
			--loc_data->nwaiting;
		}

		mtx_unlock(&loc_data->lock);
	}

	uma_zfree(khttpd_fcgi_xchg_data_zone, xchg_data);
}

static int
khttpd_fcgi_exchange_get(struct khttpd_exchange *exchange, void *arg,
    long space, struct mbuf **data_out)
{
	struct khttpd_fcgi_xchg_data *xchg_data = arg;
	struct khttpd_fcgi_conn *conn;
	struct mbuf *hd;

	KHTTPD_ENTRY("%s(%p,%p,%#lx)", __func__, exchange, arg, space);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

	if (xchg_data->aborted) {
		KHTTPD_NOTE("%s aborted", __func__);
		return (ECONNABORTED);
	}

	if ((hd = xchg_data->get_buf) == NULL) {
		if (xchg_data->get_finished) {
			*data_out = NULL;
			return (0);
		}

		KHTTPD_NOTE("%s get_suspend", __func__);
		xchg_data->get_suspended = true;

		return (EWOULDBLOCK);
	}

	if ((xchg_data->get_buf = m_split(hd, space, M_WAITOK)) == NULL &&
	    (conn = xchg_data->conn) != NULL && conn->recv_suspended) {
		conn->recv_suspended = false;
		khttpd_stream_continue_receiving(&conn->stream,
		    conn->upstream->busy_timeout);
	}

	*data_out = hd;
	return (0);
}

static void
khttpd_fcgi_exchange_put(struct khttpd_exchange *exchange, void *arg,
    struct mbuf *data, bool *pause_out)
{
	struct khttpd_fcgi_xchg_data *xchg_data = arg;
	long space;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, exchange, arg);
	KASSERT(khttpd_fcgi_xchg_data_on_worker_thread(xchg_data),
	    ("wrong thread"));

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

	if (data == NULL) {
		xchg_data->put_eof = true;
	} else if (xchg_data->put_buf == NULL) {
		xchg_data->put_buf = data;
	} else {
		m_cat(xchg_data->put_buf, data);
	}

	if (!xchg_data->active || xchg_data->put_busy) {
		*pause_out = xchg_data->put_suspended = data != NULL;
	} else {
		xchg_data->put_busy = true;
		khttpd_stream_send_bufstat(&xchg_data->conn->stream,
		    NULL, NULL, &space);
		khttpd_fcgi_send_stdin(xchg_data, space);
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
	KASSERT(exchange == NULL || khttpd_exchange_on_worker_thread(exchange),
	    ("wrong thread"));

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
			if (segend == NULL) {
				segend = sbuf_data(&sbuf) + sbuf_len(&sbuf);
			}

			oldsep = *segend;

			if (suffix_len <= segend - segbegin &&
			    memcmp(segend - suffix_len, script_suffix,
				suffix_len) == 0) {
				*segend = '\0';

				error = kern_statat(td, 0, 
				    loc_data->fs_path_fd, sbuf_data(&sbuf),
				    UIO_SYSSPACE, &statbuf, NULL);
				if (error != 0) {
					KHTTPD_NOTE("%s stat error %d \"%s\"",
					     __func__, error,
					     khttpd_ktr_printf("%s",
					     sbuf_data(&sbuf)));
					break;
				}

				*segend = oldsep;

				if (S_ISREG(statbuf.st_mode)) {
					KHTTPD_NOTE("%s %u positive \"%s\"",
					    __func__, __LINE__,
					    khttpd_ktr_printf("%.*s",
						(int)(segend - segbegin),
						segbegin));
					goto positive;
				}
			}

			if (oldsep == '\0') {
				break;
			}

			segbegin = segend + 1;
			segend = strchr(segbegin, '/');
		}

	} else {
		fd = loc_data->fs_path_fd;
		segbegin = sbuf_data(&sbuf);
		segend = strchr(segbegin, '/');
		for (;;) {
			if (segend == NULL) {
				segend = sbuf_data(&sbuf) + sbuf_len(&sbuf);
			}

			oldsep = *segend;
			*segend = '\0';

			error = kern_statat(td, 0, fd, segbegin, UIO_SYSSPACE,
			    &statbuf, NULL);
			if (error != 0) {
				break;
			}

			if (S_ISREG(statbuf.st_mode)) {
				if (fd != loc_data->fs_path_fd) {
					kern_close(td, fd);
				}
				*segend = oldsep;
				KHTTPD_NOTE("%s %u positive \"%s\"", __func__,
				    __LINE__, khttpd_ktr_printf("%.*s",
				    (int)(segend - segbegin), segbegin));
				goto positive;
			}

			if (!S_ISDIR(statbuf.st_mode)) {
				break;
			}

			error = kern_openat(td, fd, segbegin, UIO_SYSSPACE,
			    O_RDONLY | O_DIRECTORY, 0777);
			if (error != 0) {
				break;
			}
			fd = td->td_retval[0];

			*segend = oldsep;

			if (oldsep == '\0') {
				break;
			}

			segbegin = segend + 1;
			segend = strchr(segbegin, '/');
		}

		if (fd != loc_data->fs_path_fd) {
			kern_close(td, fd);
		}
	}

	KHTTPD_NOTE("%s negative", __func__);
	sbuf_delete(&sbuf);

	return (false);

 positive:
	data = uma_zalloc_arg(khttpd_fcgi_xchg_data_zone, exchange, M_WAITOK);
	if (exchange != NULL) {
		khttpd_exchange_set_ops(exchange, &khttpd_fcgi_exchange_ops,
		    data);
	}

	KASSERT(loc_data->fs_path[strlen(loc_data->fs_path) - 1] == '/',
	    ("fs_path \"%s\" is not slash terminated", loc_data->fs_path));

	cp = sbuf_data(&sbuf);
	sbuf_bcat(&data->script_name, cp, segend - cp);
	sbuf_finish(&data->script_name);

	if (translated_path != NULL) {
		sbuf_bcpy(translated_path, sbuf_data(&data->script_name),
		    sbuf_len(&data->script_name));
	}

	sbuf_cpy(&data->path_info, segend);
	sbuf_finish(&data->path_info);

	sbuf_delete(&sbuf);

	if (exchange == NULL) {
		uma_zfree(khttpd_fcgi_xchg_data_zone, data);
	}

	return (true);
}

static void
khttpd_fcgi_do_method(struct khttpd_exchange *exchange)
{
	int status;

	KHTTPD_ENTRY("%s(%p=%s)", __func__, exchange,
	    khttpd_ktr_printf("{target: \"%s\", method: \"%s\", query:\"%s\"}",
		khttpd_exchange_target(exchange),
		khttpd_method_name(khttpd_exchange_method(exchange)),
		khttpd_exchange_query(exchange)));
	KASSERT(khttpd_exchange_on_worker_thread(exchange),
	    ("wrong thread"));

	if (khttpd_exchange_request_is_chunked(exchange)) {
		status = KHTTPD_STATUS_LENGTH_REQUIRED;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		khttpd_exchange_respond(exchange, status);
		return;
	}

	khttpd_fcgi_choose_conn(exchange);
}

static int
khttpd_fcgi_conn_init(void *mem, int size, int flags)
{
	struct khttpd_fcgi_conn *conn = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);

	conn->stream.up_ops = &khttpd_fcgi_conn_ops;
	conn->stream.up = conn;
	conn->stream.down = NULL;
	conn->xchg_data = NULL;
	conn->attach_task = khttpd_task_new(NULL, khttpd_fcgi_attach_conn,
	    conn, "attach");
	conn->release_task = khttpd_task_new(NULL, khttpd_fcgi_do_conn_release,
	    conn, "release");
	conn->abort_req_task = khttpd_task_new(NULL,
	    khttpd_fcgi_conn_do_abort_request, conn, "abort");
	callout_init(&conn->end_request_co, 1);

	return (0);
}

static void
khttpd_fcgi_conn_fini(void *mem, int size)
{
	struct khttpd_fcgi_conn *conn = mem;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, mem, size);

	khttpd_task_delete(conn->attach_task);
	khttpd_task_delete(conn->release_task);
	khttpd_task_delete(conn->abort_req_task);
}

static int
khttpd_fcgi_conn_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_fcgi_conn *conn = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%p,%#x)", __func__, mem, size, arg, flags);

	conn->upstream = arg;
	bzero(&conn->khttpd_fcgi_conn_zctor_begin,
	    sizeof(struct khttpd_fcgi_conn) -
	    offsetof(struct khttpd_fcgi_conn, khttpd_fcgi_conn_zctor_begin));

	return (0);
}

static void
khttpd_fcgi_conn_dtor(void *mem, int size, void *arg)
{
	struct khttpd_fcgi_conn *conn = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%p)", __func__, mem, size, arg);
	KASSERT(conn->xchg_data == NULL, ("xchg_data %p", conn->xchg_data));
	KASSERT(conn->stream.down == NULL, 
	    ("stream.down %p", conn->stream.down));

	callout_drain(&conn->end_request_co);
	m_freem(conn->recv_buf);
}

static int
khttpd_fcgi_xchg_data_init(void *mem, int size, int flags)
{
	struct khttpd_fcgi_xchg_data *xchg_data = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);

	sbuf_new(&xchg_data->path_info, xchg_data->path_info_buf,
	    sizeof(xchg_data->path_info_buf), SBUF_AUTOEXTEND);
	sbuf_new(&xchg_data->script_name, xchg_data->script_name_buf,
	    sizeof(xchg_data->script_name_buf), SBUF_AUTOEXTEND);
	sbuf_new(&xchg_data->line, xchg_data->line_buf,
	    sizeof(xchg_data->line_buf), SBUF_AUTOEXTEND);
	sbuf_new(&xchg_data->location, xchg_data->location_buf,
	    sizeof(xchg_data->location_buf), SBUF_AUTOEXTEND);

	return (0);
}

static void
khttpd_fcgi_xchg_data_fini(void *mem, int size)
{
	struct khttpd_fcgi_xchg_data *xchg_data = mem;

	KHTTPD_ENTRY("%s(%p,%#x)", __func__, mem, size);

	sbuf_delete(&xchg_data->path_info);
	sbuf_delete(&xchg_data->script_name);
	sbuf_delete(&xchg_data->line);
	sbuf_delete(&xchg_data->location);
}

static int
khttpd_fcgi_xchg_data_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_fcgi_xchg_data *xchg_data = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%p,%#x)", __func__, mem, size, arg, flags);

	xchg_data->exchange = arg;
	bzero(&xchg_data->khttpd_fcgi_xchg_data_zctor_begin,
	    offsetof(struct khttpd_fcgi_xchg_data,
		khttpd_fcgi_xchg_data_zctor_end) -
	    offsetof(struct khttpd_fcgi_xchg_data,
		khttpd_fcgi_xchg_data_zctor_begin));

	return (0);
}

static void
khttpd_fcgi_xchg_data_dtor(void *mem, int size, void *arg)
{
	struct khttpd_fcgi_xchg_data *xchg_data = mem;

	KHTTPD_ENTRY("%s(%p,%#x,%p)", __func__, mem, size, arg);

	sbuf_clear(&xchg_data->path_info);
	sbuf_clear(&xchg_data->script_name);
	sbuf_clear(&xchg_data->line);
	sbuf_clear(&xchg_data->location);
	m_freem(xchg_data->put_buf);
	m_freem(xchg_data->get_buf);
}

static void
khttpd_fcgi_shutdown(void *arg)
{

	mtx_lock(&khttpd_fcgi_lock);
	while (0 < khttpd_fcgi_conn_count) {
		mtx_sleep(&khttpd_fcgi_conn_count, &khttpd_fcgi_lock, 0,
		    "fcgidown", 0);
	}
	mtx_unlock(&khttpd_fcgi_lock);
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
	    khttpd_fcgi_conn_init, khttpd_fcgi_conn_fini, UMA_ALIGN_PTR, 0);
	khttpd_fcgi_shutdown_tag =
	    EVENTHANDLER_REGISTER(khttpd_main_shutdown,
		khttpd_fcgi_shutdown, NULL, EVENTHANDLER_PRI_LAST - 1);

	return (0);
}

static void
khttpd_fcgi_exit(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	EVENTHANDLER_DEREGISTER(khttpd_main_shutdown, 
	    khttpd_fcgi_shutdown_tag);
	
	/*
	 * Destroying khttpd_fcgi_xchg_data_zone at this point is safe
	 * because khttpd_port guarantees that all the ports and sockets
	 * has gone, and it implies all the exchanges are destroyed too.
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

	mtx_destroy(&data->lock);
	LIST_FOREACH_SAFE(upstream, &data->upstreams, liste, tmpupstream) {
		khttpd_fcgi_upstream_destroy(upstream);
	}
	khttpd_free(data->fs_path);
	khttpd_free(data->script_suffix);
	if (data->fs_path_fd != -1) {
		kern_close(td, data->fs_path_fd);
	}
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

	status = khttpd_webapi_get_string_property(&str, 
	    "fsPath", input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;
	}

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
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;
	}
	if (str != NULL) {
		location_data->script_suffix = khttpd_strdup(str);
	}

	status = khttpd_webapi_get_array_property(&upstreams_j, "upstreams",
	    input_prop_spec, input, output, false);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		goto end;
	}

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
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		return (status);
	}

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
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		return (status);
	}

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
