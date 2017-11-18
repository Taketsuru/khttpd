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

#include <sys/types.h>
#include <sys/limits.h>
#include <sys/ctype.h>
#include <sys/queue.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>

#include "khttpd_ctrl.h"
#include "khttpd_http.h"
#include "khttpd_init.h"
#include "khttpd_json.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_problem.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_webapi.h"

#ifndef KHTTPD_SYSCTL_PUT_MAX
#define KHTTPD_SYSCTL_PUT_MAX	4096
#endif

struct khttpd_sysctl_put_data {
	struct mbuf	*head;
	struct mbuf	*tail;
	size_t		limit;
	boolean_t	rejected;
};

static void khttpd_sysctl_get(struct khttpd_exchange *exchange);
static void khttpd_sysctl_put(struct khttpd_exchange *exchange);
static void khttpd_sysctl_options(struct khttpd_exchange *exchange);
static void khttpd_sysctl_put_data_dtor(struct khttpd_exchange *, void *);
static void khttpd_sysctl_put_data_put(struct khttpd_exchange *, void *,
    struct mbuf *, boolean_t *);
static void khttpd_sysctl_put_data_end(struct khttpd_exchange *, void *);

static struct khttpd_location_ops khttpd_sysctl_location_ops = {
	.set_error_response = khttpd_exchange_set_response_body_problem_json,
	.method[KHTTPD_METHOD_GET] = khttpd_sysctl_get,
	.method[KHTTPD_METHOD_OPTIONS] = khttpd_sysctl_options,
	.method[KHTTPD_METHOD_PUT] = khttpd_sysctl_put
};

static struct khttpd_exchange_ops khttpd_sysctl_put_ops = {
	.dtor = khttpd_sysctl_put_data_dtor,
	.put = khttpd_sysctl_put_data_put,
	.end = khttpd_sysctl_put_data_end,
};	

static const char *khttpd_sysctl_types[] = {
	"<zero>"
	"node",
	"int",
	"string",
	"s64",
	"struct",
	"uint",
	"long",
	"ulong",
	"u64",
	"u8",
	"u16",
	"s8",
	"s16",
	"s32",
	"u32"
};

static const struct {
	u_int		flag;
	const char	*field_name;
} khttpd_sysctl_flags[] = {
	{ CTLFLAG_RD,		"rd" },
	{ CTLFLAG_WR,		"wr" },
	{ CTLFLAG_ANYBODY,	"anybody" },
	{ CTLFLAG_PRISON,	"prison" },
	{ CTLFLAG_DYN,		"dyn" },
	{ CTLFLAG_SKIP,		"skip" },
	{ CTLFLAG_TUN,		"tun" },
	{ CTLFLAG_MPSAFE,	"mpsafe" },
	{ CTLFLAG_VNET,		"vnet" },
	{ CTLFLAG_DYING,	"dying" },
	{ CTLFLAG_CAPRD,	"caprd" },
	{ CTLFLAG_CAPWR,	"capwr" },
	{ CTLFLAG_STATS,	"stats" },
	{ CTLFLAG_NOFETCH,	"nofetch" }
};

static const size_t khttpd_sysctl_flags_count =
    sizeof(khttpd_sysctl_flags) / sizeof(khttpd_sysctl_flags[0]);

static void
khttpd_sysctl_print_oid(struct sbuf *output, int *oid, int n)
{
	int i;

	KASSERT(1 < n, ("n(==%d) is too small", n));
	sbuf_printf(output, "%x", oid[0]);
	for (i = 1; i < n; ++i)
		sbuf_printf(output, ".%x", oid[i]);
}

static int
khttpd_sysctl_set_problem(struct khttpd_exchange *exchange,
    struct khttpd_mbuf_json *output, int error)
{
	int status;

	switch (error) {

	case 0:
		status = KHTTPD_STATUS_OK;
		break;

	case EINVAL:
		/*
		 * Note: This function ignore the case when an invalid oid
		 * is given to sysctl.  The caller should detect it and
		 * send "Not Found" response.
		 */
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		break;

	case EISDIR:
	case ENOTDIR:
	case ENOENT:
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		break;

	case EPERM:
		status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
		khttpd_problem_response_begin(output, status, NULL, NULL);

		khttpd_exchange_add_response_field(exchange, "Allow",
		    "OPTIONS, HEAD, GET");
		break;

	default:
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_response_begin(output, status, NULL, NULL);
	}

	return (status);
}

static void
khttpd_sysctl_value_in_json(struct khttpd_mbuf_json *output, void *valbuf,
    size_t valbuflen, u_int kind)
{

	switch (kind & CTLTYPE) {

	case CTLTYPE_INT:
		khttpd_mbuf_json_format(output, FALSE, "%d", *(int *)valbuf);
		break;

	case CTLTYPE_STRING:
		khttpd_mbuf_json_format(output, TRUE, "%.*s", valbuflen,
		    valbuf);
		break;

	case CTLTYPE_S64:
		khttpd_mbuf_json_format(output, FALSE, "%jd",
		    (intmax_t)*(int64_t *)valbuf);
		break;

	case CTLTYPE_UINT:
		khttpd_mbuf_json_format(output, FALSE, "%u", *(u_int *)valbuf);
		break;

	case CTLTYPE_LONG:
		khttpd_mbuf_json_format(output, FALSE, "%ld", *(long *)valbuf);
		break;

	case CTLTYPE_ULONG:
		khttpd_mbuf_json_format(output, FALSE, "%lu",
		    *(u_long *)valbuf);
		break;

	case CTLTYPE_U64:
		khttpd_mbuf_json_format(output, FALSE, "%ju",
		    (uintmax_t)*(uint64_t *)valbuf);
		break;

	case CTLTYPE_U8:
		khttpd_mbuf_json_format(output, FALSE, "%u",
		    *(uint8_t *)valbuf);
		break;

	case CTLTYPE_U16:
		khttpd_mbuf_json_format(output, FALSE, "%u",
		    *(uint16_t *)valbuf);
		break;

	case CTLTYPE_S8:
		khttpd_mbuf_json_format(output, FALSE, "%d",
		    *(int8_t *)valbuf);
		break;

	case CTLTYPE_S16:
		khttpd_mbuf_json_format(output, FALSE, "%d",
		    *(int16_t *)valbuf);
		break;

	case CTLTYPE_S32:
		khttpd_mbuf_json_format(output, FALSE, "%d",
		    *(int32_t *)valbuf);
		break;

	case CTLTYPE_U32:
		khttpd_mbuf_json_format(output, FALSE, "%u",
		    *(uint32_t *)valbuf);
		break;
	}
}

static void
khttpd_sysctl_get_index(struct khttpd_exchange *exchange)
{
	int last_oid[CTL_MAXNAME], next_oid[CTL_MAXNAME + 2];
	char buf[128];
	struct sbuf sbuf;
	struct khttpd_mbuf_json body;
	char *descbuf, *kindbuf, *namebuf, *valbuf;
	struct khttpd_location *location;
	struct thread *td;
	size_t last_oidlen, next_oidlen;
	size_t len, descbuflen, kindbuflen, namebuflen, valbuflen;
	u_int kind;
	int error, i, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	td = curthread;
	namebuf = kindbuf = descbuf = valbuf = NULL;
	namebuflen = kindbuflen = descbuflen = valbuflen = 0;
	location = khttpd_exchange_location(exchange);
	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_mbuf_json_new(&body);

	khttpd_mbuf_json_object_begin(&body);
	khttpd_mbuf_json_property_array_begin(&body, "flags");
	for (i = 0; i < khttpd_sysctl_flags_count; ++i)
		khttpd_mbuf_json_format(&body, TRUE, "%s",
		    khttpd_sysctl_flags[i].field_name);
	khttpd_mbuf_json_array_end(&body);

	khttpd_mbuf_json_property_array_begin(&body, "items");
	last_oid[0] = 1;
	last_oidlen = sizeof(int);
	next_oidlen = 0;
	for (;;) {
		/* Find the next entry of the entry named by last_oid. */
		next_oid[0] = 0; /* sysctl internal magic */
		next_oid[1] = 2; /* next */
		bcopy(last_oid, next_oid + 2, last_oidlen);
		next_oidlen = CTL_MAXNAME * sizeof(int);
		error = kernel_sysctl(td, next_oid,
		    last_oidlen / sizeof(int) + 2,
		    next_oid + 2, &next_oidlen, NULL, 0, &next_oidlen, 0);
		if (error != 0)
			break;

		/* Get the kind and the format of the next entry. */
		next_oid[1] = 4; /* oidfmt */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0, &len, 0);
		if (error != 0)
			goto next;
		if (kindbuflen < len) {
			kindbuf = khttpd_realloc(kindbuf, len);
			kindbuflen = len;
		}
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, kindbuf, &kindbuflen, NULL,
		    0, NULL, 0);
		if (error != 0)
			goto next;

		kind = *(u_int *)kindbuf;
		type = kind & CTLTYPE;

		/* Skip sysctls which are nodes or structs. */
		if (type == CTLTYPE_NODE || type == CTLTYPE_STRUCT)
			goto next;

		/* Get the name of the next entry. */
		next_oid[1] = 1; /* name */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0, &len, 0);
		if (error != 0)
			goto next;
		if (namebuflen < len) {
			namebuf = khttpd_realloc(namebuf, len);
			namebuflen = len;
		}
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, namebuf, &namebuflen, NULL,
		    0, NULL, 0);
		if (error != 0)
			goto next;

		khttpd_mbuf_json_object_begin(&body);

		/* Print "href" property. */
		sbuf_printf(&sbuf, "%s", khttpd_location_get_path(location));
		khttpd_sysctl_print_oid(&sbuf, next_oid + 2,
		    next_oidlen / sizeof(int));
		sbuf_finish(&sbuf);
		khttpd_mbuf_json_property_format(&body, "href", TRUE,
		    sbuf_data(&sbuf));
		sbuf_clear(&sbuf);

		/* Print "name" property */
		khttpd_mbuf_json_property_format(&body, "name", TRUE, "%s",
		    namebuf);

		khttpd_mbuf_json_property_array_begin(&body, "flags");
		for (i = 0; i < khttpd_sysctl_flags_count; ++i)
			if ((kind & khttpd_sysctl_flags[i].flag) != 0)
				khttpd_mbuf_json_format(&body, TRUE, "%s",
				    khttpd_sysctl_flags[i].field_name);
		khttpd_mbuf_json_array_end(&body);

		if ((kind & CTLFLAG_SECURE) != 0)
			khttpd_mbuf_json_property_format(&body, "securelevel",
			    FALSE, "%d",
			    (kind & CTLMASK_SECURE) >> CTLSHIFT_SECURE);

		khttpd_mbuf_json_property_format(&body, "type", TRUE, "%s",
			    khttpd_sysctl_types[type - 1]);

		khttpd_mbuf_json_property_format(&body, "format", TRUE, "%s",
		    kindbuf + sizeof(kind));

		/* Get the description of the next entry. */
		next_oid[1] = 5; /* oiddescr */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0, &len, 0);
		if (error == 0) {
			if (descbuflen < len) {
				descbuf = khttpd_realloc(descbuf, len);
				descbuflen = len;
			}
			error = kernel_sysctl(td, next_oid,
			    next_oidlen / sizeof(int) + 2, descbuf,
			    &descbuflen, NULL, 0, NULL, 0);
			if (error == 0 && 0 < len && descbuf[0] != '\0')
				khttpd_mbuf_json_property_format(&body,
				    "description", TRUE, "%s", descbuf);
		}

		/* Get the value of the next entry. */
		error = kernel_sysctl(td, next_oid + 2,
		    next_oidlen / sizeof(int), NULL, 0, NULL, 0, &len, 0);
		if (error == 0) {
			if (valbuflen < len) {
				valbuf = khttpd_realloc(valbuf, len);
				valbuflen = len;
			}
			error = kernel_sysctl(td, next_oid + 2,
			    next_oidlen / sizeof(int), valbuf, &valbuflen,
			    NULL, 0, NULL, 0);
			if (error == 0) {
				khttpd_mbuf_json_property(&body, "value");
				khttpd_sysctl_value_in_json(&body,
				    valbuf, valbuflen, kind);
			}
		}

		khttpd_mbuf_json_object_end(&body);

 next:
		bcopy(next_oid + 2, last_oid, next_oidlen);
		last_oidlen = next_oidlen;
	}

	khttpd_mbuf_json_array_end(&body);
	khttpd_mbuf_json_object_end(&body);

	khttpd_free(kindbuf);
	khttpd_free(namebuf);
	khttpd_free(descbuf);
	khttpd_free(valbuf);

	khttpd_exchange_set_response_body_json(exchange, &body);
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
}

static int
khttpd_sysctl_parse_oid(const char *name, int *oid)
{
	const char *cp;
	int i;
	u_int value;
	char ch;

	cp = name;
	i = 0;
	for (i = 0; i < CTL_MAXNAME; ++i) {
		if (*cp == '\0')
			return (-1);

		value = 0;
		for (;;) {
			ch = *cp++;
			if (!isxdigit(ch))
				break;
			if (value << 4 < value)
				return (-1);
			value <<= 4;
			if (isdigit(ch))
				value |= ch - '0';
			else if ('a' <= ch && ch <= 'f')
				value |= ch - 'a' + 10;
			else
				value |= ch - 'A' + 10;
		}

		if (ch != '.' && ch != '\0')
			return (-1);

		oid[i] = value;

		if (ch == '\0')
			return (i < 1 ? -1 : i + 1);
	}

	return (-1);
}

static void
khttpd_sysctl_put_not_allowed(struct khttpd_exchange *exchange)
{
	int status;

	khttpd_exchange_add_response_field(exchange, "Allow",
	    "OPTIONS, HEAD, GET");
	status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_sysctl_get_leaf(struct khttpd_exchange *exchange)
{
	int oid[CTL_MAXNAME], tmpoid[CTL_MAXNAME + 2];
	struct khttpd_mbuf_json body;
	struct thread *td;
	char *valbuf;
	size_t oidlen, vallen;
	u_int kind;
	int error, status, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	td = curthread;
	valbuf = NULL;
	khttpd_mbuf_json_new(&body);

	oidlen = khttpd_sysctl_parse_oid
	    (khttpd_exchange_suffix(exchange), oid);
	if (oidlen == -1) {
		error = ENOENT;
		goto error;
	}

	tmpoid[0] = 0;		/* sysctl internal magic */
	tmpoid[1] = 4;		/* oidfmt */
	bcopy(oid, tmpoid + 2, oidlen * sizeof(oid[0]));
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    NULL, 0, NULL, 0, &vallen, 0);
	if (error != 0)
		goto error;

	valbuf = khttpd_malloc(vallen);
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	bcopy(valbuf, &kind, sizeof(kind));
	khttpd_free(valbuf);
	valbuf = NULL;
	if (error != 0)
		goto error;

	type = kind & CTLTYPE;

	if (type == CTLTYPE_NODE || type == CTLTYPE_OPAQUE)
		error = ENOENT;
	else if ((error = kernel_sysctl(td, oid, oidlen, NULL, 0, NULL, 0,
		    &vallen, 0)) != 0)
		; 		/* nothing */
	else {
		valbuf = khttpd_malloc(vallen);
		error = kernel_sysctl(td, oid, oidlen, valbuf, &vallen, 
		    NULL, 0, NULL, 0);
		if (error == 0)
			khttpd_sysctl_value_in_json(&body, valbuf, vallen,
			    kind);
		khttpd_free(valbuf);
	}

 error:
	status = error == 0 ? KHTTPD_STATUS_OK :
	    khttpd_sysctl_set_problem(exchange, &body, error);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_response_body_json(exchange, &body);
	else
		khttpd_exchange_set_error_response_body(exchange, status,
		    &body);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_sysctl_get(struct khttpd_exchange *exchange)
{
	const char *suffix;

	suffix = khttpd_exchange_suffix(exchange);
	if (suffix[0] == '\0')
		khttpd_sysctl_get_index(exchange);
	else
		khttpd_sysctl_get_leaf(exchange);
}

static void
khttpd_sysctl_put_data_dtor(struct khttpd_exchange *exchange,
    void *arg)
{
	struct khttpd_sysctl_put_data *data;

	data = arg;
	m_freem(data->head);
	khttpd_free(data);
}

static void
khttpd_sysctl_put_data_put(struct khttpd_exchange *exchange,
    void *arg, struct mbuf *m, boolean_t *pause)
{
	char buf[128];
	struct khttpd_mbuf_json problem;
	struct khttpd_sysctl_put_data *data;
	int len, status;

	data = arg;

	if (data->rejected) {
		m_freem(m);
		return;
	}

	len = m_length(m, NULL);
	if (data->limit < len) {
		m_freem(m);
		m_freem(data->head);
		data->head = data->tail = NULL;
		data->rejected = TRUE;

		khttpd_mbuf_json_new(&problem);

		status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
		khttpd_problem_response_begin(&problem, status, NULL, NULL);

		snprintf(buf, sizeof(buf),
		    "The maximum request body size for a sysctl is %d bytes",
		    KHTTPD_SYSCTL_PUT_MAX);
		khttpd_problem_set_detail(&problem, buf);

		khttpd_exchange_set_error_response_body(exchange, status,
		    &problem);

		khttpd_exchange_respond(exchange, status);

		return;
	}

	data->limit -= len;
	m_cat(data->tail, m);
	m_length(data->tail, &data->tail);
}

static void
khttpd_sysctl_put_data_end(struct khttpd_exchange *exchange, void *arg)
{
	static struct int_trait {
		int64_t min;
		uint64_t max;
		size_t  size;
	} int_traits[] = {
		{},
		{},				  /* CTLTYPE_NODE */
		{ INT_MIN, INT_MAX, sizeof(int)}, /* CTLTYPE_INT */
		{},				  /* CTLTYPE_STRING */
		{ QUAD_MIN, QUAD_MAX, sizeof(int64_t)}, /* CTLTYPE_S64 */
		{},				     /* CTLTYPE_OPAQUE */
		{ 0, UINT_MAX, sizeof(u_int)},	     /* CTLTYPE_UINT */
		{ LONG_MIN, LONG_MAX, sizeof(long)}, /* CTLTYPE_LONG */
		{ 0, ULONG_MAX, sizeof(u_long) },    /* CTLTYPE_ULONG */
		{ 0, UQUAD_MAX, sizeof(uint64_t)},   /* CTLTYPE_U64 */
		{ 0, UCHAR_MAX, sizeof(char)},	     /* CTLTYPE_U8 */
		{ 0, USHRT_MAX, sizeof(uint16_t)},   /* CTLTYPE_U16 */
		{ SCHAR_MIN, SCHAR_MAX, sizeof(char)},	/* CTLTYPE_S8 */
		{ SHRT_MIN, SHRT_MAX, sizeof(int16_t)}, /* CTLTYPE_S16 */
		{ INT_MIN, INT_MAX, sizeof(int32_t)},	/* CTLTYPE_S32 */
		{ 0, UINT_MAX, sizeof(uint32_t)}	/* CTLTYPE_U32 */
	};

	int oid[CTL_MAXNAME], tmpoid[CTL_MAXNAME + 2];
	struct khttpd_mbuf_json problem;
	struct khttpd_sysctl_put_data *data;
	struct int_trait *traits;
	struct khttpd_json *value;
	struct thread *td;
	const char *suffix;
	char *valbuf;
	size_t oidlen, vallen;
	int64_t jival;
	u_int kind;
	int error, status;
	union {
		int		intval;
		u_int		uintval;
		long		longval;
		u_long		ulongval;
		uint8_t		u8val;
		uint16_t	u16val;
		int8_t		s8val;
		int16_t		s16val;
		int32_t		s32val;
		uint32_t	u32val;
	} ival;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));
	data = arg;
	value = NULL;
	td = curthread;
	khttpd_mbuf_json_new(&problem);

	suffix = khttpd_exchange_suffix(exchange);
	oidlen = khttpd_sysctl_parse_oid(suffix, oid);
	if (oidlen == -1) {
		error = ENOENT;
		goto error;
	}

	tmpoid[0] = 0;		/* sysctl internal magic */
	tmpoid[1] = 4;		/* oidfmt */
	bcopy(oid, tmpoid + 2, oidlen * sizeof(oid[0]));
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    NULL, 0, NULL, 0, &vallen, 0);
	if (error != 0 && error != ENOMEM)
		goto error;

	valbuf = khttpd_malloc(vallen);
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	bcopy(valbuf, &kind, sizeof(kind));
	khttpd_free(valbuf);
	if (error != 0)
		goto error;

	if ((kind & CTLFLAG_WR) == 0 || (kind & CTLTYPE) == CTLTYPE_NODE ||
	    (kind & CTLTYPE) == CTLTYPE_OPAQUE) {
		error = EPERM;
		goto error;
	}

	status = khttpd_ctrl_parse_json(&value, &problem, data->head);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto respond;

	if ((kind & CTLTYPE) == CTLTYPE_STRING) {
		if (khttpd_json_type(value) != KHTTPD_JSON_STRING) {
			khttpd_problem_wrong_type_response_begin(&problem);
			goto respond;
		}
		error = kernel_sysctl(td, oid, oidlen, NULL, 0,
		    (void *)khttpd_json_string_data(value),
		    khttpd_json_string_size(value), NULL, 0);
		if (error != 0)
			goto error;
	}

	if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
		khttpd_problem_wrong_type_response_begin(&problem);
		goto respond;
	}

	jival = khttpd_json_integer_value(value);
	traits = &int_traits[kind & CTLTYPE];

	error = 0;
	if (traits->size == sizeof(jival)) {
		error = kernel_sysctl(td, oid, oidlen,
		    NULL, 0, &jival, sizeof(jival), NULL, 0);

	} else if (jival < traits->min || traits->max < jival) {
		khttpd_problem_invalid_value_response_begin(&problem);
		goto respond;

	} else {
		switch (kind & CTLTYPE) {
		case CTLTYPE_INT:
			ival.intval = jival;
			break;
		case CTLTYPE_UINT:
			ival.uintval = jival;
			break;
		case CTLTYPE_LONG:
			ival.longval = jival;
			break;
		case CTLTYPE_ULONG:
			ival.ulongval = jival;
			break;
		case CTLTYPE_U8:
			ival.u8val = jival;
			break;
		case CTLTYPE_U16:
			ival.u16val = jival;
			break;
		case CTLTYPE_S8:
			ival.s8val = jival;
			break;
		case CTLTYPE_S16:
			ival.s16val = jival;
			break;
		case CTLTYPE_S32:
			ival.s32val = jival;
			break;
		case CTLTYPE_U32:
			ival.u32val = jival;
			break;
		default:
			panic("unexpected kind: %d", kind & CTLTYPE);
		}

		error = kernel_sysctl(td, oid, oidlen,
		    NULL, 0, &ival, traits->size, NULL, 0);
	}

 error:
	status = error == 0 ? KHTTPD_STATUS_NO_CONTENT :
	khttpd_sysctl_set_problem(exchange, &problem, error);

 respond:
	khttpd_json_delete(value);

	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_error_response_body(exchange, status,
		    &problem);
	else
		khttpd_mbuf_json_delete(&problem);

	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_sysctl_put(struct khttpd_exchange *exchange)
{
	struct khttpd_sysctl_put_data *data;
	const char *suffix;

	suffix = khttpd_exchange_suffix(exchange);
	if (suffix[0] == '\0') {
		khttpd_sysctl_put_not_allowed(exchange);
		return;
	}

	data = khttpd_malloc(sizeof(*data));
	data->head = data->tail = NULL;
	data->limit = KHTTPD_SYSCTL_PUT_MAX;
	data->rejected = FALSE;
	khttpd_exchange_set_ops(exchange, &khttpd_sysctl_put_ops, data);
}

static void
khttpd_sysctl_options(struct khttpd_exchange *exchange)
{
	int oid[CTL_MAXNAME];
	struct khttpd_mbuf_json body;
	struct thread *td;
	const char *suffix;
	char *buf;
	size_t buflen, oidlen;
	u_int kind;
	int error, status;
	boolean_t writeable;

	td = curthread;
	writeable = FALSE;
	khttpd_mbuf_json_new(&body);

	suffix = khttpd_exchange_suffix(exchange);
	if (suffix[0] == '\0')
		/* the target is a node */
		writeable = FALSE;

	else {
		/* the target is a leaf */
		oidlen = khttpd_sysctl_parse_oid(suffix, oid + 2);
		if (oidlen == -1) {
			status = khttpd_sysctl_set_problem(exchange, &body,
			    ENOENT);
			goto respond;
		}

		oid[0] = 0;	/* sysctl internal magic */
		oid[1] = 4;	/* oidfmt */
		error = kernel_sysctl(td, oid, oidlen + 2, NULL, 0, NULL, 0,
		    &buflen, 0);
		if (error == ENOENT) {
			status = khttpd_sysctl_set_problem(exchange, &body,
			    error);
			goto respond;
		}

		buf = khttpd_malloc(buflen);
		error = kernel_sysctl(td, oid, oidlen + 2, buf, &buflen,
		    NULL, 0, NULL, 0);
		bcopy(buf, &kind, sizeof(kind));
		khttpd_free(buf);
		if (error != 0) {
			status = khttpd_sysctl_set_problem(exchange, &body,
			    error);
			goto respond;
		}

		writeable = (kind & CTLFLAG_WR) != 0;
	}

	status = KHTTPD_STATUS_OK;
	khttpd_exchange_set_response_content_length(exchange, 0);
	khttpd_exchange_add_response_field(exchange, "Allow", "%s",
	    writeable ? "OPTIONS, HEAD, GET, PUT" : "OPTIONS, HEAD, GET");

respond:
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_error_response_body(exchange, status,
		    &body);
	else
		khttpd_mbuf_json_delete(&body);
	khttpd_exchange_respond(exchange, status);
}

static int
khttpd_sysctl_location_create(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input)
{

	return (khttpd_location_type_create_location(location_out, server, path,
		output, input_prop_spec, input,
		&khttpd_sysctl_location_ops, NULL));
}

static int
khttpd_sysctl_register_location_type(void)
{

	KHTTPD_ENTRY("khttpd_sysctl_register_location_type()");
	khttpd_location_type_register("khttpd_sysctl",
	    khttpd_sysctl_location_create, NULL, NULL, NULL);
	return (0);
}

static void
khttpd_sysctl_deregister_location_type(void)
{

	KHTTPD_ENTRY("khttpd_sysctl_deregister_location_type()");
	khttpd_location_type_deregister("khttpd_sysctl");
}

KHTTPD_INIT(khttpd_sysctl, khttpd_sysctl_register_location_type,
    khttpd_sysctl_deregister_location_type,
    KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES);
