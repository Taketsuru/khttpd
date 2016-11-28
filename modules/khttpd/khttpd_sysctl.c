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
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>

#include "khttpd.h"
#include "khttpd_json.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_router.h"
#include "khttpd_string.h"

#ifndef KHTTPD_SYSCTL_JSON_DEPTH_MAX
#define KHTTPD_SYSCTL_JSON_DEPTH_MAX	16
#endif

#ifndef KHTTPD_SYS_PREFIX
#define KHTTPD_SYS_PREFIX "/sys"
#endif

#ifndef KHTTPD_SYSCTL_PREFIX
#define KHTTPD_SYSCTL_PREFIX KHTTPD_SYS_PREFIX "/sysctl"
#endif

#ifndef KHTTPD_SYSCTL_PUT_MAX
#define KHTTPD_SYSCTL_PUT_MAX	4096
#endif

/* ------------------------------------------------------- type definitions */

struct khttpd_sysctl_put_leaf_request {
	struct mbuf	*head;
	struct mbuf	*tail;
	size_t		limit;
	u_int		kind;
	int		oidlen;
	int		oid[CTL_MAXNAME];
};

/* -------------------------------------------------- prototype declrations */

static void khttpd_sysctl_get(struct khttpd_request *request);
static void khttpd_sysctl_put(struct khttpd_request *request);
static void khttpd_sysctl_options(struct khttpd_request *request);
static void khttpd_sysctl_put_leaf_received_body
    (struct khttpd_request *request, struct mbuf *m);
static void khttpd_sysctl_put_leaf_end(struct khttpd_request *request);

/* --------------------------------------------------- variable definitions */

static struct khttpd_route_ops khttpd_route_ops_sysctl = {
	.method[KHTTPD_METHOD_GET] = khttpd_sysctl_get,
	.method[KHTTPD_METHOD_PUT] = khttpd_sysctl_put,
	.method[KHTTPD_METHOD_OPTIONS] = khttpd_sysctl_options
};

static const char *khttpd_sysctl_types[] = {
	"node",
	"int",
	"string",
	"s64",
	"opaque",
	"uint",
	"long",
	"ulong",
	"u64"
};

static const size_t khttpd_sysctl_types_end =
    sizeof(khttpd_sysctl_types) / sizeof(khttpd_sysctl_types[0]);

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

/* --------------------------------------------------- function definitions */

static int
khttpd_sysctl_value_in_json(struct mbuf *output, int *oid, int oidlen,
    u_int kind)
{
	struct thread *td;
	char *valbuf;
	size_t vallen;
	int error;
	u_int type;

	td = curthread;
	type = kind & CTLTYPE;
	valbuf = NULL;

	if (type == CTLTYPE_NODE) {
		error = ENOENT;
		goto out;
	}

	error = kernel_sysctl(td, oid, oidlen, NULL, 0, NULL, 0, &vallen, 0);
	if (error != 0)
		goto out;
	valbuf = khttpd_malloc(vallen);
	error = kernel_sysctl(td, oid, oidlen, valbuf, &vallen, NULL, 0,
	    NULL, 0);
	if (error != 0)
		goto out;

	switch (type) {

	case CTLTYPE_INT:
		khttpd_mbuf_printf(output, "%d", *(int *)valbuf);
		break;

	case CTLTYPE_STRING:
		if (0 < vallen && valbuf[vallen - 1] == '\0')
			--vallen;
		khttpd_mbuf_put_json_string(output, valbuf, valbuf + vallen);
		break;

	case CTLTYPE_S64:
		khttpd_mbuf_printf(output, "%jd",
		    (intmax_t)*(int64_t *)valbuf);
		break;

	case CTLTYPE_UINT:
		khttpd_mbuf_printf(output, "%u", *(u_int *)valbuf);
		break;

	case CTLTYPE_LONG:
		khttpd_mbuf_printf(output, "%ld", *(long *)valbuf);
		break;

	case CTLTYPE_ULONG:
		khttpd_mbuf_printf(output, "%lu", *(u_long *)valbuf);
		break;

	case CTLTYPE_U64:
		khttpd_mbuf_printf(output, "%ju",
		    (uintmax_t)*(uint64_t *)valbuf);
		break;

	default:
		khttpd_mbuf_printf(output, "\"");
		khttpd_mbuf_base64_encode(output, valbuf, vallen);
		khttpd_mbuf_printf(output, "\"");
	}

out:
	khttpd_free(valbuf);

	return (error);
}

static void
khttpd_sysctl_get_index(struct khttpd_request *request)
{
	int cur_oid[CTL_MAXNAME], next_oid[CTL_MAXNAME + 2];
	char *strbuf;
	struct mbuf *body, *itembuf;
	struct khttpd_response *response;
	struct thread *td;
	size_t cur_oidlen, next_oidlen, strbuflen;
	u_int kind;
	int error, i, flag_count, item_count, pos, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	td = curthread;
	strbuf = NULL;
	body = m_gethdr(M_WAITOK, MT_DATA);
	response = NULL;

	khttpd_mbuf_printf(body, "{\n\"flags\":[");
	flag_count = 0;
	for (i = 0; i < khttpd_sysctl_flags_count; ++i) {
		khttpd_mbuf_printf(body, "%s\"%s\"",
		    0 < flag_count ? "," : "",
		    khttpd_sysctl_flags[i].field_name);
		++flag_count;
	}
	khttpd_mbuf_printf(body, "]");

	khttpd_mbuf_printf(body, ",\n\"items\":[");
	itembuf = NULL;
	item_count = FALSE;
	cur_oid[0] = 1;
	cur_oidlen = sizeof(int);
	next_oidlen = 0;
	for (;;) {
		/* Find the next entry of the entry named by cur_oid. */
		next_oid[0] = 0; /* sysctl internal magic */
		next_oid[1] = 2; /* next */
		bcopy(cur_oid, next_oid + 2, cur_oidlen);
		next_oidlen = CTL_MAXNAME * sizeof(int);
		error = kernel_sysctl(td, next_oid,
		    cur_oidlen / sizeof(int) + 2,
		    next_oid + 2, &next_oidlen, NULL, 0, &next_oidlen, 0);
		if (error != 0)
			break;

		itembuf = m_get(M_WAITOK, MT_DATA);

		khttpd_mbuf_printf(itembuf, "%s{",
		    0 < item_count ? ",\n" : "\n", KHTTPD_SYSCTL_PREFIX);

		/* Print { "href":"/sys/sysctl/1.1" */
		khttpd_mbuf_printf(itembuf, "\"href\":\"%s/",
		    KHTTPD_SYSCTL_PREFIX);
		for (i = 0; i < next_oidlen / sizeof(int); ++i)
			khttpd_mbuf_printf(itembuf, i == 0 ? "%x": ".%x",
			    next_oid[i + 2]);
		khttpd_mbuf_printf(itembuf, "\"");

		/* Get the name of the next entry. */
		next_oid[1] = 1; /* name */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0,
		    &strbuflen, 0);
		if (error != 0)
			goto again;
		strbuf = khttpd_realloc(strbuf, strbuflen);
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, strbuf, &strbuflen, NULL,
		    0, NULL, 0);
		if (error != 0)
			goto again;

		/* Print ,"name":"kern.ostype", */
		khttpd_mbuf_printf(itembuf, ",\n\"name\":\"%s\"", strbuf);

		/* Get the kind and the format of the next entry. */
		next_oid[1] = 4; /* oidfmt */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0,
		    &strbuflen, 0);
		if (error != 0)
			goto again;
		strbuf = khttpd_realloc(strbuf, strbuflen);
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, strbuf, &strbuflen, NULL,
		    0, NULL, 0);
		if (error != 0)
			goto again;

		kind = *(u_int *)strbuf;

		khttpd_mbuf_printf(itembuf, ",\n\"flags\":[");
		flag_count = 0;
		for (i = 0; i < khttpd_sysctl_flags_count; ++i) {
			if ((kind & khttpd_sysctl_flags[i].flag) == 0)
				continue;
			khttpd_mbuf_printf(itembuf, "%s\"%s\"",
			    0 < flag_count ? ", " : "",
			    khttpd_sysctl_flags[i].field_name);
			++flag_count;
		}
		khttpd_mbuf_printf(itembuf, "]");

		if ((kind & CTLFLAG_SECURE) != 0) {
			khttpd_mbuf_printf(itembuf, ",\n\"securelevel\":%d",
			    (kind & CTLMASK_SECURE) >> CTLSHIFT_SECURE);
		}

		type = kind & CTLTYPE;
		if (type < khttpd_sysctl_types_end) {
			khttpd_mbuf_printf(itembuf, ",\n\"type\":\"%s\"",
			    khttpd_sysctl_types[type - 1]);
		}

		khttpd_mbuf_printf(itembuf, ",\n\"format\":\"%s\"",
		    strbuf + sizeof(kind));

		/* Get the description of the next entry. */
		next_oid[1] = 5; /* oiddescr */
		error = kernel_sysctl(td, next_oid,
		    next_oidlen / sizeof(int) + 2, NULL, 0, NULL, 0,
		    &strbuflen, 0);
		if (error == 0) {
			strbuf = khttpd_realloc(strbuf, strbuflen);
			error = kernel_sysctl(td, next_oid,
			    next_oidlen / sizeof(int) + 2, strbuf, &strbuflen,
			    NULL, 0, NULL, 0);
			if (error == 0) {
				/* Print ,"description":"hogehoge" */
				khttpd_mbuf_printf(itembuf,
				    ",\n\"description\":");
				khttpd_mbuf_put_json_string(itembuf,
				    strbuf, strbuf + strbuflen - 1);
			}
		}

		/* Get the value of the next entry */
		if (type != CTLTYPE_NODE && type != CTLTYPE_OPAQUE) {
			pos = m_length(itembuf, NULL);
			khttpd_mbuf_printf(itembuf, ",\n\"value\":");
			error = khttpd_sysctl_value_in_json(itembuf,
			    next_oid + 2, next_oidlen / sizeof(int), kind);
			if (error != 0)
				m_adj(itembuf,
				    pos - (int)m_length(itembuf, NULL));
		}

		khttpd_mbuf_printf(itembuf, "}");

		m_cat(body, itembuf);
		++item_count;
		itembuf = NULL;

		bcopy(next_oid + 2, cur_oid, next_oidlen);
		cur_oidlen = next_oidlen;

again:
		m_freem(itembuf);
		itembuf = NULL;
	}

	if (0 < item_count)
		khttpd_mbuf_printf(body, "\n");
	khttpd_mbuf_printf(body, "]\n}");

	m_fixhdr(body);

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);
	khttpd_response_set_body_mbuf(response, body);
	khttpd_response_add_field(response, "Content-Type", "%s",
	    "application/json");
	khttpd_request_set_response(request, response);

	m_freem(itembuf);
	khttpd_free(strbuf);
}

static struct mbuf *
khttpd_sysctl_entry_to_json(struct khttpd_request *request, int *oid,
    int oidlen, int *error_out)
{
	int tmpoid[CTL_MAXNAME + 2];
	struct thread *td;
	struct mbuf *result;
	char *valbuf;
	size_t vallen;
	u_int kind;
	int error, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	td = curthread;
	result = m_get(M_WAITOK, MT_DATA);
	valbuf = NULL;

	tmpoid[0] = 0;		/* sysctl internal magic */
	tmpoid[1] = 4;		/* oidfmt */
	bcopy(oid, tmpoid + 2, oidlen * sizeof(oid[0]));
	error = kernel_sysctl(td, tmpoid, oidlen + 2, NULL, 0, NULL, 0,
	    &vallen, 0);
	if (error != 0)
		goto out;

	valbuf = khttpd_malloc(vallen);
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	if (error != 0)
		goto out;
	bcopy(valbuf, &kind, sizeof(kind));
	type = kind & CTLTYPE;
	khttpd_free(valbuf);
	valbuf = NULL;

	if (type == CTLTYPE_NODE)
		error = ENOENT;
	else
		error = khttpd_sysctl_value_in_json(result, oid, oidlen,
		    kind);

out:
	khttpd_free(valbuf);

	if (error != 0) {
		m_freem(result);
		result = NULL;
	}

	*error_out = error;

	return (result);
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
			return (i + 1);
	}

	return (-1);
}

static void
khttpd_sysctl_get_leaf(struct khttpd_request *request)
{
	int oid[CTL_MAXNAME];
	struct mbuf *body;
	struct khttpd_response *response;
	const char *name;
	size_t oidlen;
	int error;

	name = khttpd_request_suffix(request) + 1;
	oidlen = khttpd_sysctl_parse_oid(name, oid);
	if (oidlen == -1) {
		khttpd_set_not_found_response(request, FALSE);
		return;
	}

	body = khttpd_sysctl_entry_to_json(request, oid, oidlen, &error);
	if (body == NULL) {
		if (error == ENOENT)
			khttpd_set_not_found_response(request, FALSE);
		else
			khttpd_set_internal_error_response(request);
		return;
	}

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);
	khttpd_response_set_body_mbuf(response, body);
	khttpd_response_add_field(response, "Content-Type", "%s",
	    "application/json");
	khttpd_request_set_response(request, response);
}

static void
khttpd_sysctl_get(struct khttpd_request *request)
{
	const char *suffix;

	suffix = khttpd_request_suffix(request);
	if (suffix[0] == '\0' || strcmp(suffix, "/") == 0)
		khttpd_sysctl_get_index(request);
	else
		khttpd_sysctl_get_leaf(request);
}

static void
khttpd_sysctl_put_leaf_request_dtor(struct khttpd_request *request,
    void *data)
{
	struct khttpd_sysctl_put_leaf_request *auxdata;

	auxdata = data;
	m_freem(auxdata->head);
	khttpd_free(auxdata);
}

static void
khttpd_sysctl_put_leaf_end(struct khttpd_request *request)
{
	struct khttpd_mbuf_pos iter;
	struct khttpd_sysctl_put_leaf_request *auxdata;
	struct khttpd_response	*response;
	struct khttpd_json *value, *noval;
	struct thread *td;
	const char *name;
	char *valbuf;
	size_t vallen;
	int64_t jival;
	long lval;
	u_int kind;
	int error, ival;

	auxdata = khttpd_request_data(request);

	name = khttpd_request_suffix(request) + 1;
	td = curthread;
	kind = auxdata->kind;
	value = NULL;

	khttpd_mbuf_pos_init(&iter, auxdata->head, 0);
	if ((kind & CTLTYPE) == CTLTYPE_OPAQUE) {
		error = khttpd_mbuf_base64_decode(&iter, (void **)&valbuf,
		    &vallen);
		if (error != 0)
			goto out;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, valbuf, vallen, NULL, 0);
		khttpd_free(valbuf);
		goto out;
	}

	error = khttpd_json_parse(&iter, &value, 
	    KHTTPD_SYSCTL_JSON_DEPTH_MAX);
	if (error != 0)
		goto out;

	error = khttpd_json_parse(&iter, &noval, 1);
	if (error != 0 || noval != NULL) {
		error = EINVAL;
		goto out;
	}

	switch (kind & CTLTYPE) {

	case CTLTYPE_INT:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		if (jival < INT_MIN || INT_MAX < jival) {
			error = EINVAL;
			break;
		}
		ival = jival;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &ival, sizeof(ival), NULL, 0);
		break;

	case CTLTYPE_STRING:
		if (khttpd_json_type(value) != KHTTPD_JSON_STRING) {
			error = EINVAL;
			break;
		}
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, (void *)khttpd_json_string_data(value),
		    khttpd_json_string_size(value), NULL, 0);
		break;

	case CTLTYPE_S64:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &jival, sizeof(jival), NULL, 0);
		break;

	case CTLTYPE_UINT:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		if (jival < 0 || UINT_MAX < jival) {
			error = EINVAL;
			break;
		}
		ival = jival;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &ival, sizeof(ival), NULL, 0);
		break;

	case CTLTYPE_LONG:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		if (jival < LONG_MIN || LONG_MAX < jival) {
			error = EINVAL;
			break;
		}
		lval = jival;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &lval, sizeof(lval), NULL, 0);
		break;

	case CTLTYPE_ULONG:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		if (jival < 0 || ULONG_MAX < jival) {
			error = EINVAL;
			break;
		}
		lval = jival;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &lval, sizeof(lval), NULL, 0);
		break;

	case CTLTYPE_U64:
		if (khttpd_json_type(value) != KHTTPD_JSON_INTEGER) {
			error = EINVAL;
			break;
		}
		jival = khttpd_json_integer_value(value);
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &jival, sizeof(jival), NULL, 0);
		break;

	default:
		error = EINVAL;
	}

out:
	switch (error) {

	case 0:
		response = khttpd_response_alloc();
		khttpd_response_set_status(response, 204);
		khttpd_request_set_response(request, response);
		break;

	case EINVAL:
	case ELOOP:
	case ENOMSG:
	case EOVERFLOW:
		khttpd_set_conflict_response(request, FALSE);
		break;

	case ENOENT:
		khttpd_set_not_found_response(request, FALSE);
		break;

	default:
		khttpd_set_internal_error_response(request);
	}

	khttpd_json_free(value);
}

static void
khttpd_sysctl_put_leaf_received_body(struct khttpd_request *request,
    struct mbuf *m)
{
	struct khttpd_sysctl_put_leaf_request *auxdata;
	int len;

	auxdata = khttpd_request_data(request);

	len = m_length(m, NULL);

	if (auxdata->limit < len) {
		khttpd_set_payload_too_large_response(request);
		return;
	}

	auxdata->limit -= len;
	m_cat(auxdata->tail, m);
	m_length(auxdata->tail, &auxdata->tail);
}

static void
khttpd_sysctl_put_leaf(struct khttpd_request *request)
{
	int oid[CTL_MAXNAME + 2];
	struct khttpd_sysctl_put_leaf_request *auxdata;
	struct thread *td;
	const char *suffix;
	char *valbuf;
	size_t vallen;
	int error;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) ==
	    sizeof(auxdata->kind));

#if 0
	/* 
	 * Content-Length is required.  The PUT method for sysctl leafs
	 * doesn't support chunked encoding.
	 */
	if (!request->has_content_length) {
		khttpd_set_length_required_response(request);
		return;
	}
#endif

	td = curthread;
	valbuf = NULL;
	auxdata = khttpd_malloc(sizeof(*auxdata));

	suffix = khttpd_request_suffix(request);
	auxdata->oidlen = khttpd_sysctl_parse_oid(suffix + 1, auxdata->oid);
	if (auxdata->oidlen == -1) {
		error = ENOENT;
		goto out;
	}

	oid[0] = 0;		/* sysctl internal magic */
	oid[1] = 4;		/* oidfmt */
	bcopy(auxdata->oid, oid + 2,
	    auxdata->oidlen * sizeof(auxdata->oid[0]));
	error = kernel_sysctl(td, oid, auxdata->oidlen + 2,
	    NULL, 0, NULL, 0, &vallen, 0);
	if (error == ENOENT)
		goto out;

	valbuf = khttpd_malloc(vallen);
	error = kernel_sysctl(td, oid, auxdata->oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	if (error != 0)
		goto out;
	bcopy(valbuf, &auxdata->kind, sizeof(auxdata->kind));

	if ((auxdata->kind & CTLFLAG_WR) == 0) {
		error = EPERM;
		goto out;
	}

	auxdata->head = auxdata->tail = m_get(M_WAITOK, MT_DATA);
	auxdata->limit = KHTTPD_SYSCTL_PUT_MAX;

	khttpd_request_set_body_proc(request,
	    khttpd_sysctl_put_leaf_received_body, khttpd_sysctl_put_leaf_end);
	khttpd_request_set_data(request, auxdata,
	    khttpd_sysctl_put_leaf_request_dtor);
	auxdata = NULL;

out:
	khttpd_free(valbuf);
	khttpd_free(auxdata);

	switch (error) {

	case 0:
		break;

	case ENOENT:
		khttpd_set_not_found_response(request, FALSE);
		break;

	case EPERM:
		khttpd_set_method_not_allowed_response(request, FALSE,
		    "OPTIONS, HEAD, GET");
		break;

	default:
		khttpd_set_internal_error_response(request);
	}
}

static void
khttpd_sysctl_put(struct khttpd_request *request)
{
	const char *suffix;

	suffix = khttpd_request_suffix(request);
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		khttpd_set_method_not_allowed_response(request, FALSE,
		    "OPTIONS, HEAD, GET");
	else
		khttpd_sysctl_put_leaf(request);
}

static void
khttpd_sysctl_options(struct khttpd_request *request)
{
	int oid[CTL_MAXNAME];
	struct thread *td;
	const char *suffix;
	char *buf;
	size_t buflen, oidlen;
	u_int kind;
	int error;
	boolean_t writeable;

	td = curthread;
	writeable = FALSE;

	suffix = khttpd_request_suffix(request);
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		/* target is "/sys/sysctl/" */
		writeable = FALSE;

	else {
		/* the target is "/sys/sysctl/<oid>" */
		oidlen = khttpd_sysctl_parse_oid(suffix + 1, oid + 2);
		if (oidlen == -1) {
			khttpd_set_not_found_response(request, FALSE);
			return;
		}

		oid[0] = 0;	/* sysctl internal magic */
		oid[1] = 4;	/* oidfmt */
		error = kernel_sysctl(td, oid, oidlen + 2,
		    NULL, 0, NULL, 0, &buflen, 0);
		if (error == ENOENT) {
			khttpd_set_not_found_response(request, FALSE);
			return;
		}

		buf = khttpd_malloc(buflen);
		error = kernel_sysctl(td, oid, oidlen + 2,
		    buf, &buflen, NULL, 0, NULL, 0);
		bcopy(buf, &kind, sizeof(kind));
		khttpd_free(buf);
		if (error != 0) {
			khttpd_set_internal_error_response(request);
			return;
		}

		writeable = (kind & CTLFLAG_WR) != 0;
	}

	khttpd_set_options_response(request, NULL, 
	    writeable ? "OPTIONS, HEAD, GET, PUT" : "OPTIONS, HEAD, GET");
}

int
khttpd_sysctl_route(struct khttpd_server *server)
{

	return (khttpd_router_add(khttpd_server_router(server),
		KHTTPD_SYSCTL_PREFIX, &khttpd_route_ops_sysctl));
}
