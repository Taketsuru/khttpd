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

#include "khttpd_webapi.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/hash.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>

#include <netinet/in.h>

#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_mbuf.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_strtab.h"

#ifndef KHTTPD_WEBAPI_PROBLEM_URL
#define KHTTPD_WEBAPI_PROBLEM_URL	"http://example.com/khttpd/problems"
#endif

struct khttpd_webapi_known_code {
	SLIST_ENTRY(khttpd_webapi_known_code) link;
	int		status;
	const char	*title;
};

SLIST_HEAD(khttpd_webapi_known_code_slist, khttpd_webapi_known_code);

static struct khttpd_webapi_known_code khttpd_webapi_known_codes[] = {
	{
		.status = KHTTPD_STATUS_CONTINUE,
		.title = "Continue"
	},
	{
		.status = KHTTPD_STATUS_SWITCHING_PROTOCOLS,
		.title = "Switching Protocols"
	},
	{
		.status = KHTTPD_STATUS_OK,
		.title = "OK"
	},
	{
		.status = KHTTPD_STATUS_CREATED,
		.title = "Created"
	},
	{
		.status = KHTTPD_STATUS_ACCEPTED,
		.title = "Accepted"
	},
	{
		.status = KHTTPD_STATUS_NON_AUTHORITATIVE_INFORMATION,
		.title = "Non-Authoritative Information"
	},
	{
		.status = KHTTPD_STATUS_NO_CONTENT,
		.title = "No Content"
	},
	{
		.status = KHTTPD_STATUS_RESET_CONTENT,
		.title = "Reset Content"
	},
	{
		.status = KHTTPD_STATUS_PARTIAL_CONTENT,
		.title = "Partial Content"
	},
	{
		.status = KHTTPD_STATUS_MULTIPLE_CHOICES,
		.title = "Multiple Choices"
	},
	{
		.status = KHTTPD_STATUS_MOVED_PERMANENTLY,
		.title = "Moved Permanently"
	},
	{
		.status = KHTTPD_STATUS_FOUND,
		.title = "Found"
	},
	{
		.status = KHTTPD_STATUS_SEE_OTHER,
		.title = "See Other"
	},
	{
		.status = KHTTPD_STATUS_NOT_MODIFIED,
		.title = "Not Modified"
	},
	{
		.status = KHTTPD_STATUS_USE_PROXY,
		.title = "Use Proxy"
	},
	{
		.status = KHTTPD_STATUS_TEMPORARY_REDIRECT,
		.title = "Temporary Redirect"
	},
	{
		.status = KHTTPD_STATUS_BAD_REQUEST,
		.title = "Bad Request"
	},
	{
		.status = KHTTPD_STATUS_UNAUTHORIZED,
		.title = "Unauthorized"
	},
	{
		.status = KHTTPD_STATUS_PAYMENT_REQUIRED,
		.title = "Payment Required"
	},
	{
		.status = KHTTPD_STATUS_FORBIDDEN,
		.title = "Forbidden"
	},
	{
		.status = KHTTPD_STATUS_NOT_FOUND,
		.title = "Not Found"
	},
	{
		.status = KHTTPD_STATUS_METHOD_NOT_ALLOWED,
		.title = "Method Not Allowed"
	},
	{
		.status = KHTTPD_STATUS_NOT_ACCEPTABLE,
		.title = "Not Acceptable"
	},
	{
		.status = KHTTPD_STATUS_PROXY_AUTHENTICATION_REQUIRED,
		.title = "Proxy Authentication Required"
	},
	{
		.status = KHTTPD_STATUS_REQUEST_TIMEOUT,
		.title = "Request Timeout"
	},
	{
		.status = KHTTPD_STATUS_CONFLICT,
		.title = "Conflict"
	},
	{
		.status = KHTTPD_STATUS_GONE,
		.title = "Gone"
	},
	{
		.status = KHTTPD_STATUS_LENGTH_REQUIRED,
		.title = "Length Required"
	},
	{
		.status = KHTTPD_STATUS_PRECONDITION_FAILED,
		.title = "Precondition Failed"
	},
	{
		.status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE,
		.title = "Request Entity Too Large"
	},
	{
		.status = KHTTPD_STATUS_REQUEST_URI_TOO_LONG,
		.title = "Request-URI Too Long"
	},
	{
		.status = KHTTPD_STATUS_UNSUPPORTED_MEDIA_TYPE,
		.title = "Unsupported Media Type"
	},
	{
		.status = KHTTPD_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE,
		.title = "Requested Range Not Satisfiable"
	},
	{
		.status = KHTTPD_STATUS_EXPECTATION_FAILED,
		.title = "Expectation Failed"
	},
	{
		.status = KHTTPD_STATUS_UPGRADE_REQUIRED,
		.title = "Upgrade Required"
	},
	{
		.status = KHTTPD_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE,
		.title = "Request Header Fields Too Large"
	},
	{
		.status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR,
		.title = "Internal Server Error"
	},
	{
		.status = KHTTPD_STATUS_NOT_IMPLEMENTED,
		.title = "Not Implemented"
	},
	{
		.status = KHTTPD_STATUS_BAD_GATEWAY,
		.title = "Bad Gateway"
	},
	{
		.status = KHTTPD_STATUS_SERVICE_UNAVAILABLE,
		.title = "Service Unavailable"
	},
	{
		.status = KHTTPD_STATUS_GATEWAY_TIMEOUT,
		.title = "Gateway Timeout"
	},
	{
		.status = KHTTPD_STATUS_HTTP_VERSION_NOT_SUPPORTED,
		.title = "HTTP Version Not Supported"
	},
};

#define KHTTPD_WEBAPI_CODE_HASH_TABLE_SIZE				\
	(KHTTPD_STRTAB_POW2_CEIL(sizeof(khttpd_webapi_known_codes) /	\
	    sizeof(khttpd_webapi_known_codes[0])))

static struct khttpd_webapi_known_code_slist 
    khttpd_webapi_code_table[KHTTPD_WEBAPI_CODE_HASH_TABLE_SIZE];

static struct khttpd_webapi_known_code_slist *
khttpd_webapi_known_code_slist_head(int code)
{
	uint32_t codebuf, h;

	codebuf = code;
	h = murmur3_32_hash32(&codebuf, 1, 0xdeadbeef) &
	    (KHTTPD_WEBAPI_CODE_HASH_TABLE_SIZE - 1);

	return (khttpd_webapi_code_table + h);
}

static void
khttpd_webapi_init(void *arg)
{
	struct khttpd_webapi_known_code_slist *head;
	struct khttpd_webapi_known_code *ptr;
	int i;

	for (i = 0; i < sizeof(khttpd_webapi_known_codes) /
		 sizeof(khttpd_webapi_known_codes[0]); ++i) {
		ptr = &khttpd_webapi_known_codes[i];
		head = khttpd_webapi_known_code_slist_head(ptr->status);
		SLIST_INSERT_HEAD(head, ptr, link);
	}
}

SYSINIT(khttpd_webapi_init, SI_SUB_TUNABLES, SI_ORDER_FIRST,
    khttpd_webapi_init, NULL);

void
khttpd_webapi_property_specifier_to_string(struct sbuf *output,
    struct khttpd_webapi_property *prop_spec)
{
	struct khttpd_webapi_property *ptr, *top, *next, *prev;

	if (prop_spec == NULL)
		return;

	ptr = top = prop_spec;

	/* reverse the chain */

	prev = NULL;
	while (ptr != NULL) {
		next = ptr->link;
		ptr->link = prev;
		prev = ptr;
		ptr = next;
	}

	/*
	 * Put the name of each prop_spec and reverse the chain simultaneously.
	 */

	ptr = prev;
	prev = NULL;
	while (ptr != NULL) {
		if (prev != NULL) {
			if (ptr->name[0] != '[')
				sbuf_putc(output, '.');
			prev->link = ptr;
		}
		sbuf_cat(output, ptr->name);

		prev = ptr;
		ptr = ptr->link;
	}
	if (prev != NULL)
		prev->link = NULL;
}

#ifdef KHTTPD_KTR_LOGGING

const char *
khttpd_webapi_ktr_print_property(struct khttpd_webapi_property *prop_spec)
{
	struct khttpd_webapi_property *ptr, *top, *next, *prev;
	char *buf, *cp, *end;
	size_t len;
	int bufsiz;

	if (prop_spec == NULL)
		return ("<empty>");

	buf = khttpd_ktr_newbuf(&bufsiz);
	if (buf == NULL)
		return ("<buffer full>");

	ptr = top = prop_spec;

	/* reverse the chain */

	prev = NULL;
	while (ptr != NULL) {
		next = ptr->link;
		ptr->link = prev;
		prev = ptr;
		ptr = next;
	}

	/*
	 * Put the name of each prop_spec and reverse the chain simultaneously.
	 */

	cp = buf;
	end = buf + bufsiz - 1;
	ptr = prev;
	prev = NULL;
	while (ptr != NULL) {
		if (prev != NULL) {
			if (ptr->name[0] != '[' && cp < end)
				*cp++ = '.';
			prev->link = ptr;
		}
		len = MIN(strlen(ptr->name), end - cp);
		bcopy(ptr->name, cp, len);
		cp += len;

		prev = ptr;
		ptr = ptr->link;
	}
	if (prev != NULL)
		prev->link = NULL;

	*cp++ = '\0';

	return (buf);
}

#endif

void
khttpd_webapi_set_problem(struct khttpd_mbuf_json *output, int status,
    const char *type, const char *title)
{
	struct khttpd_webapi_known_code *codep;
	struct khttpd_webapi_known_code_slist *head;

	KHTTPD_ENTRY("%s(%p,%d,%s,%s)", __func__, output, status,
	    type == NULL ? "<null>" : type, title == NULL ? "<null>" : title);
#ifdef KHTTPD_TRACE_BRANCH
	struct stack st;
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 16, 0);
#endif

	khttpd_mbuf_json_delete(output);
	khttpd_mbuf_json_new(output);
	khttpd_mbuf_json_object_begin(output);
	if (type != NULL) {
		khttpd_mbuf_json_property_format(output, "type", TRUE,
		    "%s/%s", KHTTPD_WEBAPI_PROBLEM_URL, type);
	} else if (title == NULL) {
		head = khttpd_webapi_known_code_slist_head(status);
		SLIST_FOREACH(codep, head, link)
		    if (codep->status == status) {
			    title = codep->title;
			    break;
		    }
	}

	if (title != NULL)
		khttpd_mbuf_json_property_format(output, "title", TRUE,
		    "%s", title);
	khttpd_mbuf_json_property_format(output, "status", FALSE, "%d",
	    status);
}

void
khttpd_webapi_set_problem_property(struct khttpd_mbuf_json *output,
    struct khttpd_webapi_property *prop_spec)
{
	char buf[32];
	struct sbuf sbuf;

	if (prop_spec == NULL)
		return;

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_webapi_property_specifier_to_string(&sbuf, prop_spec);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_property_format(output, "property", TRUE,
	    "%s", sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void
khttpd_webapi_set_problem_detail(struct khttpd_mbuf_json *output,
    const char *detail)
{

	khttpd_mbuf_json_property_format(output, "detail", TRUE, "%s", detail);
}

void khttpd_webapi_set_problem_errno(struct khttpd_mbuf_json *output,
    int error)
{
	if (error != 0)
		khttpd_mbuf_json_property_format(output, "errno", FALSE, "%d",
		    error);
}

void
khttpd_webapi_set_no_value_problem(struct khttpd_mbuf_json *output)
{

	khttpd_webapi_set_problem(output, KHTTPD_STATUS_BAD_REQUEST,
	    "no_value", "no value");
}

void
khttpd_webapi_set_wrong_type_problem(struct khttpd_mbuf_json *output)
{

	khttpd_webapi_set_problem(output, KHTTPD_STATUS_BAD_REQUEST,
	    "wrong_type", "wrong type");
}

void
khttpd_webapi_set_invalid_value_problem(struct khttpd_mbuf_json *output)
{

	khttpd_webapi_set_problem(output, KHTTPD_STATUS_BAD_REQUEST,
	    "invalid_value", "invalid value");
}

int
khttpd_webapi_get_string_property(const char **value_out, const char *name,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_webapi_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = NULL;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_webapi_set_no_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_STRING) {
		khttpd_webapi_set_wrong_type_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = khttpd_json_string_data(value_j);

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_integer_property(int64_t *value_out, const char *name,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_webapi_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = 0;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_webapi_set_no_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_INTEGER) {
		khttpd_webapi_set_wrong_type_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = khttpd_json_integer_value(value_j);

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_object_property(struct khttpd_json **value_out,
    const char *name,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_webapi_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = 0;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_webapi_set_no_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_OBJECT) {
		khttpd_webapi_set_wrong_type_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = value_j;

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_sockaddr_properties(struct sockaddr *addr, socklen_t len,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output)
{
	struct khttpd_webapi_property prop_spec;
	struct sockaddr_un *un;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	const char *family, *address;
	in_port_t *port_field;
	size_t alen;
	int64_t port;
	int status;

	status = khttpd_webapi_get_string_property(&family, "family",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_webapi_get_string_property(&address, "address",
	    input_prop_spec, input, output, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	port_field = NULL;

	prop_spec.link = input_prop_spec;
	prop_spec.name = "address";

	if (strcmp(family, "unix") == 0) {
		if (address == NULL) {
			khttpd_webapi_set_no_value_problem(output);
			khttpd_webapi_set_problem_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		if (address[0] != '/') {
			khttpd_webapi_set_invalid_value_problem(output);
			khttpd_webapi_set_problem_detail(output,
			    "absolute path only");
			khttpd_webapi_set_problem_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		un = (struct sockaddr_un *)addr;
		alen = offsetof(struct sockaddr_un, sun_path) + strlen(address)
		    + 1;
		if (len < MIN(sizeof(struct sockaddr_un), alen)) {
			khttpd_webapi_set_invalid_value_problem(output);
			khttpd_webapi_set_problem_property(output, &prop_spec);
			khttpd_webapi_set_problem_detail(output, "too long");
			return (KHTTPD_STATUS_BAD_REQUEST);
		}
		un->sun_len = alen;
		un->sun_family = AF_UNIX;
		strlcpy(un->sun_path, address,
		    len - offsetof(struct sockaddr_un, sun_path));

	} else if (strcmp(family, "inet") == 0) {
		in = (struct sockaddr_in *)addr;
		port_field = &in->sin_port;
		in->sin_len = sizeof(struct sockaddr_in);
		in->sin_family = AF_INET;
		if (address == NULL) {
			in->sin_addr.s_addr = INADDR_ANY;
		} else if (khttpd_parse_ip_addresss(&in->sin_addr.s_addr, 
			address) != 0) {
			khttpd_webapi_set_invalid_value_problem(output);
			khttpd_webapi_set_problem_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

	} else if (strcmp(family, "inet6") == 0) {
		in6 = (struct sockaddr_in6 *)addr;
		port_field = &in6->sin6_port;
		bzero(in6, sizeof(*in6));
		in6->sin6_len = sizeof(struct sockaddr_in6);
		in6->sin6_family = AF_INET6;
		if (address == NULL) {
			in6->sin6_addr = in6addr_any;
		} else if (khttpd_parse_ipv6_address(in6->sin6_addr.s6_addr,
			address) != 0) {
			khttpd_webapi_set_invalid_value_problem(output);
			khttpd_webapi_set_problem_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

	} else {
		prop_spec.name = "family";
		khttpd_webapi_set_invalid_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (port_field != NULL) {
		status = khttpd_webapi_get_integer_property(&port, "port",
		    input_prop_spec, input, output, FALSE);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			return (status);

		if (port < 1 || IPPORT_MAX < port) {
			prop_spec.name = "port";
			khttpd_webapi_set_invalid_value_problem(output);
			khttpd_webapi_set_problem_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		*port_field = htons(port);
	}

	return (KHTTPD_STATUS_OK);
}
