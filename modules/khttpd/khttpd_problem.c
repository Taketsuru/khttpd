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

#include "khttpd_problem.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/hash.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>

#include <netinet/in.h>

#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_mbuf.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_strtab.h"

#ifndef KHTTPD_PROBLEM_URL
#define KHTTPD_PROBLEM_URL	"http://example.com/khttpd/problems"
#endif

struct khttpd_problem_known_code {
	SLIST_ENTRY(khttpd_problem_known_code) link;
	int		status;
	const char	*title;
};

SLIST_HEAD(khttpd_problem_known_code_slist, khttpd_problem_known_code);

static struct khttpd_problem_known_code khttpd_problem_known_codes[] = {
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

#define KHTTPD_PROBLEM_CODE_HASH_TABLE_SIZE \
	(KHTTPD_STRTAB_POW2_CEIL(nitems(khttpd_problem_known_codes)))

static struct khttpd_problem_known_code_slist 
    khttpd_problem_code_table[KHTTPD_PROBLEM_CODE_HASH_TABLE_SIZE];

static const char *khttpd_problem_severities[] = {
	"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"
};

static struct khttpd_problem_known_code_slist *
khttpd_problem_known_code_slist_head(int code)
{
	uint32_t codebuf, h;

	codebuf = code;
	h = murmur3_32_hash32(&codebuf, 1, 0xdeadbeef) &
	    (KHTTPD_PROBLEM_CODE_HASH_TABLE_SIZE - 1);

	return (khttpd_problem_code_table + h);
}

static void
khttpd_problem_init(void *arg)
{
	struct khttpd_problem_known_code_slist *head;
	struct khttpd_problem_known_code *ptr;
	int i;

	for (i = 0; i < nitems(khttpd_problem_known_codes); ++i) {
		ptr = &khttpd_problem_known_codes[i];
		head = khttpd_problem_known_code_slist_head(ptr->status);
		SLIST_INSERT_HEAD(head, ptr, link);
	}
}

SYSINIT(khttpd_problem_init, SI_SUB_TUNABLES, SI_ORDER_FIRST,
    khttpd_problem_init, NULL);

void
khttpd_problem_property_specifier_to_string(struct sbuf *output,
    struct khttpd_problem_property *prop_spec)
{
	struct khttpd_problem_property *ptr, *top, *next, *prev;

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
		next = ptr->link;
		ptr->link = prev;
		if (prev != NULL && ptr->name[0] != '[')
			sbuf_putc(output, '.');
		sbuf_cat(output, ptr->name);
		ptr = next;
	}
}

#ifdef KHTTPD_KTR_LOGGING

const char *
khttpd_problem_ktr_print_property(struct khttpd_problem_property *prop_spec)
{
	struct khttpd_problem_property *ptr, *top, *next, *prev;
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
khttpd_problem_response_begin(struct khttpd_mbuf_json *output, int status,
    const char *type, const char *title)
{
	struct khttpd_problem_known_code *codep;
	struct khttpd_problem_known_code_slist *head;

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
		khttpd_mbuf_json_property(output, "type");
		khttpd_mbuf_json_format(output, TRUE, "%s/%s",
		    KHTTPD_PROBLEM_URL, type);
	} else if (title == NULL) {
		head = khttpd_problem_known_code_slist_head(status);
		SLIST_FOREACH(codep, head, link)
		    if (codep->status == status) {
			    title = codep->title;
			    break;
		    }
	}

	if (title != NULL) {
		khttpd_mbuf_json_property(output, "title");
		khttpd_mbuf_json_cstr(output, TRUE, title);
	}
	khttpd_mbuf_json_property(output, "status");
	khttpd_mbuf_json_format(output, FALSE, "%d", status);
}

void
khttpd_problem_log_new(struct khttpd_mbuf_json *output, int severity,
    const char *type, const char *title)
{
	const char *label;

	KHTTPD_ENTRY("%s(%p,%d,%s,%s)", __func__, output, severity,
	    type == NULL ? "<null>" : type, title == NULL ? "<null>" : title);
#ifdef KHTTPD_TRACE_BRANCH
	struct stack st;
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, 16, 0);
#endif

	label = khttpd_problem_get_severity_label(severity);

	khttpd_mbuf_json_new(output);
	khttpd_mbuf_json_object_begin(output);
	khttpd_mbuf_json_property(output, "type");
	khttpd_mbuf_json_format(output, TRUE, "%s/%s", KHTTPD_PROBLEM_URL,
	    type != NULL ? type : label);
	khttpd_mbuf_json_property(output, "title");
	khttpd_mbuf_json_cstr(output, TRUE, title != NULL ? title :
	    type != NULL ? type : label);
	khttpd_mbuf_json_property(output, "severity");
	khttpd_mbuf_json_cstr(output, TRUE, label);
}

void
khttpd_problem_set_property(struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *prop_spec)
{
	char buf[32];
	struct sbuf sbuf;

	if (prop_spec == NULL)
		return;

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_problem_property_specifier_to_string(&sbuf, prop_spec);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_property(output, "property");
	khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void
khttpd_problem_set_detail(struct khttpd_mbuf_json *output,
    const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	khttpd_mbuf_json_property(output, "detail");
	khttpd_mbuf_json_vformat(output, TRUE, fmt, args);
	va_end(args);
}

void khttpd_problem_set_errno(struct khttpd_mbuf_json *output,
    int error)
{
	if (error == 0)
		return;

	khttpd_mbuf_json_property(output, "errno");
	khttpd_mbuf_json_format(output, FALSE, "%d", error);
}

void
khttpd_problem_no_value_response_begin(struct khttpd_mbuf_json *output)
{

	khttpd_problem_response_begin(output, KHTTPD_STATUS_BAD_REQUEST,
	    "no_value", "no value");
}

void
khttpd_problem_wrong_type_response_begin(struct khttpd_mbuf_json *output)
{

	khttpd_problem_response_begin(output, KHTTPD_STATUS_BAD_REQUEST,
	    "wrong_type", "wrong type");
}

void
khttpd_problem_invalid_value_response_begin(struct khttpd_mbuf_json *output)
{

	khttpd_problem_response_begin(output, KHTTPD_STATUS_BAD_REQUEST,
	    "invalid_value", "invalid value");
}

const char *
khttpd_problem_get_severity_label(int severity)
{

	KASSERT(LOG_EMERG <= severity && severity <= LOG_DEBUG,
	    ("unknown severity: %d", severity));

	return (khttpd_problem_severities[severity]);
}

void
khttpd_problem_internal_error_log_new(struct khttpd_mbuf_json *output)
{

	khttpd_problem_log_new(output, LOG_ERR, "internal_error",
	    "internal error");
}
