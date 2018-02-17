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

#include "khttpd_mbuf.h"

#include <sys/limits.h>
#include <sys/ctype.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>

#include "khttpd.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_string.h"

static const char khttpd_mbuf_null_literal[] = "null";
static const char khttpd_mbuf_true_literal[] = "true";
static const char khttpd_mbuf_false_literal[] = "false";
static const char khttpd_mbuf_colon[] = ": ";
static const char khttpd_mbuf_comma[] = ", ";

static struct mbuf *khttpd_mbuf_escape(struct mbuf *, const char *,
    const char *);

struct mbuf *
khttpd_mbuf_append_ch(struct mbuf *dst, char ch)
{
	struct mbuf *ptr;

	ptr = m_last(dst);
	if (M_TRAILINGSPACE(ptr) == 0) {
		ptr = ptr->m_next = m_get(M_WAITOK, MT_DATA);
	}
	mtod(ptr, char *)[ptr->m_len++] = ch;

	return (ptr);
}

struct mbuf *
khttpd_mbuf_append(struct mbuf *dst, const char *begin, const char *end)
{
	const char *cp;
	struct mbuf *ptr;
	size_t space, len;

	ptr = m_last(dst);
	cp = begin;

	if (0 < (space = M_TRAILINGSPACE(ptr))) {
		len = MIN(end - cp, space);
		bcopy(cp, mtod(ptr, char *) + ptr->m_len, len);
		ptr->m_len += len;
		cp += len;
	}

	if (end <= cp) {
		return (ptr);
	}

	for (ptr = ptr->m_next = m_getm2(NULL, end - cp, M_WAITOK, MT_DATA, 0);
	     ptr != NULL; ptr = ptr->m_next) {
		len = MIN(end - cp, M_TRAILINGSPACE(ptr));
		bcopy(cp, mtod(ptr, void *), len);
		ptr->m_len = len;
		cp += len;
	}

	return (ptr);
}

static void
khttpd_mbuf_vprintf_free(struct mbuf *buf, void *arg1, void *arg2)
{

	khttpd_free(mtod(buf, char *) - sizeof(u_int));
}

int
khttpd_mbuf_vprintf(struct mbuf *dst, const char *fmt, va_list vl)
{
	char *extbuf;
	struct mbuf *buf;
	va_list vlcopy;
	int req, buflen;

	va_copy(vlcopy, vl);

	buf = m_last(dst);
	buflen = M_TRAILINGSPACE(buf);
	req = vsnprintf(mtod(buf, char *) + buf->m_len, buflen, fmt, vl);
	if (buflen < req + 1) {
		if (req < MCLBYTES) {
			buf = buf->m_next =
			    m_getm2(NULL, req + 1, M_WAITOK, MT_DATA, 0);

		} else {
			buf = buf->m_next = m_get(M_WAITOK, MT_DATA);
			extbuf = khttpd_malloc(sizeof(u_int) + req + 1);
			buf->m_ext.ext_cnt = (u_int *)extbuf;
			*buf->m_ext.ext_cnt = 1;
			MEXTADD(buf, extbuf + sizeof(u_int), req + 1,
			    khttpd_mbuf_vprintf_free, NULL, NULL, 0,
			    EXT_EXTREF);
		}

		req = vsnprintf(mtod(buf, char *), M_TRAILINGSPACE(buf), fmt,
		    vlcopy);
	}

	buf->m_len += req;
	va_end(vlcopy);

	return (req);
}

int
khttpd_mbuf_printf(struct mbuf *dst, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = khttpd_mbuf_vprintf(dst, fmt, vl);
	va_end(vl);

	return (result);
}

static struct mbuf *
khttpd_mbuf_escape(struct mbuf *dst, const char *begin, const char *end)
{
	struct mbuf *tail;
	const char *srcp;
	char *dstp, *dend;
	int32_t code;
	int flc, i, len;
	uint16_t code1, code2;
	unsigned char ch;

	srcp = begin;
	tail = dst;
	dstp = mtod(tail, char *) + tail->m_len;
	dend = M_START(tail) + M_SIZE(tail);

	while (srcp < end) {
		ch = (unsigned char)*srcp;
		switch (ch) {

		case '\b':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'b';
			++srcp;
			break;

		case '\f':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'f';
			++srcp;
			break;

		case '\n':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'n';
			++srcp;
			break;

		case '\r':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'r';
			++srcp;
			break;

		case '\t':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 't';
			++srcp;
			break;

		case '\"':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = '\"';
			++srcp;
			break;

		case '\\':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = '\\';
			++srcp;
			break;

		default:
			if (ch < 0x80) {
				code = ch;
				len = 1;

			} else {
				flc = fls(~ch & 0xff);
				code = ch & (0xff >> (CHAR_BIT + 1 - flc));
				len = CHAR_BIT - flc;

				/*
				 * Write as is if we found a multibyte
				 * sequence starts with 10xxxxxx, a premature
				 * end of string, or a sequence longer than 4
				 * bytes.
				 */
				if (len == 1 || end - srcp < len || 4 < len)
					code = ch;

				for (i = 1; i < len; ++i)
					code = (code << 6) |
					    (srcp[i] & 0x3f);

				/*
				 * Write as is if the code point is not
				 * representable with utf-16, or in the range
				 * reserved for surrogate pairs.
				 */
				if (0x110000 <= code ||
				    (0xd800 <= code && code < 0xe000))
					code = ch;
			}

			if (0x20 <= code && code < 0x80) {
				if (dend - dstp < 1)
					goto expand;
				*dstp++ = code;

			} else if (code < 0x10000) {
				if (dend - dstp < 7)
					goto expand;
				snprintf(dstp, 7, "\\u%04x", code);
				dstp += 6;

			} else {
				if (dend - dstp < 13)
					goto expand;
				code1 = ((code - 0x10000) >> 10) + 0xd800;
				code2 = ((code - 0x10000) & 0x3ff) + 0xdc00;
				snprintf(dstp, 13, "\\u%04x\\u%04x", code1,
				    code2);
				dstp += 12;
			}

			srcp += len;
		}
		continue;

expand:
		tail->m_len = dstp - mtod(tail, char *);
		tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
		dstp = mtod(tail, char *);
		dend = M_START(tail) + M_SIZE(tail);
	}

	tail->m_len = dstp - mtod(tail, char *);

	return (tail);
}

static struct mbuf *
khttpd_mbuf_escape_mbuf(struct mbuf *dst, struct mbuf *source)
{
	struct mbuf *tail;
	struct mbuf *srcp;
	const char *begin, *end;
	
	tail = dst;
	for (srcp = source; srcp != NULL; srcp = srcp->m_next) {
		begin = mtod(srcp, char *);
		end = begin + srcp->m_len;
		tail = khttpd_mbuf_escape(tail, begin, end);
	}
	return (tail);
}

static void
khttpd_mbuf_json_begin_element(struct khttpd_mbuf_json *dst)
{
	if (dst->is_first)
		dst->is_first = false;
	else if (dst->is_property_value)
		dst->is_property_value = false;
	else
		khttpd_mbuf_append(dst->mbuf, khttpd_mbuf_comma,
		    khttpd_mbuf_comma + sizeof(khttpd_mbuf_comma) - 1);
}

void
khttpd_mbuf_json_new(struct khttpd_mbuf_json *dst)
{

	dst->mbuf = m_get(M_WAITOK, MT_DATA);
	dst->is_first = true;
	dst->is_property_value = false;
}

struct mbuf *
khttpd_mbuf_json_data(struct khttpd_mbuf_json *dst)
{

	return (dst->mbuf);
}

struct mbuf *
khttpd_mbuf_json_move(struct khttpd_mbuf_json *dst)
{
	struct mbuf *m;

	m = dst->mbuf;
	dst->mbuf = NULL;
	dst->is_first = true;
	dst->is_property_value = false;

	return (m);
}

void
khttpd_mbuf_json_delete(struct khttpd_mbuf_json *dst)
{

	m_freem(dst->mbuf);
	dst->mbuf = NULL;
}

void
khttpd_mbuf_json_null(struct khttpd_mbuf_json *dst)
{

	khttpd_mbuf_json_begin_element(dst);
	khttpd_mbuf_append(dst->mbuf, khttpd_mbuf_null_literal,
	    khttpd_mbuf_null_literal + sizeof(khttpd_mbuf_null_literal) - 1);
}

void
khttpd_mbuf_json_boolean(struct khttpd_mbuf_json *dst, bool value)
{

	khttpd_mbuf_json_begin_element(dst);
	if (value)
		khttpd_mbuf_append(dst->mbuf, khttpd_mbuf_true_literal,
		    khttpd_mbuf_true_literal +
		    sizeof(khttpd_mbuf_true_literal) - 1);
	else
		khttpd_mbuf_append(dst->mbuf, khttpd_mbuf_false_literal,
		    khttpd_mbuf_false_literal +
		    sizeof(khttpd_mbuf_false_literal) - 1);
}

void
khttpd_mbuf_json_cstr(struct khttpd_mbuf_json *dst, bool is_string,
    const char *value)
{
	struct mbuf *tail;

	khttpd_mbuf_json_begin_element(dst);

	if (value == NULL) {
		value = "null";
		is_string = false;
	}

	if (is_string) {
		tail = khttpd_mbuf_append_ch(dst->mbuf, '"');
		tail = khttpd_mbuf_escape(tail, value, value + strlen(value));
		khttpd_mbuf_append_ch(tail, '"');
	} else
		khttpd_mbuf_append(dst->mbuf, value, value + strlen(value));
}

void
khttpd_mbuf_json_bytes(struct khttpd_mbuf_json *dst, bool is_string,
    const char *begin, const char *end)
{
	struct mbuf *tail;

	khttpd_mbuf_json_begin_element(dst);

	if (is_string) {
		tail = khttpd_mbuf_append_ch(dst->mbuf, '"');
		tail = khttpd_mbuf_escape(tail, begin, end);
		khttpd_mbuf_append_ch(tail, '"');
	} else
		khttpd_mbuf_append(dst->mbuf, begin, end);
}

void
khttpd_mbuf_json_mbuf(struct khttpd_mbuf_json *dst, bool is_string,
    struct mbuf *m)
{
	struct mbuf *tail;

	khttpd_mbuf_json_begin_element(dst);
	if (is_string) {
		tail = khttpd_mbuf_append_ch(dst->mbuf, '\"');
		tail = khttpd_mbuf_escape_mbuf(tail, m);
		khttpd_mbuf_append_ch(tail, '\"');
	} else
		m_cat(dst->mbuf, m_copym(m, 0, M_COPYALL, M_WAITOK));
}

void
khttpd_mbuf_json_format(struct khttpd_mbuf_json *dst, bool is_string,
    const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	khttpd_mbuf_json_vformat(dst, is_string, fmt, args);
	va_end(args);
}

void
khttpd_mbuf_json_vformat(struct khttpd_mbuf_json *dst, bool is_string,
    const char *fmt, va_list args)
{
	struct sbuf sbuf;

	sbuf_new(&sbuf, NULL, 256, SBUF_AUTOEXTEND);
	sbuf_vprintf(&sbuf, fmt, args);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_cstr(dst, is_string, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void
khttpd_mbuf_json_object_begin(struct khttpd_mbuf_json *dst)
{

	khttpd_mbuf_json_begin_element(dst);
	khttpd_mbuf_append_ch(dst->mbuf, '{');
	dst->is_first = true;
}

void
khttpd_mbuf_json_object_end(struct khttpd_mbuf_json *dst)
{

	khttpd_mbuf_append_ch(dst->mbuf, '}');
	dst->is_first = false;
}

void
khttpd_mbuf_json_array_begin(struct khttpd_mbuf_json *dst)
{

	khttpd_mbuf_json_begin_element(dst);
	khttpd_mbuf_append_ch(dst->mbuf, '[');
	dst->is_first = true;
}

void
khttpd_mbuf_json_array_end(struct khttpd_mbuf_json *dst)
{
	khttpd_mbuf_append_ch(dst->mbuf, ']');
	dst->is_first = false;
}

void
khttpd_mbuf_json_property(struct khttpd_mbuf_json *dst, const char *name)
{

	KASSERT(!dst->is_property_value,
	    ("the previous property name isn't followed by a value"));

	khttpd_mbuf_json_cstr(dst, true, name);
	khttpd_mbuf_append(dst->mbuf, khttpd_mbuf_colon, khttpd_mbuf_colon +
	    sizeof(khttpd_mbuf_colon) - 1);
	dst->is_property_value = true;
}

void
khttpd_mbuf_json_now(struct khttpd_mbuf_json *entry)
{
	struct timeval tv;

	microtime(&tv);
	khttpd_mbuf_json_format(entry, false, "%ld.%06ld",
	    tv.tv_sec, tv.tv_usec);
}

void 
khttpd_mbuf_json_sockaddr(struct khttpd_mbuf_json *dst,
    const struct sockaddr *sockaddr)
{
	char buf[64];
	struct sockaddr_in *addr_in;
	struct sockaddr_in6 *addr_in6;
	struct sockaddr_un *addr_un;
	socklen_t len;
	struct sbuf sbuf;
	in_addr_t ip_addr;
	in_port_t port;

	if (sockaddr->sa_family == AF_UNSPEC) {
		KHTTPD_BRANCH("%s AF_UNSPEC", __func__);
		khttpd_mbuf_json_null(dst);
		return;
	}

	khttpd_mbuf_json_object_begin(dst);

	switch (sockaddr->sa_family) {

	case AF_INET:
		addr_in = (struct sockaddr_in *)sockaddr;
		khttpd_mbuf_json_property(dst, "family");
		khttpd_mbuf_json_cstr(dst, true, "inet");
		ip_addr = ntohl(addr_in->sin_addr.s_addr);
		port = ntohs(addr_in->sin_port);
		if (ip_addr != 0) {
			khttpd_mbuf_json_property(dst, "address");
			khttpd_mbuf_json_format(dst, true, "%d.%d.%d.%d",
			    (ip_addr >> 24) & 0xff, (ip_addr >> 16) & 0xff,
			    (ip_addr >> 8) & 0xff, ip_addr & 0xff);
		}
		khttpd_mbuf_json_property(dst, "port");
		khttpd_mbuf_json_format(dst, false, "%u", port);
		break;

	case AF_INET6:
		addr_in6 = (struct sockaddr_in6 *)sockaddr;
		khttpd_mbuf_json_property(dst, "family");
		khttpd_mbuf_json_cstr(dst, true, "inet6");
		if (addr_in6->sin6_addr.s6_addr32[3] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[2] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[1] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[0] != 0) {
			sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
			khttpd_print_ipv6_address(&sbuf,
			    addr_in6->sin6_addr.s6_addr8);
			sbuf_finish(&sbuf);
			khttpd_mbuf_json_property(dst, "address");
			khttpd_mbuf_json_cstr(dst, true, sbuf_data(&sbuf));
			sbuf_delete(&sbuf);
		}
		port = ntohs(addr_in6->sin6_port);
		khttpd_mbuf_json_property(dst, "port");
		khttpd_mbuf_json_format(dst, false, "%u", port);
		break;

	case AF_UNIX:
		addr_un = (struct sockaddr_un *)sockaddr;
		khttpd_mbuf_json_property(dst, "family");
		khttpd_mbuf_json_cstr(dst, true, "unix");
		len = MIN(sizeof(struct sockaddr_un), addr_un->sun_len);
		if (offsetof(struct sockaddr_un, sun_path) < len
		    && addr_un->sun_path[0] != '\0')
			khttpd_mbuf_json_property(dst, "address");
			khttpd_mbuf_json_format(dst, true, "%.*s", 
			    len - offsetof(struct sockaddr_un, sun_path),
			    addr_un->sun_path);
		break;

	default:
		panic("unsupported address family: %d", sockaddr->sa_family);
	}

	khttpd_mbuf_json_object_end(dst);
}
