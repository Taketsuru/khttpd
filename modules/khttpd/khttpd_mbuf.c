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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* ----------------------------------------------------- function definitions */

static void
khttpd_mbuf_vprintf_free(struct mbuf *buf, void *arg1, void *arg2)
{
	free(mtod(buf, char *) - sizeof(u_int), M_KHTTPD);
}

void
khttpd_mbuf_vprintf(struct mbuf *output, const char *fmt, va_list vl)
{
	char *extbuf;
	struct mbuf *buf;
	int req, buflen;

	m_length(output, &buf);

	extbuf = NULL;
	buflen = M_TRAILINGSPACE(buf);
	req = vsnprintf(mtod(buf, char *) + buf->m_len, buflen, fmt, vl);
	if (req + 1 <= buflen) {
		buf->m_len += req;
		return;
	}

	if (req + 1 <= MCLBYTES)
		buf = m_getm2(buf, req + 1, M_WAITOK, MT_DATA, 0);
	else {
		buf = buf->m_next = m_get(M_WAITOK, MT_DATA);
		extbuf = malloc(sizeof(u_int) + req + 1, M_KHTTPD, M_WAITOK);
		buf->m_ext.ext_cnt = (u_int *)extbuf;
		MEXTADD(buf, extbuf + sizeof(u_int), req + 1,
		    khttpd_mbuf_vprintf_free, NULL, NULL, 0, EXT_EXTREF);
	}

	vsnprintf(mtod(buf, char *), req + 1, fmt, vl);
}

void
khttpd_mbuf_printf(struct mbuf *output, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	khttpd_mbuf_vprintf(output, fmt, vl);
	va_end(vl);
}

struct mbuf *
khttpd_mbuf_append(struct mbuf *output, const char *begin, const char *end)
{
	struct mbuf *ptr;
	const char *cp;
	size_t space, len;

	m_length(output, &ptr);
	cp = begin;
	while (cp < end && 0 < (space = M_TRAILINGSPACE(ptr))) {
		len = MIN(end - cp, space);
		bcopy(cp, mtod(ptr, char *) + ptr->m_len, len);
		ptr->m_len += len;
		cp += len;
	}

	if (end <= cp)
		return (ptr);

	for (ptr = m_getm2(ptr, end - cp, M_WAITOK, MT_DATA, 0); cp < end;
	     ptr = ptr->m_next) {
		len = MIN(end - cp, M_TRAILINGSPACE(ptr));
		bcopy(cp, mtod(ptr, void *), len);
		ptr->m_len = len;
		cp += len;
	}

	return (ptr);
}

struct mbuf *
khttpd_mbuf_append_ch(struct mbuf *output, char ch)
{
	struct mbuf *ptr;

	m_length(output, &ptr);
	if (M_TRAILINGSPACE(ptr) == 0)
		ptr = ptr->m_next = m_get(M_WAITOK, MT_DATA);
	mtod(ptr, char *)[ptr->m_len++] = ch;

	return (ptr);
}

void
khttpd_mbuf_iter_init(struct khttpd_mbuf_iter *iter, struct mbuf *ptr, int off)
{
	iter->unget = -1;
	iter->ptr = ptr;
	iter->off = off;
}

int
khttpd_mbuf_getc(struct khttpd_mbuf_iter *iter)
{
	int result;

	TRACE("enter");

	if (0 < iter->unget) {
		result = iter->unget;
		iter->unget = -1;
		return (result);
	}

	while (iter->ptr != NULL && iter->ptr->m_len <= iter->off) {
		iter->off = 0;
		iter->ptr = iter->ptr->m_next;
	}

	if (iter->ptr == NULL)
		return (-1);
	
	result = mtod(iter->ptr, unsigned char *)[iter->off];
	++iter->off;

	return (result);
}

void
khttpd_mbuf_ungetc(struct khttpd_mbuf_iter *iter, int ch)
{
	TRACE("enter '%c'", ch);

	KASSERT(iter->unget == -1, ("unget=%#02x", iter->unget));
	iter->unget = ch;
}

void
khttpd_mbuf_base64_encode(struct mbuf *output, const char *buf, size_t size)
{
	struct mbuf *tail;
	char *encbuf;
	size_t i, j, n;
	unsigned q, v;
	int space;

	TRACE("enter %p %#zx", buf, size);

	m_length(output, &tail);
	encbuf = mtod(tail, char *) + tail->m_len;

	n = size / 3 * 3;
	for (i = 0; i < n; i += 3) {
		space = M_TRAILINGSPACE(tail);
		if (space < 4) {
			tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
			encbuf = mtod(tail, char *);
		}

		q = ((int)buf[i] << 16) | ((int)buf[i + 1] << 8) |
		    (int)buf[i + 2];
		for (j = 0; j < 4; ++j) {
			v = (q >> 18) & 0x3f;
			if (v < 26)
				encbuf[j] = 'A' + v;
			else if (v < 52)
				encbuf[j] = 'a' + (v - 26);
			else if (v < 62)
				encbuf[j] = '0' + (v - 52);
			else if (v == 62)
				encbuf[j] = '+';
			else
				encbuf[j] = '/';
			q <<= 6;
		}

		encbuf += 4;
		tail->m_len += 4;
	}

	q = 0;
	switch (size - n) {
	case 0:
		break;

	case 2:
		q = ((int)buf[i + 1] << 8);
		/* FALLTHROUGH */

	case 1:
		q |= ((int)buf[i] << 16);

		space = M_TRAILINGSPACE(tail);
		if (space < 4) {
			tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
			encbuf = mtod(tail, char *);
		}

		for (j = 0; j < 1 + (size - n); ++j) {
			v = (q >> 18) & 0x3f;
			if (v < 26)
				encbuf[j] = 'A' + v;
			else if (v < 52)
				encbuf[j] = 'a' + (v - 26);
			else if (v < 62)
				encbuf[j] = '0' + (v - 52);
			else if (v == 62)
				encbuf[j] = '+';
			else
				encbuf[j] = '/';
			q <<= 6;
		}
		for (; j < 4; ++j)
			encbuf[j] = '=';

		tail->m_len += 4;
	}
}

int
khttpd_mbuf_base64_decode(struct khttpd_mbuf_iter *iter, void **buf_out,
    size_t *size_out)
{
	unsigned char *buf;
	size_t bufsize, size;
	int ch, code, equals, i;

	size = 0;
	bufsize = 128;
	buf = malloc(bufsize, M_KHTTPD, M_WAITOK);

	while ((ch = khttpd_mbuf_getc(iter)) != -1) {
		code = 0;
		equals = 0;
		for (i = 0; i < 4; ++i) {
			code <<= 6;
			if ('A' <= ch && ch <= 'Z')
				code |= ch - 'A';
			else if ('a' <= ch && ch <= 'z')
				code |= ch - 'a' + 26;
			else if ('0' <= ch && ch <= '9')
				code |= ch - '0' + 52;
			else if (ch == '+')
				code |= 62;
			else if (ch == '/')
				code |= 63;
			else if (ch == '=')
				++equals;
			else
				return (EINVAL);
			ch = khttpd_mbuf_getc(iter);
		}
		khttpd_mbuf_ungetc(iter, ch);

		if (bufsize < size + 3 - equals) {
			bufsize = bufsize < 65536 ? bufsize <<= 1
			    : bufsize + 65536;
			buf = realloc(buf, bufsize, M_KHTTPD, M_WAITOK);
		}

		for (i = 2; equals <= i; --i)
			buf[size++] = (code >> (i * 8)) & 0xff;

		if (0 < equals)
			break;
	}

	*buf_out = buf;
	*size_out = size;

	return (0);
}

