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
#include <sys/ctype.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include <netinet/in.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* --------------------------------------------------- function definitions */

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
	va_list vlcopy;

	va_copy(vlcopy, vl);

	m_length(output, &buf);
	buflen = M_TRAILINGSPACE(buf);
	req = vsnprintf(mtod(buf, char *) + buf->m_len, buflen, fmt, vl);
	if (req + 1 <= buflen)
		goto end;

	if (req + 1 <= MCLBYTES) {
		m_getm2(buf, req + 1, M_WAITOK, MT_DATA, 0);
		buf = buf->m_next;
	} else {
		buf = buf->m_next = m_get(M_WAITOK, MT_DATA);
		extbuf = malloc(sizeof(u_int) + req + 1, M_KHTTPD, M_WAITOK);
		buf->m_ext.ext_cnt = (u_int *)extbuf;
		MEXTADD(buf, extbuf + sizeof(u_int), req + 1,
		    khttpd_mbuf_vprintf_free, NULL, NULL, 0, EXT_EXTREF);
	}

	req = vsnprintf(mtod(buf, char *), M_TRAILINGSPACE(buf), fmt, vlcopy);

end:
	buf->m_len += req;
	va_end(vlcopy);
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

	m_getm2(ptr, end - cp, M_WAITOK, MT_DATA, 0);

	for (ptr = ptr->m_next; cp < end; ptr = ptr->m_next) {
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
khttpd_mbuf_pos_init(struct khttpd_mbuf_pos *iter, struct mbuf *ptr,
    int off)
{

	iter->unget = -1;
	iter->ptr = ptr;
	iter->off = off;
}

void
khttpd_mbuf_pos_copy(struct khttpd_mbuf_pos *x, struct khttpd_mbuf_pos *y)
{

	bcopy(x, y, sizeof(*x));
}

int
khttpd_mbuf_getc(struct khttpd_mbuf_pos *iter)
{
	int result;

	if (0 <= iter->unget) {
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
khttpd_mbuf_ungetc(struct khttpd_mbuf_pos *iter, int ch)
{

	KASSERT(iter->unget == -1, ("unget=%#02x", iter->unget));
	iter->unget = ch;
}

int
khttpd_mbuf_next_segment(struct khttpd_mbuf_pos *iter, int term_ch)
{
	struct mbuf *ptr;
	const char *begin, *cp, *end, *found;
	int error, off, uch;

	uch = iter->unget;
	if (uch == '\n')
		return (ENOENT);
	if (uch == term_ch) {
		iter->unget = -1;
		return (0);
	}

	error = 0;
	ptr = iter->ptr;
	off = iter->off;

	while (ptr != NULL) {
		begin = mtod(ptr, char *);
		end = begin + ptr->m_len;
		cp = begin + off;
		found = khttpd_find_ch_in2(cp, end, term_ch, '\n');
		if (found != NULL) {
			off = found + 1 - begin;
			if (*found == '\n')
				break;
			goto end;
		}

		off = 0;
		ptr = ptr->m_next;
	}

	error = ENOENT;

end:
	iter->ptr = ptr;
	iter->off = off;

	return (error);
}

int
khttpd_mbuf_copy_segment(struct khttpd_mbuf_pos *pos,
    int term_ch, char *buffer, size_t size, char **end_out)
{
	struct mbuf *ptr;
	const char *begin, *end, *cp, *found;
	char *bp, *bend;
	int error, off, uch;

	uch = pos->unget;
	if (uch == '\n')
		return (ENOENT);
	if (uch == term_ch) {
		pos->unget = -1;
		if (end_out != NULL)
			*end_out = buffer;
		return (0);
	}

	bp = buffer;
	bend = bp + size;
	if (uch != -1) {
		if (bp == bend) {
			if (end_out != NULL)
				*end_out = bp;
			return (ENOMEM);
		}
		pos->unget = -1;
		*bp++ = uch;
	}

	ptr = pos->ptr;
	off = pos->off;

	error = 0;

	while (ptr != NULL) {
		begin = mtod(ptr, char *);
		end = begin + ptr->m_len;
		cp = begin + off;
		found = khttpd_find_ch_in2(cp, end, term_ch, '\n');
		if (found != NULL) {
			off = found + 1 - begin;

			if (*found == '\n')
				break;

			if (bend - bp < found - cp)
				goto enomem;

			bcopy(cp, bp, found - cp);
			bp += found - cp;
			goto end;
		}

		if (bend - bp < end - cp) {
			off = end - begin;
			goto enomem;
		}

		bcopy(cp, bp, end - cp);
		bp += end - cp;

		off = 0;
		ptr = ptr->m_next;
	}

	error = ENOENT;
	goto end;

enomem:
	error = ENOMEM;
	bcopy(cp, bp, bend - bp);
	bp = bend;

end:
	pos->ptr = ptr;
	pos->off = off;

	if (end_out != NULL)
		*end_out = bp;
	
	return (error);
}

int
khttpd_mbuf_parse_digits(struct khttpd_mbuf_pos *pos, uintmax_t *value_out)
{
	uintmax_t value, digit;
	int ch;

	TRACE("enter");

	while ((ch = khttpd_mbuf_getc(pos)) == ' ' || ch == '\t')
		;		/* nothing */
	khttpd_mbuf_ungetc(pos, ch);

	value = 0;
	for (;;) {
		ch = khttpd_mbuf_getc(pos);
		if (!isdigit(ch)) {
			khttpd_mbuf_ungetc(pos, ch);
			break;
		}

		digit = ch - '0';
		if (value * 10 + digit < value) {
			TRACE("error range");
			return (ERANGE);
		}
		value = value * 10 + digit;
	}

	while ((ch = khttpd_mbuf_getc(pos)) == ' ' || ch == '\t')
		;		/* nothing */
	if (ch == '\r')
		ch = khttpd_mbuf_getc(pos);
	if (ch != '\n')
		return (EINVAL);

	*value_out = value;

	return (0);
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
khttpd_mbuf_base64_decode(struct khttpd_mbuf_pos *iter, void **buf_out,
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
			else {
				free(buf, M_KHTTPD);
				return (EINVAL);
			}
			ch = khttpd_mbuf_getc(iter);
		}
		khttpd_mbuf_ungetc(iter, ch);

		if (bufsize < size + 3 - equals) {
			bufsize = bufsize < 65536 ? bufsize << 1
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

int
khttpd_mbuf_next_list_element(struct khttpd_mbuf_pos *pos, struct sbuf *output)
{
	int consecutive_ws_count;
	char ch;

	while ((ch = khttpd_mbuf_getc(pos)) == ' ' || ch == '\t')
		;		/* nothing */

	khttpd_mbuf_ungetc(pos, ch);

	consecutive_ws_count = 0;
	for (;;) {
		ch = khttpd_mbuf_getc(pos);

		switch (ch) {

		case '\n':
			khttpd_mbuf_ungetc(pos, ch);
			/* FALLTHROUGH */

		case -1:
			if (sbuf_len(output) == consecutive_ws_count)
				return (ENOMSG);
			/* FALLTHROUGH */

		case ',':
			goto out;

		case ' ': case '\t':
			++consecutive_ws_count;
			continue;

		case '\r':
			ch = khttpd_mbuf_getc(pos);
			khttpd_mbuf_ungetc(pos, ch);
			if (ch == '\n') {
				if (sbuf_len(output) == consecutive_ws_count)
					return (ENOMSG);
				goto out;
			}
			/* FALLTHROUGH */

		default:
			consecutive_ws_count = 0;
			sbuf_putc(output, ch);
			break;
		}
	}
out:
	sbuf_setpos(output, sbuf_len(output) - consecutive_ws_count);

	return (sbuf_finish(output));
}

boolean_t
khttpd_mbuf_list_contains_token(struct khttpd_mbuf_pos *pos, char *token,
    boolean_t ignore_case)
{
	const char *cptr, *token_end;
	size_t token_len;
	int ch;
	boolean_t found_no_ws;

	TRACE("enter");

	token_len = strlen(token);
	token_end = token + token_len;

	for (;;) {
		while ((ch = khttpd_mbuf_getc(pos)) == ' ' || ch == '\t')
			;		/* nothing */
		khttpd_mbuf_ungetc(pos, ch);

		for (cptr = token; cptr < token_end; ++cptr) {
			ch = khttpd_mbuf_getc(pos);
			if (ignore_case ? tolower(ch) != tolower(*cptr) :
			    ch != *cptr) {
				khttpd_mbuf_ungetc(pos, ch);
				break;
			}
		}

		found_no_ws = FALSE;
		for (;;) {
			ch = khttpd_mbuf_getc(pos);

			switch (ch) {

			case ',': case '\n':
				goto out;

			case ' ': case '\t':
				continue;

			case '\r':
				ch = khttpd_mbuf_getc(pos);
				if (ch == '\n')
					goto out;
				khttpd_mbuf_ungetc(pos, ch);

			default:
				break;
			}

			found_no_ws = TRUE;
		}
 out:
		if (cptr == token_end && !found_no_ws)
			return (TRUE);

		if (ch == '\n')
			break;
	}

	return (FALSE);
}

void
khttpd_mbuf_print_sockaddr_in(struct mbuf *out, struct sockaddr_in *addr)
{
	uint8_t *ap;
	int i;

	addr = (struct sockaddr_in *)addr;
	ap = (uint8_t *)&addr->sin_addr.s_addr;
	khttpd_mbuf_printf(out, "%d", ap[0]);
	for (i = 1; i < sizeof(addr->sin_addr.s_addr); ++i)
		khttpd_mbuf_printf(out, ".%d", ap[i]);
}

void
khttpd_mbuf_print_sockaddr_in6(struct mbuf *out, struct sockaddr_in6 *addr)
{
	uint16_t *sp;
	int i, ns, current_run_pos, longest_run_pos;
	int current_run_len, longest_run_len;

	sp = addr->sin6_addr.s6_addr16;

	longest_run_pos = -1;
	longest_run_len = 0;
	current_run_len = 0;
	ns = sizeof(addr->sin6_addr.s6_addr16) / sizeof(uint16_t);
	for (i = 0; i < ns; ++i) {
		if (sp[i] != 0) {
			current_run_len = 0;
			continue;
		}

		if (i == 0 || sp[i - 1] != 0) {
			current_run_len = 1;
			current_run_pos = i;
			continue;
		}

		if (++current_run_len <= longest_run_len)
			continue;

		longest_run_pos = current_run_pos;
		longest_run_len = current_run_len;
	}

	if (longest_run_len <= 1)
		longest_run_pos = -1;

	for (i = 0; i < ns; ) { 
		if (i == longest_run_pos) {
			khttpd_mbuf_printf(out, ":");
			i += longest_run_len;
			if (i == ns)
				khttpd_mbuf_printf(out, ":");
			continue;
		}

		khttpd_mbuf_printf(out, i == 0 ? "%x" : ":%x",
		    ntohs(sp[i]));
		++i;
	}
}
