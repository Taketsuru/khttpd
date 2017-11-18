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

#include "khttpd_mbuf.h"

#include <sys/types.h>
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

static struct mbuf *khttpd_mbuf_put_json_string_wo_quote(struct mbuf *output,
    const char *begin, const char *end);
static struct mbuf *khttpd_mbuf_put_json_string_mbuf(struct mbuf *output,
    struct mbuf *src);
static struct mbuf *khttpd_mbuf_put_json_string_mbuf_1st_line(struct mbuf *out,
    struct mbuf *m);

static void
khttpd_mbuf_vprintf_free(struct mbuf *buf, void *arg1, void *arg2)
{

	khttpd_free(mtod(buf, char *) - sizeof(u_int));
}

int
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
	if (buflen < req + 1) {
		if (req + 1 <= MCLBYTES) {
			m_getm2(buf, req + 1, M_WAITOK, MT_DATA, 0);
			buf = buf->m_next;
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
khttpd_mbuf_printf(struct mbuf *output, const char *fmt, ...)
{
	va_list vl;
	int result;

	va_start(vl, fmt);
	result = khttpd_mbuf_vprintf(output, fmt, vl);
	va_end(vl);

	return (result);
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

boolean_t
khttpd_mbuf_skip_ws(struct khttpd_mbuf_pos *iter)
{
	int ch;

	while ((ch = khttpd_mbuf_getc(iter)) != -1)
		if (!isspace(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			return (TRUE);
		}

	return (FALSE);
}

boolean_t
khttpd_mbuf_next_line(struct khttpd_mbuf_pos *iter)
{
	struct mbuf *ptr;
	const char *begin, *cp, *end;
	int off;
	boolean_t found;

	if (iter->unget == '\n') {
		iter->unget = -1;
		return (TRUE);
	}

	if (iter->unget != -1)
		iter->unget = -1;

	ptr = iter->ptr;
	off = iter->off;

	for (;;) {
		begin = mtod(ptr, char *) + off;
		end = mtod(ptr, char *) + ptr->m_len;
		cp = khttpd_find_ch_in(begin, end, '\n');
		if (cp != NULL) {
			off = cp + 1 - begin;
			found = TRUE;
			break;
		}

		if (ptr->m_next == NULL) {
			off = ptr->m_len;
			found = FALSE;
			break;
		}

		ptr = ptr->m_next;
		off = 0;
	}

	iter->ptr = ptr;
	iter->off = off;

	return (found);
}

void khttpd_mbuf_get_line_and_column(struct khttpd_mbuf_pos *origin,
    struct khttpd_mbuf_pos *pos, unsigned *line_out, unsigned *column_out)
{
	enum {
		tab_width = 8
	};
	struct mbuf *ptr, *eptr;
	const char *begin, *cp, *end;
	int off, eoff;
	unsigned line, column;

	KASSERT(origin->unget == -1 || 0 < origin->off,
	    ("origin->unget=%#x, origin->off=%d", origin->unget, origin->off));

	eptr = pos->ptr;
	eoff = pos->off;

	if (pos->unget != -1) {
		if (0 < eoff) {
			--eoff;
		} else {
			KASSERT(eptr != origin->ptr, 
			    ("ptr=eptr=%p, eoff=0", ptr));

			eptr = NULL;
			eoff = 0;
			
			for (ptr = origin->ptr; ; ptr = ptr->m_next) {
				if (0 < ptr->m_len) {
					eptr = ptr;
					eoff = ptr->m_len - 1;
				}

				if (ptr->m_next == pos->ptr)
					break;
			}

			KASSERT(eptr != NULL, ("chain of empty mbufs"));
		}
	}

	ptr = origin->ptr;
	off = origin->off;

	KASSERT(ptr != eptr || (origin->unget == -1 ? off : off - 1) < eoff,
	    ("ptr=%p, off=%#x, eptr=%p, eoff=%#x", ptr, off, eptr, eoff));

	line = 1;
	column = 1;

	if (origin->unget == '\n')
		++line;
	else if (origin->unget == '\t')
		column = 9;
	else if (origin->unget != -1)
		++column;

	while (ptr != NULL) {
		begin = mtod(ptr, char *) + off;
		end = mtod(ptr, char *) + (ptr == eptr ? eoff : ptr->m_len);
		cp = khttpd_find_ch_in(begin, end, '\n');
		if (cp != NULL) {
			++line;
			column = 1;
			off = cp + 1 - mtod(ptr, char *);
			continue;
		}

		for (cp = begin; cp < end; ++cp)
			if (*cp == '\t')
				column = roundup2(column - 1 + tab_width,
				    tab_width) + 1;
			else
				++column;

		if (ptr == eptr && eoff <= off)
			break;

		off = 0;
		ptr = ptr->m_next;
	}

	*line_out = line;
	*column_out = column;
}

boolean_t
khttpd_mbuf_get_header_field(struct khttpd_mbuf_pos *iter, const char *name,
    struct sbuf *value)
{
	struct mbuf *ptr;
	const char *begin, *cp, *end;
	int off;
	int ch, nch, uch;

	for (;;) {
		for (cp = name; (nch = *cp) != '\0'; ++cp) {
			ch = khttpd_mbuf_getc(iter);
			if (ch == -1)
				return (FALSE);
			if (tolower(ch) != tolower(*cp))
				break;
		}

		if (ch == ':' && nch == '\0')
			break;

		if (ch != '\n' && !khttpd_mbuf_next_line(iter))
			return (FALSE);
	}

	khttpd_mbuf_skip_ws(iter);

	uch = iter->unget;
	iter->unget = -1;
	
	if (uch == '\n')
		return (TRUE);

	if (uch != -1)
		sbuf_putc(value, uch);

	ptr = iter->ptr;
	off = iter->off;

	for (;;) {
		begin = mtod(ptr, char *) + off;
		end = begin + ptr->m_len;
		cp = khttpd_find_ch_in(begin + off, end, '\n');
		if (cp != NULL) {
			sbuf_bcat(value, begin, cp - begin);
			off = cp + 1 - begin;
			break;
		}

		sbuf_bcat(value, begin, end - begin);

		if (ptr->m_next == NULL) {
			off = ptr->m_len;
			break;
		}

		ptr = ptr->m_next;
		off = 0;
	}

	iter->ptr = ptr;
	iter->off = off;

	return (TRUE);
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
		found = khttpd_find_2ch_in(cp, end, term_ch, '\n');
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
		found = khttpd_find_2ch_in(cp, end, term_ch, '\n');
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
		if (value * 10 + digit < value)
			return (ERANGE);
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
	buf = khttpd_malloc(bufsize);

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
				khttpd_free(buf);
				return (EINVAL);
			}
			ch = khttpd_mbuf_getc(iter);
		}
		khttpd_mbuf_ungetc(iter, ch);

		if (bufsize < size + 3 - equals) {
			bufsize = bufsize < 65536 ? bufsize << 1
			    : bufsize + 65536;
			buf = khttpd_realloc(buf, bufsize);
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

static struct mbuf *
khttpd_mbuf_put_json_string_wo_quote(struct mbuf *output, const char *begin,
    const char *end)
{
	struct mbuf *tail;
	const char *srcp;
	char *dstp, *dend;
	int32_t code;
	int flc, i, len;
	uint16_t code1, code2;
	unsigned char ch;

	srcp = begin;
	tail = output;
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

struct mbuf *
khttpd_mbuf_put_json_string_wo_quote_mbuf(struct mbuf *output,
    struct mbuf *source)
{
	struct mbuf *tail;
	struct mbuf *srcp;
	const char *begin, *end;
	
	tail = output;
	for (srcp = source; srcp != NULL; srcp = srcp->m_next) {
		begin = mtod(srcp, char *);
		end = begin + srcp->m_len;
		tail = khttpd_mbuf_put_json_string_wo_quote(tail, begin, end);
	}
	return (tail);
}

struct mbuf *
khttpd_mbuf_put_json_string(struct mbuf *output, const char *begin,
    const char *end)
{
	struct mbuf *tail;

	tail = khttpd_mbuf_append_ch(output, '"');
	tail = khttpd_mbuf_put_json_string_wo_quote(tail, begin, end);
	tail = khttpd_mbuf_append_ch(tail, '"');
	return (tail);
}

static struct mbuf *
khttpd_mbuf_put_json_string_mbuf(struct mbuf *output, struct mbuf *src)
{
	struct mbuf *tail;

	tail = khttpd_mbuf_append_ch(output, '\"');
	tail = khttpd_mbuf_put_json_string_wo_quote_mbuf(tail, src);
	tail = khttpd_mbuf_append_ch(tail, '\"');
	return (tail);
}

struct mbuf *
khttpd_mbuf_put_json_string_cstr(struct mbuf *output, const char *str)
{

	return str != NULL
	    ? khttpd_mbuf_put_json_string(output, str, str + strlen(str))
	    : khttpd_mbuf_append(output, khttpd_mbuf_null_literal,
		khttpd_mbuf_null_literal + sizeof(khttpd_mbuf_null_literal) -
		1);
}

static struct mbuf *
khttpd_mbuf_put_json_string_mbuf_1st_line(struct mbuf *out, struct mbuf *m)
{
	struct mbuf *tail;
	char *begin, *end, *cp;
	
	tail = khttpd_mbuf_append_ch(out, '\"');

	for (; m != NULL; m = m->m_next) {
		begin = mtod(m, char *);
		end = begin + m->m_len;
		cp = khttpd_find_ch_in(begin, end, '\n');
		if (cp == NULL)
			tail = khttpd_mbuf_put_json_string_wo_quote(tail,
			    begin, end);
		else  {
			tail = khttpd_mbuf_put_json_string_wo_quote(tail,
			    begin, cp + 1);
			break;
		}
	}

	tail = khttpd_mbuf_append_ch(tail, '"');

	return (tail);
}

void
khttpd_mbuf_json_new(struct khttpd_mbuf_json *v)
{

	v->mbuf = m_get(M_WAITOK, MT_DATA);
	v->is_first = TRUE;
	v->is_property_value = FALSE;
}

struct mbuf *
khttpd_mbuf_json_data(struct khttpd_mbuf_json *v)
{

	return (v->mbuf);
}

struct mbuf *
khttpd_mbuf_json_move(struct khttpd_mbuf_json *v)
{
	struct mbuf *m;

	m = v->mbuf;
	v->mbuf = NULL;

	return (m);
}

void
khttpd_mbuf_json_copy_to_sbuf(struct khttpd_mbuf_json *v, struct sbuf *sbuf)
{
	struct mbuf *ptr;

	for (ptr = v->mbuf; ptr != NULL; ptr = ptr->m_next)
		sbuf_bcat(sbuf, mtod(ptr, char *), ptr->m_len);
}

void
khttpd_mbuf_json_print(struct khttpd_mbuf_json *v)
{
	struct sbuf sbuf;

	sbuf_new(&sbuf, NULL, 0, SBUF_AUTOEXTEND);
	khttpd_mbuf_json_copy_to_sbuf(v, &sbuf);
	sbuf_finish(&sbuf);
	printf("%s", sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void
khttpd_mbuf_json_delete(struct khttpd_mbuf_json *v)
{

	m_freem(v->mbuf);
	v->mbuf = NULL;
}

static void
khttpd_mbuf_json_begin_element(struct khttpd_mbuf_json *v)
{
	if (v->is_first)
		v->is_first = FALSE;
	else if (v->is_property_value)
		v->is_property_value = FALSE;
	else
		khttpd_mbuf_append(v->mbuf, khttpd_mbuf_comma,
		    khttpd_mbuf_comma + sizeof(khttpd_mbuf_comma) - 1);
}

void
khttpd_mbuf_json_null(struct khttpd_mbuf_json *v)
{

	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_append(v->mbuf, khttpd_mbuf_null_literal,
	    khttpd_mbuf_null_literal + sizeof(khttpd_mbuf_null_literal) - 1);
}

void
khttpd_mbuf_json_boolean(struct khttpd_mbuf_json *v, boolean_t value)
{

	khttpd_mbuf_json_begin_element(v);
	if (value)
		khttpd_mbuf_append(v->mbuf, khttpd_mbuf_true_literal,
		    khttpd_mbuf_true_literal +
		    sizeof(khttpd_mbuf_true_literal) - 1);
	else
		khttpd_mbuf_append(v->mbuf, khttpd_mbuf_false_literal,
		    khttpd_mbuf_false_literal +
		    sizeof(khttpd_mbuf_false_literal) - 1);
}

void
khttpd_mbuf_json_cstr(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *value)
{

	khttpd_mbuf_json_begin_element(v);
	if (is_string)
		khttpd_mbuf_put_json_string_cstr(v->mbuf, value);
	else
		khttpd_mbuf_append(v->mbuf, value, value + strlen(value));
}

void
khttpd_mbuf_json_mbuf(struct khttpd_mbuf_json *v, boolean_t is_string,
    struct mbuf *m)
{

	khttpd_mbuf_json_begin_element(v);
	if (is_string)
		khttpd_mbuf_put_json_string_mbuf(v->mbuf, m);
	else
		m_cat(v->mbuf, m_copym(m, 0, M_COPYALL, M_WAITOK));
}

void
khttpd_mbuf_json_format(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	khttpd_mbuf_json_vformat(v, is_string, fmt, args);
	va_end(args);
}

void
khttpd_mbuf_json_vformat(struct khttpd_mbuf_json *v, boolean_t is_string,
    const char *fmt, va_list args)
{
	struct sbuf sbuf;

	sbuf_new(&sbuf, NULL, 256, SBUF_AUTOEXTEND);
	sbuf_vprintf(&sbuf, fmt, args);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_cstr(v, is_string, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void 
khttpd_mbuf_json_sockaddr(struct khttpd_mbuf_json *v,
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

	KHTTPD_ENTRY("%s(%p,%p)", __func__, v, sockaddr);

	if (sockaddr->sa_family == AF_UNSPEC) {
		KHTTPD_BRANCH("%s AF_UNSPEC", __func__);
		khttpd_mbuf_json_null(v);
		return;
	}

	khttpd_mbuf_json_object_begin(v);

	switch (sockaddr->sa_family) {

	case AF_INET:
		addr_in = (struct sockaddr_in *)sockaddr;
		khttpd_mbuf_json_property_cstr(v, "family", TRUE, "inet");
		ip_addr = ntohl(addr_in->sin_addr.s_addr);
		port = ntohs(addr_in->sin_port);
		if (ip_addr != 0)
			khttpd_mbuf_json_property_format(v, "address", TRUE,
			    "%d.%d.%d.%d", (ip_addr >> 24) & 0xff, 
			    (ip_addr >> 16) & 0xff, (ip_addr >> 8) & 0xff, 
			    ip_addr & 0xff);
		khttpd_mbuf_json_property_format(v, "port", FALSE, "%u", port);
		break;

	case AF_INET6:
		addr_in6 = (struct sockaddr_in6 *)sockaddr;
		khttpd_mbuf_json_property_cstr(v, "family", TRUE, "inet6");
		if (addr_in6->sin6_addr.s6_addr32[3] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[2] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[1] != 0 ||
		    addr_in6->sin6_addr.s6_addr32[0] != 0) {
			sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
			khttpd_print_ipv6_addr(&sbuf,
			    addr_in6->sin6_addr.s6_addr8);
			sbuf_finish(&sbuf);
			khttpd_mbuf_json_property_cstr(v, "address", TRUE,
			    sbuf_data(&sbuf));
			sbuf_delete(&sbuf);
		}
		port = ntohs(addr_in6->sin6_port);
		khttpd_mbuf_json_property_format(v, "port", FALSE, "%u", port);
		break;

	case AF_UNIX:
		addr_un = (struct sockaddr_un *)sockaddr;
		khttpd_mbuf_json_property_cstr(v, "family", TRUE, "unix");
		len = MIN(sizeof(struct sockaddr_un), addr_un->sun_len);
		if (offsetof(struct sockaddr_un, sun_path) < len
		    && addr_un->sun_path[0] != '\0')
			khttpd_mbuf_json_property_format(v, "address", TRUE,
			    "%.*s", 
			    len - offsetof(struct sockaddr_un, sun_path),
			    addr_un->sun_path);
		break;

	default:
		panic("unsupported address family: %d", sockaddr->sa_family);
	}

	khttpd_mbuf_json_object_end(v);
}

void
khttpd_mbuf_json_object_begin(struct khttpd_mbuf_json *v)
{

	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_append_ch(v->mbuf, '{');
	v->is_first = TRUE;
}

void
khttpd_mbuf_json_object_end(struct khttpd_mbuf_json *v)
{

	khttpd_mbuf_append_ch(v->mbuf, '}');
	v->is_first = FALSE;
}

void
khttpd_mbuf_json_property(struct khttpd_mbuf_json *v, const char *name)
{

	KASSERT(!v->is_property_value,
	    ("the previous property name isn't followed by a value"));

	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_put_json_string_cstr(v->mbuf, name);
	khttpd_mbuf_append(v->mbuf, khttpd_mbuf_colon, khttpd_mbuf_colon +
	    sizeof(khttpd_mbuf_colon) - 1);
	v->is_property_value = TRUE;
}

void
khttpd_mbuf_json_property_null(struct khttpd_mbuf_json *v, const char *name)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_append(v->mbuf, khttpd_mbuf_null_literal,
	    khttpd_mbuf_null_literal + sizeof(khttpd_mbuf_null_literal) - 1);
}

void
khttpd_mbuf_json_property_boolean(struct khttpd_mbuf_json *v, const char *name,
    boolean_t value)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_begin_element(v);
	if (value)
		khttpd_mbuf_append(v->mbuf, khttpd_mbuf_true_literal,
		    khttpd_mbuf_true_literal +
		    sizeof(khttpd_mbuf_true_literal) - 1);
	else
		khttpd_mbuf_append(v->mbuf, khttpd_mbuf_false_literal,
		    khttpd_mbuf_false_literal +
		    sizeof(khttpd_mbuf_false_literal) - 1);
}

void
khttpd_mbuf_json_property_cstr(struct khttpd_mbuf_json *v, const char *name,
    boolean_t is_string, const char *value)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_begin_element(v);
	if (is_string)
		khttpd_mbuf_put_json_string_cstr(v->mbuf, value);
	else
		khttpd_mbuf_append(v->mbuf, value, value + strlen(value));
}

void
khttpd_mbuf_json_property_mbuf(struct khttpd_mbuf_json *v, const char *name,
    boolean_t is_string, struct mbuf *m)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_begin_element(v);
	if (is_string)
		khttpd_mbuf_put_json_string_mbuf(v->mbuf, m);
	else
		m_cat(v->mbuf, m_copym(m, 0, M_COPYALL, M_WAITOK));
}

void khttpd_mbuf_json_property_mbuf_1st_line(struct khttpd_mbuf_json *v,
    const char *name, struct mbuf *m)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_put_json_string_mbuf_1st_line(v->mbuf, m);
}

void
khttpd_mbuf_json_property_format(struct khttpd_mbuf_json *v, const char *name,
    boolean_t is_string, const char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	khttpd_mbuf_json_property_vformat(v, name, is_string, fmt, args);
	va_end(args);
}

void
khttpd_mbuf_json_property_vformat(struct khttpd_mbuf_json *v, const char *name,
    boolean_t is_string, const char *fmt, va_list args)
{
	struct sbuf sbuf;

	KASSERT(!v->is_property_value,
	    ("the previous property name isn't followed by a value"));

	sbuf_new(&sbuf, NULL, 256, SBUF_AUTOEXTEND);
	sbuf_vprintf(&sbuf, fmt, args);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_property_cstr(v, name, is_string, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

void
khttpd_mbuf_json_property_sockaddr(struct khttpd_mbuf_json *v,
    const char *name, struct sockaddr *addr)
{
	struct khttpd_mbuf_json sa;

	khttpd_mbuf_json_new(&sa);
	khttpd_mbuf_json_sockaddr(&sa, addr);
	khttpd_mbuf_json_property_mbuf(v, name, FALSE,
	    khttpd_mbuf_json_move(&sa));
}

void
khttpd_mbuf_json_property_array_begin(struct khttpd_mbuf_json *v,
    const char *name)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_array_begin(v);
}

void
khttpd_mbuf_json_property_object_begin(struct khttpd_mbuf_json *v,
    const char *name)
{

	khttpd_mbuf_json_property(v, name);
	khttpd_mbuf_json_object_begin(v);
}

void
khttpd_mbuf_json_array_begin(struct khttpd_mbuf_json *v)
{

	khttpd_mbuf_json_begin_element(v);
	khttpd_mbuf_append_ch(v->mbuf, '[');
	v->is_first = TRUE;
}

void
khttpd_mbuf_json_array_end(struct khttpd_mbuf_json *v)
{
	khttpd_mbuf_append_ch(v->mbuf, ']');
	v->is_first = FALSE;
}

void
khttpd_mbuf_json_now(struct khttpd_mbuf_json *entry)
{
	struct timeval tv;

	microtime(&tv);
	khttpd_mbuf_json_format(entry, FALSE, "%ld.%06ld",
	    tv.tv_sec, tv.tv_usec);
}
