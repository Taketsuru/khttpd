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
#include <sys/hash.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* --------------------------------------------------- function definitions */

char *
khttpd_find_ch(const char *begin, const char search)
{
	const char *ptr;
	char ch;

	for (ptr = begin; (ch = *ptr) != '\0'; ++ptr)
		if (ch == search)
			return ((char *)ptr);

	return (NULL);
}

char *
khttpd_find_ch_in(const char *begin, const char *end, char ch)
{
	const char *ptr;

	for (ptr = begin; ptr < end; ++ptr)
		if (*ptr == ch)
			return ((char *)ptr);

	return (NULL);
}

char *
khttpd_skip_whitespace(const char *ptr)
{
	const char *cp;

	for (cp = ptr; *cp == ' ' || *cp == '\t'; ++cp)
		;		/* nothing */

	return ((char *)cp);
}

char *
khttpd_rskip_whitespace(const char *ptr)
{
	const char *cp;

	for (cp = ptr; cp[-1] == ' ' || cp[-1] == '\t'; --cp)
		;		/* nothing */

	return ((char *)cp);
}

char *
khttpd_find_whitespace(const char *ptr, const char *end)
{
	const char *cp;

	for (cp = ptr; cp < end && (*cp != ' ' && *cp != '\t'); ++cp)
		;		/* nothing */

	return ((char *)cp);
}

char *
khttpd_dup_first_line(const char *str)
{
	char *buf;
	const char *end;

	end = khttpd_find_ch(str, '\n');
	if (end == NULL)
		return (NULL);

	if (str < end && end[-1] == '\r')
		--end;

	buf = malloc(end - str + 1, M_KHTTPD, M_WAITOK);
	bcopy(str, buf, end - str);
	buf[end - str] = '\0';

	return (buf);
}

char *
khttpd_find_list_item_end(const char *begin, const char **sep)
{
	const char *ptr;
	char *result;
	char ch;

	result = (char *)begin;
	for (ptr = begin; (ch = *ptr) != ',' && ch != '\n' && ch != '\r';
	     ++ptr)
		if (ch != ' ' && ch != '\t')
			result = (char *)(ptr + 1);

	*sep = ptr;

	return (result);
}

char *
khttpd_unquote_uri(char *begin, char *end)
{
	char *dstp, *srcp;
	int code, i;
	char ch;

	dstp = begin;
	for (srcp = begin; srcp < end; ++srcp) {
		KASSERT(dstp <= srcp, ("srcp=%p, dstp=%p", srcp, dstp));

		ch = *srcp;

		if (ch == '\0')
			return (NULL);

		if (ch == '%' && 2 < end - srcp) {
			code = 0;
			for (i = 0; i < 2; ++i) {
				code <<= 4;

				if ('0' <= ch && ch <= '9')
					code |= ch - '0';

				else if ('A' <= ch && ch <= 'F')
					code |= ch - 'A' + 10;

				else if ('a' <= ch && ch <= 'f')
					code |= ch - 'a' + 10;

				else
					return (NULL);
			}

			if (code == 0)
				return (NULL);

			*dstp++ = code;
			continue;
		}

		*dstp++ = ch;
	}

	return (dstp);
}

boolean_t
khttpd_is_token(const char *start, const char *end)
{
	static const char is_tchar[] = {
		/*	    4		8	    c */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00 */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10 */
		0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, /* 0x20 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30 */
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, /* 0x50 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, /* 0x70 */
	};

	const char *cp;
	unsigned char ch;

	for (cp = start; cp < end; ++cp) {
		ch = (unsigned char)*cp;
		if (sizeof(is_tchar) <= ch || is_tchar[ch] == 0)
			return (FALSE);
	}

	return (TRUE);
}

uint32_t
khttpd_hash32_buf_ci(const char *begin, const char *end)
{
	const char *bp;
	uint32_t hash;
	unsigned char ch;

	hash = 0;
	for (bp = begin; bp < end; ++bp) {
		ch = *bp;
		hash = HASHSTEP(hash, tolower(ch));
	}

	return (hash);
}

uint32_t
khttpd_hash32_str_ci(const char *str)
{
	const char *bp;
	uint32_t hash;
	char ch;

	hash = 0;
	for (bp = str; ((ch = *bp) != '\0'); ++bp)
		hash = HASHSTEP(hash, tolower(ch));

	return (hash);
}
