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
#include <sys/hash.h>
#include <sys/sbuf.h>
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
khttpd_find_ch_in2(const char *begin, const char *end, char ch1, char ch2)
{
	const char *ptr;

	for (ptr = begin; ptr < end; ++ptr)
		if (*ptr == ch1 || *ptr == ch2)
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

	buf = khttpd_malloc(end - str + 1);
	bcopy(str, buf, end - str);
	buf[end - str] = '\0';

	return (buf);
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
khttpd_hash32_buf_ci(const void *begin, const void *end, uint32_t hash)
{
	const char *bp;
	unsigned char ch;

	for (bp = begin; bp < (const char *)end; ++bp) {
		ch = *bp;
		hash = HASHSTEP(hash, tolower(ch));
	}

	return (hash);
}

uint32_t
khttpd_hash32_str_ci(const void *str, uint32_t hash)
{
	const char *bp;
	char ch;

	for (bp = str; ((ch = *bp) != '\0'); ++bp)
		hash = HASHSTEP(hash, tolower(ch));

	return (hash);
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

int
khttpd_parse_ip_addresss(uint32_t *out, const char *value)
{
	uint32_t result;
	int i, values[4];

	if (sscanf(value, "%d.%d.%d.%d", values, values + 1, values + 2,
		values + 3) != 4)
		return (EINVAL);


	result = 0;
	for (i = 0; i < sizeof(values) / sizeof(values[0]); ++i) {
		if (values[i] < 0 || 255 < values[i])
			return (EINVAL);
		result = (result << 8) | values[i];
	}

	*out = result;

	return (0);
}

int
khttpd_parse_ipv6_address(u_char *out, const char *value)
{
	uint16_t nums[8];
	u_char *op;
	const char *cp, *cp2, *numhead;
	uint32_t ipv4_addr;
	int i, dbl_colon, error, n, nnums, num;
	char ch, termch;

	dbl_colon = -1;
	n = sizeof(nums) / sizeof(nums[0]);
	cp = value;
	i = 0;
	for (;;) {
		if (n <= i)
			return (EINVAL);

		numhead = cp;
		while (ch = *cp, isxdigit(ch))
			++cp;

		if (numhead == cp)
			return (EINVAL);

		termch = ch;
		switch (termch) {
		case '\0':
		case ':':
			num = 0;
			for (cp2 = numhead; cp2 != cp; ++cp2) {
				ch = *cp2;
				num <<= 4;

				if (0x10000 <= num)
					return (EINVAL);

				num |= isdigit(ch) ? ch - '0'
				    : tolower(ch) - 'a' + 10;
			}

			nums[i++] = num;

			if (termch == '\0')
				goto quit;

			if (dbl_colon != -1 || i == n || cp[1] != ':')
				++cp;
			else {
				dbl_colon = i;
				cp += 2;
			}
			break;

		case '.':
			if (dbl_colon == -1 ? i != n - 2 : n - 2 < i)
				return (EINVAL);

			error = khttpd_parse_ip_addresss(&ipv4_addr, numhead);
			if (error != 0)
				return (error);

			nums[i++] = (uint16_t)(ipv4_addr >> 16);
			nums[i++] = (uint16_t)ipv4_addr;
			goto quit;

		default:
			return (EINVAL);
		}
	}

 quit:
	op = out;
	nnums = i;
	for (i = 0; i < nnums; ++i) {
		if (i == dbl_colon) {
			bzero(op, (n - nnums) * sizeof(int16_t));
			op += (n - nnums) * sizeof(int16_t);
		}
		num = nums[i];
		*op++ = (u_char)(num >> 8);
		*op++ = (u_char)num;
	}

	return (0);
}
