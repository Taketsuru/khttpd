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

#include "khttpd_string.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>

int
khttpd_parse_digits(uintmax_t *value_out, const char *begin, const char *end)
{
	uintmax_t value;
	const char *cp;
	int ch, digit;

	value = 0;
	for (cp = begin; cp < end; ++cp) {
		ch = *cp;
		if (!isdigit(ch)) {
			return (EINVAL);
		}
		digit = ch - '0';
		if (value * 10 + digit < value) {
			return (ERANGE);
		}
		value = value * 10 + digit;
	}

	*value_out = value;

	return (0);
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
	for (i = 0; i < nitems(values); ++i) {
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
	n = nitems(nums);
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

				num |= isdigit(ch) ? ch - '0' :
				    tolower(ch) - 'a' + 10;
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

void
khttpd_print_ipv6_address(struct sbuf *out, const uint8_t *addr)
{
	const uint8_t *ap;
	uint16_t v, lv;
	int i, ns, current_run_pos, longest_run_pos;
	int current_run_len, longest_run_len;

	longest_run_pos = -1;
	longest_run_len = 0;
	current_run_len = 0;
	ap = addr;
	ns = 8;
	lv = 0;
	for (i = 0; i < ns; ++i, lv = v) {
		v = (unsigned)*ap++ << 8;
		v |= (unsigned)*ap++;

		if (v != 0) {
			current_run_len = 0;
			continue;
		}

		if (i == 0 || lv != 0) {
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

	ap = addr;
	for (i = 0; i < ns; ) { 
		if (i == longest_run_pos) {
			sbuf_printf(out, ":");
			i += longest_run_len;
			if (i == ns)
				sbuf_printf(out, ":");
			continue;
		}

		v = (unsigned)addr[i * sizeof(uint16_t)] << 8;
		v |= (unsigned)addr[i * sizeof(uint16_t) + 1];
		sbuf_printf(out, i == 0 ? "%x" : ":%x", v);
		++i;
	}
}

int
khttpd_decode_hexdigit(int ch)
{
	if ('0' <= ch && ch <= '9')
		return (ch - '0');

	if ('A' <= ch && ch <= 'F')
		return (ch - 'A' + 10);

	if ('a' <= ch && ch <= 'f')
		return (ch - 'a' + 10);

	return (-1);
}

int
khttpd_unescape_uri(struct sbuf *out, const char *in)
{
	const char *src, *pp;
	int code, digit;

	src = in;
	while ((pp = strchr(src, '%')) != NULL) {
		sbuf_bcat(out, src, pp - src);

		digit = khttpd_decode_hexdigit(pp[1]);
		if (digit == -1)
			return (EINVAL);
		code = digit << 4;

		digit = khttpd_decode_hexdigit(pp[2]);
		if (digit == -1)
			return (EINVAL);
		code = digit | (code << 4);

		sbuf_putc(out, code);
		src = pp + 3;
	}
	sbuf_cat(out, src);

	return (0);
}

void
khttpd_string_trim(const char **begin_io, const char **end_io)
{
	const char *begin, *end;
	int ch;

	begin = *begin_io;
	end = *end_io;

	for (; begin < end && ((ch = *begin) == ' ' || ch == '\t'); ++begin) {
	}

	for (; begin < end - 1 && ((ch = end[-1]) == ' ' || ch == '\t');
	     --end) {
	}

	*begin_io = begin;
	*end_io = end;
}

void
khttpd_string_for_each_token(const char *begin, const char *end,
    bool (*fn)(void *arg, const char *begin, const char *end), void *arg)
{
	const char *cp, *ep, *sp;
	int ch;

	cp = begin;
	for (;;) {
		sp = memchr(cp, ',', end - cp);

		if (sp == NULL) {
			ep = end;
		} else {
			for (ep = sp;
			     cp < ep - 1 &&
			     ((ch = ep[-1]) == ' ' || ch == '\t');
			     --ep) {
			}
		}

		if (cp < ep && !fn(arg, cp, ep)) {
			break;
		}

		if (sp == NULL) {
			break;
		}

		for (cp = sp + 1; (ch = *cp) == ' ' || ch == '\t'; ++cp) {
		}
	}
}
