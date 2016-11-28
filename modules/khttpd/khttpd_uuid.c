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

#include "khttpd_uuid.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/libkern.h>

enum {
	khttpd_uuid_time_low_off = 0,
	khttpd_uuid_time_mid_off = 4,
	khttpd_uuid_time_hi_and_version_off = 6,
	khttpd_uuid_clk_seq_hi_res_off = 8,
	khttpd_uuid_clk_seq_low_off = 9,
	khttpd_uuid_clk_seq_node_off = 10
};

void
khttpd_uuid_new(void *uuid_out)
{
	char *cp;

	arc4rand(uuid_out, KHTTPD_UUID_SIZE, 0);

	cp = uuid_out;

	/* Set bit6 and bit7 of the clock_seq_hi_and_reserved to 0 and 1 */
	cp[khttpd_uuid_clk_seq_hi_res_off] =
	    (cp[khttpd_uuid_clk_seq_hi_res_off] & 0x3f) | 0x80;

	/* Set bits 12 through 15 of the time_hi_and_version field to 4 */
 	cp[khttpd_uuid_time_hi_and_version_off] =
	    (cp[khttpd_uuid_time_hi_and_version_off] & 0x0f) | 0x40;
}

void
khttpd_uuid_to_string(const void *uuid, char *out)
{
	const u_char *srcp;
	u_char *dstp, nib, v;
	int i;

	srcp = uuid;
	dstp = out;
	for (i = 0; i < KHTTPD_UUID_SIZE; ++i) {
		switch (i) {
		case 4:
		case 6:
		case 8:
		case 10:
			*dstp++ = '-';
			break;
		default:
			break;
		}
		v = *srcp++;
		nib = v >> 4;
		*dstp++ = hex2ascii(nib);
		nib = v & 0xf;
		*dstp++ = hex2ascii(nib);
	}
	*dstp = 0;
}

int
khttpd_uuid_parse(const char *str, void *uuid)
{
	u_char buf[KHTTPD_UUID_SIZE];
	const char *srcp;
	u_char *dstp, v;
	char ch1, ch2;
	int i;

	srcp = str;
	dstp = buf;
	for (i = 0; i < KHTTPD_UUID_SIZE; ++i) {
		switch (i) {
		case 4:
		case 6:
		case 8:
		case 10:
			if (*srcp++ != '-')
				return (EINVAL);
			break;
		default:
			break;
		}

		ch1 = *srcp++;
		ch1 = tolower(ch1);
		if (!isxdigit(ch1))
			return (EINVAL);
		v = isdigit(ch1) ? ch1 - '0' : ch1 - 'a' + 10;

		ch2 = *srcp++;
		ch2 = tolower(ch2);
		if (!isxdigit(ch2))
			return (EINVAL);
		v = (v << 4) | (isdigit(ch2) ? ch2 - '0' : ch2 - 'a' + 10);

		*dstp++ = v;
	}

	bcopy(buf, uuid, sizeof(buf));
	return (0);
}
