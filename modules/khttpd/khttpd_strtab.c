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

#include "khttpd_strtab.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/smp.h>
#include <sys/pcpu.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_ktr.h"
#include "khttpd_string.h"
#include "khttpd_malloc.h"

struct khttpd_strtab {
	const char	**strings;
	short		*table;
	char		**buf;
	u_int		maxlen;
	u_int		mask;
};

static uint32_t
khttpd_strtab_hash(struct khttpd_strtab *table, const char *begin,
    const char *end)
{
	const char *srcp;
	char *buf, *dstp;
	int ch;
	uint32_t h;

	KASSERT(end - begin < table->maxlen, ("too long"));

	srcp = begin;
	critical_enter();
	dstp = buf = table->buf[PCPU_GET(cpuid)];
	while ((ch = *srcp++) != '\0')
		*dstp++ = tolower(ch);
	h = murmur3_32_hash(buf, dstp - buf, 0);
	critical_exit();

	return (h);
}

void
khttpd_strtab_delete(struct khttpd_strtab *strtab)
{
	int i;

	KHTTPD_ENTRY("%s(%p)", __func__, strtab);

	if (strtab == NULL)
		return;

	for (i = 0; i < mp_ncpus; ++i)
		khttpd_free(strtab->buf[i]);
	khttpd_free(strtab->buf);
	khttpd_free(strtab->table);
	khttpd_free(strtab);
}

int
khttpd_strtab_find(struct khttpd_strtab *strtab,
    const char *begin, const char *end, boolean_t ci)
{
	int (*cmp)(const char *, const char *, size_t);
	uint32_t h;
	int i;

	if (strtab->maxlen < end - begin)
		return (-1);

	h = khttpd_strtab_hash(strtab, begin, end) & strtab->mask;
	i = strtab->table[h];
	if (i == -1)
		return (-1);

	cmp = ci ? strncasecmp : strncmp;

	return (cmp(begin, strtab->strings[i], end - begin) == 0 ? i : -1);
}

int
khttpd_strtab_maxlen(struct khttpd_strtab *strtab)
{

	return (strtab->maxlen);
}

struct khttpd_strtab *
khttpd_strtab_new(const char **strings, int n)
{
	struct khttpd_strtab *result;
	size_t len;
	uint32_t h, *hashes;
	short *table;
	int bit, i, mask;
	extern int uma_align_cache;

	KHTTPD_ENTRY("%s(%p,%d)", __func__, strings, n);
	KASSERT(0 < n && n < SHRT_MAX, ("n=%d", n));

	result = khttpd_malloc(sizeof(*result));
	bzero(result, sizeof(*result));
	result->buf = khttpd_malloc(mp_ncpus * sizeof(char *));

	len = 0;
	for (i = 0; i < n; ++i)
		len = MAX(len, strlen(strings[i]));
	result->maxlen = len = roundup2(len + 1, uma_align_cache + 1);

	for (i = 0; i < mp_ncpus; ++i)
		result->buf[i] = khttpd_malloc(len);

	hashes = khttpd_malloc(n * sizeof(uint32_t));

	for (i = 0; i < n; ++i)
		hashes[i] = khttpd_strtab_hash(result, strings[i],
		    strings[i] + strlen(strings[i]));

	for (bit = flsl(n - 1); bit < 32; ++bit) {
		table = khttpd_malloc(sizeof(int) << bit);
		mask = (1 << bit) - 1;
		for (i = 0; i <= mask; ++i)
			table[i] = -1;

		for (i = 0; i < n; ++i) {
			h = hashes[i] & mask;
			if (table[h] != -1)
				goto next;
			table[h] = i;
		}

		khttpd_free(hashes);

		result->strings = strings;
		result->table = table;
		result->mask = mask;

		return (result);

next:
		khttpd_free(table);
	}

	khttpd_free(hashes);
	khttpd_strtab_delete(result);

	return (NULL);
}
