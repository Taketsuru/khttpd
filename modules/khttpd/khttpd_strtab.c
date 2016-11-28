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
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_string.h"

void
khttpd_strtab_init(struct khttpd_strtab_entry_slist *table, int table_size,
    struct khttpd_strtab_entry *symbols, int n)
{
	uint32_t h;
	int i;

	KASSERT((table_size & -table_size) == table_size,
	    ("table_size=%d", table_size));

	for (i = 0; i < table_size; ++i)
		SLIST_INIT(&table[i]);

	for (i = 0; i < n; ++i) {
		h = khttpd_hash32_str_ci(symbols[i].name, 0) &
		    (table_size - 1);
		SLIST_INSERT_HEAD(&table[h], &symbols[i], link);
	}
}

struct khttpd_strtab_entry *
khttpd_strtab_find(struct khttpd_strtab_entry_slist *table, int table_size,
    const char *begin, const char *end, boolean_t ci)
{
	struct khttpd_strtab_entry *ptr;
	uint32_t h;

	KASSERT((table_size & -table_size) == table_size,
	    ("table_size=%d", table_size));

	h = khttpd_hash32_buf_ci(begin, end, 0) & (table_size - 1);
	SLIST_FOREACH(ptr, &table[h], link)
		if ((ci ? strncasecmp : strncmp)
		    (begin, ptr->name, end - begin) == 0)
			return (ptr);

	return (NULL);
}
