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
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#pragma once

#ifdef _KERNEL

#include <sys/types.h>
#include <sys/queue.h>

#define KHTTPD_STRTAB_POW2_CEIL_HELPER(x,f) \
	(x) <= 1ul << (f) ? 1ul << (f) :
#define KHTTPD_STRTAB_POW2_CEIL(x) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,1) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,2) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,3) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,4) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,5) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,6) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,7) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,8) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,9) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,10) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,11) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,12) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,13) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,14) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,15) \
	KHTTPD_STRTAB_POW2_CEIL_HELPER(x,16) \
	1ul << 17

struct khttpd_strtab_entry {
	const char	*name;
	SLIST_ENTRY(khttpd_strtab_entry) link;
};

SLIST_HEAD(khttpd_strtab_entry_slist, khttpd_strtab_entry);

void khttpd_strtab_init(struct khttpd_strtab_entry_slist *table,
    int table_size, struct khttpd_strtab_entry *symbols, int n);
struct khttpd_strtab_entry *khttpd_strtab_find
    (struct khttpd_strtab_entry_slist *table, int table_size,
     const char *begin, const char *end, boolean_t ci);

#endif	/* ifdef _KERNEL */
