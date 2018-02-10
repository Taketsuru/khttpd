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

#ifndef _KERNEL
#error This file is not for userland code.
#endif

#include <sys/types.h>

struct sbuf;

char *khttpd_find_2ch_in(const char *begin, const char *end,
    char ch1, char ch2);
char *khttpd_skip_ws(const char *ptr);
char *khttpd_rtrim_ws(const char *begin, const char *end);
uint32_t khttpd_hash32_buf_ci(const char *begin, const char *end,
    uint32_t hash);
uint32_t khttpd_hash32_str_ci(const char *str, uint32_t hash);
int khttpd_parse_digits_field(const char *_begin, const char *_end,
    uintmax_t *_value_out);
int khttpd_parse_ip_addresss(uint32_t *out, const char *value);
int khttpd_parse_ipv6_address(u_char *out, const char *value);
void khttpd_print_ipv6_addr(struct sbuf *out, const uint8_t *addr);
boolean_t khttpd_is_json_media_type(const char *input);
int khttpd_decode_hexdigit(char);
int khttpd_unescape_uri(struct sbuf *, const char *);
