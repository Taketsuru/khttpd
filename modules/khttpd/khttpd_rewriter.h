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

#pragma once

#ifdef _KERNEL

#include "khttpd_refcount.h"

struct khttpd_costruct_info;
struct khttpd_rewriter;
struct khttpd_rewriter_rule;
struct sbuf;

extern struct khttpd_costruct_info *khttpd_rewriter_costruct_info;

typedef enum {
	KHTTPD_REWRITER_RULE_SUFFIX,

	KHTTPD_REWRITER_RULE_END
} khttpd_rewriter_rule_type_t;

int khttpd_rewriter_new(struct khttpd_rewriter **);
void khttpd_rewriter_swap(struct khttpd_rewriter *, struct khttpd_rewriter *);
void khttpd_rewriter_add_suffix_rule(struct khttpd_rewriter *rewriter,
    const char *pattern, const char *result);
void khttpd_rewriter_set_default(struct khttpd_rewriter *rewriter,
    const char *result);
boolean_t khttpd_rewriter_get_default(struct khttpd_rewriter *rewriter,
    struct sbuf *output);
boolean_t khttpd_rewriter_rewrite(struct khttpd_rewriter *rewriter,
    struct sbuf *output, const char *input);
struct khttpd_rewriter_rule *khttpd_rewriter_iteration_begin
    (struct khttpd_rewriter *rewriter);
struct khttpd_rewriter_rule *khttpd_rewriter_iteration_next
    (struct khttpd_rewriter *rewriter, struct khttpd_rewriter_rule *rule);
void khttpd_rewriter_iteration_end(struct khttpd_rewriter *rewriter);

khttpd_rewriter_rule_type_t khttpd_rewriter_rule_get_type
    (struct khttpd_rewriter_rule *rule);
void khttpd_rewriter_rule_inspect_suffix_rule
    (struct khttpd_rewriter_rule *rule, const char **pattern,
     const char **result);

KHTTPD_REFCOUNT1_PROTOTYPE(khttpd_rewriter);

#endif
