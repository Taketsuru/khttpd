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

#include "khttpd_rewriter.h"

#include <sys/param.h>
#include <sys/hash.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/sbuf.h>

#include <vm/uma.h>

#include "khttpd_costruct.h"
#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

#ifndef KHTTPD_REWRITER_SUFFIX_TABLE_SIZE
#define KHTTPD_REWRITER_SUFFIX_TABLE_SIZE	32
#endif

struct khttpd_rewriter_rule {
	khttpd_rewriter_rule_type_t type;
};

struct khttpd_rewriter_suffix_rule {
	struct khttpd_rewriter_rule hdr;
	SLIST_ENTRY(khttpd_rewriter_suffix_rule) hlink;
	char	*suffix;
	char	*result;
};

SLIST_HEAD(khttpd_rewriter_suffix_rule_slist, khttpd_rewriter_suffix_rule);

struct khttpd_rewriter {
	struct sx	lock;
	char		*default_value;
	KHTTPD_REFCOUNT1_MEMBERS;
	unsigned	active_iterations;
	unsigned	costructs_ready:1;
	unsigned	waiting_iteration:1;
	struct khttpd_rewriter_suffix_rule_slist
			suffix_table[KHTTPD_REWRITER_SUFFIX_TABLE_SIZE];
};

static void khttpd_rewriter_dtor(struct khttpd_rewriter *rewriter);

struct khttpd_costruct_info *khttpd_rewriter_costruct_info;

KHTTPD_REFCOUNT1_GENERATE(khttpd_rewriter, khttpd_rewriter,
    khttpd_rewriter_dtor, khttpd_free);

int
khttpd_rewriter_new(struct khttpd_rewriter **rewriter_out)
{
	struct khttpd_rewriter *rewriter;
	uint32_t i;
	int error;

	KHTTPD_ENTRY("khttpd_rewriter_new()");

	rewriter = khttpd_malloc(sizeof(*rewriter));
	sx_init(&rewriter->lock, "rewriter");
	rewriter->default_value = NULL;
	for (i = 0; i < KHTTPD_REWRITER_SUFFIX_TABLE_SIZE; ++i)
		SLIST_INIT(&rewriter->suffix_table[i]);
	rewriter->active_iterations = 0;
	rewriter->costructs_ready = FALSE;
	rewriter->waiting_iteration = FALSE;
	KHTTPD_REFCOUNT1_INIT(khttpd_rewriter, rewriter);

	error = khttpd_costruct_call_ctors(khttpd_rewriter_costruct_info,
	    rewriter);
	if (error != 0) {
		khttpd_rewriter_release(rewriter);
		return (error);
	}
	rewriter->costructs_ready = TRUE;

	*rewriter_out = rewriter;

	return (0);
}

void
khttpd_rewriter_swap(struct khttpd_rewriter *x, struct khttpd_rewriter *y)
{
	struct khttpd_rewriter *t;
	uint32_t i;
	char *tmps;
	boolean_t tmpb;

	if (y < x) {
		t = x;
		x = y;
		y = t;
	}

	sx_xlock(&x->lock);

	while (0 < x->active_iterations) {
		x->waiting_iteration = TRUE;
		sx_sleep(&x->active_iterations, &x->lock, 0, "rewriter-busy",
		    0);
	}

	sx_xlock(&y->lock);

	while (0 < y->active_iterations) {
		y->waiting_iteration = TRUE;
		sx_sleep(&y->active_iterations, &y->lock, 0, "rewriter-busy",
		    0);
	}

	for (i = 0; i < KHTTPD_REWRITER_SUFFIX_TABLE_SIZE; ++i)
		SLIST_SWAP(&x->suffix_table[i], &y->suffix_table[i],
		    khttpd_rewriter_suffix_rule);

	tmps = x->default_value;
	x->default_value = y->default_value;
	y->default_value = tmps;

	tmpb = x->costructs_ready;
	x->costructs_ready = y->costructs_ready;
	y->costructs_ready = tmpb;

	sx_xunlock(&y->lock);
	sx_xunlock(&x->lock);
}

static void
khttpd_rewriter_dtor(struct khttpd_rewriter *rewriter)
{
	struct khttpd_rewriter_suffix_rule *rule;
	struct khttpd_rewriter_suffix_rule_slist *head;
	int i;

	KHTTPD_ENTRY("khttpd_rewriter_dtor(%p)", rewriter);

	if (rewriter->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_rewriter_costruct_info,
		    rewriter);

	khttpd_free(rewriter->default_value);

	for (i = 0; i < KHTTPD_REWRITER_SUFFIX_TABLE_SIZE; ++i) {
		head = &rewriter->suffix_table[i];
		while (!SLIST_EMPTY(head)) {
			rule = SLIST_FIRST(head);
			SLIST_REMOVE_HEAD(head, hlink);
			khttpd_free(rule->suffix);
			khttpd_free(rule->result);
			khttpd_free(rule);
		}
	}

	sx_destroy(&rewriter->lock);
}

static struct khttpd_rewriter_suffix_rule_slist *
khttpd_rewriter_hash_suffix(struct khttpd_rewriter *rewriter,
    const char *suffix)
{
	uint32_t h;

	h = murmur3_32_hash(suffix, strlen(suffix), 0) &
	    (KHTTPD_REWRITER_SUFFIX_TABLE_SIZE - 1);

	return (&rewriter->suffix_table[h]);
}

/* 
 * This function must not be called while any other rewriter functions is
 * running.
 */
void
khttpd_rewriter_add_suffix_rule(struct khttpd_rewriter *rewriter,
    const char *pattern, const char *result)
{
	struct khttpd_rewriter_suffix_rule *rule;
	struct khttpd_rewriter_suffix_rule_slist *head;

	rule = khttpd_malloc(sizeof(struct khttpd_rewriter_suffix_rule));
	rule->suffix = khttpd_strdup(pattern);
	rule->result = khttpd_strdup(result);

	head = khttpd_rewriter_hash_suffix(rewriter, pattern);
	SLIST_INSERT_HEAD(head, rule, hlink);
}

/* 
 * This function must not be called while any other rewriter functions is
 * running.
 */
void
khttpd_rewriter_set_default(struct khttpd_rewriter *rewriter,
    const char *result)
{

	KHTTPD_ENTRY("khttpd_rewriter_set_default(%p,%p)", rewriter, result);

	khttpd_free(rewriter->default_value);
	rewriter->default_value = result == NULL ? NULL :
	    khttpd_strdup(result);
}

boolean_t
khttpd_rewriter_get_default(struct khttpd_rewriter *rewriter,
    struct sbuf *output)
{
	boolean_t result;

	sx_slock(&rewriter->lock);
	result = rewriter->default_value != NULL;
	if (result)
		sbuf_cat(output, rewriter->default_value);
	sx_sunlock(&rewriter->lock);

	return (result);
}

boolean_t
khttpd_rewriter_rewrite(struct khttpd_rewriter *rewriter,
    struct sbuf *output, const char *input)
{
	struct khttpd_rewriter_suffix_rule *rule;
	struct khttpd_rewriter_suffix_rule_slist *head;
	const char *cp;

	for (cp = input + strlen(input); input < cp && cp[-1] != '.'; --cp)
		;		/* nothing */

	if (cp == input)
		goto not_found;

	sx_slock(&rewriter->lock);

	head = khttpd_rewriter_hash_suffix(rewriter, input);
	SLIST_FOREACH(rule, head, hlink)
		if (strcmp(rule->suffix, cp) == 0) {
			sbuf_cat(output, rule->result);
			sx_sunlock(&rewriter->lock);
			return (TRUE);
		}

 not_found:
	cp = rewriter->default_value;
	if (cp != NULL)
		sbuf_cat(output, cp);

	sx_sunlock(&rewriter->lock);

	return (cp != NULL);
}

struct khttpd_rewriter_rule *
khttpd_rewriter_iteration_begin(struct khttpd_rewriter *rewriter)
{
	struct khttpd_rewriter_suffix_rule *rule;
	struct khttpd_rewriter_suffix_rule_slist *head;

	sx_xlock(&rewriter->lock);
	++rewriter->active_iterations;
	sx_xunlock(&rewriter->lock);

	for (head = &rewriter->suffix_table[0];
	     head - rewriter->suffix_table < KHTTPD_REWRITER_SUFFIX_TABLE_SIZE;
	     ++head)
		if ((rule = SLIST_FIRST(head)) != NULL)
			return (&rule->hdr);

	return (NULL);
}

struct khttpd_rewriter_rule *
khttpd_rewriter_iteration_next(struct khttpd_rewriter *rewriter,
    struct khttpd_rewriter_rule *prev)
{
	struct khttpd_rewriter_suffix_rule *rule, *sprev;
	struct khttpd_rewriter_suffix_rule_slist *head;

	sprev = (struct khttpd_rewriter_suffix_rule *)prev;

	if ((rule = SLIST_NEXT(sprev, hlink)) != NULL)
		return (&rule->hdr);

	for (head = khttpd_rewriter_hash_suffix(rewriter, sprev->suffix) + 1;
	     head - rewriter->suffix_table < KHTTPD_REWRITER_SUFFIX_TABLE_SIZE;
	     ++head)
		if ((rule = SLIST_FIRST(head)) != NULL)
			return (&rule->hdr);

	return (NULL);
}

void 
khttpd_rewriter_iteration_end(struct khttpd_rewriter *rewriter)
{

	sx_xlock(&rewriter->lock);
	if (--rewriter->active_iterations == 0 &&
	    rewriter->waiting_iteration) {
		rewriter->waiting_iteration = FALSE;
		wakeup(&rewriter->active_iterations);
	}
	sx_xunlock(&rewriter->lock);
}

/* 
 * This function must be called between the calls of
 * khttpd_rewriter_iteration_begin() and khttpd_rewriter_iteration_end().
 */

khttpd_rewriter_rule_type_t
khttpd_rewriter_rule_get_type(struct khttpd_rewriter_rule *rule)
{

	return (rule->type);
}

/* 
 * This function must be called between the calls of
 * khttpd_rewriter_iteration_begin() and khttpd_rewriter_iteration_end().
 */

void
khttpd_rewriter_rule_inspect_suffix_rule(struct khttpd_rewriter_rule *rule,
    const char **pattern, const char **result)
{
	struct khttpd_rewriter_suffix_rule *srule;

	KASSERT(rule->type == KHTTPD_REWRITER_RULE_SUFFIX,
	    ("rule->type=%d", rule->type));

	srule = (struct khttpd_rewriter_suffix_rule *)rule;
	*pattern = srule->suffix;
	*result = srule->result;
}

static int
khttpd_rewriter_costruct_init(void)
{

	KHTTPD_ENTRY("khttpd_rewriter_costruct_init()");
	khttpd_costruct_info_new(&khttpd_rewriter_costruct_info,
	    sizeof(struct khttpd_rewriter));
	return (0);
}

static void
khttpd_rewriter_costruct_fini(void)
{

	KHTTPD_ENTRY("khttpd_rewriter_costruct_fini()");
	khttpd_costruct_info_destroy(khttpd_rewriter_costruct_info);
}

KHTTPD_INIT(, khttpd_rewriter_costruct_init, khttpd_rewriter_costruct_fini,
    KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS - 1);
