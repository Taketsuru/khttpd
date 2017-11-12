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

#include "khttpd_init.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/queue.h>
#include <sys/hash.h>
#include <sys/eventhandler.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/module.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/linker.h>

#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

SET_DECLARE(khttpd_init_set, struct khttpd_init);

struct khttpd_init_node {
	SLIST_ENTRY(khttpd_init_node) link;
	struct khttpd_init *init;
	struct linker_file *linker_file;
	union {
		int	in_degree;
		int	order;
	};
};

SLIST_HEAD(khttpd_init_node_slist, khttpd_init_node);

struct khttpd_init_file {
	LIST_ENTRY(khttpd_init_file) link;
	struct linker_file *linker_file;
	int		node_count;
	struct khttpd_init_node nodes[];
};

LIST_HEAD(khttpd_init_file_list, khttpd_init_file);

static struct sx khttpd_init_lock;
static struct khttpd_init_file_list khttpd_init_files =
    LIST_HEAD_INITIALIZER(&khttpd_init_files);
static struct khttpd_init_node **khttpd_init_nodes;
static struct khttpd_init *khttpd_init_current;
static int khttpd_init_generation;
static eventhandler_tag khttpd_init_kldload_tag;

SX_SYSINIT(khttpd_init_lock, &khttpd_init_lock, "khttpd-init");

int
khttpd_init_get_phase(void)
{
	int phase;

	sx_slock(&khttpd_init_lock);
	phase = khttpd_init_current == NULL ? INT_MIN :
	    khttpd_init_current->phase;
	sx_sunlock(&khttpd_init_lock);

	return (phase);
}

int
khttpd_init_run(void (*fn)(int))
{

	return (khttpd_init_run_focusing(fn, NULL, 0));
}

static boolean_t
khttpd_init_may_run(struct khttpd_init *init, const char **files, int nfiles)
{
	size_t iflen, flen;
	int i;

	KHTTPD_ENTRY("%s(%p(%s),%p,%d)", __func__, init, init->file, files,
	    nfiles);

	if (files == NULL)
		return (TRUE);

	iflen = strlen(init->file);
	for (i = 0; i < nfiles; ++i) {
		flen = strlen(files[i]);
		if (flen <= iflen &&
		    memcmp(init->file + iflen - flen, files, flen) == 0)
			return (TRUE);
	}

	return (FALSE);
}

int
khttpd_init_run_focusing(void (*fn)(int), const char **files, int nfiles)
{
	static struct khttpd_init marker = {
		.name = "<ready>",
		.phase = INT_MAX
	};
	struct thread *td;
	struct khttpd_init *init;
	struct khttpd_init_node **nodes;
	int error, gen, i;

	KHTTPD_ENTRY("khttpd_init_run_focusing(%p,%p,%d)", fn, files, nfiles);

	td = curthread;
	error = 0;

	sx_xlock(&khttpd_init_lock);

	if (khttpd_init_current != NULL) {
		sx_xunlock(&khttpd_init_lock);
		return (EBUSY);
	}

	nodes = khttpd_init_nodes;
	khttpd_init_nodes = NULL;
	gen = khttpd_init_generation;

	if (nodes == NULL) {
		i = 0;
		goto init_end;
	}

	for (i = 0; error == 0 && nodes[i] != NULL; ++i) {
		init = nodes[i]->init;
		if (init->init == NULL)
			continue;
		if (!khttpd_init_may_run(init, files, nfiles))
			continue;

		khttpd_init_current = init;
		sx_xunlock(&khttpd_init_lock);

		KHTTPD_NOTE("init %p \"%s\" %d", init, init->name,
		    init->phase);
		error = init->init();
		KASSERT(0 <= error && error <= ELAST, ("error %d", error));

		sx_xlock(&khttpd_init_lock);
	}

 init_end:
	khttpd_init_current = &marker;
	sx_xunlock(&khttpd_init_lock);

	fn(error);

	sx_xlock(&khttpd_init_lock);

	for (; 0 < i; --i) {
		init = nodes[i - 1]->init;
		if (init->fini == NULL)
			continue;
		if (!khttpd_init_may_run(init, files, nfiles))
			continue;

		khttpd_init_current = init;
		sx_xunlock(&khttpd_init_lock);

		KHTTPD_NOTE("fini %p \"%s\" %d", init, init->name,
		    init->phase);
		init->fini();

		sx_xlock(&khttpd_init_lock);
	}

	khttpd_init_current = NULL;
	if (gen != khttpd_init_generation)
		khttpd_free(nodes);
	else
		khttpd_init_nodes = nodes;
	sx_xunlock(&khttpd_init_lock);

	return (0);
}

static int
khttpd_compare_init(const void *a1, const void *a2)
{
	const struct khttpd_init_node *i1, *i2;

	i1 = *(struct khttpd_init_node *const *)a1;
	i2 = *(struct khttpd_init_node *const *)a2;
	if (i1->init->phase != i2->init->phase)
		return (i1->init->phase < i2->init->phase ? -1 : 1);
	return (i1->order > i2->order ? -1 : 1);
}

static boolean_t
khttpd_init_add_node(struct khttpd_init_node_slist *table, size_t table_size,
    int phase, const char *name, struct khttpd_init_node *elm)
{
	struct khttpd_init_node *p;
	uint32_t h;

	h = hash32_str(name, phase) % table_size;
	SLIST_FOREACH(p, table + h, link) {
		if (phase == p->init->phase &&
		    strcmp(name, p->init->name) == 0) {
			log(LOG_ERR, "khttpd: conflict on name '%s' "
			    "(module1: \"%s\", module2: \"%s\", "
			    "phase: %d)", p->init->name, 
			    p->linker_file->pathname,
			    elm->linker_file->pathname, p->init->phase);
			return (FALSE);
		}
	}

	SLIST_INSERT_HEAD(table + h, elm, link);

	return (TRUE);
}

static struct khttpd_init_node *
khttpd_init_find_node(struct khttpd_init_node_slist *table, size_t table_size,
    int phase, const char *name)
{
	struct khttpd_init_node *p;
	uint32_t h;

	h = hash32_str(name, phase) % table_size;
	SLIST_FOREACH(p, table + h, link)
		if (phase == p->init->phase &&
		    strcmp(name, p->init->name) == 0)
			return (p);

	return (NULL);
}

static void
khttpd_init_order_entries(void)
{
	struct khttpd_init_node_slist *node_table;
	struct khttpd_init_node *dependee, *nodes, **sorted_nodes;
	struct khttpd_init *init;
	struct khttpd_init_file *mod;
	const char **depnamep;
	int error, i, n, order, total_count;

	KHTTPD_ENTRY("khttpd_init_order_entries()");

	node_table = NULL;
	sorted_nodes = NULL;
	error = 0;

	sx_assert(&khttpd_init_lock, SA_XLOCKED);

	total_count = 0;
	LIST_FOREACH(mod, &khttpd_init_files, link)
		total_count += mod->node_count;

	if (total_count == 0) {
		khttpd_free(khttpd_init_nodes);
		khttpd_init_nodes = NULL;
		++khttpd_init_generation;
		return;
	}

	node_table = khttpd_malloc(total_count *
	    sizeof(struct khttpd_init_node_slist));
	for (i = 0; i < total_count; ++i)
		SLIST_INIT(node_table + i);

	LIST_FOREACH(mod, &khttpd_init_files, link) {
		nodes = mod->nodes;
		n = mod->node_count;
		for (i = 0; i < n; ++i) {
			nodes[i].in_degree = 0;
			init = nodes[i].init;
			if (init->name[0] != '\0' &&
			    !khttpd_init_add_node(node_table, total_count,
				init->phase, init->name, &nodes[i]))
				goto error;
		}
	}

	sorted_nodes = khttpd_malloc((total_count + 1) *
	    sizeof(struct khttpd_init_node *));

	/* Do topological sort */

	LIST_FOREACH(mod, &khttpd_init_files, link) {
		nodes = mod->nodes;
		n = mod->node_count;
		for (i = 0; i < n; ++i) {
			init = nodes[i].init;
			for (depnamep = init->dependee; *depnamep != NULL;
			     ++depnamep) {
				dependee = khttpd_init_find_node(node_table,
				    total_count, init->phase, *depnamep);
				if (dependee == NULL) {
					log(LOG_ERR, "khttpd: unknown "
					    "dependee \"%s\".  (file: "
					    "\"%s\", name: \"%s\", phase: %d)",
					    *depnamep, 
					    mod->linker_file->pathname,
					    init->name, init->phase);
					error = EINVAL;
					goto error;
				}
				++dependee->in_degree;
			}
		}
	}

	order = 0;
	LIST_FOREACH(mod, &khttpd_init_files, link) {
		nodes = mod->nodes;
		n = mod->node_count;
		for (i = 0; i < n; ++i) {
			if (nodes[i].in_degree == 0) {
				nodes[i].order = order;
				sorted_nodes[order++] = nodes + i;
			}
		}
	}

	for (i = 0; i < order; ++i) {
		init = sorted_nodes[i]->init;
		for (depnamep = init->dependee; *depnamep != NULL;
		     ++depnamep) {
			dependee = khttpd_init_find_node(node_table,
			    total_count, init->phase, *depnamep);
			if (dependee != NULL && --dependee->in_degree == 0) {
				dependee->order = order;
				sorted_nodes[order++] = dependee;
			}
		}
	}
	sorted_nodes[order] = NULL;

	if (order != total_count) {
		log(LOG_ERR, "khttpd: there are cyclic dependencies "
		    "among the following inits");

		/*
		 * Note that order and in_degree are the members of the
		 * same union, and in_degree of each element was 0 when it
		 * was added to sorted_nodes.
		 */
		for (i = 0; i < order; ++i)
			sorted_nodes[i]->order = 0;

		LIST_FOREACH(mod, &khttpd_init_files, link) {
			nodes = mod->nodes;
			n = mod->node_count;
			for (i = 0; i < n; ++i)
				if (nodes[i].in_degree != 0)
					log(LOG_ERR, "  (file: \"%s\", "
					    "name: \"%s\", phase: %d)",
					    mod->linker_file->pathname,
					    nodes[i].init->name,
					    nodes[i].init->phase);
		}

		goto error;
	}

	khttpd_free(node_table);

	qsort(sorted_nodes, total_count, sizeof(struct khttpd_init_node *),
	    khttpd_compare_init);

	khttpd_free(khttpd_init_nodes);
	khttpd_init_nodes = sorted_nodes;
	++khttpd_init_generation;

	return;

 error:
	khttpd_free(node_table);
	khttpd_free(sorted_nodes);
}

int
khttpd_init_quiesce(void)
{
	int error;

	sx_slock(&khttpd_init_lock);
	error = khttpd_init_current != NULL ? 0 : EBUSY;
	sx_sunlock(&khttpd_init_lock);

	return (error);
}

static void
khttpd_init_kldload(void *arg, struct linker_file *lf)
{
	struct khttpd_init_file *file;
	struct khttpd_init_node *node;
	struct khttpd_init **begin, **end, **initp;
	int count, error;

	KHTTPD_ENTRY("khttpd_init_kldload(%p{path=%s})", lf, lf->pathname);

	error = linker_file_lookup_set(lf, "khttpd_init_set", &begin, &end,
	    &count);
	if (error != 0)
		return;

	file = khttpd_malloc(sizeof(*file) +
	    count * sizeof(struct khttpd_init_node));
	file->node_count = count;
	file->linker_file = lf;

	node = file->nodes;
	for (initp = begin; initp != end; ++initp) {
		node->init = *initp;
		node->linker_file = lf;
		++node;
	}

	sx_xlock(&khttpd_init_lock);

	LIST_INSERT_HEAD(&khttpd_init_files, file, link);
	wakeup(&khttpd_init_files);

	khttpd_init_order_entries();

	sx_xunlock(&khttpd_init_lock);
}

void
khttpd_init_unload(struct module *mod)
{
	struct khttpd_init_file *ptr, *tptr;
	struct linker_file *lf;

	KHTTPD_ENTRY("khttpd_init_unload(%p)", mod);

	lf = module_file(mod);
	sx_xlock(&khttpd_init_lock);

	while (khttpd_init_current != NULL) {
		sx_xunlock(&khttpd_init_lock);
		EVENTHANDLER_INVOKE(khttpd_init_shutdown);
		sx_xlock(&khttpd_init_lock);
	}

	LIST_FOREACH_SAFE(ptr, &khttpd_init_files, link, tptr)
		if (ptr->linker_file == lf) {
			LIST_REMOVE(ptr, link);
			khttpd_init_order_entries();
			break;
		}

	sx_xunlock(&khttpd_init_lock);

	khttpd_free(ptr);
}

void
khttpd_init_wait_load_completion(struct module *mod)
{
	struct linker_file *lf;
	struct khttpd_init_file *ptr;

	KHTTPD_ENTRY("khttpd_init_wait_load_completion(%p)", mod);

	lf = module_file(mod);

	sx_slock(&khttpd_init_lock);

	for (;;) {
		LIST_FOREACH(ptr, &khttpd_init_files, link)
			if (ptr->linker_file == lf)
				break;

		if (ptr != NULL)
			break;

		sx_sleep(&khttpd_init_files, &khttpd_init_lock, 0, 
		    "initload", 0);
	}

	sx_sunlock(&khttpd_init_lock);
}

static void
khttpd_init_sysinit(void *arg)
{

	KHTTPD_ENTRY("khttpd_init_sysinit");
	khttpd_init_kldload_tag = EVENTHANDLER_REGISTER(kld_load,
	    khttpd_init_kldload, NULL, 0);
}

static void
khttpd_init_sysuninit(void *arg)
{

	KHTTPD_ENTRY("khttpd_init_sysuninit");
	EVENTHANDLER_DEREGISTER(kld_load, khttpd_init_kldload_tag);
	sx_xlock(&khttpd_init_lock);
	sx_xunlock(&khttpd_init_lock);
}

SYSINIT(khttpd_init, SI_SUB_CONFIGURE, SI_ORDER_ANY, khttpd_init_sysinit,
    NULL);
SYSUNINIT(khttpd_init, SI_SUB_CONFIGURE, SI_ORDER_ANY, khttpd_init_sysuninit,
    NULL);
