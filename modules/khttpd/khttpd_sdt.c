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

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/pcpu.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/proc.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/mbuf.h>
#include <sys/sdt.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <machine/cpu.h>

#include <vm/uma.h>

#include "khttpd.h"
#include "khttpd_private.h"

#ifndef KHTTPD_SDT_KO_FILE_HASH_SIZE
#define KHTTPD_SDT_KO_FILE_HASH_SIZE	16
#endif

#ifndef KHTTPD_SDT_PROVIDER_HASH_SIZE
#define KHTTPD_SDT_PROVIDER_HASH_SIZE	128
#endif

#ifndef KHTTPD_SDT_HISTORY_PAGE_SIZE
#define KHTTPD_SDT_HISTORY_PAGE_SIZE	(32UL * 1024)
#endif

#ifndef KHTTPD_SDT_HISTORY_PAGES
#define KHTTPD_SDT_HISTORY_PAGES	64
#endif

#define KHTTPD_SDT_PROBE_PREFIX "/probe"
#define KHTTPD_SDT_HISTORY_PREFIX "/history"

/* --------------------------------------------------------- type definitions */

struct khttpd_sdt_probe {
	SPLAY_ENTRY(khttpd_sdt_probe)	tree_entry;
	TAILQ_ENTRY(khttpd_sdt_probe)	list_entry;
	LIST_ENTRY(khttpd_sdt_probe)	file_list_entry;
	struct sdt_probe		*probe;
};

struct khttpd_sdt_ko_file {
	SLIST_ENTRY(khttpd_sdt_ko_file)	hash_link;
	LIST_HEAD(, khttpd_sdt_probe)	probes;
	struct linker_file		*file;
};

struct khttpd_sdt_history_entry {
	uint64_t	timestamp;
	uintptr_t	args[5];
	int		cpuid;
	lwpid_t		tid;
	uint32_t	id;
};

struct khttpd_sdt_history_page {
	struct bintime	timestamp;
	struct khttpd_sdt_history_entry *contents;
	int		seqno;
	int		size;
};

#define KHTTPD_SDT_HISTORY_ENTRIES_PER_PAGE \
	(KHTTPD_SDT_HISTORY_PAGE_SIZE /	    \
	    sizeof(struct khttpd_sdt_history_entry))

SPLAY_HEAD(khttpd_sdt_probe_tree, khttpd_sdt_probe);
TAILQ_HEAD(khttpd_sdt_probe_list, khttpd_sdt_probe);

/* -------------------------------------------------- prototype declrations */

static int khttpd_sdt_probe_tree_comparator(struct khttpd_sdt_probe *x,
    struct khttpd_sdt_probe *y);
static void khttpd_sdt_history_received_header(struct khttpd_receiver *receiver, 
    struct khttpd_request *request);
static void khttpd_sdt_probe_received_header(struct khttpd_receiver *receiver, 
    struct khttpd_request *request);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

SPLAY_PROTOTYPE(khttpd_sdt_probe_tree, khttpd_sdt_probe, tree_entry,
    khttpd_sdt_probe_tree_comparator);
SPLAY_GENERATE(khttpd_sdt_probe_tree, khttpd_sdt_probe, tree_entry,
    khttpd_sdt_probe_tree_comparator);

#pragma clang diagnostic pop

/* --------------------------------------------------- variable definitions */

static struct khttpd_route_type khttpd_route_type_sdt_probe = {
	.name = "sdt-probe",
	.received_header = khttpd_sdt_probe_received_header
};

static struct khttpd_route_type khttpd_route_type_sdt_history = {
	.name = "sdt-history",
	.received_header = khttpd_sdt_history_received_header
};

static TAILQ_HEAD(, sdt_provider)
	khttpd_sdt_providers[KHTTPD_SDT_PROVIDER_HASH_SIZE];
static SLIST_HEAD(, khttpd_sdt_ko_file)
	khttpd_sdt_ko_files[KHTTPD_SDT_KO_FILE_HASH_SIZE];
static struct khttpd_sdt_history_page
    khttpd_sdt_history_pages[KHTTPD_SDT_HISTORY_PAGES];
static struct mtx khttpd_sdt_history_lock;
static eventhandler_tag khttpd_sdt_kld_load_tag;
static eventhandler_tag khttpd_sdt_kld_unload_try_tag;
static struct khttpd_sdt_probe_tree khttpd_sdt_all_probes_tree;
static struct khttpd_sdt_probe_list khttpd_sdt_all_probes_list;
static uma_zone_t khttpd_sdt_probe_zone;
static int khttpd_sdt_history_current;

/* --------------------------------------------------- function definitions */

static uint32_t
khttpd_sdt_ko_file_hash(struct linker_file *file)
{

	return ((uintptr_t)file >> 4) & (KHTTPD_SDT_KO_FILE_HASH_SIZE - 1);
}

static struct khttpd_sdt_ko_file *
khttpd_sdt_ko_file_find(struct linker_file *file)
{
	struct khttpd_sdt_ko_file *ptr;
	uint32_t hash;

	TRACE("enter %s", file->filename);

	hash = khttpd_sdt_ko_file_hash(file);
	SLIST_FOREACH(ptr, &khttpd_sdt_ko_files[hash], hash_link) {
		if (ptr->file == file)
			return (ptr);
	}
	return (NULL);
}

static struct khttpd_sdt_ko_file *
khttpd_sdt_ko_file_add(struct linker_file *file)
{
	struct khttpd_sdt_ko_file *filep;
	uint32_t hash;

	TRACE("enter %s", file->filename);

	KASSERT(khttpd_sdt_ko_file_find(file) == NULL,
	    ("duplicate entry %s", file->filename));

	hash = khttpd_sdt_ko_file_hash(file);
	filep = malloc(sizeof(*filep), M_KHTTPD, M_WAITOK);
	SLIST_INSERT_HEAD(&khttpd_sdt_ko_files[hash], filep,
	    hash_link);
	LIST_INIT(&filep->probes);
	filep->file = file;

	return (filep);
}

static void
khttpd_sdt_ko_file_remove(struct linker_file *file)
{
	struct khttpd_sdt_ko_file *ptr, *prev;
	struct khttpd_sdt_probe *probe;
	uint32_t hash;

	TRACE("enter %s", file->filename);

	KASSERT(khttpd_sdt_ko_file_find(file) != NULL,
	    ("duplicate entry %s", file->filename));

	hash = khttpd_sdt_ko_file_hash(file);
	prev = NULL;
	SLIST_FOREACH(ptr, &khttpd_sdt_ko_files[hash], hash_link) {
		if (ptr->file == file)
			break;
		prev = ptr;
	}

	if (ptr == NULL) {
		TRACE("error enoent");
		return;
	}

	if (prev == NULL)
		SLIST_REMOVE_HEAD(&khttpd_sdt_ko_files[hash], hash_link);
	else
		SLIST_REMOVE_AFTER(prev, hash_link);

	while ((probe = LIST_FIRST(&ptr->probes)) != NULL) {
		LIST_REMOVE(probe, file_list_entry);
		TAILQ_REMOVE(&khttpd_sdt_all_probes_list, probe, list_entry);
		SPLAY_REMOVE(khttpd_sdt_probe_tree,
		    &khttpd_sdt_all_probes_tree, probe);
		uma_zfree(khttpd_sdt_probe_zone, probe);
	}

	khttpd_free(ptr);
}

static int
khttpd_sdt_probe_tree_comparator(struct khttpd_sdt_probe *x,
    struct khttpd_sdt_probe *y)
{
	struct sdt_probe *px, *py;
	int result;

	px = x->probe;
	py = y->probe;

	result = strcmp(px->prov->name, py->prov->name);
	if (result != 0)
		return (result);
	result = strcmp(px->mod, py->mod);
	if (result != 0)
		return (result);
	result = strcmp(px->func, py->func);
	if (result != 0)
		return (result);
	result = strcmp(px->name, py->name);
	if (result != 0)
		return (result);
	return (x < y ? -1 : y < x ? 1 : 0);
}

static void
khttpd_sdt_history_leaf_get_or_head(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{
	struct khttpd_response *response;
	char *buffer;
	const char *suffix;
	char *endptr;
	size_t size;
	uintmax_t page;
	int i;

	TRACE("enter %s", khttpd_request_suffix(request));

	buffer = NULL;
	suffix = khttpd_request_suffix(request);
	if (*suffix == '/')
		++suffix;

	if (!isdigit(*suffix) || *suffix == '\0') {
		TRACE("error firstch");
		goto enoent;
	}

	page = strtoul(suffix, &endptr, 10);
	if (*endptr != '\0') {
		TRACE("error lastch");
		goto enoent;
	}

	buffer = khttpd_malloc(KHTTPD_SDT_HISTORY_PAGE_SIZE);

	mtx_lock(&khttpd_sdt_history_lock);

	for (i = 0; i < KHTTPD_SDT_HISTORY_PAGES &&
		 khttpd_sdt_history_pages[i].seqno != page; ++i)
		; /* nothing */

	if (KHTTPD_SDT_HISTORY_PAGES <= i) {
		mtx_unlock(&khttpd_sdt_history_lock);
		TRACE("error nopage");
		goto enoent;
	}

	size = khttpd_sdt_history_pages[i].size *
	    sizeof(struct khttpd_sdt_history_entry);
	bcopy(khttpd_sdt_history_pages[i].contents, buffer, size);

	mtx_unlock(&khttpd_sdt_history_lock);

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);
	khttpd_response_set_body_bytes(response, buffer, size, khttpd_free);
	khttpd_response_add_field(response, "Content-Type", "%s",
	    "application/octet-stream");
	khttpd_set_response(receiver, request, response);

	return;

enoent:
	khttpd_set_not_found_response(receiver, request, FALSE);
	khttpd_free(buffer);
}

static void
khttpd_sdt_history_leaf_received_header(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{

	TRACE("enter");

	switch (khttpd_request_method(request)) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_sdt_history_leaf_get_or_head(receiver, request);
		break;

	case KHTTPD_METHOD_OPTIONS:
		/*
		 * XXX khttpd_set_not_found_response must be called if the
		 * specified page doesn't exist.
		 */
		khttpd_set_options_response(receiver, request, NULL,
		    "OPTIONS, HEAD, GET");
		break;

	default:
		khttpd_set_not_implemented_response(receiver, request, FALSE);
	}
}

static void
khttpd_sdt_history_index_get_or_head(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{
	struct mbuf *payload;
	struct khttpd_sdt_history_page *page;
	struct khttpd_response *response;
	int i;

	TRACE("enter");

	payload = m_get(M_WAITOK, MT_DATA);

	khttpd_mbuf_printf(payload, "{\"entriesPerPage\": %zd,\n"
	    "\"entrySize\": %zd,\n\"items\": [",
	    KHTTPD_SDT_HISTORY_ENTRIES_PER_PAGE,
	    sizeof(struct khttpd_sdt_history_entry));

	mtx_lock(&khttpd_sdt_history_lock);
	for (i = 0; i < KHTTPD_SDT_HISTORY_PAGES; ++i) {
		page = khttpd_sdt_history_pages + i;
		if (page->size == 0 || page->seqno == 0)
			continue;
		mtx_unlock(&khttpd_sdt_history_lock);

		khttpd_mbuf_printf(payload, "{\"page\": %u, "
		    "\"size\": %zd, \"href\": \"" KHTTPD_SDT_HISTORY_PREFIX
		    "/%u\", \"timestampMin\": %ju, \"timestampMax\": %ju}",
		    page->seqno, page->size, page->seqno,
		    (uintmax_t)page->contents[0].timestamp,
		    (uintmax_t)page->contents[page->size - 1].timestamp);

		mtx_lock(&khttpd_sdt_history_lock);
	}
	mtx_unlock(&khttpd_sdt_history_lock);

	khttpd_mbuf_printf(payload, "]}");

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);
	khttpd_response_set_body_mbuf(response, payload);
	khttpd_response_add_field(response, "Content-Type", "%s", 
	    "application/json");
	khttpd_set_response(receiver, request, response);
}

static void
khttpd_sdt_history_index_received_header(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{

	TRACE("enter");

	switch (khttpd_request_method(request)) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_sdt_history_index_get_or_head(receiver, request);
		break;

	case KHTTPD_METHOD_OPTIONS:
		khttpd_set_options_response(receiver, request, NULL,
		    "OPTIONS, HEAD, GET, POST");
		break;

	default:
		khttpd_set_not_implemented_response(receiver, request, FALSE);
	}
}

static void
khttpd_sdt_history_received_header(struct khttpd_receiver *receiver, 
    struct khttpd_request *request)
{
	const char *suffix;

	TRACE("enter %d", khttpd_socket_fd(khttpd_receiver_socket(receiver)));

	suffix = khttpd_request_suffix(request);
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		khttpd_sdt_history_index_received_header(receiver, request);
	else
		khttpd_sdt_history_leaf_received_header(receiver, request);
}

static void
khttpd_sdt_probe_json_encode(struct mbuf *output,
    struct khttpd_sdt_probe *probe)
{
	struct sdt_probe *ptr;
	struct sdt_argtype *arg;

	ptr = probe->probe;

	khttpd_mbuf_printf(output, "{\"provider\": ");
	khttpd_json_mbuf_append_cstring(output, ptr->prov->name);
	khttpd_mbuf_printf(output, ",\n\"module\": ");
	khttpd_json_mbuf_append_cstring(output, ptr->mod);
	khttpd_mbuf_printf(output, ",\n\"function\": ");
	khttpd_json_mbuf_append_cstring(output, ptr->func);
	khttpd_mbuf_printf(output, ",\n\"name\": ");
	khttpd_json_mbuf_append_cstring(output, ptr->name);
	khttpd_mbuf_printf(output, ",\n\"index\": %jd", (intmax_t)ptr->id);

	khttpd_mbuf_printf(output, ",\n\"arguments\": [ ");
	TAILQ_FOREACH(arg, &ptr->argtype_list, argtype_entry) {
		if (arg != TAILQ_FIRST(&ptr->argtype_list))
			khttpd_mbuf_printf(output, ", ");
		khttpd_mbuf_printf(output, "{\"type\": ");
		khttpd_json_mbuf_append_cstring(output, arg->type);
		if (arg->xtype != NULL) {
			khttpd_mbuf_printf(output, ", \"xtype\": ");
			khttpd_json_mbuf_append_cstring(output, arg->xtype);
		}
		khttpd_mbuf_printf(output, "}");
	}
	khttpd_mbuf_printf(output, " ] }");
}

static void
khttpd_sdt_probe_index_get_or_head(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{
	struct mbuf *payload;
	struct khttpd_response *response;
	struct khttpd_sdt_probe *probe;

	TRACE("enter");

	payload = m_get(M_WAITOK, MT_DATA);
	khttpd_mbuf_append_ch(payload, '{');

	khttpd_mbuf_printf(payload, "\n\"items\": [");
	TAILQ_FOREACH(probe, &khttpd_sdt_all_probes_list, list_entry) {
		if (probe != TAILQ_FIRST(&khttpd_sdt_all_probes_list))
			khttpd_mbuf_append_ch(payload, ',');
		khttpd_mbuf_append_ch(payload, '\n');
		khttpd_sdt_probe_json_encode(payload, probe);
	}
	if (!TAILQ_EMPTY(&khttpd_sdt_all_probes_list))
		khttpd_mbuf_append_ch(payload, '\n');
	khttpd_mbuf_append_ch(payload, ']');

	khttpd_mbuf_printf(payload, "\n}");

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);
	khttpd_response_set_body_mbuf(response, payload);
	khttpd_response_add_field(response, "Content-Type", "%s", 
	    "application/json");
	khttpd_set_response(receiver, request, response);
}

static void
khttpd_sdt_probe_index_received_header(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{

	TRACE("enter");

	switch (khttpd_request_method(request)) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_sdt_probe_index_get_or_head(receiver, request);
		break;

	case KHTTPD_METHOD_OPTIONS:
		khttpd_set_options_response(receiver, request, NULL,
		    "OPTIONS, HEAD, GET");
		break;

	default:
		khttpd_set_not_implemented_response(receiver, request, FALSE);
	}
}

static void
khttpd_sdt_probe_leaf_received_header(struct khttpd_receiver *receiver,
    struct khttpd_request *request)
{

	TRACE("enter");

	khttpd_set_not_found_response(receiver, request, FALSE);
}

static void
khttpd_sdt_probe_received_header(struct khttpd_receiver *receiver, 
    struct khttpd_request *request)
{
	const char *suffix;

	TRACE("enter %d", khttpd_socket_fd(khttpd_receiver_socket(receiver)));

	suffix = khttpd_request_suffix(request);
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		khttpd_sdt_probe_index_received_header(receiver, request);
	else
		khttpd_sdt_probe_leaf_received_header(receiver, request);
}

static void
khttpd_sdt_probe(uint32_t id, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	struct khttpd_sdt_history_page *page;
	struct khttpd_sdt_history_entry *entry;
	int current, seqno;

	TRACE("enter %d %#lx %#lx %#lx %#lx %#lx",
	    id, arg0, arg1, arg2, arg3, arg4);

	mtx_lock(&khttpd_sdt_history_lock);

	current = khttpd_sdt_history_current;
	page = khttpd_sdt_history_pages + current;
	if (KHTTPD_SDT_HISTORY_ENTRIES_PER_PAGE <= page->size) {
		if (KHTTPD_SDT_HISTORY_PAGES <= ++current)
			current = 0;
		khttpd_sdt_history_current = current;
		seqno = page->seqno + 1;
		page = khttpd_sdt_history_pages + current;
		page->seqno = seqno;
		page->size = 0;
	}

	entry = &page->contents[page->size++];
	entry->timestamp = get_cyclecount();
	entry->args[0] = arg0;
	entry->args[1] = arg1;
	entry->args[2] = arg2;
	entry->args[3] = arg3;
	entry->args[4] = arg4;
	entry->cpuid = PCPU_GET(cpuid);
	entry->tid = curthread->td_tid;
	entry->id = id;

	mtx_unlock(&khttpd_sdt_history_lock);
}

static struct sdt_provider *
khttpd_sdt_provider_find(const char *name)
{
	struct sdt_provider *ptr;
	uint32_t hash;
	
	TRACE("enter %s", name);

	hash = hash32_str(name, 0) & (KHTTPD_SDT_PROVIDER_HASH_SIZE - 1);
	TAILQ_FOREACH(ptr, &khttpd_sdt_providers[hash], prov_entry)
		if (strcmp(name, ptr->name) == 0)
			return (ptr);
	return (NULL);
}

static void
khttpd_sdt_provider_new(const char *name)
{
	struct sdt_provider *ptr, *provider;
	uint32_t hash;

	TRACE("enter %s", name);

	ptr = khttpd_sdt_provider_find(name);
	if (ptr != NULL) {
		++ptr->sdt_refs;
		return;
	}

	provider = khttpd_malloc(sizeof(*provider));
	provider->name = strdup(name, M_KHTTPD);
	provider->sdt_refs = 1;

	hash = hash32_str(name, 0) & (KHTTPD_SDT_PROVIDER_HASH_SIZE - 1);
	TAILQ_INSERT_TAIL(&khttpd_sdt_providers[hash], provider, prov_entry);
}

static void
khttpd_sdt_provider_free(const char *name)
{
	struct sdt_provider *ptr;
	uint32_t hash;
	
	TRACE("enter %s", name);

	hash = hash32_str(name, 0) & (KHTTPD_SDT_PROVIDER_HASH_SIZE - 1);
	TAILQ_FOREACH(ptr, &khttpd_sdt_providers[hash], prov_entry)
		if (strcmp(name, ptr->name) == 0) {
			if (1 < ptr->sdt_refs)
				--ptr->sdt_refs;
			else {
				TAILQ_REMOVE(&khttpd_sdt_providers[hash],
				    ptr, prov_entry);
				khttpd_free(ptr->name);
				khttpd_free(ptr);
			}

			return;
		}
}

static struct khttpd_sdt_probe *
khttpd_sdt_probe_new(struct khttpd_sdt_ko_file *file, struct sdt_probe *peer)
{
	struct khttpd_sdt_probe *probe, *next;

	probe = uma_zalloc(khttpd_sdt_probe_zone, M_WAITOK);
	probe->probe = peer;
	SPLAY_INSERT(khttpd_sdt_probe_tree, &khttpd_sdt_all_probes_tree,
	    probe);
	next = SPLAY_NEXT(khttpd_sdt_probe_tree, &khttpd_sdt_all_probes_tree,
	    probe);
	if (next == NULL)
		TAILQ_INSERT_TAIL(&khttpd_sdt_all_probes_list, probe,
		    list_entry);
	else
		TAILQ_INSERT_BEFORE(next, probe, list_entry);
	LIST_INSERT_HEAD(&file->probes, probe, file_list_entry);

	return (probe);
}

static void
khttpd_sdt_kld_load(void *arg, struct linker_file *file)
{
	struct sdt_argtype **argt, **argt_begin, **argt_end;
	struct sdt_provider **prov, **prov_begin, **prov_end;
	struct sdt_probe **prob, **prob_begin, **prob_end;
	struct khttpd_sdt_ko_file *filep;
	int error;

	TRACE("enter %s", file->filename);

	error = linker_file_lookup_set(file, "sdt_providers_set", &prov_begin,
	    &prov_end, NULL);
	if (error != 0) {
		TRACE("error sdt_providers_set %d", error);
	} else
		for (prov = prov_begin; prov < prov_end; ++prov)
			khttpd_sdt_provider_new((*prov)->name);

	error = linker_file_lookup_set(file, "sdt_probes_set", &prob_begin,
	    &prob_end, NULL);
	if (error != 0) {
		TRACE("error sdt_probes_set %d", error);

	} else {
		filep = khttpd_sdt_ko_file_add(file);

		for (prob = prob_begin; prob < prob_end; ++prob) {
			(*prob)->sdtp_lf = file;
			TAILQ_INIT(&(*prob)->argtype_list);
			khttpd_sdt_probe_new(filep, *prob);
		}
	}

	error = linker_file_lookup_set(file, "sdt_argtypes_set", &argt_begin,
	    &argt_end, NULL);
	if (error != 0) {
		TRACE("error sdt_argtypes_set %d", error);
	} else
		for (argt = argt_begin; argt < argt_end; ++argt) {
			++(*argt)->probe->n_args;
			TAILQ_INSERT_TAIL(&(*argt)->probe->argtype_list,
			    *argt, argtype_entry);
		}
}

static void
khttpd_sdt_kld_unload_try(void *arg, struct linker_file *file, int *error)
{
	struct sdt_provider **prov, **prov_begin, **prov_end;

	TRACE("enter %d", *error);

	if (*error != 0)
		return;

	if (linker_file_lookup_set(file, "sdt_providers_set", &prov_begin,
		&prov_end, NULL) != 0)
		return;

	for (prov = prov_begin; prov < prov_end; prov++)
		khttpd_sdt_provider_free((*prov)->name);

	khttpd_sdt_ko_file_remove(file);
}

static int khttpd_sdt_on_each_linked_file(linker_file_t file, void *context)
{

	khttpd_sdt_kld_load(context, file);
	return (0);
}

int khttpd_sdt_mount(struct khttpd_route *root, const char *prefix)
{
	int error;

	/* XXX: prefix and KHTTPD_SDT_(PROBE|HISTORY)_PREFIX should be
	   concatenated */

	error = khttpd_route_add(root, KHTTPD_SDT_PROBE_PREFIX,
	    &khttpd_route_type_sdt_probe);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to add route %s: %d\n",
		     KHTTPD_SDT_PROBE_PREFIX, error);
		return (error);
	}

	error = khttpd_route_add(root, KHTTPD_SDT_HISTORY_PREFIX,
	    &khttpd_route_type_sdt_history);
	if (error != 0) {
		log(LOG_WARNING, "khttpd: failed to add route %s: %d\n",
		    KHTTPD_SDT_HISTORY_PREFIX, error);
		return (error);
	}

	return (0);
}

static int
khttpd_sdt_load_proc(void *arg)
{
	int i;

	TRACE("enter");

	if (sdt_probe_func != sdt_probe_stub)
		return (EBUSY);
	sdt_probe_func = khttpd_sdt_probe;

	khttpd_sdt_probe_zone = uma_zcreate("khttpd-sdt-probe",
	    sizeof(struct khttpd_sdt_probe), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	for (i = 0; i < KHTTPD_SDT_HISTORY_PAGES; ++i)
		khttpd_sdt_history_pages[i].contents =
		    khttpd_malloc(KHTTPD_SDT_HISTORY_PAGE_SIZE);
	khttpd_sdt_history_pages[0].size =
	    KHTTPD_SDT_HISTORY_ENTRIES_PER_PAGE;

	mtx_init(&khttpd_sdt_history_lock, "khttpd-sdt-history-lock", NULL,
	    0);

	for (i = 0; i < sizeof(khttpd_sdt_providers) /
		 sizeof(khttpd_sdt_providers[0]); ++i)
		TAILQ_INIT(&khttpd_sdt_providers[i]);
	TAILQ_INIT(&khttpd_sdt_all_probes_list);
	SPLAY_INIT(&khttpd_sdt_all_probes_tree);

	for (i = 0; i < sizeof(khttpd_sdt_ko_files) /
		 sizeof(khttpd_sdt_ko_files[0]); ++i)
		SLIST_INIT(&khttpd_sdt_ko_files[0]);

	khttpd_sdt_kld_load_tag = EVENTHANDLER_REGISTER(kld_load,
	    khttpd_sdt_kld_load, NULL, EVENTHANDLER_PRI_ANY);
	khttpd_sdt_kld_unload_try_tag = EVENTHANDLER_REGISTER(kld_unload_try,
	    khttpd_sdt_kld_unload_try, NULL, EVENTHANDLER_PRI_ANY);

	linker_file_foreach(khttpd_sdt_on_each_linked_file, NULL);

	return (0);
}

static int
khttpd_sdt_unload_proc(void *arg)
{
	struct sdt_provider *provider;
	struct khttpd_sdt_ko_file *file;
	struct khttpd_sdt_probe *probe;
	int i;

	TRACE("enter");

	if (sdt_probe_func == khttpd_sdt_probe)
		sdt_probe_func = sdt_probe_stub;

	EVENTHANDLER_DEREGISTER(kld_load, khttpd_sdt_kld_load_tag);
	EVENTHANDLER_DEREGISTER(kld_unload_try,
	    khttpd_sdt_kld_unload_try_tag);

	for (i = 0; i < sizeof(khttpd_sdt_providers) /
		 sizeof(khttpd_sdt_providers[0]); ++i)
		while ((provider = TAILQ_FIRST(&khttpd_sdt_providers[i])) !=
		    NULL) {
			TAILQ_REMOVE(&khttpd_sdt_providers[i], provider,
			    prov_entry);
			khttpd_free(provider->name);
			khttpd_free(provider);
		}

	while ((probe = TAILQ_FIRST(&khttpd_sdt_all_probes_list)) != NULL) {
		TAILQ_REMOVE(&khttpd_sdt_all_probes_list, probe, list_entry);
		probe->probe->id = 0;
		uma_zfree(khttpd_sdt_probe_zone, probe);
	}

	uma_zdestroy(khttpd_sdt_probe_zone);

	for (i = 0; i < sizeof(khttpd_sdt_ko_files) /
		 sizeof(khttpd_sdt_ko_files[0]); ++i) {
		while ((file = SLIST_FIRST(&khttpd_sdt_ko_files[i])) !=
		    NULL) {
			SLIST_REMOVE_HEAD(&khttpd_sdt_ko_files[i], hash_link);
			khttpd_free(file);
		}
	}

	for (i = 0; i < KHTTPD_SDT_HISTORY_PAGES; ++i)
		khttpd_free(khttpd_sdt_history_pages[i].contents);

	mtx_destroy(&khttpd_sdt_history_lock);

	return (0);
}

static int
khttpd_sdt_quiesce_proc(void *arg)
{
	struct khttpd_sdt_probe *probe;

	TRACE("enter");

	TAILQ_FOREACH(probe, &khttpd_sdt_all_probes_list, list_entry)
		if (probe->probe->id != 0) {
			printf("khttpd: probe %s:%s:%s:%s is still enabled\n",
			    probe->probe->prov->name, probe->probe->mod,
			    probe->probe->func, probe->probe->name);
			return (EBUSY);
		}

	return (0);
}

int
khttpd_sdt_load(void)
{

	return (khttpd_run_proc(khttpd_sdt_load_proc, NULL));
}

void
khttpd_sdt_unload(void)
{

	khttpd_run_proc(khttpd_sdt_unload_proc, NULL);
}

int
khttpd_sdt_quiesce(void)
{

	return (khttpd_run_proc(khttpd_sdt_quiesce_proc, NULL));
}
