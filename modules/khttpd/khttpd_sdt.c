/*-
 * Copyright (c) 2015 Taketsuru <taketsuru11@gmail.com>.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <sys/linker.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sdt.h>

#include <vm/uma.h>

#include "khttpd.h"
#include "khttpd_private.h"

#ifndef KHTTPD_SDT_PREFIX
#define KHTTPD_SDT_PREFIX KHTTPD_SYS_PREFIX "/sdt"
#endif

#define KHTTPD_SDT_PROBE "/probe"
#define KHTTPD_SDT_CHANNEL "/chan"

/* --------------------------------------------------------- type definitions */

/* ---------------------------------------------------- prototype declrations */

static void khttpd_sdt_received_header(struct khttpd_socket *socket, 
    struct khttpd_request *request);

/* ----------------------------------------------------- variable definitions */

static struct khttpd_route_type khttpd_route_type_sdt = {
	.name = "sdt",
	.received_header_fn = khttpd_sdt_received_header
};

static TAILQ_HEAD(, sdt_provider) khttpd_sdt_providers;
static eventhandler_tag khttpd_sdt_kld_load_tag;
static eventhandler_tag khttpd_sdt_kld_unload_try_tag;

static void
khttpd_sdt_get_or_head(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");

	khttpd_send_not_found_response(socket, request, FALSE);
}

static void
khttpd_sdt_put(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");

	khttpd_send_not_found_response(socket, request, FALSE);
}

static void khttpd_sdt_options(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");

	khttpd_send_not_found_response(socket, request, FALSE);
}

static void khttpd_sdt_received_header(struct khttpd_socket *socket, 
    struct khttpd_request *request)
{
	TRACE("enter %d", khttpd_socket_fd(socket));

	switch (khttpd_request_method(request)) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_sdt_get_or_head(socket, request);
		break;

	case KHTTPD_METHOD_PUT:
		khttpd_sdt_put(socket, request);
		break;

	case KHTTPD_METHOD_OPTIONS:
		khttpd_sdt_options(socket, request);
		break;

	default:
		khttpd_send_not_implemented_response(socket, request, FALSE);
	}
}

static void
khttpd_sdt_probe(uint32_t id, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{
	TRACE("enter %d %#lx %#lx %#lx %#lx %#lx",
	    id, arg0, arg1, arg2, arg3, arg4);
}

static struct sdt_provider *
khttpd_sdt_find_provider(const char *name)
{
	struct sdt_provider *ptr;
	
	TRACE("enter %s", name);

	TAILQ_FOREACH(ptr, &khttpd_sdt_providers, prov_entry)
		if (strcmp(name, ptr->name) == 0)
			return (ptr);
	return (NULL);
}

static
void khttpd_sdt_provider_new(const char *name)
{
	struct sdt_provider *ptr, *provider;

	TRACE("enter %s", name);

	ptr = khttpd_sdt_find_provider(name);
	if (ptr != NULL) {
		++ptr->sdt_refs;
		return;
	}

	provider = malloc(sizeof(*provider), M_KHTTPD, M_WAITOK);
	provider->name = strdup(name, M_KHTTPD);
	provider->sdt_refs = 1;

	TAILQ_INSERT_TAIL(&khttpd_sdt_providers, provider, prov_entry);
}

static void
khttpd_sdt_kld_load(void *arg, struct linker_file *file)
{
	struct sdt_argtype **argt, **argt_begin, **argt_end;
	struct sdt_provider **prov, **prov_begin, **prov_end;
	struct sdt_probe **prob, **prob_begin, **prob_end;
	int error;

	TRACE("enter");

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
	} else
		for (prob = prob_begin; prob < prob_end; ++prob) {
			(*prob)->sdtp_lf = file;
			TAILQ_INIT(&(*prob)->argtype_list);
			(*prob)->prov =
			    khttpd_sdt_find_provider((*prob)->prov->name);
			TRACE("prove %s:%s:%s:%s",
			    (*prob)->prov->name, (*prob)->mod, (*prob)->func,
			    (*prob)->name);
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
	struct sdt_provider *prov, **provp, **prov_begin, **prov_end;

	TRACE("enter %d", *error);

	if (*error != 0)
		return;

	if (linker_file_lookup_set(file, "sdt_providers_set", &prov_begin,
		&prov_end, NULL) != 0)
		return;

	for (provp = prov_begin; provp < prov_end; provp++) {
		prov = khttpd_sdt_find_provider((*provp)->name);
		if (prov == NULL)
			continue;

		if (1 < prov->sdt_refs)
			--prov->sdt_refs;
		else {
			TAILQ_REMOVE(&khttpd_sdt_providers, prov, prov_entry);
			free(prov->name, M_KHTTPD);
			free(prov, M_KHTTPD);
		}
	}
}

static int khttpd_sdt_on_each_linked_file(linker_file_t file, void *context)
{
	khttpd_sdt_kld_load(context, file);
	return (0);
}

static int
khttpd_sdt_load_proc(void *arg)
{
	int error;

	TRACE("enter");

	if (sdt_probe_func != sdt_probe_stub)
		return (EBUSY);
	sdt_probe_func = khttpd_sdt_probe;

	TAILQ_INIT(&khttpd_sdt_providers);

	khttpd_sdt_kld_load_tag = EVENTHANDLER_REGISTER(kld_load,
	    khttpd_sdt_kld_load, NULL, EVENTHANDLER_PRI_ANY);
	khttpd_sdt_kld_unload_try_tag = EVENTHANDLER_REGISTER(kld_unload_try,
	    khttpd_sdt_kld_unload_try, NULL, EVENTHANDLER_PRI_ANY);

	linker_file_foreach(khttpd_sdt_on_each_linked_file, NULL);

	error = khttpd_route_add(&khttpd_route_root, KHTTPD_SDT_PREFIX,
	    &khttpd_route_type_sdt);
	if (error != 0)
		printf("khttpd: failed to add route " KHTTPD_SDT_PREFIX
		    ": %d\n", error);

	return (error);
}

static int
khttpd_sdt_unload_proc(void *arg)
{
	struct sdt_provider *provider;
	struct khttpd_route *route;

	TRACE("enter");

	route = khttpd_route_find(&khttpd_route_root, KHTTPD_SDT_PREFIX, NULL);
	if (route != NULL)
		khttpd_route_remove(route);

	if (sdt_probe_func == khttpd_sdt_probe)
		sdt_probe_func = sdt_probe_stub;

	EVENTHANDLER_DEREGISTER(kld_load, khttpd_sdt_kld_load_tag);
	EVENTHANDLER_DEREGISTER(kld_unload_try, khttpd_sdt_kld_unload_try_tag);

	while ((provider = TAILQ_FIRST(&khttpd_sdt_providers)) != NULL) {
		TAILQ_REMOVE(&khttpd_sdt_providers, provider, prov_entry);
		free(provider, M_KHTTPD);
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
