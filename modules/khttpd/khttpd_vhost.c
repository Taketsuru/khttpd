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

#include "khttpd_vhost.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <vm/uma.h>

#include "khttpd_costruct.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_string.h"
#include "khttpd_json.h"
#include "khttpd_port.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"

struct khttpd_vhost_tie {
	LIST_ENTRY(khttpd_vhost_tie)	port_link;
	LIST_ENTRY(khttpd_vhost_tie)	server_link;
	struct khttpd_port		*port;
	struct khttpd_server		*server;
};

LIST_HEAD(khttpd_vhost_tie_list, khttpd_vhost_tie);

struct khttpd_vhost_port_data {
	struct khttpd_vhost_tie_list ties;
};

struct khttpd_server_name {
	char		*canonical_name;
	char		**exact_aliases;
	int		exact_alias_count;
};

struct khttpd_vhost_server_data {
	struct khttpd_vhost_tie_list ties;
	struct khttpd_server_name *name;
	u_int	name_update_count;
};

static struct rwlock khttpd_vhost_lock;
static uma_zone_t khttpd_vhost_tie_zone;
static khttpd_costruct_key_t khttpd_vhost_server_key;
static khttpd_costruct_key_t khttpd_vhost_port_key;

RW_SYSINIT(khttpd_vhost_lock, &khttpd_vhost_lock, "khttpd-vhost");

struct khttpd_server_name *
khttpd_vhost_server_name_new(void)
{
	struct khttpd_server_name *name;

	name = khttpd_malloc(sizeof(struct khttpd_server_name));
	name->canonical_name = NULL;
	name->exact_aliases = NULL;
	name->exact_alias_count = 0;
	return (name);
}

void
khttpd_vhost_server_name_delete(struct khttpd_server_name *name)
{

	if (name == NULL)
		return;

	khttpd_free(name->canonical_name);
	if (0 < name->exact_alias_count)
		khttpd_free(name->exact_aliases[0]);
	khttpd_free(name->exact_aliases);
	khttpd_free(name);
}

void
khttpd_vhost_set_canonical_name(struct khttpd_server_name *name,
    const char *value)
{
	char *copied_value;

	copied_value = khttpd_strdup(value);
	khttpd_free(name->canonical_name);
	name->canonical_name = copied_value;
}

const char *
khttpd_vhost_get_canonical_name(struct khttpd_server_name *name)
{

	return (name->canonical_name);
}

void 
khttpd_vhost_set_exact_alias_list(struct khttpd_server_name *name,
    const char **aliases, int n)
{
	char *bufp;
	size_t size;
	int i;

	KASSERT(0 <= n, ("n=%d", n));

	if (0 < name->exact_alias_count)
		khttpd_free(name->exact_aliases[0]);
	khttpd_free(name->exact_aliases);

	name->exact_alias_count = n;

	if (n == 0) {
		name->exact_aliases = NULL;
		return;
	}

	name->exact_aliases = khttpd_malloc(n * sizeof(char *));

	size = 0;
	for (i = 0; i < n; ++i)
		size += strlen(aliases[i]) + 1;

	bufp = khttpd_malloc(size);
	for (i = 0; i < n; ++i) {
		name->exact_aliases[i] = bufp;
		strcpy(bufp, aliases[i]);
		bufp += strlen(bufp) + 1;
	}
}

int
khttpd_vhost_get_exact_alias_list_length(struct khttpd_server_name *name)
{

	return (name->exact_alias_count);
}

const char *
khttpd_vhost_get_exact_alias(struct khttpd_server_name *name, int index)
{

	KASSERT(0 <= index && index < name->exact_alias_count,
	    ("index=%d, count=%d", index, name->exact_alias_count));
	return (name->exact_aliases[index]);
}

void
khttpd_vhost_set_server_name(struct khttpd_server *server,
    struct khttpd_server_name *name)
{
	struct khttpd_server_name *old_name;
	struct khttpd_vhost_server_data *data;

	KASSERT(name != NULL, ("name is NULL"));

	data = khttpd_costruct_get(server, khttpd_vhost_server_key);

	rw_wlock(&khttpd_vhost_lock);
	old_name = data->name;
	data->name = name;
	++data->name_update_count;
	rw_wunlock(&khttpd_vhost_lock);

	khttpd_vhost_server_name_delete(old_name);
}

struct khttpd_server_name *
khttpd_vhost_copy_server_name(struct khttpd_server *server)
{
	struct khttpd_server_name *old_name, *result;
	struct khttpd_vhost_server_data *data;
	char *bufp;
	size_t canon_size, exact_aliases_size;
	u_int update_count;
	int exact_alias_count, i;

	data = khttpd_costruct_get(server, khttpd_vhost_server_key);
	result = khttpd_malloc(sizeof(struct khttpd_server_name));

	for (;;) {
		rw_rlock(&khttpd_vhost_lock);
		old_name = data->name;
		update_count = data->name_update_count;
		canon_size = strlen(old_name->canonical_name) + 1;
		exact_alias_count = old_name->exact_alias_count;
		exact_aliases_size = 0;
		for (i = 0; i < exact_alias_count; ++i)
			exact_aliases_size += 
			    strlen(old_name->exact_aliases[i]) + 1;
		rw_runlock(&khttpd_vhost_lock);

		result->canonical_name = khttpd_malloc(canon_size);
		result->exact_alias_count = exact_alias_count;
		if (exact_alias_count == 0) {
			result->exact_aliases = NULL;
		} else {
			result->exact_aliases =
			    khttpd_malloc(exact_alias_count * sizeof(char *));
			result->exact_aliases[0] =
			    khttpd_malloc(exact_aliases_size);
		}

		rw_rlock(&khttpd_vhost_lock);
		if (data->name_update_count == update_count) {
			bcopy(old_name->canonical_name, result->canonical_name,
			    canon_size);
			bcopy(old_name->exact_aliases[0],
			    result->exact_aliases[0], exact_aliases_size);
			bufp = result->exact_aliases[0];
			for (i = 1; i < exact_alias_count; ++i) {
				bufp += strlen(bufp) + 1;
				result->exact_aliases[i] = bufp;
			}
			rw_runlock(&khttpd_vhost_lock);
			break;
		}
		rw_runlock(&khttpd_vhost_lock);

		khttpd_free(result->canonical_name);
		if (0 < exact_alias_count)
			khttpd_free(result->exact_aliases[0]);
		khttpd_free(result->exact_aliases);
	}

	return (result);
}

void
khttpd_vhost_clear_server_list(struct khttpd_port *port)
{
	struct khttpd_vhost_tie_list old_list;
	struct khttpd_vhost_port_data *data;
	struct khttpd_vhost_tie *tie, *ttie;

	data = khttpd_costruct_get(port, khttpd_vhost_port_key);
	LIST_INIT(&old_list);

	rw_wlock(&khttpd_vhost_lock);

	LIST_SWAP(&old_list, &data->ties, khttpd_vhost_tie, port_link);
	LIST_FOREACH(tie, &old_list, port_link)
		LIST_REMOVE(tie, server_link);

	rw_wunlock(&khttpd_vhost_lock);

	LIST_FOREACH_SAFE(tie, &old_list, port_link, ttie)
		uma_zfree(khttpd_vhost_tie_zone, tie);
}

void
khttpd_vhost_clear_port_list(struct khttpd_server *server)
{
	struct khttpd_vhost_tie_list old_list;
	struct khttpd_vhost_server_data *data;
	struct khttpd_vhost_tie *tie, *ttie;

	data = khttpd_costruct_get(server, khttpd_vhost_server_key);
	LIST_INIT(&old_list);

	rw_wlock(&khttpd_vhost_lock);

	LIST_SWAP(&old_list, &data->ties, khttpd_vhost_tie, server_link);
	LIST_FOREACH(tie, &old_list, server_link)
		LIST_REMOVE(tie, port_link);

	rw_wunlock(&khttpd_vhost_lock);

	LIST_FOREACH_SAFE(tie, &old_list, server_link, ttie)
		uma_zfree(khttpd_vhost_tie_zone, tie);
}

static int
khttpd_vhost_port_ctor(void *host, void *arg)
{
	struct khttpd_vhost_port_data *data;

	data = khttpd_costruct_get(host, khttpd_vhost_port_key);
	LIST_INIT(&data->ties);

	return (0);
}

static void
khttpd_vhost_port_dtor(void *host, void *arg)
{

	khttpd_vhost_clear_server_list(host);
}

static int
khttpd_vhost_server_ctor(void *host, void *arg)
{
	struct khttpd_vhost_server_data *data;

	data = khttpd_costruct_get(host, khttpd_vhost_server_key);
	LIST_INIT(&data->ties);
	data->name = khttpd_vhost_server_name_new();
	data->name_update_count = 0;

	return (0);
}

static void
khttpd_vhost_server_dtor(void *host, void *arg)
{
	struct khttpd_vhost_server_data *data;

	khttpd_vhost_clear_port_list(host);

	data = khttpd_costruct_get(host, khttpd_vhost_server_key);
	khttpd_vhost_server_name_delete(data->name);
}

#ifdef INVARIANTS
static int
khttpd_vhost_compare_ports(const void *x, const void *y)
{

	return (x == y ? 0 : x < y ? -1 : 1);
}

static boolean_t
khttpd_vhost_is_valid_port_list(struct khttpd_port **port_list, int len)
{
	struct khttpd_port **buf;
	int i;

	buf = khttpd_malloc(len * sizeof(struct khttpd_port *));
	bcopy(port_list, buf, len * sizeof(struct khttpd_port *));
	qsort(buf, len, sizeof(struct khttpd_port *),
	    khttpd_vhost_compare_ports);

	for (i = 0; i < len - 1; ++i)
		if (buf[i] == buf[i + 1])
			break;

	khttpd_free(buf);

	return (i == len - 1);
}
#endif

void
khttpd_vhost_set_port_list(struct khttpd_server *server,
    struct khttpd_port **port_list, int len)
{
	struct khttpd_vhost_tie_list old_list;
	struct khttpd_port *port;
	struct khttpd_vhost_server_data *data;
	struct khttpd_vhost_tie **new_ties, *tie, *ttie;
	struct khttpd_vhost_port_data *port_data;
	int i;

	KHTTPD_ENTRY("%s(%p,,%d)", __func__, server, len);
	KASSERT(khttpd_vhost_is_valid_port_list(port_list, len),
		("duplicated entries in the port list"));

	data = khttpd_costruct_get(server, khttpd_vhost_server_key);
	LIST_INIT(&old_list);

	new_ties = khttpd_malloc(sizeof(*new_ties) * len);
	bzero(new_ties, sizeof(*new_ties) * len);
	for (i = 0; i < len; ++i)
		new_ties[i] = uma_zalloc(khttpd_vhost_tie_zone, 0);

	rw_wlock(&khttpd_vhost_lock);

	LIST_SWAP(&old_list, &data->ties, khttpd_vhost_tie, server_link);
	LIST_FOREACH(tie, &old_list, server_link)
		LIST_REMOVE(tie, port_link);

	for (i = 0; i < len; ++i) {
		tie = new_ties[i];
		port = port_list[i];

		tie->server = server;
		tie->port = port;

		port_data = khttpd_costruct_get(port, khttpd_vhost_port_key);

		LIST_INSERT_HEAD(&port_data->ties, tie, port_link);
		LIST_INSERT_HEAD(&data->ties, tie, server_link);
	}

	rw_wunlock(&khttpd_vhost_lock);

	khttpd_free(new_ties);

	LIST_FOREACH_SAFE(tie, &old_list, server_link, ttie)
		uma_zfree(khttpd_vhost_tie_zone, tie);
}

#ifdef INVARIANTS
static int
khttpd_vhost_compare_servers(const void *x, const void *y)
{

	return (x == y ? 0 : x < y ? -1 : 1);
}

static boolean_t
khttpd_vhost_is_valid_server_list(struct khttpd_server **server_list, int len)
{
	struct khttpd_server **buf;
	int i;

	buf = khttpd_malloc(len * sizeof(struct khttpd_server *));
	bcopy(server_list, buf, len * sizeof(struct khttpd_server *));
	qsort(buf, len, sizeof(struct khttpd_server *),
	    khttpd_vhost_compare_servers);

	for (i = 0; i < len - 1; ++i)
		if (server_list[i] == server_list[i + 1])
			break;

	khttpd_free(buf);

	return (i == len - 1);
}
#endif

void
khttpd_vhost_set_server_list(struct khttpd_port *port,
    struct khttpd_server **server_list, int len)
{
	struct khttpd_vhost_tie_list old_list;
	struct khttpd_server *server;
	struct khttpd_vhost_port_data *data;
	struct khttpd_vhost_tie **new_ties, *tie, *ttie;
	struct khttpd_vhost_server_data *server_data;
	int i;

	KASSERT(khttpd_vhost_is_valid_server_list(server_list, len),
	    ("invalid server list"));

	data = khttpd_costruct_get(port, khttpd_vhost_port_key);
	LIST_INIT(&old_list);

	new_ties = khttpd_malloc(sizeof(*new_ties) * len);
	bzero(new_ties, sizeof(*new_ties) * len);
	for (i = 0; i < len; ++i)
		new_ties[i] = uma_zalloc(khttpd_vhost_tie_zone, 0);

	rw_wlock(&khttpd_vhost_lock);

	LIST_SWAP(&old_list, &data->ties, khttpd_vhost_tie, port_link);

	LIST_FOREACH(tie, &old_list, port_link)
		LIST_REMOVE(tie, server_link);

	for (i = 0; i < len; ++i) {
		tie = new_ties[i];
		server = server_list[i];

		tie->server = server;
		tie->port = port;

		server_data = khttpd_costruct_get(server,
		    khttpd_vhost_server_key);

		LIST_INSERT_HEAD(&server_data->ties, tie, server_link);
		LIST_INSERT_HEAD(&data->ties, tie, port_link);
	}

	rw_wunlock(&khttpd_vhost_lock);

	khttpd_free(new_ties);

	LIST_FOREACH_SAFE(tie, &old_list, port_link, ttie)
		uma_zfree(khttpd_vhost_tie_zone, tie);
}

struct khttpd_server *
khttpd_vhost_find_server(struct khttpd_port *port, const char *host_begin,
	const char *host_end)
{
	struct khttpd_server *server;
	struct khttpd_vhost_port_data *data;
	struct khttpd_vhost_server_data *server_data;
	struct khttpd_vhost_tie *tie;
	char *canonical_name, **exact_aliases;
	size_t host_len;
	int exact_alias_count, i;

	KHTTPD_ENTRY("%s(%p,%s)", __func__, port, khttpd_ktr_printf("%.*s",
		(int)(host_end - host_begin), host_begin));

	data = khttpd_costruct_get(port, khttpd_vhost_port_key);
	host_len = host_end - host_begin;

	rw_rlock(&khttpd_vhost_lock);

	LIST_FOREACH(tie, &data->ties, port_link) {
		server = tie->server;
		server_data = khttpd_costruct_get(server,
		    khttpd_vhost_server_key);

		/*
		 * Check whether the canonical server name matches the given
		 * host name.
		 */
		canonical_name = server_data->name->canonical_name;
		if (canonical_name != NULL && 
		    strncasecmp(host_begin, canonical_name, host_len) == 0 &&
		    canonical_name[host_len] == '\0') {
			khttpd_server_acquire(server);
			goto found;
		}

		/*
		 * Check whether one of the alias names matches the given host
		 * name.
		 */
		exact_alias_count = server_data->name->exact_alias_count;
		exact_aliases = server_data->name->exact_aliases;
		for (i = 0; i < exact_alias_count; ++i)
			if (strncasecmp(host_begin, exact_aliases[i], 
				host_len) == 0 &&
			    exact_aliases[i][host_len] == '\0') {
				khttpd_server_acquire(server);
				goto found;
			}
	}
	server = NULL;
 found:

	rw_runlock(&khttpd_vhost_lock);

	return (server);
}

struct khttpd_vhost_tie *
khttpd_vhost_port_iterator(struct khttpd_server *server)
{
	struct khttpd_vhost_server_data *data;

	data = khttpd_costruct_get(server, khttpd_vhost_server_key);
	return (LIST_FIRST(&data->ties));
}

struct khttpd_vhost_tie *
khttpd_vhost_port_iterator_next(struct khttpd_vhost_tie *tie,
    struct khttpd_port **port_out)
{

	*port_out = tie->port;
	return (LIST_NEXT(tie, server_link));
}

static int
khttpd_vhost_load(void)
{

	khttpd_vhost_tie_zone = uma_zcreate("khttpd-tie",
	    sizeof(struct khttpd_vhost_tie), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	return (0);
}

static void
khttpd_vhost_unload(void)
{

	uma_zdestroy(khttpd_vhost_tie_zone);
}

KHTTPD_INIT(khttpd_vhost, khttpd_vhost_load, khttpd_vhost_unload,
	KHTTPD_INIT_PHASE_RUN);

static int
khttpd_vhost_register_costructs(void)
{

	khttpd_vhost_server_key = khttpd_costruct_register
	    (khttpd_server_costruct_info, 
		sizeof(struct khttpd_vhost_server_data),
		khttpd_vhost_server_ctor, khttpd_vhost_server_dtor, NULL);

	khttpd_vhost_port_key = khttpd_costruct_register
	    (khttpd_port_costruct_info, sizeof(struct khttpd_vhost_port_data),
		khttpd_vhost_port_ctor, khttpd_vhost_port_dtor, NULL);

	return (0);
}

KHTTPD_INIT(khttpd_vhost, khttpd_vhost_register_costructs, NULL,
	KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS);

