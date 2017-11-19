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

#include "khttpd_ctrl.h"

#include <sys/param.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>

#include "khttpd.h"
#include "khttpd_costruct.h"
#include "khttpd_http.h"
#include "khttpd_init.h"
#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_main.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_problem.h"
#include "khttpd_rewriter.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_uuid.h"
#include "khttpd_vhost.h"
#include "khttpd_webapi.h"

#define KHTTPD_CTRL_VERSION "1"
#define KHTTPD_CTRL_PATH_PREFIX "/sys/khttpd/" KHTTPD_CTRL_VERSION "/"
#define KHTTPD_CTRL_PATH_REWRITERS KHTTPD_CTRL_PATH_PREFIX "rewriters"
#define KHTTPD_CTRL_PATH_PORTS KHTTPD_CTRL_PATH_PREFIX "ports"
#define KHTTPD_CTRL_PATH_SERVERS KHTTPD_CTRL_PATH_PREFIX "servers"
#define KHTTPD_CTRL_PATH_LOCATIONS KHTTPD_CTRL_PATH_PREFIX "locations"

#ifndef KHTTPD_CTRL_MAX_JSON_DEPTH
#define KHTTPD_CTRL_MAX_JSON_DEPTH 16
#endif

#ifndef KHTTPD_CTRL_MAX_DATA_SIZE
#define KHTTPD_CTRL_MAX_DATA_SIZE 65536ul
#endif
CTASSERT(KHTTPD_CTRL_MAX_DATA_SIZE <= INT_MAX);

#ifndef KHTTPD_LOCATION_TYPE_HASH_TABLE_SIZE
#define KHTTPD_LOCATION_TYPE_HASH_TABLE_SIZE	32
#endif

#ifndef KHTTPD_OBJ_TYPE_TABLE_SIZE_MIN
#define KHTTPD_OBJ_TYPE_TABLE_SIZE_MIN	8
#endif

struct khttpd_ctrl_leaf {
	LIST_ENTRY(khttpd_ctrl_leaf) link;
	SLIST_ENTRY(khttpd_ctrl_leaf) hlink;
	void		*object;
	u_char		uuid[KHTTPD_UUID_SIZE];
};

LIST_HEAD(khttpd_ctrl_leaf_list, khttpd_ctrl_leaf);
SLIST_HEAD(khttpd_ctrl_leaf_slist, khttpd_ctrl_leaf);

typedef void (*khttpd_ctrl_obj_fn_t)(void *);
typedef int (*khttpd_ctrl_json_io_t)(void *, struct khttpd_mbuf_json *,
    struct khttpd_problem_property *, struct khttpd_json *);
typedef int (*khttpd_ctrl_json_out_t)(void *, struct khttpd_mbuf_json *);

struct khttpd_obj_type {
	struct khttpd_ctrl_leaf_list	leafs;
	struct sbuf			allowed_node_methods;
	struct sbuf			allowed_leaf_methods;
	const char			*name;
	struct khttpd_location		*node;
	struct khttpd_ctrl_leaf_slist	*table;
	khttpd_ctrl_obj_fn_t		show;
	khttpd_ctrl_obj_fn_t		hide;
	khttpd_ctrl_obj_fn_t		acquire;
	khttpd_ctrl_obj_fn_t		release;
	khttpd_ctrl_json_io_t		create;
	khttpd_ctrl_json_out_t		delete;
	khttpd_ctrl_json_out_t		get_index;
	khttpd_ctrl_json_out_t		get;
	khttpd_ctrl_json_io_t		put;
	khttpd_costruct_key_t		leaf_ptr_key;
	unsigned			table_size;
	unsigned			leaf_count;
};

struct khttpd_ctrl_port_data {
	struct sockaddr_storage addr;
	int		protocol;
};

struct khttpd_ctrl_location_data {
	struct khttpd_location_type *type;
};

struct khttpd_location_type;
SLIST_HEAD(khttpd_location_type_slist, khttpd_location_type);

struct khttpd_location_type {
	SLIST_ENTRY(khttpd_location_type)	slink;
	const char				*name;
	khttpd_ctrl_location_create_fn_t	create;
	khttpd_ctrl_location_delete_fn_t	delete;
	khttpd_ctrl_location_get_fn_t		get;
	khttpd_ctrl_location_put_fn_t		put;
};

struct khttpd_ctrl_json_io_data {
	khttpd_ctrl_json_io_t op;
	struct mbuf	*buf;
	boolean_t	drain;
};

struct khttpd_main_start_command {
	struct khttpd_main_command hdr;
	struct mbuf	*data;
};

static void khttpd_ctrl_options_asterisc(struct khttpd_exchange *);
static void khttpd_ctrl_get(struct khttpd_exchange *);
static void khttpd_ctrl_put(struct khttpd_exchange *);
static void khttpd_ctrl_options(struct khttpd_exchange *);
static void khttpd_ctrl_post(struct khttpd_exchange *);
static void khttpd_ctrl_delete(struct khttpd_exchange *);
static void khttpd_ctrl_json_io_dtor(struct khttpd_exchange *, void *);
static void khttpd_ctrl_json_io_put(struct khttpd_exchange *, void *,
    struct mbuf *, boolean_t *);
static void khttpd_ctrl_json_io_end(struct khttpd_exchange *, void *);
static void khttpd_ctrl_post_end(struct khttpd_exchange *, void *);

enum {
	KHTTPD_CTRL_PROTOCOL_UNKNOWN = -1,
	KHTTPD_CTRL_PROTOCOL_HTTP,
	KHTTPD_CTRL_PROTOCOL_HTTPS,
	KHTTPD_CTRL_PROTOCOL_END
};

static const char *khttpd_ctrl_protocol_table[] = {
	"http", "https",
};

CTASSERT(sizeof(khttpd_ctrl_protocol_table) /
    sizeof(khttpd_ctrl_protocol_table[0]) == KHTTPD_CTRL_PROTOCOL_END);

static void (*khttpd_ctrl_accept_fns[])(void *) = {
	khttpd_http_accept_http_client,
	khttpd_http_accept_https_client,
};

CTASSERT(sizeof(khttpd_ctrl_accept_fns) / sizeof(khttpd_ctrl_accept_fns[0]) ==
    KHTTPD_CTRL_PROTOCOL_END);

static struct khttpd_location_ops khttpd_ctrl_asterisc_ops = {
	.method[KHTTPD_METHOD_OPTIONS] = khttpd_ctrl_options_asterisc
};

static struct khttpd_location_ops khttpd_ctrl_ops = {
	.set_error_response = khttpd_exchange_set_response_body_problem_json,
	.method[KHTTPD_METHOD_DELETE] = khttpd_ctrl_delete,
	.method[KHTTPD_METHOD_GET] = khttpd_ctrl_get,
	.method[KHTTPD_METHOD_OPTIONS] = khttpd_ctrl_options,
	.method[KHTTPD_METHOD_POST] = khttpd_ctrl_post,
	.method[KHTTPD_METHOD_PUT] = khttpd_ctrl_put,
};

static struct khttpd_exchange_ops khttpd_ctrl_post_ops = {
	.dtor = khttpd_ctrl_json_io_dtor,
	.put = khttpd_ctrl_json_io_put,
	.end = khttpd_ctrl_post_end,
};

static struct khttpd_exchange_ops khttpd_ctrl_json_io_ops = {
	.dtor = khttpd_ctrl_json_io_dtor,
	.put = khttpd_ctrl_json_io_put,
	.end = khttpd_ctrl_json_io_end,
};

static struct sx khttpd_ctrl_lock;
static struct khttpd_server *khttpd_ctrl_server;
static khttpd_costruct_key_t khttpd_ctrl_port_data_key;
static khttpd_costruct_key_t khttpd_ctrl_location_data_key;
static struct khttpd_location_type_slist
    khttpd_location_types[KHTTPD_LOCATION_TYPE_HASH_TABLE_SIZE];

struct khttpd_obj_type khttpd_ctrl_rewriters;
struct khttpd_obj_type khttpd_ctrl_ports;
struct khttpd_obj_type khttpd_ctrl_servers;
struct khttpd_obj_type khttpd_ctrl_locations;

SX_SYSINIT(khttpd_ctrl_lock, &khttpd_ctrl_lock, "ctrl");

static void
khttpd_ctrl_options_asterisc(struct khttpd_exchange *exchange)
{
	char buf[128];
	struct sbuf sbuf;
	int i;

	KHTTPD_ENTRY("khttpd_ctrl_options_asterisc(%p)", exchange);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	sbuf_cpy(&sbuf, "OPTIONS");
	for (i = 0; i < KHTTPD_METHOD_END; ++i)
		if (i != KHTTPD_METHOD_OPTIONS)
			sbuf_printf(&sbuf, ", %s", khttpd_method_name(i));
	sbuf_finish(&sbuf);
	khttpd_exchange_set_response_content_length(exchange, 0);
	khttpd_exchange_add_response_field(exchange, "Allow", "%s",
	    sbuf_data(&sbuf));
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
	sbuf_delete(&sbuf);
}

int
khttpd_ctrl_parse_json(struct khttpd_json **value_out,
    struct khttpd_mbuf_json *response, struct mbuf *input)
{
	struct khttpd_json_problem diag;
	int status;

	KHTTPD_ENTRY("khttpd_ctrl_parse_json()");

	if (khttpd_json_parse(value_out, &diag, input,
		KHTTPD_CTRL_MAX_JSON_DEPTH))
		return (KHTTPD_STATUS_OK);

	status = KHTTPD_STATUS_BAD_REQUEST;
	khttpd_problem_response_begin(response, status, diag.type, diag.title);

	if (diag.detail != NULL) {
		khttpd_problem_set_detail(response, "%s", 
		    sbuf_data(diag.detail));
		sbuf_delete(diag.detail);
	}

	khttpd_mbuf_json_property(response, "line");
	khttpd_mbuf_json_format(response, FALSE, "%u", diag.line);
	khttpd_mbuf_json_property(response, "column");
	khttpd_mbuf_json_format(response, FALSE, "%u", diag.column);

	return (status);
}

static u_long
khttpd_ctrl_uuid_hash(const u_char *uuid)
{
	u_long result;
	unsigned i;

	result = 0;
	for (i = sizeof(uint32_t); 0 < i; --i)
		result = (result << 8) | uuid[i - 1];

	return (result);
}

static void
khttpd_ctrl_leaf_init(struct khttpd_ctrl_leaf *leaf, void *object, 
    const u_char *uuid)
{

	KHTTPD_ENTRY("khttpd_ctrl_leaf_init(%p,%p,%p)", leaf, object, uuid);

	leaf->object = object;
	bcopy(uuid, leaf->uuid, KHTTPD_UUID_SIZE);
}

static struct khttpd_ctrl_leaf_slist *
khttpd_obj_type_get_hash_chain(struct khttpd_obj_type *type,
    const u_char *uuid)
{
	struct khttpd_ctrl_leaf_slist *head;
	unsigned h;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	h = khttpd_ctrl_uuid_hash(uuid);
	head = type->table + (h & (type->table_size - 1));

	return (head);
}

static void
khttpd_obj_type_expand_table(struct khttpd_obj_type *type)
{
	struct khttpd_ctrl_leaf_slist *table;
	struct khttpd_ctrl_leaf *last, *cur, *next;
	unsigned i, old_size, new_size;
	unsigned disc_bit, disc_byte, disc_mask;

	KHTTPD_ENTRY("khttpd_obj_type_expand_table(%p)", type);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);	

	old_size = type->table_size;
	new_size = old_size << 1;
	disc_bit = ffs(old_size) - 1;
	disc_byte = disc_bit >> 3;
	disc_mask = 1 << (disc_bit & 7);
	type->table = table = khttpd_realloc(type->table,
	    (size_t)new_size * sizeof(struct khttpd_ctrl_leaf_slist));
	for (i = 0; i < old_size; ++i) {
		SLIST_INIT(&table[i + old_size]);
		last = NULL;
		for (cur = SLIST_FIRST(&table[i]); cur != NULL; cur = next) {
			next = SLIST_NEXT(cur, hlink);

			if ((cur->uuid[disc_byte] & disc_mask) == 0) {
				last = cur;
				continue;
			}

			if (last == NULL)
				SLIST_REMOVE_HEAD(&table[i], hlink);
			else
				SLIST_REMOVE_AFTER(last, hlink);

			SLIST_INSERT_HEAD(&table[i + old_size], cur, hlink);
		}
	}
}

static void
khttpd_obj_type_contract_table(struct khttpd_obj_type *type)
{
	struct khttpd_ctrl_leaf_slist *table;
	unsigned i, old_size, new_size;

	KHTTPD_ENTRY("khttpd_obj_type_contract_table(%p)", type);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);	

	old_size = type->table_size;
	new_size = old_size >> 1;
	table = type->table;
	for (i = new_size; i < old_size; ++i)
		SLIST_CONCAT(&table[i - new_size], &table[i],
		    khttpd_ctrl_leaf, hlink);
	type->table = khttpd_realloc(type->table,
	    (size_t)new_size * sizeof(struct khttpd_ctrl_leaf_slist));
}

static struct khttpd_ctrl_leaf *
khttpd_obj_type_lookup(struct khttpd_obj_type *type,
    const u_char *uuid)
{
	struct khttpd_ctrl_leaf_slist *head;
	struct khttpd_ctrl_leaf *leaf;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	head = khttpd_obj_type_get_hash_chain(type, uuid);
	SLIST_FOREACH(leaf, head, hlink)
	    if (memcmp(uuid, leaf->uuid, KHTTPD_UUID_SIZE) == 0)
		    return (leaf);

	return (NULL);
}

static boolean_t
khttpd_obj_type_add_obj(struct khttpd_obj_type *type,
    struct khttpd_ctrl_leaf *leaf)
{
	struct khttpd_ctrl_leaf *ptr;
	struct khttpd_ctrl_leaf_slist *head;

	KHTTPD_ENTRY("khttpd_obj_type_add_obj(%p,%p{object=%p})", type,
	    leaf, leaf->object);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	head = khttpd_obj_type_get_hash_chain(type, leaf->uuid);
	SLIST_FOREACH(ptr, head, hlink)
	    if (memcmp(leaf->uuid, ptr->uuid, KHTTPD_UUID_SIZE) == 0)
		    return (FALSE);

	SLIST_INSERT_HEAD(head, leaf, hlink);

	return (TRUE);
}

static boolean_t
khttpd_obj_type_remove_obj(struct khttpd_obj_type *type,
    struct khttpd_ctrl_leaf *leaf)
{
	struct khttpd_ctrl_leaf_slist *head;
	struct khttpd_ctrl_leaf *ptr;

	KHTTPD_ENTRY("khttpd_obj_type_remove_obj(%p,%p{object=%p})", type,
	    leaf, leaf->object);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	ptr = khttpd_obj_type_lookup(type, leaf->uuid);
	head = khttpd_obj_type_get_hash_chain(type, leaf->uuid);
	SLIST_FOREACH(ptr, head, hlink)
	    if (memcmp(leaf->uuid, ptr->uuid, KHTTPD_UUID_SIZE) == 0)
		    break;

	if (ptr == NULL)
		return (FALSE);

	SLIST_REMOVE(head, leaf, khttpd_ctrl_leaf, hlink);

	return (TRUE);
}

static struct khttpd_ctrl_leaf *
khttpd_obj_type_get_leaf(struct khttpd_obj_type *type, void *obj)
{
	struct khttpd_ctrl_leaf **leafp;

	leafp = khttpd_costruct_get(obj, type->leaf_ptr_key);
	return (*leafp);
}

static void
khttpd_obj_type_set_leaf(struct khttpd_obj_type *type, void *obj,
    struct khttpd_ctrl_leaf *leaf)
{
	struct khttpd_ctrl_leaf **leafp;

	KHTTPD_ENTRY("khttpd_obj_type_set_leaf(%p,%p,%p)", type, obj, leaf);
	leafp = khttpd_costruct_get(obj, type->leaf_ptr_key);
	*leafp = leaf;
}

static int
khttpd_obj_type_obj_ctor(void *host, void *arg)
{

	KHTTPD_ENTRY("khttpd_obj_type_obj_ctor(%p,%p)", host, arg);
	khttpd_obj_type_set_leaf(arg, host, NULL);
	return (0);
}

#ifdef INVARIANTS

static void
khttpd_obj_type_obj_dtor(void *host, void *arg)
{

	KHTTPD_ENTRY("khttpd_obj_type_obj_dtor(%p,%p)", host, arg);
	KASSERT(khttpd_obj_type_get_leaf(arg, host) == NULL,
	    ("obj %p of type %p is still visible", host, arg));
}

#endif

static void
khttpd_obj_type_show_obj(struct khttpd_obj_type *type, void *object,
    const u_char *uuid)
{
	struct khttpd_ctrl_leaf *leaf;

	KHTTPD_ENTRY("khttpd_obj_type_show_obj(%p,%p,%016lx%016lx)", type,
	    object, ((u_long *)uuid)[0], ((u_long *)uuid)[1]);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	leaf = khttpd_obj_type_get_leaf(type, object);
	if (leaf != NULL)
		return;

	leaf = khttpd_malloc(sizeof(struct khttpd_ctrl_leaf));
	khttpd_ctrl_leaf_init(leaf, object, uuid);
	LIST_INSERT_HEAD(&type->leafs, leaf, link);
	khttpd_obj_type_set_leaf(type, object, leaf);

	khttpd_obj_type_add_obj(type, leaf);
	type->acquire(object);

	if (type->table_size << 1 < ++type->leaf_count)
		khttpd_obj_type_expand_table(type);

	if (type->show != NULL)
		type->show(object);
}

static void
khttpd_obj_type_hide_obj(struct khttpd_obj_type *type, void *object)
{
	struct khttpd_ctrl_leaf *leaf;

	KHTTPD_ENTRY("khttpd_obj_type_hide_obj(%p,%p)", type, object);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	leaf = khttpd_obj_type_get_leaf(type, object);
	if (leaf == NULL)
		return;

	if (type->hide != NULL)
		type->hide(object);

	LIST_REMOVE(leaf, link);
	khttpd_obj_type_set_leaf(type, object, NULL);

	khttpd_obj_type_remove_obj(type, leaf);
	khttpd_free(leaf);
	type->release(object);

	if (--type->leaf_count < type->table_size >> 1 &&
	    KHTTPD_OBJ_TYPE_TABLE_SIZE_MIN < type->table_size)
		khttpd_obj_type_contract_table(type);
}

static void
khttpd_obj_type_new(struct khttpd_obj_type *type, const char *name,
    struct khttpd_costruct_info *obj_info,
    khttpd_ctrl_obj_fn_t show, khttpd_ctrl_obj_fn_t hide,
    khttpd_ctrl_obj_fn_t acquire, khttpd_ctrl_obj_fn_t release,
    khttpd_ctrl_json_io_t create, khttpd_ctrl_json_out_t delete,
    khttpd_ctrl_json_out_t get_index, khttpd_ctrl_json_out_t get,
    khttpd_ctrl_json_io_t put)
{
	unsigned table_size = KHTTPD_OBJ_TYPE_TABLE_SIZE_MIN;
	int i;

	KHTTPD_ENTRY("khttpd_obj_type_new(%p,%s,%p)", type, name, obj_info);

	LIST_INIT(&type->leafs);
	sbuf_new(&type->allowed_node_methods, NULL, 0, SBUF_AUTOEXTEND);
	sbuf_new(&type->allowed_leaf_methods, NULL, 0, SBUF_AUTOEXTEND);
	type->name = name;
	type->node = NULL;
	type->table = khttpd_malloc(table_size * 
	    sizeof(struct khttpd_ctrl_leaf_slist));
	type->show = show;
	type->hide = hide;
	type->acquire = acquire;
	type->release = release;
	type->acquire = acquire;
	type->release = release;
	type->create = create;
	type->delete = delete;
	type->get_index = get_index;
	type->get = get;
	type->put = put;
	type->leaf_ptr_key = khttpd_costruct_register(obj_info,
	    sizeof(struct khttpd_ctrl_leaf **),
	    khttpd_obj_type_obj_ctor,
#ifdef INVARIANTS
	    khttpd_obj_type_obj_dtor,
#else
	    NULL,
#endif
	    type);
	type->table_size = table_size;
	type->leaf_count = 0;

	sbuf_cpy(&type->allowed_node_methods, "OPTIONS");
	sbuf_cpy(&type->allowed_leaf_methods, "OPTIONS");
	if (type->create != NULL)
		sbuf_cat(&type->allowed_node_methods, ", POST");
	if (type->delete != NULL)
		sbuf_cat(&type->allowed_leaf_methods, ", DELETE");
	if (type->get != NULL)
		sbuf_cat(&type->allowed_leaf_methods, ", HEAD, GET");
	if (type->put != NULL)
		sbuf_cat(&type->allowed_leaf_methods, ", PUT");
	sbuf_cat(&type->allowed_node_methods, ", HEAD, GET");
	sbuf_finish(&type->allowed_node_methods);
	sbuf_finish(&type->allowed_leaf_methods);

	for (i = 0; i < table_size; ++i)
		SLIST_INIT(&type->table[i]);
}

static void
khttpd_obj_type_delete(struct khttpd_obj_type *type)
{

	KHTTPD_ENTRY("khttpd_obj_type_delete(%p)", type);
	KASSERT(LIST_EMPTY(&type->leafs), ("leafs list is not empty"));
	KASSERT(type->leaf_count == 0,
	    ("there still is %d object(s)", type->leaf_count));

	khttpd_free(type->table);
	sbuf_delete(&type->allowed_leaf_methods);
	sbuf_delete(&type->allowed_node_methods);
}

static int
khttpd_obj_type_mount(struct khttpd_obj_type *type,
    struct khttpd_server *server, const char *path)
{
	int error;

	KHTTPD_ENTRY("khttpd_obj_type_mount(%p,%p,%s)", type, server, path);
	KASSERT(type->node == NULL, ("type->node=%p", type->node));

	error = 0;
	type->node = khttpd_location_new(&error, server, path,
	    &khttpd_ctrl_ops, type);

	return (error);
}

void
khttpd_obj_type_get_id(struct khttpd_obj_type *type,
    void *object, struct sbuf *output)
{
	char uuid_str[KHTTPD_UUID_STR_REP_SIZE + 1];
	struct khttpd_ctrl_leaf *leaf;

	leaf = khttpd_obj_type_get_leaf(type, object);
	khttpd_uuid_to_string(leaf->uuid, uuid_str);
	sbuf_cat(output, uuid_str);
}

static void
khttpd_obj_type_put_id_property(struct khttpd_obj_type *type,
    void *object, struct khttpd_mbuf_json *output)
{
	char buf[64];
	struct sbuf sbuf;

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_obj_type_get_id(type, object, &sbuf);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_property(output, "id");
	khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);
}

static void *
khttpd_obj_type_get_obj_for_id(struct khttpd_obj_type *type, const char *id)
{
	u_char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_ctrl_leaf *leaf;

	KHTTPD_ENTRY("khttpd_obj_type_get_obj_for_id(%p,%s)", type, id);
	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	if (khttpd_uuid_parse(id, uuid) != 0)
		return (NULL);

	leaf = khttpd_obj_type_lookup(type, uuid);
	if (leaf == NULL)
		return (NULL);

	return (leaf->object);
}

static void
khttpd_obj_type_clear(struct khttpd_obj_type *type)
{
	struct khttpd_ctrl_leaf *leaf;

	KHTTPD_ENTRY("khttpd_obj_type_clear(%p)", type);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	while (!LIST_EMPTY(&type->leafs)) {
		leaf = LIST_FIRST(&type->leafs);
		khttpd_obj_type_hide_obj(type, leaf->object);
	}
}

int
khttpd_obj_type_get_obj_from_property(struct khttpd_obj_type *type,
    void **obj_out, const char *name, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec;
	const char *str;
	void *value;
	int status;

	status = khttpd_webapi_get_string_property(&str, name, input_prop_spec,
	    input, output, may_not_exist);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	if (status == KHTTPD_STATUS_NO_CONTENT) {
		*obj_out = NULL;
		return (status);
	}

	value = khttpd_obj_type_get_obj_for_id(type, str);
	if (value == NULL) {
		prop_spec.link = input_prop_spec;
		prop_spec.name = name;
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*obj_out = value;

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_obj_type_load(struct khttpd_obj_type *type, 
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	char uuid[KHTTPD_UUID_SIZE];
	char buf[16];
	struct sbuf sbuf;
	struct khttpd_problem_property prop_specs[2];
	struct khttpd_json *obj_j, *id_j;
	void *obj;
	int i, n, status;

	KHTTPD_ENTRY("khttpd_obj_type_load(%p)", type);
	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	if (khttpd_json_type(input) != KHTTPD_JSON_ARRAY) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, input_prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	prop_specs[0].link = input_prop_spec;
	for (i = 1; i < sizeof(prop_specs) / sizeof(prop_specs[0]); ++i)
		prop_specs[i].link = &prop_specs[i - 1];

	n = khttpd_json_array_size(input);
	for (i = 0; i < n; ++i) {
		sbuf_clear(&sbuf);
		sbuf_printf(&sbuf, "[%d]", i);
		sbuf_finish(&sbuf);

		prop_specs[0].name = sbuf_data(&sbuf);

		obj_j = khttpd_json_array_get(input, i);
		if (obj_j == NULL) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_no_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_specs[0]);
			goto quit;
		}

		if (khttpd_json_type(obj_j) != KHTTPD_JSON_OBJECT) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_wrong_type_response_begin(output);
			khttpd_problem_set_property(output, &prop_specs[0]);
			goto quit;
		}

		prop_specs[1].name = "id";
		id_j = khttpd_json_object_get(obj_j, "id");
		if (id_j == NULL)
			khttpd_uuid_new(uuid);

		else if (khttpd_json_type(id_j) != KHTTPD_JSON_STRING) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_wrong_type_response_begin(output);
			khttpd_problem_set_property(output, &prop_specs[1]);
			goto quit;

		} else if (khttpd_uuid_parse(khttpd_json_string_data(id_j),
			uuid) != 0) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_specs[1]);
			goto quit;

		} else if (khttpd_obj_type_lookup(type, uuid) != NULL) {
			status = KHTTPD_STATUS_CONFLICT;
			khttpd_problem_response_begin(output, status,
			    NULL, NULL);
			khttpd_problem_set_property(output, &prop_specs[1]);
			goto quit;
		}

		obj = NULL;
		status = type->create(&obj, output, &prop_specs[0], obj_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto quit;

		khttpd_obj_type_show_obj(type, obj, uuid);

		type->release(obj);
	}

	status = KHTTPD_STATUS_OK;

 quit:
	sbuf_delete(&sbuf);

	return (status);
}

static int
khttpd_ctrl_null_obj_fn(void *object, struct khttpd_mbuf_json *response)
{

	return (KHTTPD_STATUS_NO_CONTENT);
}

static void
khttpd_ctrl_json_io_dtor(struct khttpd_exchange *exchange, void *arg)
{
	struct khttpd_ctrl_json_io_data *json_io_data;

	KHTTPD_ENTRY("khttpd_ctrl_json_io_dtor(%p,%p)", exchange, arg);
	json_io_data = arg;
	m_freem(json_io_data->buf);
	khttpd_free(json_io_data);
}

static void
khttpd_ctrl_json_io_put(struct khttpd_exchange *exchange, void *arg, 
    struct mbuf *m, boolean_t *pause)
{
	struct khttpd_ctrl_json_io_data *json_io_data;
	struct mbuf *last;
	int size, status;

	KHTTPD_ENTRY("khttpd_ctrl_json_io_put(%p,%p,%p)", exchange, arg, m);
	json_io_data = arg;

	if (json_io_data->drain) {
		m_freem(m);
		return;
	}

	if (json_io_data->buf == NULL) {
		json_io_data->buf = m;
		return;
	}

	size = m_length(json_io_data->buf, &last);
	if (size + m_length(m, NULL) <= KHTTPD_CTRL_MAX_DATA_SIZE) {
		m_cat(last, m);
		return;
	}

	m_freem(m);
	json_io_data->drain = TRUE;

	status = KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE;
	khttpd_exchange_close(exchange);
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_ctrl_get_node(struct khttpd_exchange *exchange)
{
	struct khttpd_mbuf_json response;
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_leaf *leaf;
	void *object;

	KHTTPD_ENTRY("khttpd_ctrl_get_node(%p)", exchange);

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	khttpd_mbuf_json_new(&response);

	sx_slock(&khttpd_ctrl_lock);

	khttpd_mbuf_json_object_begin(&response);
	khttpd_mbuf_json_property(&response, "totalItems");
	khttpd_mbuf_json_format(&response, FALSE, "%u", type->leaf_count);
	khttpd_mbuf_json_property(&response, "items");
	khttpd_mbuf_json_array_begin(&response);

	LIST_FOREACH(leaf, &type->leafs, link) {
		object = leaf->object;
		khttpd_mbuf_json_object_begin(&response);
		if (type->get_index != NULL)
			type->get_index(object, &response);
		else
			khttpd_obj_type_put_id_property(type, object,
			    &response);
		khttpd_mbuf_json_object_end(&response);
	}

	khttpd_mbuf_json_array_end(&response);
	khttpd_mbuf_json_object_end(&response);

	sx_sunlock(&khttpd_ctrl_lock);

	khttpd_exchange_set_response_body_json(exchange, &response);
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
}

static void
khttpd_ctrl_get_leaf(struct khttpd_exchange *exchange)
{
	u_char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_mbuf_json response;
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_leaf *leaf;
	void *object;
	int status;

	KHTTPD_ENTRY("khttpd_ctrl_get_leaf(%p)", exchange);

	if (khttpd_uuid_parse(khttpd_exchange_suffix(exchange), uuid) != 0) {
		KHTTPD_BRANCH("%s khttpd_uuid_parse failure", __func__);
		goto not_found;
	}

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	sx_slock(&khttpd_ctrl_lock);

	leaf = khttpd_obj_type_lookup(type, uuid);
	if (leaf == NULL) {
		KHTTPD_BRANCH("%s leaf == NULL", __func__);
		sx_sunlock(&khttpd_ctrl_lock);
		goto not_found;
	}

	object = leaf->object;
	khttpd_mbuf_json_new(&response);
	status = type->get(object, &response);

	sx_sunlock(&khttpd_ctrl_lock);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_response_body_json(exchange, &response);
	else
		khttpd_exchange_set_error_response_body(exchange, status,
		    &response);

	khttpd_exchange_respond(exchange, status);
	return;

 not_found:
	status = KHTTPD_STATUS_NOT_FOUND;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_ctrl_get(struct khttpd_exchange *exchange)
{

	if (khttpd_exchange_suffix(exchange)[0] != '\0')
		khttpd_ctrl_get_leaf(exchange);
	else
		khttpd_ctrl_get_node(exchange);
}

enum {
	KHTTPD_OBJ_DIR_FLAGS_LEAF = 1 << 0,
	KHTTPD_OBJ_DIR_FLAGS_NODE = 1 << 1
};

static void
khttpd_ctrl_json_io_method(struct khttpd_exchange *exchange,
    khttpd_ctrl_json_io_t method, struct khttpd_exchange_ops *ops,
    int flags)
{
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_json_io_data *json_io_data;
	int status;

	KHTTPD_ENTRY("khttpd_ctrl_json_io_method(%p)", exchange);

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	if (method == NULL || (khttpd_exchange_suffix(exchange)[0] != '\0' ?
		(flags & KHTTPD_OBJ_DIR_FLAGS_LEAF) == 0 :
		(flags & KHTTPD_OBJ_DIR_FLAGS_NODE) == 0)) {
		status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
		goto error;
	}

	if (!khttpd_exchange_is_request_media_type_json(exchange, TRUE)) {
		status = KHTTPD_STATUS_UNSUPPORTED_MEDIA_TYPE;
		goto error;
	}

	json_io_data = khttpd_malloc(sizeof(*json_io_data));
	json_io_data->op = method;
	json_io_data->buf = NULL;
	json_io_data->drain = FALSE;

	khttpd_exchange_set_ops(exchange, ops, json_io_data);
	return;

 error:
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_ctrl_json_io_end(struct khttpd_exchange *exchange, void *arg)
{
	u_char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_mbuf_json response;
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *post_data, *id_j;
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_leaf *leaf;
	struct khttpd_ctrl_json_io_data *json_io_data;
	void *object;
	int status;

	KHTTPD_ENTRY("khttpd_ctrl_json_io_end(%p,%p)", exchange, arg);

	json_io_data = arg;

	if (khttpd_uuid_parse(khttpd_exchange_suffix(exchange), uuid) != 0) {
		KHTTPD_BRANCH("%s khttpd_uuid_parse failure", __func__);
		goto not_found;
	}

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	sx_xlock(&khttpd_ctrl_lock);

	leaf = khttpd_obj_type_lookup(type, uuid);
	if (leaf == NULL) {
		KHTTPD_BRANCH("%s leaf == NULL", __func__);
		sx_xunlock(&khttpd_ctrl_lock);
		goto not_found;
	}

	object = leaf->object;
	post_data = NULL;
	khttpd_mbuf_json_new(&response);

	status = khttpd_ctrl_parse_json(&post_data, &response,
	    json_io_data->buf);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto respond;

	if (khttpd_json_type(post_data) != KHTTPD_JSON_OBJECT) {
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_wrong_type_response_begin(&response);
		goto respond;
	}

	id_j = khttpd_json_object_get(post_data, "id");
	if (id_j != NULL) {
		prop_spec.link = NULL;
		prop_spec.name = "id";

		if (khttpd_json_type(id_j) != KHTTPD_JSON_STRING) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_wrong_type_response_begin(&response);
			khttpd_problem_set_property(&response, &prop_spec);
			goto respond;
		}

		if (khttpd_uuid_parse(khttpd_json_string_data(id_j), uuid)
		    != 0) {
			status = KHTTPD_STATUS_BAD_REQUEST;
			khttpd_problem_invalid_value_response_begin(&response);
			khttpd_problem_set_property(&response, &prop_spec);
			goto respond;
		}

		if (memcmp(uuid, leaf->uuid, sizeof(uuid)) != 0) {
			status = KHTTPD_STATUS_CONFLICT;
			khttpd_problem_response_begin(&response, status,
			    NULL, NULL);
			khttpd_problem_set_property(&response, &prop_spec);
			goto respond;
		}
	}

	status = json_io_data->op(object, &response, NULL, post_data);

 respond:
	khttpd_json_delete(post_data);

	sx_xunlock(&khttpd_ctrl_lock);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_response_body_json(exchange, &response);
	else
		khttpd_exchange_set_error_response_body(exchange, status,
		    &response);

	khttpd_exchange_respond(exchange, status);
	return;

 not_found:
	status = KHTTPD_STATUS_NOT_FOUND;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_ctrl_options(struct khttpd_exchange *exchange)
{
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	const char *suffix;

	KHTTPD_ENTRY("khttpd_ctrl_options(%p)", exchange);

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);
	suffix = khttpd_exchange_suffix(exchange);
	khttpd_exchange_set_response_content_length(exchange, 0);
	khttpd_exchange_add_response_field(exchange, "Allow", "%s",
	    sbuf_data(suffix[0] == '\0' ? &type->allowed_node_methods :
		&type->allowed_leaf_methods));
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
}

static void
khttpd_ctrl_post(struct khttpd_exchange *exchange)
{
	struct khttpd_location *node;
	struct khttpd_obj_type *type;

	KHTTPD_ENTRY("khttpd_ctrl_post(%p)", exchange);
	KASSERT(khttpd_exchange_suffix(exchange)[0] == '\0',
	    ("POST on a leaf %s", khttpd_exchange_suffix(exchange)));

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	if (type->create == NULL) {
		khttpd_exchange_add_response_field(exchange, "Allow", "%s",
		    sbuf_data(&type->allowed_node_methods));
		khttpd_exchange_set_error_response_body(exchange,
		    KHTTPD_STATUS_METHOD_NOT_ALLOWED, NULL);
		khttpd_exchange_respond(exchange,
		    KHTTPD_STATUS_METHOD_NOT_ALLOWED);
		return;
	}

	khttpd_ctrl_json_io_method(exchange, type->create,
	    &khttpd_ctrl_post_ops, KHTTPD_OBJ_DIR_FLAGS_NODE);
}

static void
khttpd_ctrl_post_end(struct khttpd_exchange *exchange, void *arg)
{
	char uuid_str[KHTTPD_UUID_STR_REP_SIZE + 1];
	char uuid[KHTTPD_UUID_SIZE];
	char buf[64];
	struct sbuf sbuf;
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *post_data;
	struct khttpd_mbuf_json response;
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_json_io_data *json_io_data;
	void *object;
	int status;

	json_io_data = arg;

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);
	post_data = NULL;

	khttpd_mbuf_json_new(&response);

	status = khttpd_ctrl_parse_json(&post_data, &response,
	    json_io_data->buf);
	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto error;

	if (post_data == NULL) {
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_no_value_response_begin(&response);
		goto error;
	}

	if (khttpd_json_type(post_data) != KHTTPD_JSON_OBJECT) {
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_wrong_type_response_begin(&response);
		goto error;
	}

	if (khttpd_json_object_get(post_data, "id") != NULL) {
		status = KHTTPD_STATUS_CONFLICT;
		khttpd_problem_response_begin(&response, status, NULL, NULL);
		prop_spec.link = NULL;
		prop_spec.name = "id";
		khttpd_problem_set_property(&response, &prop_spec);
		khttpd_problem_set_detail(&response,
		    "POST method can't specify \"id\" property.");
		goto error;
	}

	sx_xlock(&khttpd_ctrl_lock);
	object = NULL;
	status = type->create(&object, &response, NULL, post_data);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		sx_xunlock(&khttpd_ctrl_lock);
		goto error;
	}

	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(type, object, uuid);

	sx_xunlock(&khttpd_ctrl_lock);
	type->release(object);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	sbuf_cpy(&sbuf, khttpd_location_get_path(type->node));
	khttpd_uuid_to_string(uuid, uuid_str);
	sbuf_cat(&sbuf, uuid_str);
	sbuf_finish(&sbuf);
	khttpd_exchange_add_response_field(exchange, "Location", "%s",
	    sbuf_data(&sbuf));
	sbuf_delete(&sbuf);

 error:
	khttpd_json_delete(post_data);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_response_body_json(exchange, &response);
	else 
		khttpd_exchange_set_error_response_body(exchange, status,
		    &response);
	khttpd_exchange_respond(exchange, status);
}

static void
khttpd_ctrl_put(struct khttpd_exchange *exchange)
{
	struct khttpd_location *node;
	struct khttpd_obj_type *type;

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);

	if (type->put == NULL) {
		khttpd_exchange_add_response_field(exchange, "Allow", "%s",
		    sbuf_data(&type->allowed_leaf_methods));
		khttpd_exchange_set_error_response_body(exchange,
		    KHTTPD_STATUS_METHOD_NOT_ALLOWED, NULL);
		khttpd_exchange_respond(exchange,
		    KHTTPD_STATUS_METHOD_NOT_ALLOWED);
		return;
	}

	khttpd_ctrl_json_io_method(exchange, type->put,
	    &khttpd_ctrl_json_io_ops, KHTTPD_OBJ_DIR_FLAGS_LEAF);
}

static void
khttpd_ctrl_delete(struct khttpd_exchange *exchange)
{
	u_char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_location *node;
	struct khttpd_obj_type *type;
	struct khttpd_ctrl_leaf *leaf;
	struct khttpd_mbuf_json response;
	const char *suffix;
	int error, status;

	node = khttpd_exchange_location(exchange);
	type = khttpd_location_data(node);
	khttpd_mbuf_json_new(&response);

	suffix = khttpd_exchange_suffix(exchange);
	if (suffix[0] == '\0') {
		status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
		khttpd_problem_response_begin(&response, status, NULL, NULL);
		khttpd_exchange_add_response_field(exchange, "Allow", "%s",
		    sbuf_data(&type->allowed_node_methods));
		goto respond;
	}

	if (type->delete == NULL) {
		status = KHTTPD_STATUS_METHOD_NOT_ALLOWED;
		khttpd_problem_response_begin(&response, status, NULL, NULL);
		khttpd_exchange_add_response_field(exchange, "Allow", "%s",
		    sbuf_data(&type->allowed_leaf_methods));
		goto respond;
	}

	error = khttpd_uuid_parse(suffix, uuid);
	if (error != 0) {
		KHTTPD_BRANCH("%s khttpd_uuid_parse %d", __func__, error);
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_problem_response_begin(&response, status, NULL, NULL);
		goto respond;
	}

	sx_xlock(&khttpd_ctrl_lock);

	leaf = khttpd_obj_type_lookup(type, uuid);
	if (leaf == NULL) {
		KHTTPD_BRANCH("%s leaf==NULL", __func__);
		sx_xunlock(&khttpd_ctrl_lock);
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_problem_response_begin(&response, status, NULL, NULL);
		goto respond;
	}

	status = type->delete(leaf->object, &response);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_obj_type_hide_obj(type, leaf->object);

	sx_xunlock(&khttpd_ctrl_lock);

 respond:
	if (status == KHTTPD_STATUS_NO_CONTENT)
		;
	else if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_exchange_set_response_body_json(exchange, &response);
	else
		khttpd_exchange_set_error_response_body(exchange, status,
		    &response);

	khttpd_exchange_respond(exchange, status);
}

static int
khttpd_ctrl_protocol_for_name(const char *name)
{
	int i;

	for (i = 0; i < sizeof(khttpd_ctrl_protocol_table) /
		 sizeof(khttpd_ctrl_protocol_table[0]); ++i)
		if (strcmp(name, khttpd_ctrl_protocol_table[i]) == 0)
			return (i);
	return (KHTTPD_CTRL_PROTOCOL_UNKNOWN);
}

static const char *
khttpd_ctrl_protocol_name(int protocol)
{

	return (protocol < 0 || KHTTPD_CTRL_PROTOCOL_END <= protocol ? NULL :
	    khttpd_ctrl_protocol_table[protocol]);
}

static struct khttpd_location_type_slist *
khttpd_location_type_get_hash_chain(const char *type_name)
{

	return (&khttpd_location_types[hash32_str(type_name, 0) % 
		KHTTPD_LOCATION_TYPE_HASH_TABLE_SIZE]);
}

static struct khttpd_location_type *
khttpd_location_type_find(const char *name)

{
	struct khttpd_location_type *ptr;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	SLIST_FOREACH(ptr, khttpd_location_type_get_hash_chain(name),
	    slink)
	    if (strcmp(name, ptr->name) == 0)
		    break;

	return (ptr);
}

int
khttpd_location_type_create_location(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, struct khttpd_location_ops *ops, void *arg)
{
	struct khttpd_location *location;
	int error, status;

	error = 0;
	location = khttpd_location_new(&error, server, path, ops, arg);
	if (error == 0) {
		status = KHTTPD_STATUS_OK;
		*location_out = location;
	} else {
		status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_errno(output, error);
		khttpd_problem_set_detail(output, "location routing failure");
		khttpd_problem_set_property(output, input_prop_spec);
	}

	return (status);
}

static int
khttpd_location_type_default_delete(struct khttpd_location *location,
    struct khttpd_mbuf_json *output)
{

	return (KHTTPD_STATUS_OK);
}

static void
khttpd_location_type_default_get(struct khttpd_location *location,
    struct khttpd_mbuf_json *output)
{
}

static int
khttpd_location_type_default_put(struct khttpd_location *location,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{

	return (KHTTPD_STATUS_OK);
}

void
khttpd_location_type_register(const char *name,
    khttpd_ctrl_location_create_fn_t create,
    khttpd_ctrl_location_delete_fn_t delete,
    khttpd_ctrl_location_get_fn_t get, khttpd_ctrl_location_put_fn_t put)
{
	struct khttpd_location_type *ptr;
	struct khttpd_location_type_slist *head;

	KASSERT(khttpd_init_get_phase() == KHTTPD_INIT_PHASE_RUN,
	    ("khttpd_init_get_phase()=%d", khttpd_init_get_phase()));

	if (create == NULL) {
		log(LOG_ERR, "khttpd: parameter 'create' given to %s is NULL",
		    __func__);
		return;
	}

	sx_xlock(&khttpd_ctrl_lock);

	if (khttpd_location_type_find(name) != NULL) {
		sx_xunlock(&khttpd_ctrl_lock);
		log(LOG_ERR, "khttpd: duplicated location type '%s'", name);
		return;
	}

	head = khttpd_location_type_get_hash_chain(name);
	SLIST_FOREACH(ptr, head, slink)
	    if (strcmp(name, ptr->name) == 0)
		    break;

	ptr = khttpd_malloc(sizeof(*ptr));
	bzero(ptr, sizeof(*ptr));
	ptr->name = name;
	ptr->create = create;
	ptr->delete = delete != NULL ? delete :
	    khttpd_location_type_default_delete;
	ptr->get = get != NULL ? get : khttpd_location_type_default_get;
	ptr->put = put != NULL ? put : khttpd_location_type_default_put;

	SLIST_INSERT_HEAD(head, ptr, slink);

	sx_xunlock(&khttpd_ctrl_lock);
}

void
khttpd_location_type_deregister(const char *name)
{
	struct khttpd_location_type *ptr, *next;
	struct khttpd_location_type_slist *head;

	KASSERT(khttpd_init_get_phase() == KHTTPD_INIT_PHASE_RUN,
	    ("khttpd_init_get_phase()=%d", khttpd_init_get_phase()));

	sx_xlock(&khttpd_ctrl_lock);

	head = khttpd_location_type_get_hash_chain(name);
	ptr = SLIST_FIRST(head);
	if (ptr == NULL)
		;		/* nothing */
	else if (strcmp(name, ptr->name) == 0)
		SLIST_REMOVE_HEAD(head, slink);
	else {
		for (;;) {
			next = SLIST_NEXT(ptr, slink);
			if (next == NULL)
				break;
			if (strcmp(name, next->name) == 0) {
				SLIST_REMOVE_AFTER(ptr, slink);
				break;
			}
			ptr = next;
		}
		ptr = next;
	}

	sx_xunlock(&khttpd_ctrl_lock);

	if (ptr == NULL)
		log(LOG_ERR, "khttpd: try to deregister "
		    "unknown location type '%s'", name);

	khttpd_free(ptr);
}

static int
khttpd_location_type_get_from_property(struct khttpd_location_type **type_out,
    const char *name, struct khttpd_mbuf_json *output, 
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_location_type *type;
	const char *type_str;
	int status;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	status = khttpd_webapi_get_string_property(&type_str, "type",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	type = khttpd_location_type_find(type_str);
	if (type == NULL) {
		prop_spec.link = input_prop_spec;
		prop_spec.name = "type";
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*type_out = type;

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_log_new(struct khttpd_log **log_out, 
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	struct thread *td;
	struct khttpd_log *log;
	const char *type_str, *path_str;
	int error, fd, status;

	KHTTPD_ENTRY("%s(,%p,%s,%p)", __func__, output,
	    khttpd_problem_ktr_print_property(input_prop_spec), input);

	if (khttpd_json_type(input) != KHTTPD_JSON_OBJECT) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, input_prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	status = khttpd_webapi_get_string_property(&type_str, "type",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec.link = input_prop_spec;

	if (strcmp(type_str, "file") != 0) {
		prop_spec.name = "type";
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	status = khttpd_webapi_get_string_property(&path_str, "path",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec.name = "path";

	if (path_str[0] != '/') {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		khttpd_problem_set_detail(output,
		    "absolute path name is expected.");
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	td = curthread;
	error = kern_openat(td, AT_FDCWD, (char *)path_str, UIO_SYSSPACE, 
	    O_WRONLY | O_APPEND | O_CREAT, 0644);
	if (error != 0) {
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_property(output, &prop_spec);
		khttpd_problem_set_detail(output, "file open error");
		khttpd_problem_set_errno(output, error);
		return (status);
	}
	fd = td->td_retval[0];

	log = khttpd_log_new();
	khttpd_log_set_fd(log, fd);
	khttpd_log_set_name(log, path_str);

	*log_out = log;

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_port_ctor(void *host, void *arg)
{
	struct khttpd_ctrl_port_data *data;

	data = khttpd_costruct_get(host, khttpd_ctrl_port_data_key);
	data->addr.ss_len = 0;

	return (0);
}

static void
khttpd_ctrl_port_acquire(void *object)
{
	struct khttpd_port *port;

	port = object;
	khttpd_port_acquire(port);
}

static void
khttpd_ctrl_port_release(void *object)
{
	struct khttpd_port *port;

	port = object;
	khttpd_port_release(port);
}

static int
khttpd_ctrl_port_get_index(void *object, struct khttpd_mbuf_json *output)
{
	struct khttpd_ctrl_port_data *port_data;
	struct khttpd_port *port;
	const char *proto_name;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	port = object;
	port_data = khttpd_costruct_get(port, khttpd_ctrl_port_data_key);

	khttpd_obj_type_put_id_property(&khttpd_ctrl_ports, object, output);
	khttpd_mbuf_json_property(output, "address");
	khttpd_mbuf_json_sockaddr(output, (struct sockaddr *)&port_data->addr);
	proto_name = khttpd_ctrl_protocol_name(port_data->protocol);
	if (proto_name != NULL) {
		khttpd_mbuf_json_property(output, "protocol");
		khttpd_mbuf_json_cstr(output, TRUE, proto_name);
	}

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_port_get(void *object, struct khttpd_mbuf_json *output)
{

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	khttpd_mbuf_json_object_begin(output);
	khttpd_ctrl_port_get_index(object, output);
	khttpd_mbuf_json_object_end(output);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_port_put(void *object, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct sockaddr_storage addr;
	struct khttpd_problem_property prop_spec;
	struct khttpd_ctrl_port_data *port_data;
	struct khttpd_json *address_j;
	struct khttpd_port *port;
	const char *detail, *protocol;
	int protocol_id;
	int error, status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);
	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	port = object;

	status = khttpd_webapi_get_string_property(&protocol, "protocol", 
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec.link = input_prop_spec;
	prop_spec.name = "protocol";

	protocol_id = khttpd_ctrl_protocol_for_name(protocol);
	if (protocol_id == KHTTPD_CTRL_PROTOCOL_UNKNOWN ||
	    protocol_id == KHTTPD_CTRL_PROTOCOL_HTTPS) {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	status = khttpd_webapi_get_object_property(&address_j, "address",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec.name = "address";
	bzero(&addr, sizeof(addr));
	status = khttpd_webapi_get_sockaddr_properties
	    ((struct sockaddr *)&addr, sizeof(addr), &prop_spec, address_j,
		output);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	port_data = khttpd_costruct_get(port, khttpd_ctrl_port_data_key);

	if (protocol_id != port_data->protocol ||
	    addr.ss_len != port_data->addr.ss_len ||
	    memcmp(&addr, &port_data->addr, addr.ss_len) != 0) {
		if (port_data->addr.ss_len != 0)
			khttpd_port_stop(port);
		port_data->protocol = protocol_id;
		port_data->addr = addr;
	}

	error = khttpd_port_start(port, (struct sockaddr *)&port_data->addr,
	    khttpd_ctrl_accept_fns[protocol_id], &detail);
	if (error == EADDRNOTAVAIL || error == EADDRINUSE) {
		khttpd_problem_response_begin(output, KHTTPD_STATUS_CONFLICT,
		    NULL, NULL);
		khttpd_problem_set_property(output, input_prop_spec);
		khttpd_problem_set_errno(output, error);
		if (detail != NULL)
			khttpd_problem_set_detail(output, detail);

	} else if (error != 0) {
		khttpd_problem_response_begin(output, 
		    KHTTPD_STATUS_INTERNAL_SERVER_ERROR, NULL, NULL);
		khttpd_problem_set_errno(output, error);
		if (detail != NULL)
			khttpd_problem_set_detail(output, detail);
	}

	return (status);
}

static int
khttpd_ctrl_port_create(void *object_out, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_port *port;
	int error, status;

	error = khttpd_port_new(&port);
	if (error != 0) {
		status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_detail(output, "failed to create a port");
		khttpd_problem_set_errno(output, error);
		khttpd_problem_set_property(output, input_prop_spec);
		return (status);
	}

	status = khttpd_ctrl_port_put(port, output, input_prop_spec, input);
	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		*(void **)object_out = port;
	else
		khttpd_port_release(port);

	return (status);
}

static void
khttpd_ctrl_port_hide(void *object)
{

	khttpd_vhost_clear_server_list(object);
	khttpd_port_stop(object);
}

static int
khttpd_ctrl_parse_server_name(struct khttpd_server_name *name,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, struct khttpd_mbuf_json *output)
{
	char buf[32];
	struct sbuf spec_buf;
	struct khttpd_problem_property *prop_spec, prop_spec1;
	struct khttpd_json *alias_j, *aliases_j;
	const char **exact_aliases, *name_str, *type_str;
	int i, n, status;

	exact_aliases = NULL;
	n = 0;
	prop_spec = input_prop_spec;
	prop_spec1.link = input_prop_spec;
	sbuf_new(&spec_buf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	if (khttpd_json_type(input) != KHTTPD_JSON_OBJECT) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, input_prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	prop_spec = &prop_spec1;
	prop_spec1.name = "name";
	status = khttpd_webapi_get_string_property(&name_str, "name",
	    input_prop_spec, input, output, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	if (name_str != NULL)
		khttpd_vhost_set_canonical_name(name, name_str);

	prop_spec1.name = "aliases";
	aliases_j = khttpd_json_object_get(input, "aliases");

	if (aliases_j != NULL) {
		if (khttpd_json_type(aliases_j) != KHTTPD_JSON_ARRAY)
			goto wrong_type;

		n = khttpd_json_array_size(aliases_j);
		exact_aliases = khttpd_malloc(n * sizeof(char *));

		for (i = 0; i < n; ++i) {
			sbuf_clear(&spec_buf);
			sbuf_printf(&spec_buf, "aliases[%d]", i);
			sbuf_finish(&spec_buf);
			prop_spec->name = sbuf_data(&spec_buf);

			alias_j = khttpd_json_array_get(aliases_j, i);

			if (khttpd_json_type(alias_j) != KHTTPD_JSON_OBJECT)
				goto wrong_type;

			status = khttpd_webapi_get_string_property(&type_str,
			    "type", prop_spec, alias_j, output, FALSE);
			if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
				goto quit;

			if (strcmp(type_str, "exact") != 0)
				goto invalid_value;

			status = khttpd_webapi_get_string_property
			    (&exact_aliases[i], "alias", prop_spec, alias_j,
				output, FALSE);
			if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
				goto quit;
		}

		khttpd_vhost_set_exact_alias_list(name, exact_aliases, n);
	}

	status = KHTTPD_STATUS_OK;
	goto quit;

 invalid_value:
	khttpd_problem_invalid_value_response_begin(output);
	goto bad_request;

 wrong_type:
	khttpd_problem_wrong_type_response_begin(output);

 bad_request:
	khttpd_problem_set_property(output, prop_spec);
	status = KHTTPD_STATUS_BAD_REQUEST;

 quit:
	khttpd_free(exact_aliases);
	sbuf_delete(&spec_buf);

	return (status);
}

static int
khttpd_ctrl_parse_ports(struct khttpd_port ***ports_out, int *port_count_out,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output)
{
	char buf[16];
	struct khttpd_problem_property *prop_spec, prop_spec1;
	struct sbuf spec_buf;
	struct khttpd_json *port_j;
	struct khttpd_port *port, **ports;
	int i, n, status;

	ports = NULL;
	sbuf_new(&spec_buf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	prop_spec = input_prop_spec;

	if (khttpd_json_type(input) != KHTTPD_JSON_ARRAY)
		goto wrong_type;

	n = khttpd_json_array_size(input);
	ports = khttpd_malloc(n * sizeof(struct khttpd_port *));
	bzero(ports, n * sizeof(struct khttpd_port *));

	prop_spec = &prop_spec1;
	prop_spec1.link = input_prop_spec;
	for (i = 0; i < n; ++i) {
		sbuf_clear(&spec_buf);
		sbuf_printf(&spec_buf, "[%d]", i);
		sbuf_finish(&spec_buf);
		prop_spec->name = sbuf_data(&spec_buf);

		port_j = khttpd_json_array_get(input, i);

		if (khttpd_json_type(port_j) != KHTTPD_JSON_STRING)
			goto wrong_type;

		ports[i] = port =
		    khttpd_obj_type_get_obj_for_id(&khttpd_ctrl_ports,
			khttpd_json_string_data(port_j));
		if (port == NULL)
			goto invalid_value;
	}

	*ports_out = ports;
	*port_count_out = n;
	status = KHTTPD_STATUS_OK;
	goto quit;

 invalid_value:
	khttpd_problem_invalid_value_response_begin(output);
	goto bad_request;

 wrong_type:
	khttpd_problem_wrong_type_response_begin(output);

 bad_request:
	khttpd_problem_set_property(output, prop_spec);
	status = KHTTPD_STATUS_BAD_REQUEST;
	khttpd_free(ports);

 quit:
	sbuf_delete(&spec_buf);

	return (status);
}

static void
khttpd_ctrl_server_acquire(void *object)
{
	struct khttpd_server *server;

	server = object;
	khttpd_server_acquire(server);
}

static void
khttpd_ctrl_server_release(void *object)
{
	struct khttpd_server *server;

	server = object;
	khttpd_server_release(server);
}

static int
khttpd_ctrl_server_get_index(void *object, struct khttpd_mbuf_json *output)
{
	struct khttpd_server *server;
	struct khttpd_server_name *name;
	const char *value;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	server = object;

	if (server == khttpd_ctrl_server) {
		khttpd_mbuf_json_property(output, "hasConfigurator");
		khttpd_mbuf_json_cstr(output, FALSE, "true");
	}

	name = khttpd_vhost_copy_server_name(server);

	value = khttpd_vhost_get_canonical_name(name);
	if (value != NULL) {
		khttpd_mbuf_json_property(output, "name");
		khttpd_mbuf_json_cstr(output, TRUE, "%s");
	}

	khttpd_vhost_server_name_delete(name);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_server_get(void *object, struct khttpd_mbuf_json *output)
{
	char buf[64];
	struct sbuf url;
	struct khttpd_server *server;
	struct khttpd_server_name *name;
	struct khttpd_port *port;
	struct khttpd_vhost_tie *iter;
	int i, n;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	server = object;
	khttpd_mbuf_json_object_begin(output);
	khttpd_ctrl_server_get_index(object, output);

	name = khttpd_vhost_copy_server_name(server);

	khttpd_mbuf_json_property(output, "aliases");
	khttpd_mbuf_json_array_begin(output);
	n = khttpd_vhost_get_exact_alias_list_length(name);
	for (i = 0; i < n; ++i) {
		khttpd_mbuf_json_object_begin(output);
		khttpd_mbuf_json_property(output, "type");
		khttpd_mbuf_json_cstr(output, TRUE, "exact");
		khttpd_mbuf_json_property(output, "value");
		khttpd_mbuf_json_cstr(output, TRUE,
		    khttpd_vhost_get_exact_alias(name, i));
		khttpd_mbuf_json_object_end(output);
	}
	khttpd_mbuf_json_array_end(output);

	khttpd_vhost_server_name_delete(name);

	sbuf_new(&url, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_mbuf_json_property(output, "ports");
	khttpd_mbuf_json_array_begin(output);
	for (iter = khttpd_vhost_port_iterator(server); iter != NULL; ) {
		sbuf_clear(&url);
		iter = khttpd_vhost_port_iterator_next(iter, &port);
		khttpd_obj_type_get_id(&khttpd_ctrl_ports, port, &url);
		sbuf_finish(&url);
		khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&url));
	}
	khttpd_mbuf_json_array_end(output);
	sbuf_delete(&url);

	khttpd_mbuf_json_object_end(output);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_server_put(void *object, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property *prop_spec, prop_spec1;
	struct khttpd_port **ports;
	struct khttpd_server *server;
	struct khttpd_server_name *name;
	struct khttpd_json *has_config_j, *ports_j;
	int port_count, status;
	boolean_t has_config;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	server = object;
	ports = NULL;
	port_count = 0;

	name = khttpd_vhost_server_name_new();
	status = khttpd_ctrl_parse_server_name(name, input_prop_spec, input,
	    output);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	prop_spec = &prop_spec1;
	prop_spec1.link = input_prop_spec;

	prop_spec1.name = "hasConfigurator";
	has_config_j = khttpd_json_object_get(input, "hasConfigurator");
	if (has_config_j != NULL && 
	    khttpd_json_type(has_config_j) != KHTTPD_JSON_BOOL) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, prop_spec);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}
	has_config = has_config_j != NULL &&
	    khttpd_json_integer_value(has_config_j) != 0;
	if (has_config != (server == khttpd_ctrl_server)) {
		status = KHTTPD_STATUS_CONFLICT;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_property(output, prop_spec);
		goto quit;
	}

	prop_spec1.name = "ports";
	ports_j = khttpd_json_object_get(input, "ports");
	if (ports_j != NULL) {
		status = khttpd_ctrl_parse_ports(&ports, &port_count,
		    prop_spec, ports_j, output);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto quit;
	}

	khttpd_vhost_set_server_name(server, name);
	name = NULL;
	khttpd_vhost_set_port_list(server, ports, port_count);
	status = KHTTPD_STATUS_OK;

 quit:
	khttpd_free(ports);
	khttpd_vhost_server_name_delete(name);

	return (status);
}

static int
khttpd_ctrl_server_create(void *object_out, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_problem_property prop_spec;
	struct khttpd_server *server;
	struct khttpd_json *has_config_j;
	struct khttpd_location *location;
	int error, status;
	boolean_t has_config;

	prop_spec.link = input_prop_spec;
	prop_spec.name = "hasConfigurator";

	has_config_j = khttpd_json_object_get(input, "hasConfigurator");
	if (has_config_j == NULL)
		has_config = FALSE;
	else if (khttpd_json_type(has_config_j) != KHTTPD_JSON_BOOL) {
		status = KHTTPD_STATUS_BAD_REQUEST;
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (status);
	} else
		has_config = khttpd_json_integer_value(has_config_j);

	if (has_config) {
		if ((khttpd_obj_type_get_leaf(&khttpd_ctrl_servers,
			    khttpd_ctrl_server) != NULL)) {
			status = KHTTPD_STATUS_CONFLICT;
			khttpd_problem_wrong_type_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec);
			return (status);
		}

		server = khttpd_server_acquire(khttpd_ctrl_server);

	} else {
		server = khttpd_server_new(&error);
		if (server == NULL) {
			khttpd_problem_response_begin(output,
			    KHTTPD_STATUS_INTERNAL_SERVER_ERROR, NULL, NULL);
			khttpd_problem_set_detail(output, 
			    "server construction failed");
			khttpd_problem_set_errno(output, error);
			return (KHTTPD_STATUS_INTERNAL_SERVER_ERROR);
		}
	}

	status = khttpd_ctrl_server_put(server, output, NULL, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		khttpd_server_release(server);
		return (status);
	}

	if (!has_config) {
		khttpd_uuid_new(uuid);
		location = khttpd_location_new(&error, server, "*",
		    &khttpd_ctrl_asterisc_ops, NULL);
		khttpd_obj_type_show_obj(&khttpd_ctrl_locations, location,
		    uuid);
		khttpd_location_release(location);
	}

	*(void **)object_out = server;

	return (status);
}

static void
khttpd_ctrl_server_hide(void *object)
{
	struct khttpd_server *server;
	struct khttpd_location *location, *nextloc;

	server = object;
	khttpd_vhost_clear_port_list(server);

	for (location = khttpd_server_first_location(server); location != NULL;
	     location = nextloc) {
		nextloc = khttpd_server_next_location(server, location);
		khttpd_obj_type_hide_obj(&khttpd_ctrl_locations, location);
		khttpd_location_release(location);
	}
}

static int
khttpd_ctrl_location_ctor(void *host, void *arg)
{
	struct khttpd_ctrl_location_data *data;
	
	data = khttpd_costruct_get(host, khttpd_ctrl_location_data_key);
	data->type = NULL;

	return (0);
}

static void
khttpd_ctrl_location_acquire(void *object)
{
	struct khttpd_location *location;

	location = object;
	khttpd_location_acquire(location);
}

static void
khttpd_ctrl_location_release(void *object)
{
	struct khttpd_location *location;

	location = object;
	khttpd_location_release(location);
}

static int
khttpd_ctrl_location_get_index(void *object, struct khttpd_mbuf_json *output)
{
	char buf[64];
	struct sbuf sbuf;
	struct khttpd_ctrl_location_data *location_data;
	struct khttpd_location_type *type;
	struct khttpd_location *location;
	struct khttpd_server *server;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	location = object;
	location_data = khttpd_costruct_get(location, 
	    khttpd_ctrl_location_data_key);
	type = location_data->type;

	if (type != NULL) {
		khttpd_mbuf_json_property(output, "type");
		khttpd_mbuf_json_cstr(output, TRUE, type->name);
	}

	server = khttpd_location_get_server(location);
	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	khttpd_obj_type_get_id(&khttpd_ctrl_servers, server, &sbuf);
	sbuf_finish(&sbuf);
	khttpd_mbuf_json_property(output, "server");
	khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&sbuf));
	sbuf_delete(&sbuf);

	khttpd_mbuf_json_property(output, "path");
	khttpd_mbuf_json_cstr(output, TRUE,
	    khttpd_location_get_path(location));

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_location_get(void *object, struct khttpd_mbuf_json *output)
{
	struct khttpd_ctrl_location_data *location_data;
	struct khttpd_location_type *type;
	struct khttpd_location *location;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	location = object;
	location_data = khttpd_costruct_get(location,
	    khttpd_ctrl_location_data_key);
	type = location_data->type;

	khttpd_ctrl_location_get_index(location, output);

	if (type != NULL)
		type->get(object, output);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_location_put(void *object, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_location *location;
	struct khttpd_ctrl_location_data *location_data;
	struct khttpd_location_type *type;
	const char *path;
	void *obj;
	int status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	location = object;
	location_data = khttpd_costruct_get(location,
	    khttpd_ctrl_location_data_key);

	status = khttpd_location_type_get_from_property(&type, "type", output,
	    input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec.link = NULL;

	if (type != location_data->type) {
		prop_spec.name = "type";
		status = KHTTPD_STATUS_CONFLICT;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_property(output, &prop_spec);
		return (status);
	}

	status = khttpd_webapi_get_string_property(&path, "path", NULL, input,
	    output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	if (strcmp(path, khttpd_location_get_path(location)) != 0) {
		prop_spec.name = "path";
		status = KHTTPD_STATUS_CONFLICT;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_property(output, &prop_spec);
		return (status);
	}

	status = khttpd_obj_type_get_obj_from_property(&khttpd_ctrl_servers,
	    &obj, "server", output, NULL, input, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	if (obj != khttpd_location_get_server(location)) {
		prop_spec.name = "server";
		status = KHTTPD_STATUS_CONFLICT;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_property(output, &prop_spec);
		return (status);
	}

	return (type->put(location, output, NULL, input));
}

static int
khttpd_ctrl_location_create(void *object_out, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_location_type *type;
	struct khttpd_location *location;
	struct khttpd_ctrl_location_data *location_data;
	struct khttpd_server *server;
	const char *path;
	void *obj;
	int status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	prop_spec.link = NULL;

	status = khttpd_location_type_get_from_property(&type, "type", output,
	    input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_webapi_get_string_property(&path, "path",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_obj_type_get_obj_from_property(&khttpd_ctrl_servers,
	    &obj, "server", output, input_prop_spec, input, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);
	server = obj;

	status = type->create(&location, server, path, output, input_prop_spec,
	    input);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		location_data = khttpd_costruct_get(location,
		    khttpd_ctrl_location_data_key);
		location_data->type = type;
		*(void **)object_out = location;
	}

	return (status);
}

static void
khttpd_ctrl_rewriter_acquire(void *object)
{
	struct khttpd_rewriter *rewriter;

	rewriter = object;
	khttpd_rewriter_acquire(rewriter);
}

static void
khttpd_ctrl_rewriter_release(void *object)
{
	struct khttpd_rewriter *rewriter;

	rewriter = object;
	khttpd_rewriter_release(rewriter);
}

static int
khttpd_ctrl_rewriter_get(void *object, struct khttpd_mbuf_json *output)
{
	char buf[128];
	struct sbuf sbuf;
	struct khttpd_rewriter *rewriter;
	struct khttpd_rewriter_rule *rule;
	const char *str1, *str2;
	boolean_t has_default;

	sx_assert(&khttpd_ctrl_lock, SA_LOCKED);

	rewriter = object;

	khttpd_mbuf_json_object_begin(output);

	khttpd_mbuf_json_property(output, "rules");
	khttpd_mbuf_json_array_begin(output);

	for (rule = khttpd_rewriter_iteration_begin(rewriter);
	     rule != NULL;
	     rule = khttpd_rewriter_iteration_next(rewriter, rule)) {

		khttpd_mbuf_json_object_begin(output);

		switch (khttpd_rewriter_rule_get_type(rule)) {

		case KHTTPD_REWRITER_RULE_SUFFIX:
			khttpd_mbuf_json_property(output, "type");
			khttpd_mbuf_json_cstr(output, TRUE, "suffix");
			khttpd_rewriter_rule_inspect_suffix_rule(rule, &str1,
			    &str2);
			khttpd_mbuf_json_property(output, "pattern");
			khttpd_mbuf_json_cstr(output, TRUE, str1);
			khttpd_mbuf_json_property(output, "result");
			khttpd_mbuf_json_cstr(output, TRUE, str2);
			break;

		default:
			log(LOG_ERR, "khttpd: unknown rewriter rule type: %d",
			    khttpd_rewriter_rule_get_type(rule));
		}

		khttpd_mbuf_json_object_end(output);
	}

	khttpd_rewriter_iteration_end(rewriter);

	khttpd_mbuf_json_array_end(output);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	has_default = khttpd_rewriter_get_default(rewriter, &sbuf);
	sbuf_finish(&sbuf);
	if (has_default) {
		khttpd_mbuf_json_property(output, "default");
		khttpd_mbuf_json_format(output, TRUE, "%s", sbuf_data(&sbuf));
	}
	sbuf_delete(&sbuf);

	khttpd_mbuf_json_object_end(output);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_rewriter_add_rule_from_propery(struct khttpd_rewriter *rewriter,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	const char *type, *pattern, *result;
	int status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	status = khttpd_webapi_get_string_property(&type, "type",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	if (strcmp(type, "suffix") != 0) {
		prop_spec.link = input_prop_spec;
		prop_spec.name = "type";
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	status = khttpd_webapi_get_string_property(&pattern, "pattern",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_webapi_get_string_property(&result, "result",
	    input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	khttpd_rewriter_add_suffix_rule(rewriter, pattern, result);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_rewriter_modify(struct khttpd_rewriter *rewriter,
    struct khttpd_mbuf_json *output, 
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	char buf[64];
	struct sbuf sbuf;
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *rules_j, *rule_j;
	const char *str1;
	int i, n, status;

	KHTTPD_ENTRY("%s(%p,,%s,%p)", __func__, rewriter, output,
	    khttpd_problem_ktr_print_property(input_prop_spec), input);

	prop_spec.link = NULL;
	prop_spec.name = "rules";
	rules_j = khttpd_json_object_get(input, "rules");
	if (rules_j != NULL) {
		if (khttpd_json_type(rules_j) != KHTTPD_JSON_ARRAY) {
			khttpd_problem_wrong_type_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
		n = khttpd_json_array_size(rules_j);
		for (i = 0; i < n; ++i) {
			sbuf_clear(&sbuf);
			sbuf_printf(&sbuf, "rules[%d]", i);
			sbuf_finish(&sbuf);

			rule_j = khttpd_json_array_get(rules_j, i);
			prop_spec.name = sbuf_data(&sbuf);
			status = khttpd_ctrl_rewriter_add_rule_from_propery
			    (rewriter, output, &prop_spec, rule_j);
			if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
				break;
		}
		sbuf_delete(&sbuf);
	}

	status = khttpd_webapi_get_string_property(&str1, "default", NULL,
	    input, output, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	khttpd_rewriter_set_default(rewriter, str1);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_ctrl_rewriter_put(void *object, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_rewriter *rewriter, *tmp_rewriter;
	int error, status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	rewriter = object;
	error = khttpd_rewriter_new(&tmp_rewriter);
	if (error != 0) {
		status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_errno(output, error);
		khttpd_problem_set_detail(output, 
		    "failed to construct a rewriter");
		return (status);
	}

	status = khttpd_ctrl_rewriter_modify(tmp_rewriter, output,
	    input_prop_spec, input);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		khttpd_rewriter_swap(rewriter, tmp_rewriter);

	khttpd_rewriter_release(tmp_rewriter);

	return (status);
}

static int
khttpd_ctrl_rewriter_create(void *object_out, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_rewriter *rewriter;
	int error, status;

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	error = khttpd_rewriter_new(&rewriter);
	if (error != 0) {
		status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR;
		khttpd_problem_response_begin(output, status, NULL, NULL);
		khttpd_problem_set_errno(output, error);
		khttpd_problem_set_detail(output,
		    "failed to construct a rewriter");
		return (status);
	}

	status = khttpd_ctrl_rewriter_modify(rewriter, output,
	    input_prop_spec, input);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status))
		*(void **)object_out = rewriter;
	else
		khttpd_rewriter_release(rewriter);

	return (status);
}

static int
khttpd_ctrl_clear(void)
{
	char uuid[KHTTPD_UUID_SIZE];
	struct khttpd_location *location;
	int error;

	KHTTPD_ENTRY("khttpd_ctrl_clear()");

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	location = khttpd_location_new(&error, khttpd_ctrl_server, "*",
	    &khttpd_ctrl_asterisc_ops, NULL);
	if (location == NULL)
		return (error);

	khttpd_obj_type_clear(&khttpd_ctrl_rewriters);
	khttpd_obj_type_clear(&khttpd_ctrl_locations);
	khttpd_obj_type_clear(&khttpd_ctrl_servers);
	khttpd_obj_type_clear(&khttpd_ctrl_ports);

	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_locations, location, uuid);
	khttpd_location_release(location);

	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_servers,
	    khttpd_ctrl_server, uuid);
	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_locations,
	    khttpd_ctrl_rewriters.node, uuid);
	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_locations,
	    khttpd_ctrl_ports.node, uuid);
	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_locations,
	    khttpd_ctrl_servers.node, uuid);
	khttpd_uuid_new(uuid);
	khttpd_obj_type_show_obj(&khttpd_ctrl_locations,
	    khttpd_ctrl_locations.node, uuid);

	return (0);
}

static void
khttpd_ctrl_start(void *arg)
{
	char buf[128];
	struct khttpd_mbuf_json output;
	struct khttpd_problem_property prop_spec;
	struct sbuf sbuf;
	struct khttpd_main_start_command *cmd;
	struct khttpd_json *args_j, *rewriters_j, *ports_j;
	struct khttpd_json *servers_j, *locations_j;
	struct khttpd_json *access_log_j, *error_log_j;
	struct khttpd_log *access_log, *error_log;
	struct mbuf *data, *mb, *tmb;
	int status;

	cmd = arg;
	data = cmd->data;
	KHTTPD_ENTRY("khttpd_ctrl_start({data=%p})", data);

	prop_spec.link = NULL;
	khttpd_mbuf_json_new(&output);
	args_j = NULL;
	access_log = error_log = NULL;

	status = khttpd_ctrl_parse_json(&args_j, &output, data);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	if (khttpd_json_type(args_j) != KHTTPD_JSON_OBJECT) {
		khttpd_problem_wrong_type_response_begin(&output);
		khttpd_problem_set_property(&output, &prop_spec);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}

	prop_spec.name = "accessLog";
	access_log_j = khttpd_json_object_get(args_j, "accessLog");
	if (access_log_j != NULL) {
		status = khttpd_ctrl_log_new(&access_log, &output, &prop_spec,
		    access_log_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto quit;
	}

	prop_spec.name = "errorLog";
	error_log_j = khttpd_json_object_get(args_j, "errorLog");
	if (error_log_j != NULL) {
		status = khttpd_ctrl_log_new(&error_log, &output, &prop_spec,
		    error_log_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto quit;
	}

	prop_spec.name = "rewriters";
	rewriters_j = khttpd_json_object_get(args_j, "rewriters");

	prop_spec.name = "ports";
	ports_j = khttpd_json_object_get(args_j, "ports");

	prop_spec.name = "servers";
	servers_j = khttpd_json_object_get(args_j, "servers");

	prop_spec.name = "locations";
	locations_j = khttpd_json_object_get(args_j, "locations");

	sx_xlock(&khttpd_ctrl_lock);

	khttpd_obj_type_clear(&khttpd_ctrl_rewriters);
	khttpd_obj_type_clear(&khttpd_ctrl_ports);
	khttpd_obj_type_clear(&khttpd_ctrl_servers);
	khttpd_obj_type_clear(&khttpd_ctrl_locations);

	status = KHTTPD_STATUS_OK;

	if (rewriters_j != NULL) {
		status = khttpd_obj_type_load(&khttpd_ctrl_rewriters, &output,
		    &prop_spec, rewriters_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto unlock;
	}

	if (ports_j != NULL) {
		status = khttpd_obj_type_load(&khttpd_ctrl_ports, &output,
		    &prop_spec, ports_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto unlock;
	}

	if (servers_j != NULL) {
		status = khttpd_obj_type_load(&khttpd_ctrl_servers, &output,
		    &prop_spec, servers_j);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			goto unlock;
	}

	if (locations_j != NULL)
		status = khttpd_obj_type_load(&khttpd_ctrl_locations, &output,
		    &prop_spec, locations_j);

	khttpd_http_set_log(KHTTPD_HTTP_LOG_ACCESS, access_log);
	khttpd_http_set_log(KHTTPD_HTTP_LOG_ERROR, error_log);
	access_log = error_log = NULL;

 unlock:
	sx_xunlock(&khttpd_ctrl_lock);

 quit:
	khttpd_log_delete(access_log);
	khttpd_log_delete(error_log);

	khttpd_json_delete(args_j);

	if (KHTTPD_STATUS_IS_SUCCESSFUL(status)) {
		cmd->hdr.error = 0;
		return;
	}

	khttpd_ctrl_clear();

	khttpd_mbuf_json_object_end(&output);
	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);
	mb = khttpd_mbuf_json_move(&output);
	while (mb != NULL) {
		sbuf_bcat(&sbuf, mb->m_data, mb->m_len);
		tmb = mb;
		mb = mb->m_next;
		m_free(tmb);
	}
	sbuf_finish(&sbuf);
	log(LOG_ERR, "khttpd: failed to initialize the server. %s",
	    sbuf_data(&sbuf));
	sbuf_delete(&sbuf);

	cmd->hdr.error = EINVAL;
}

static void
khttpd_ctrl_free_cmdbuf_data(struct mbuf *m, void *arg1, void *arg2)
{

	KHTTPD_ENTRY("khttpd_ctrl_free_cmdbuf_data(%p,%p)", m, arg1);
	free(arg1, M_TEMP);
}

static int
khttpd_ctrl_ioctl_start(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct khttpd_main_start_command cmdbuf;
	struct khttpd_ioctl_start_args *args;
	char *buf;
	int error;

	args = (void *)data;

	KHTTPD_ENTRY("khttpd_ctrl_ioctl_start(%p,%#lx,%p,%#x)", dev, cmd,
	    data, fflag);

	if (KHTTPD_CTRL_MAX_DATA_SIZE < args->size) {
		log(LOG_ERR, "khttpd: configuration data size is larger than "
		    "the limit (%#zx bytes)",
		    KHTTPD_CTRL_MAX_DATA_SIZE);
		return (EINVAL);
	}

	cmdbuf.hdr.handler = khttpd_ctrl_start;
	cmdbuf.data = m_get(M_WAITOK, MT_DATA);
	buf = malloc(roundup2(args->size, sizeof(u_int)) +
	    sizeof(u_int), M_TEMP, M_WAITOK);
	cmdbuf.data->m_len = args->size;
	MEXTADD(cmdbuf.data, buf, args->size, khttpd_ctrl_free_cmdbuf_data,
	    buf, NULL, 0, EXT_EXTREF);
	cmdbuf.data->m_ext.ext_cnt = (u_int *)
	    (buf + roundup2(args->size, sizeof(u_int)));
	*cmdbuf.data->m_ext.ext_cnt = 1;

	error = copyin(args->data, buf, args->size);

	if (error == 0) {
		khttpd_main_call(&cmdbuf.hdr);
		error = cmdbuf.hdr.error;
	}

	m_free(cmdbuf.data);

	return (error);
}

static void
khttpd_ctrl_register_ioctl(const void *arg)
{

	KHTTPD_ENTRY("khttpd_ctrl_register_ioctl()");
	khttpd_main_register_ioctl(KHTTPD_IOC_START, khttpd_ctrl_ioctl_start);
}

SYSINIT(khttpd, SI_SUB_CONFIGURE, SI_ORDER_ANY, khttpd_ctrl_register_ioctl,
    NULL);

static void
khttpd_ctrl_deregister_ioctl(const void *arg)
{

	KHTTPD_ENTRY("khttpd_ctrl_deregister_ioctl()");
	khttpd_main_deregister_ioctl(KHTTPD_IOC_START);
}

SYSUNINIT(khttpd, SI_SUB_CONFIGURE, SI_ORDER_ANY, khttpd_ctrl_deregister_ioctl,
    NULL);

static int
khttpd_ctrl_register_costruct(void)
{

	KHTTPD_ENTRY("khttpd_ctrl_register_costruct()");

	khttpd_ctrl_port_data_key = 
	    khttpd_costruct_register(khttpd_port_costruct_info,
		sizeof(struct khttpd_ctrl_port_data),
		khttpd_ctrl_port_ctor, NULL, NULL);

	khttpd_ctrl_location_data_key = 
	    khttpd_costruct_register(khttpd_location_costruct_info,
		sizeof(struct khttpd_ctrl_location_data), 
		khttpd_ctrl_location_ctor, NULL, NULL);

	khttpd_obj_type_new(&khttpd_ctrl_rewriters, "rewriter",
	    khttpd_rewriter_costruct_info, NULL, NULL,
	    khttpd_ctrl_rewriter_acquire, khttpd_ctrl_rewriter_release,
	    khttpd_ctrl_rewriter_create, khttpd_ctrl_null_obj_fn, NULL,
	    khttpd_ctrl_rewriter_get, khttpd_ctrl_rewriter_put);

	khttpd_obj_type_new(&khttpd_ctrl_ports, "port",
	    khttpd_port_costruct_info, NULL, khttpd_ctrl_port_hide,
	    khttpd_ctrl_port_acquire, khttpd_ctrl_port_release,
	    khttpd_ctrl_port_create, khttpd_ctrl_null_obj_fn,
	    khttpd_ctrl_port_get_index,
	    khttpd_ctrl_port_get, khttpd_ctrl_port_put);

	khttpd_obj_type_new(&khttpd_ctrl_servers, "server",
	    khttpd_server_costruct_info, NULL, khttpd_ctrl_server_hide,
	    khttpd_ctrl_server_acquire, khttpd_ctrl_server_release,
	    khttpd_ctrl_server_create, khttpd_ctrl_null_obj_fn,
	    khttpd_ctrl_server_get_index,
	    khttpd_ctrl_server_get, khttpd_ctrl_server_put);

	khttpd_obj_type_new(&khttpd_ctrl_locations, "location",
	    khttpd_location_costruct_info, NULL, NULL,
	    khttpd_ctrl_location_acquire, khttpd_ctrl_location_release,
	    khttpd_ctrl_location_create, khttpd_ctrl_null_obj_fn,
	    khttpd_ctrl_location_get_index,
	    khttpd_ctrl_location_get, khttpd_ctrl_location_put);

	return (0);
}

static void
khttpd_ctrl_deregister_costruct(void)
{

	KHTTPD_ENTRY("khttpd_ctrl_deregister_costruct()");

	khttpd_obj_type_delete(&khttpd_ctrl_locations);
	khttpd_obj_type_delete(&khttpd_ctrl_servers);
	khttpd_obj_type_delete(&khttpd_ctrl_ports);
	khttpd_obj_type_delete(&khttpd_ctrl_rewriters);
}

KHTTPD_INIT(, khttpd_ctrl_register_costruct, khttpd_ctrl_deregister_costruct,
    KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS);

static int
khttpd_ctrl_preregister_location_types(void)
{
	int i;

	KHTTPD_ENTRY("khttpd_ctrl_preregister_location_types()");

	for (i = 0; i < sizeof(khttpd_location_types) / 
		 sizeof(khttpd_location_types[0]); ++i)
		SLIST_INIT(&khttpd_location_types[i]);

	return (0);
}

static void
khttpd_ctrl_postderegister_location_types(void)
{
	struct khttpd_location_type *loctype, *tloctype;
	int i;

	KHTTPD_ENTRY("khttpd_ctrl_postderegister_location_types()");

	for (i = 0; i < sizeof(khttpd_location_types) / 
		 sizeof(khttpd_location_types[0]); ++i)
		SLIST_FOREACH_SAFE(loctype, &khttpd_location_types[i],
		    slink, tloctype) {
			log(LOG_WARNING, "khttpd: location type \"%s\" is "
			    "left registered", loctype->name);
			khttpd_free(loctype);
		}
}

KHTTPD_INIT(, khttpd_ctrl_preregister_location_types, 
    khttpd_ctrl_postderegister_location_types,
    KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES - 1);

static void
khttpd_ctrl_release_all(void)
{

	KHTTPD_ENTRY("khttpd_ctrl_release_all()");

	sx_assert(&khttpd_ctrl_lock, SA_XLOCKED);

	khttpd_location_release(khttpd_ctrl_rewriters.node);
	khttpd_ctrl_rewriters.node = NULL;

	khttpd_location_release(khttpd_ctrl_ports.node);
	khttpd_ctrl_ports.node = NULL;

	khttpd_location_release(khttpd_ctrl_servers.node);
	khttpd_ctrl_servers.node = NULL;

	khttpd_location_release(khttpd_ctrl_locations.node);
	khttpd_ctrl_locations.node = NULL;

	khttpd_server_release(khttpd_ctrl_server);
	khttpd_ctrl_server = NULL;
}

static int
khttpd_ctrl_run(void)
{
	struct khttpd_server *server;
	int error;

	KHTTPD_ENTRY("khttpd_ctrl_run()");

	sx_xlock(&khttpd_ctrl_lock);

	KASSERT(LIST_EMPTY(&khttpd_ctrl_rewriters.leafs),
	    ("rewriter leak is detected"));
	KASSERT(LIST_EMPTY(&khttpd_ctrl_ports.leafs),
	    ("port leak is detected"));
	KASSERT(LIST_EMPTY(&khttpd_ctrl_servers.leafs),
	    ("server leak is detected"));
	KASSERT(LIST_EMPTY(&khttpd_ctrl_locations.leafs),
	    ("location leak is detected"));

	khttpd_ctrl_server = server = khttpd_server_new(&error);
	if (server == NULL) {
		log(LOG_ERR, "khttpd: failed to construct a server "
		    "(error: %d)", error);
		goto quit;
	}

	error = khttpd_obj_type_mount(&khttpd_ctrl_rewriters, server,
	    KHTTPD_CTRL_PATH_REWRITERS);
	if (error != 0)
		goto quit;

	error = khttpd_obj_type_mount(&khttpd_ctrl_ports, server,
	    KHTTPD_CTRL_PATH_PORTS);
	if (error != 0)
		goto quit;

	error = khttpd_obj_type_mount(&khttpd_ctrl_servers, server,
	    KHTTPD_CTRL_PATH_SERVERS);
	if (error != 0)
		goto quit;

	error = khttpd_obj_type_mount(&khttpd_ctrl_locations, server,
	    KHTTPD_CTRL_PATH_LOCATIONS);
	if (error != 0)
		goto quit;

 quit:
	if (error != 0)
		khttpd_ctrl_release_all();

	sx_xunlock(&khttpd_ctrl_lock);

	return (error);
}

static void
khttpd_ctrl_exit(void)
{

	KHTTPD_ENTRY("khttpd_ctrl_exit()");

	sx_xlock(&khttpd_ctrl_lock);
	khttpd_http_set_log(KHTTPD_HTTP_LOG_ERROR, NULL);
	khttpd_http_set_log(KHTTPD_HTTP_LOG_ACCESS, NULL);
	khttpd_obj_type_clear(&khttpd_ctrl_rewriters);
	khttpd_obj_type_clear(&khttpd_ctrl_locations);
	khttpd_obj_type_clear(&khttpd_ctrl_servers);
	khttpd_obj_type_clear(&khttpd_ctrl_ports);
	khttpd_ctrl_release_all();
	sx_xunlock(&khttpd_ctrl_lock);
}

KHTTPD_INIT(khttpd_ctrl, khttpd_ctrl_run, khttpd_ctrl_exit,
    KHTTPD_INIT_PHASE_RUN, khttpd_port, khttpd_vhost);
