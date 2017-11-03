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

#include "khttpd_server.h"

#include <sys/param.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/refcount.h>
#include <sys/lock.h>
#include <sys/rwlock.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/fcntl.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>
#include <machine/atomic.h>

#include "khttpd_costruct.h"
#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_refcount.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_method.h"

RB_HEAD(khttpd_location_tree, khttpd_location);
TAILQ_HEAD(khttpd_location_list, khttpd_location);

/* 
 * 'parent' becomes NULL if a location is replaced by another location.
 */
struct khttpd_location {
	TAILQ_ENTRY(khttpd_location) children_link;
	RB_ENTRY(khttpd_location) children_node;
	struct khttpd_location_tree children_tree;
	struct khttpd_location_list children_list;
	struct khttpd_location_ops *ops;
	struct khttpd_server *server;
	const char	*path;
	const char	*key;
	void		*data;
	size_t		key_len;

#define khttpd_location_zctor_begin parent
	struct khttpd_location *parent;
	struct khttpd_log *logs[KHTTPD_SERVER_LOG_END];
	unsigned	costructs_ready:1;
	unsigned	hide:1;

#define khttpd_location_zctor_end refcount
	KHTTPD_REFCOUNT1_MEMBERS;
};

/* 
 *  Don't be confused!  The root of the location tree is **NOT** a
 *  location for path '/'.
 */

struct khttpd_server {
	struct rwlock		lock;
	struct khttpd_location	*root;
	unsigned costructs_ready:1;
	KHTTPD_REFCOUNT1_MEMBERS;
};

static int khttpd_location_compare(struct khttpd_location *x,
    struct khttpd_location *y);
static void khttpd_location_dtor(struct khttpd_location *location);
static struct khttpd_location *khttpd_location_new_root
    (struct khttpd_server *server);

static void khttpd_server_dtor(struct khttpd_server *server);
static void khttpd_server_adopt_successors(struct khttpd_location *parent,
    struct khttpd_location *new_parent, char *lbegin, size_t len);

struct khttpd_costruct_info *khttpd_location_costruct_info;
struct khttpd_costruct_info *khttpd_server_costruct_info;

static struct khttpd_location_ops khttpd_location_null_ops;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

RB_PROTOTYPE_STATIC(khttpd_location_tree, khttpd_location, children_node,
    khttpd_location_compare);
RB_GENERATE_STATIC(khttpd_location_tree, khttpd_location, children_node,
    khttpd_location_compare);

#pragma clang diagnostic pop

KHTTPD_REFCOUNT1_GENERATE(khttpd_location, khttpd_location,
    khttpd_location_dtor, khttpd_free);
KHTTPD_REFCOUNT1_GENERATE(khttpd_server, khttpd_server, khttpd_server_dtor,
    khttpd_free);

static int
khttpd_location_compare(struct khttpd_location *x, struct khttpd_location *y)
{
	size_t xl, yl;
	int r;

	xl = x->key_len;
	yl = y->key_len;
	r = memcmp(x->key, y->key, MIN(xl, yl));
	return (r != 0 ? r : xl == yl ? 0 : xl < yl ? -1 : 1);
}

static void
khttpd_location_unlink(struct khttpd_location *loc)
{
	struct khttpd_location *child, *parent, *tmpptr;
	struct khttpd_server *server;
	size_t len;

	KHTTPD_ENTRY("khttpd_location_unlink(%p)", loc);

	server = loc->server;
	rw_wlock(&server->lock);

	parent = loc->parent;
	KASSERT(parent != NULL, ("location %p, parent %p", location, parent));

	RB_REMOVE(khttpd_location_tree, &parent->children_tree, loc);

	/* Make all the children of 'loc' be children of the parent. */

	len = loc->key_len;
	TAILQ_FOREACH_REVERSE_SAFE(child, &loc->children_list,
	    khttpd_location_list, children_link, tmpptr) {
		TAILQ_REMOVE(&loc->children_list, child, children_link);

		child->parent = parent;
		child->key -= len;
		child->key_len += len;

		RB_INSERT(khttpd_location_tree, &parent->children_tree,
		    child);
		TAILQ_INSERT_AFTER(&parent->children_list, loc, child,
		    children_link);
	}

	TAILQ_REMOVE(&parent->children_list, loc, children_link);

	rw_wunlock(&server->lock);
}

static void
khttpd_location_dtor(struct khttpd_location *location)
{
	struct khttpd_location_ops *ops;
	struct khttpd_server *server;
	khttpd_location_fn_t dtor;
	int i, nlogs;

	KHTTPD_TR("%s(%p)", __func__, location);

	ops = location->ops;
	dtor = ops->dtor;
	if (dtor != NULL)
		dtor(location);

	if (location->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_location_costruct_info,
		    location);

	if (location->parent != NULL) {
		server = location->server;
		khttpd_location_unlink(location);
		khttpd_server_release(server);
	}

	nlogs = sizeof(location->logs) / sizeof(location->logs[0]);
	for (i = 0; i < nlogs; ++i)
		khttpd_log_delete(location->logs[i]);
}

struct khttpd_location_ops *
khttpd_location_get_ops(struct khttpd_location *location)
{

	return (location->ops);
}

struct khttpd_log *
khttpd_location_get_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id)
{
	struct khttpd_log *log;
	struct khttpd_location *loc;

	KASSERT(0 <= log_id && log_id < KHTTPD_SERVER_LOG_END,
	    ("invalid log id %d", log_id));

	log = NULL;
	for (loc = location; loc != NULL; loc = loc->parent) {
		log = loc->logs[log_id];
		if (log != NULL)
			return (log);
	}

	return (NULL);
}

void
khttpd_location_set_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id, struct khttpd_log *log)
{

	KASSERT(0 <= log_id && log_id < KHTTPD_SERVER_LOG_END,
	    ("invalid log id %d", log_id));

	location->logs[log_id] = log;
}

void
khttpd_location_log(struct khttpd_location *location,
    enum khttpd_server_log_id log_id, struct mbuf *entry)
{
	struct khttpd_log *log;

	log = khttpd_location_get_log(location, log_id);
	if (log == NULL && log_id != KHTTPD_SERVER_LOG_ERROR)
		return;

	khttpd_log_put(log, entry);
}

void
khttpd_location_error(struct khttpd_location *location, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, ...)
{
	va_list args;

	va_start(args, desc_fmt);
	khttpd_location_verror(location, severity, entry, desc_fmt, args);
	va_end(args);
}

void
khttpd_location_verror(struct khttpd_location *location, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, va_list args)
{
	struct khttpd_mbuf_json new_entry;

	if (entry == NULL) {
		entry = &new_entry;
		khttpd_mbuf_json_new(entry);
		khttpd_mbuf_json_object_begin(entry);
	}

	khttpd_log_vput_error_properties(entry, severity, desc_fmt, args);
	khttpd_mbuf_json_object_end(entry);
	khttpd_location_log(location, KHTTPD_SERVER_LOG_ERROR,
	    khttpd_mbuf_json_move(entry));
}

const char *
khttpd_location_get_path(struct khttpd_location *location)
{

	return (location->path);
}

struct khttpd_server *
khttpd_location_get_server(struct khttpd_location *location)
{

	return (location->server);
}

static struct khttpd_location *
khttpd_location_new_root(struct khttpd_server *server)
{
	struct khttpd_location *loc;

	loc = khttpd_malloc(sizeof(struct khttpd_location) + 1);

	bzero(&loc->khttpd_location_zctor_begin,
	    offsetof(struct khttpd_location, khttpd_location_zctor_end) -
	    offsetof(struct khttpd_location, khttpd_location_zctor_begin));

	RB_INIT(&loc->children_tree);
	TAILQ_INIT(&loc->children_list);
	loc->ops = &khttpd_location_null_ops;
	loc->server = server;
	loc->parent = NULL;
	loc->data = NULL;
	loc->path = (char *)(loc + 1);
	loc->key = loc->path;
	loc->key_len = 0;
	KHTTPD_REFCOUNT1_INIT(khttpd_location, loc);
	*(char *)(loc + 1) = '\0';

	return (loc);
}

struct khttpd_location *
khttpd_location_new(int *error_out, struct khttpd_server *server,
    const char *path, struct khttpd_location_ops *ops, void *data)
{
	struct khttpd_location *loc, *parent, *ptr;
	struct khttpd_location *oldloc;
	char *lbegin, *lend;
	size_t len;
	boolean_t need_not_append_slash;

	/*
	 * This function doesn't accept NULL ops.  NULL ops means it is a root
	 * location.
	 */
	KASSERT(ops != NULL, ("ops for location \"%s\" is NULL", ops));

	/* 
	 * The path must be '*' or start with '/'.  The trailing '/' can be
	 * omitted.
	 */
	KASSERT(path[0] == '/' || (path[0] == '*' && path[1] == '\0'),
	    ("path %s doesn't start with '/'", path));

	/* Allocate location instance and the path buffer. */

	len = strlen(path);
	need_not_append_slash = (0 < len && path[len - 1] == '/') || 
	    (len == 1 && path[0] == '*');

	loc = khttpd_malloc
	    (khttpd_costruct_instance_size(khttpd_location_costruct_info) +
		(need_not_append_slash ? len + 1 : len + 2));

	/* Initialize the allocated instance. */

	RB_INIT(&loc->children_tree);
	TAILQ_INIT(&loc->children_list);
	loc->ops = ops;
	loc->server = khttpd_server_acquire(server);
	loc->path = lbegin = (char *)loc +
	    khttpd_costruct_instance_size(khttpd_location_costruct_info);
	loc->key = lbegin;
	loc->data = data;
	bzero(&loc->khttpd_location_zctor_begin,
	    offsetof(struct khttpd_location, khttpd_location_zctor_end) -
	    offsetof(struct khttpd_location, khttpd_location_zctor_begin));
	KHTTPD_REFCOUNT1_INIT(khttpd_location, loc);

	bcopy(path, lbegin, len);
	lend = lbegin + len;
	if (!need_not_append_slash)
		*lend++ = '/';
	*lend = '\0';

	if ((*error_out = khttpd_costruct_call_ctors
		(khttpd_location_costruct_info, loc)) != 0) {
		khttpd_location_release(loc);
		return (NULL);
	}

	loc->costructs_ready = TRUE;

	rw_wlock(&server->lock);

	/*
	 * Find the parent of the new location and insert the new location into
	 * the children list of the parent.
	 */

	oldloc = NULL;
	parent = server->root;
	for (;;) {
		/*
		 * Find the location that might be the previous element in the
		 * list.  Let 'ptr' point to it.
		 */

		len = lend - lbegin;
		loc->key = lbegin;
		loc->key_len = len;
		ptr = RB_NFIND(khttpd_location_tree, &parent->children_tree,
		    loc);
		if (ptr == NULL) {
			ptr = TAILQ_LAST(&parent->children_list,
			    khttpd_location_list);
			if (ptr == NULL) {
				/*
				 * If the list was empty, insert the new
				 * location to the list.
				 */

				TAILQ_INSERT_HEAD(&parent->children_list, loc, 
				    children_link);
				break;
			}

		} else if (khttpd_location_compare(ptr, loc) != 0) {
			ptr = TAILQ_PREV(ptr, khttpd_location_list,
			    children_link);
			if (ptr == NULL) {
				/*
				 * If the new location will be the first
				 * element of the list, insert it at the head
				 * of the list.
				 */

				TAILQ_INSERT_HEAD(&parent->children_list, loc, 
				    children_link);
				break;
			}

		} else {
			/* 
			 * If there is a location with an identical path,
			 * insert the new location after it.
			 */

			TAILQ_INSERT_AFTER(&parent->children_list, ptr,
			    loc, children_link);
			oldloc = ptr;
			break;
		}

		/*
		 * If the path of the might-be-previous location is not a
		 * prefix of the new path, insert the new location after the
		 * might-be-previous location.
		 */

		if (len < ptr->key_len ||
		    memcmp(ptr->key, lbegin, ptr->key_len) != 0) {
			TAILQ_INSERT_AFTER(&parent->children_list, ptr,
			    loc, children_link);
			break;
		}

		/* 
		 * The new location is a descendant of the might-be-previous
		 * location.
		 */

		lbegin += len;
		parent = ptr;
	}

	if (oldloc == NULL) {	/* normal case */
		/*
		 * Let the succeeding elements whose path starts with the new
		 * path descend into the new location.
		 */

		khttpd_server_adopt_successors(parent, loc, lbegin, len);

		/* Insert the new location into the tree. */

		RB_INSERT(khttpd_location_tree, &parent->children_tree, loc);
		loc->parent = parent;

	} else { 
		/*
		 * Inserting new location whose path matches an existing
		 * location.  Replace the matching location with the new
		 * location.
		 */

		TAILQ_REMOVE(&parent->children_list, ptr, children_link);

		RB_REMOVE(khttpd_location_tree, &parent->children_tree, ptr);
		RB_INSERT(khttpd_location_tree, &parent->children_tree, loc);

		ptr->parent = NULL;

		loc->children_tree = ptr->children_tree;
		RB_INIT(&ptr->children_tree);

		TAILQ_SWAP(&loc->children_list, &ptr->children_list,
		    khttpd_location, children_link);
		TAILQ_FOREACH(ptr, &loc->children_list, children_link)
		    ptr->parent = loc;
	}

	rw_wunlock(&server->lock);

	return (loc);
}

struct khttpd_location *
khttpd_location_get_parent(struct khttpd_location *location)
{
	return (location->parent);
}

void
khttpd_location_get_options(struct khttpd_location *location,
    struct sbuf *output)
{
	struct khttpd_location_ops *ops;
	int i;

	ops = khttpd_location_get_ops(location);

	sbuf_cpy(output, "OPTIONS");

	for (i = 0; i < KHTTPD_METHOD_END; ++i)
		if (i != KHTTPD_METHOD_OPTIONS && ops->method[i] != NULL)
			sbuf_printf(output, ", %s", khttpd_method_name(i));

	if (ops->method[KHTTPD_METHOD_HEAD] == NULL &&
	    ops->method[KHTTPD_METHOD_GET] != NULL)
		sbuf_cat(output, ", HEAD");
}

static void
khttpd_server_dtor(struct khttpd_server *server)
{

	if (server->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_server_costruct_info, server);
	khttpd_location_release(server->root);
	rw_destroy(&server->lock);
}

struct khttpd_server *
khttpd_server_new(int *error_out)
{
	struct khttpd_server *server;

	server = khttpd_malloc(khttpd_costruct_instance_size
	    (khttpd_server_costruct_info));

	rw_init_flags(&server->lock, "server", RW_NEW);
	server->root = khttpd_location_new_root(server);
	server->costructs_ready = FALSE;
	KHTTPD_REFCOUNT1_INIT(khttpd_server, server);

	if ((*error_out = khttpd_costruct_call_ctors(khttpd_server_costruct_info,
		    server)) != 0) {
		khttpd_server_release(server);
		return (NULL);
	}

	server->costructs_ready = TRUE;

	return (server);
}

/* 
 * For each element that succeeds 'location' and its path starts with [lbegin,
 * lbegin + len), make it be a child of 'location'.
 */

static void
khttpd_server_adopt_successors(struct khttpd_location *parent,
    struct khttpd_location *new_parent, char *lbegin, size_t len)
{
	struct khttpd_location *next, *ptr;

	for (ptr = TAILQ_NEXT(new_parent, children_link);
	     ptr != NULL && len <= ptr->key_len &&
		 memcmp(ptr->key, lbegin, len) == 0;
	     ptr = next) {
		next = TAILQ_NEXT(ptr, children_link);

		RB_REMOVE(khttpd_location_tree, &parent->children_tree, ptr);
		TAILQ_REMOVE(&parent->children_list, ptr, children_link);

		ptr->parent = new_parent;
		ptr->key += len;
		ptr->key_len -= len;

		RB_INSERT(khttpd_location_tree, &new_parent->children_tree,
		    ptr);

		TAILQ_INSERT_TAIL(&new_parent->children_list, ptr, 
		    children_link);
	}
}

/* 
 * Notes
 * - This function increments the reference count of the result location.
 * - This function never returns NULL.  It always can return the root location.
 */

struct khttpd_location *
khttpd_server_find_location(struct khttpd_server *server,
    const char *begin, const char *end, const char **suffix_out)
{
	struct khttpd_location key;
	struct khttpd_location *ptr, *prev, *parent, *root;
	const char *cp;

	KHTTPD_ENTRY("%s(%p,%s)\n", __func__, server,
	    khttpd_ktr_printf("%*s", (int)(end - begin), begin));
	cp = begin;

	rw_rlock(&server->lock);

	parent = root = server->root;
	while (!RB_EMPTY(&parent->children_tree)) {
		key.key = cp;
		key.key_len = end - cp;
		ptr = RB_NFIND(khttpd_location_tree, &parent->children_tree,
		    &key);

		/* If 'ptr' matches the key, */
		if (ptr != NULL && (khttpd_location_compare(ptr, &key) == 0 ||
			/* ... or matches except the trailing '/' */
			(end - cp == ptr->key_len - 1 &&
			    memcmp(ptr->key, cp, end - cp) == 0))) {
			parent = ptr;
			break;
		}

		prev = ptr == NULL ?
		    TAILQ_LAST(&parent->children_list, khttpd_location_list) :
		    TAILQ_PREV(ptr, khttpd_location_list, children_link);

		/*
		 * If the path of 'prev' is not a prefix of the target path,
		 * the parent is the result.
		 */

		if (prev == NULL || end - cp < prev->key_len ||
		    memcmp(prev->key, cp, prev->key_len) != 0)
			break;

		/*
		 * We found a location whose path is a prefix of the target
		 * path.  Descend into it.
		 */

		parent = prev;
		cp += prev->key_len;
	}

	while (parent->parent != NULL && parent->hide) {
		cp -= parent->key_len;
		parent = parent->parent;
	}

	khttpd_location_acquire(parent);

	rw_runlock(&server->lock);

	*suffix_out = cp;

	return (parent);
}

/* 
 * Notes
 * - This function increments the reference count of the returned location.
 * - If location 'ptr' has been replaced, this function returns NULL.
 */

static struct khttpd_location *
khttpd_server_next_location_locked(struct khttpd_server *server,
    struct khttpd_location *ptr)
{
	struct khttpd_location *result;

	KHTTPD_TR("%s %p", __func__, ptr);

	if ((result = TAILQ_FIRST(&ptr->children_list)) != NULL)
		/* If 'ptr' has a child, it's the result. */
		KHTTPD_TR("%s child %p", __func__, result);
	else if ((result = TAILQ_NEXT(ptr, children_link)) != NULL)
		/* If 'ptr' has a next sibling, it's the result. */
		KHTTPD_TR("%s sibling %p", __func__, result);
	else
		/*
		 * Find the first ancestor which has the next sibling.  The
		 * sibling is the result.
		 */
		do {
			KHTTPD_TR("%s parent %p -> %p", __func__, ptr,
			    ptr->parent);
			ptr = ptr->parent;
			if (ptr->parent == NULL) {
				KHTTPD_TR("%s finish", __func__);
				return (NULL);
			}
			result = TAILQ_NEXT(ptr, children_link);
		} while (result == NULL);

	KHTTPD_TR("%s acquire %p", __func__, result);
	khttpd_location_acquire(result);

	return (result);
}

struct khttpd_location *
khttpd_server_first_location(struct khttpd_server *server)
{
	struct khttpd_location *result;

	rw_rlock(&server->lock);
	/* The first location is the next location of the root location */
	result = khttpd_server_next_location_locked(server, server->root);
	rw_runlock(&server->lock);

	return (result);
}

struct khttpd_location *
khttpd_server_next_location(struct khttpd_server *server,
	struct khttpd_location *ptr)
{
	struct khttpd_location *result;

	rw_rlock(&server->lock);
	result = khttpd_server_next_location_locked(server, ptr);
	rw_runlock(&server->lock);

	return (result);
}

void *
khttpd_location_data(struct khttpd_location *location)
{
	void *data;

	rw_rlock(&location->server->lock);
	data = location->data;
	rw_runlock(&location->server->lock);

	return (data);
}

void *
khttpd_location_set_data(struct khttpd_location *location, void *data)
{
	void *old_data;

	rw_wlock(&location->server->lock);
	old_data = location->data;
	location->data = data;
	rw_wunlock(&location->server->lock);

	return (old_data);
}

void
khttpd_location_hide(struct khttpd_location *location)
{
	struct khttpd_server *server;

	server = location->server;
	rw_wlock(&server->lock);
	location->hide = TRUE;
	rw_wunlock(&server->lock);
}

void
khttpd_location_show(struct khttpd_location *location)
{
	struct khttpd_server *server;

	server = location->server;
	rw_wlock(&server->lock);
	location->hide = FALSE;
	rw_wunlock(&server->lock);
}

struct khttpd_log *
khttpd_server_get_log(struct khttpd_server *server,
    enum khttpd_server_log_id log_id)
{

	return (khttpd_location_get_log(server->root, log_id));
}

void
khttpd_server_set_log(struct khttpd_server *server,
    enum khttpd_server_log_id log_id, struct khttpd_log *log)
{

	khttpd_location_set_log(server->root, log_id, log);
}

void
khttpd_server_error(struct khttpd_server *server, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, ...)
{
	va_list args;

	va_start(args, desc_fmt);
	khttpd_server_verror(server, severity, entry, desc_fmt, args);
	va_end(args);
}

void
khttpd_server_verror(struct khttpd_server *server, int severity,
    struct khttpd_mbuf_json *entry, const char *desc_fmt, va_list args)
{

	khttpd_location_verror(server->root, severity, entry, desc_fmt, args);
}

static int
khttpd_server_register_costructs(void)
{

	KHTTPD_ENTRY("khttpd_server_register_costructs()");
	khttpd_costruct_info_new(&khttpd_server_costruct_info,
	    sizeof(struct khttpd_server));
	khttpd_costruct_info_new(&khttpd_location_costruct_info, 
	    sizeof(struct khttpd_location));

	return (0);
}

static void
khttpd_server_deregister_costructs(void)
{

	KHTTPD_ENTRY("khttpd_server_deregister_costructs()");
	khttpd_costruct_info_destroy(khttpd_server_costruct_info);
	khttpd_costruct_info_destroy(khttpd_location_costruct_info);
}

KHTTPD_INIT(khttpd_server, khttpd_server_register_costructs,
    khttpd_server_deregister_costructs,
    KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS - 1);

#ifdef INVARIANTS

static void
khttpd_server_exit(void)
{
	unsigned n;

	KHTTPD_ENTRY("khttpd_server_exit()");

	n = khttpd_costruct_instance_count(&khttpd_server_costruct_info);
	KASSERT(n == 0, ("server instance count=%d", n));
	n = khttpd_costruct_instance_count(&khttpd_location_costruct_info);
	KASSERT(n == 0, ("location instance count=%d", n));
}

KHTTPD_INIT(khttpd_server, NULL, khttpd_server_exit, KHTTPD_INIT_PHASE_RUN);

#endif

/*
 * If 'server' is NULL, this function doesn't check whether the location's
 * 'server' field matches 'server'
 */
int
khttpd_location_check_invariants(struct khttpd_location *location,
	struct khttpd_server *server)
{
	struct khttpd_location *locp1, *locp2;
	const char *path, *path_end;

	path = location->path;
	path_end = location->path + strlen(location->path);

	/* 'server' is correct */
	if (server != NULL && location->server != server) {
		log(LOG_ERR, "khttpd: wrong 'server' . "
		    "(file: \"%s\", line: %u, location: %s, "
		    "expect: %p, actual: %p)", __FILE__, __LINE__,
		    path, server, location->server);
		return (EDOOFUS);
	}

	/* 'key' points a character in or the terminator of 'path'. */
	if (location->key < path || path_end < location->key) {
		log(LOG_ERR, "khttpd: 'key' doesn't point a ch. in 'path'. "
		    "(file: \"%s\", line: %u, location: \"%s\")", __FILE__,
		    __LINE__, path);
		return (EDOOFUS);
	}

	/*
	 * 'key_len' of root locations must be 0.
	 * 'key_len' of non-root locations must be larger than 0.
	 */
	if (location->parent != NULL ? location->key_len <= 0 :
	    location->key_len != 0) {
		log(LOG_ERR, "khttpd: 'key_len' is wrong. "
		    "(file: \"%s\", line: %u, location: \"%s\", "
		    "key_len: %zu)", __FILE__, __LINE__, path,
		    location->key_len);
		return (EDOOFUS);
	}

	/* 'key' + key_len points a character in 'path' or the terminator */
	if (path_end < location->key + location->key_len) {
		log(LOG_ERR, "khttpd: 'key_len' is too large. "
		    "(file: \"%s\", line: %u, location: \"%s\", "
		    "key_len: \"%zu\")", __FILE__, __LINE__, path,
		    location->key_len);
		return (EDOOFUS);
	}

	/* 'key' is not a prefix of the key of a sibling */
	if (location->parent != NULL) {
		locp1 = RB_NEXT(khttpd_location_tree, &parent->children_tree,
		    location);
		if (locp1 != NULL && strncmp(location->key, locp1->key,
			location->key_len) == 0) {
			log(LOG_ERR, "khttpd: the key is a prefix of "
			    "the key of a sibling "
			    "(file: \"%s\", line: %u, location: \"%s\", "
			    "sibling: \"%s\")", __FILE__, __LINE__, path,
			    locp1->path);
			return (EDOOFUS);
		}
	}

	/* All the children's 'parent' is me */
	TAILQ_FOREACH(locp1, &location->children_list, children_link)
		if (locp1->parent != location) {
			log(LOG_ERR, "khttpd: a child does't believe "
			    "I am his father. "
			    "(file: \"%s\", line: %u, location: \"%s\", "
			    "child: \"%s\")", __FILE__, __LINE__, path,
			    locp1->path);
			return (EDOOFUS);
		}

	/* The children list is ordered. */
	TAILQ_FOREACH(locp1, &location->children_list, children_link) {
		locp2 = TAILQ_NEXT(locp1, children_link);
		if (locp2 != NULL && 0 <= strcmp(locp1->path, locp2->path)) {
			log(LOG_ERR, "khttpd: children list is not ordered. "
			    "(file: \"%s\", line: %u, location: \"%s\", "
			    "child: \"%s\", next: \"%s\")",
			    __FILE__, __LINE__, path, locp1->path, locp2->path);
			return (EDOOFUS);
		}
	}

	/*
	 * The member sets of the children tree and the children list are
	 * identical with each other.
	 */
	locp2 = TAILQ_FIRST(&location->children_list);
	RB_FOREACH(locp1, khttpd_location_tree, &location->children_tree) {
		if (locp1 != locp2) {
			log(LOG_ERR, "khttpd: the children tree and the list "
			    "doesn't match. "
			    "(file: \"%s\", line: %u, location: \"%s\", "
			    "tree element: \"%s\", list element: \"%s\")",
			    __FILE__, __LINE__, path, locp1->path,
			    locp2 != NULL ? locp2->path : "<null>");
			return (EDOOFUS);
		}
		locp2 = TAILQ_NEXT(locp2, children_link);
	}
	if (locp2 != NULL) {
		log(LOG_ERR, "khttpd: the children tree and the list "
		    "doesn't match. "
		    "(file: \"%s\", line: %u, location: \"%s\", "
		    "tree element: \"<null>\", tree element: \"%s\")",
		    __FILE__, __LINE__, path, locp2->path);
		return (EDOOFUS);
	}

	/* Check the invariants of all the children. */
	TAILQ_FOREACH(locp1, &location->children_list, children_link)
	    khttpd_location_check_invariants(locp1, server);

	return (0);
}

int
khttpd_server_check_invariants(struct khttpd_server *server)
{

	/* 'root' location doesn't have any parents. */
	if (server->root->parent != NULL) {
		log(LOG_ERR, "khttpd: root->parent != NULL "
		    "(file: \"%s\", line: %u, server: %p, "
		    "parent: %p)", __FILE__, __LINE__, server,
		    server->root->parent);
		return (EDOOFUS);
	}

	return (khttpd_location_check_invariants(server->root, server));
}
