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
#include "khttpd_refcount.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_method.h"
#include "khttpd_webapi.h"

RB_HEAD(khttpd_prefix_tree, khttpd_prefix);
TAILQ_HEAD(khttpd_prefix_tailq, khttpd_prefix);
TAILQ_HEAD(khttpd_location_tailq, khttpd_location);

struct khttpd_prefix {
	TAILQ_ENTRY(khttpd_prefix) children_link;
	RB_ENTRY(khttpd_prefix)	children_node;
	struct khttpd_prefix_tree children_tree;
	struct khttpd_prefix_tailq children_tailq;
	struct khttpd_location_tailq location_tailq;
	struct khttpd_server *server;
	struct khttpd_prefix *parent;
	const char	*key;
	size_t		key_len;
	char		path[];
};

struct khttpd_location {
	TAILQ_ENTRY(khttpd_location) link;
	struct khttpd_location_ops *ops;
	struct khttpd_prefix *prefix;
	void		*data;
	unsigned	costructs_ready:1;
	KHTTPD_REFCOUNT1_MEMBERS;
};

/* 
 *  Don't be confused!  The root of the location tree is **NOT** a
 *  location for path '/'.
 */

struct khttpd_server {
	struct rwlock		lock;
	unsigned		costructs_ready:1;
	KHTTPD_REFCOUNT1_MEMBERS;
	struct khttpd_prefix	root;
};

static int khttpd_prefix_compare(struct khttpd_prefix *,
    struct khttpd_prefix *);

static void khttpd_location_dtor(struct khttpd_location *location);

static void khttpd_server_dtor(struct khttpd_server *server);
static void khttpd_server_adopt_successors(struct khttpd_prefix *parent,
    struct khttpd_prefix *new_parent, char *lbegin, size_t len);

struct khttpd_costruct_info *khttpd_location_costruct_info;
struct khttpd_costruct_info *khttpd_server_costruct_info;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

RB_PROTOTYPE_STATIC(khttpd_prefix_tree, khttpd_prefix, children_node,
    khttpd_prefix_compare);
RB_GENERATE_STATIC(khttpd_prefix_tree, khttpd_prefix, children_node,
    khttpd_prefix_compare);

#pragma clang diagnostic pop

KHTTPD_REFCOUNT1_GENERATE(khttpd_location, khttpd_location_dtor, khttpd_free);
KHTTPD_REFCOUNT1_GENERATE(khttpd_server, khttpd_server_dtor, khttpd_free);

static int
khttpd_prefix_compare(struct khttpd_prefix *x, struct khttpd_prefix *y)
{
	size_t xl, yl;
	int r;

	xl = x->key_len;
	yl = y->key_len;
	r = memcmp(x->key, y->key, MIN(xl, yl));
	return (r != 0 ? r : xl == yl ? 0 : xl < yl ? -1 : 1);
}

static void
khttpd_prefix_unlink(struct khttpd_prefix *prefix)
{
	struct khttpd_prefix *child, *parent, *tmpptr;
	struct khttpd_server *server;
	size_t len;

	KHTTPD_ENTRY("%s(%p)", __func__, prefix);

	server = prefix->server;
	rw_wlock(&server->lock);

	parent = prefix->parent;
	KASSERT(parent != NULL, ("prefix %p, parent %p", prefix, parent));

	RB_REMOVE(khttpd_prefix_tree, &parent->children_tree, prefix);

	/* Make all the children of 'prefix' be children of the parent. */

	len = prefix->key_len;
	TAILQ_FOREACH_REVERSE_SAFE(child, &prefix->children_tailq,
	    khttpd_prefix_tailq, children_link, tmpptr) {
		TAILQ_REMOVE(&prefix->children_tailq, child, children_link);

		child->parent = parent;
		child->key -= len;
		child->key_len += len;

		RB_INSERT(khttpd_prefix_tree, &parent->children_tree,
		    child);
		TAILQ_INSERT_AFTER(&parent->children_tailq, prefix, child,
		    children_link);
	}

	TAILQ_REMOVE(&parent->children_tailq, prefix, children_link);

	rw_wunlock(&server->lock);
}

static void
khttpd_location_dtor(struct khttpd_location *location)
{
	struct khttpd_location_ops *ops;
	struct khttpd_prefix *prefix;
	khttpd_location_fn_t dtor;

	KHTTPD_ENTRY("%s(%p)", __func__, location);

	ops = location->ops;
	dtor = ops->dtor;
	if (dtor != NULL)
		dtor(location);

	if (location->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_location_costruct_info,
		    location);

	prefix = location->prefix;
	if (prefix == NULL)
		return;

	TAILQ_REMOVE(&prefix->location_tailq, location, link);
	if (TAILQ_EMPTY(&prefix->location_tailq)) {
		khttpd_prefix_unlink(prefix);
		khttpd_server_release(prefix->server);
		khttpd_free(prefix);
	}
}

struct khttpd_location_ops *
khttpd_location_get_ops(struct khttpd_location *location)
{

	return (location->ops);
}

const char *
khttpd_location_get_path(struct khttpd_location *location)
{

	return (location->prefix->path);
}

struct khttpd_server *
khttpd_location_get_server(struct khttpd_location *location)
{

	return (location->prefix->server);
}

/*
 * The trailing '/' can be omitted.
 */
struct khttpd_location *
khttpd_location_new(int *error_out, struct khttpd_server *server,
    const char *path, struct khttpd_location_ops *ops, void *data)
{
	struct khttpd_location *loc;
	struct khttpd_prefix *prefix, *parent, *ptr;
	char *lbegin, *lend;
	size_t len;
	bool need_not_append_slash, found_exact_match;

	KHTTPD_ENTRY("%s(%p,%s,%p,%p)", __func__, server,
	    khttpd_ktr_printf("\"%s\"", path), ops, data);

	/* The path must be '*' or start with '/'. */
	KASSERT(path[0] == '/' || (path[0] == '*' && path[1] == '\0'),
	    ("path %s doesn't start with '/'", path));

	/* Construct a location. */

	loc = khttpd_malloc
	    (khttpd_costruct_instance_size(khttpd_location_costruct_info));
	loc->prefix = NULL;
	loc->ops = ops;
	loc->data = data;
	loc->costructs_ready = false;
	KHTTPD_REFCOUNT1_INIT(khttpd_location, loc);

	if ((*error_out = khttpd_costruct_call_ctors
		(khttpd_location_costruct_info, loc)) != 0) {
		khttpd_location_release(loc);
		return (NULL);
	}

	loc->costructs_ready = true;

	/* Allocate a prefix */

	len = strlen(path);
	need_not_append_slash = (0 < len && path[len - 1] == '/') || 
	    (len == 1 && path[0] == '*');
	prefix = khttpd_malloc(sizeof(struct khttpd_prefix) +
	    (need_not_append_slash ? len + 1 : len + 2));
	lbegin = prefix->path;
	lend = lbegin + len;
	bcopy(path, lbegin, len);
	if (!need_not_append_slash)
		*lend++ = '/';
	*lend = '\0';

	/* Find a parent prefix. */

	rw_wlock(&server->lock);

	found_exact_match = false;
	parent = &server->root;
	KHTTPD_TR("&server->root %p", parent);
	for (;;) {
		/*
		 * Find the location that might be the previous element in the
		 * list.  Let 'ptr' point to it.
		 */

		len = lend - lbegin;
		prefix->key = lbegin;
		prefix->key_len = len;
		ptr = RB_NFIND(khttpd_prefix_tree, &parent->children_tree,
		    prefix);
		if (ptr == NULL) {
			ptr = TAILQ_LAST(&parent->children_tailq,
			    khttpd_prefix_tailq);

		} else if (khttpd_prefix_compare(ptr, prefix) != 0) {
			ptr = TAILQ_PREV(ptr, khttpd_prefix_tailq,
			    children_link);

		} else {
			/* Found a prefix with an identical path. */
			found_exact_match = true;
			break;
		}

		if (ptr == NULL) {
			/*
			 * If the new prefix is the smallest among the
			 * children, we found the parent.
			 */
			TAILQ_INSERT_HEAD(&parent->children_tailq,
			    prefix, children_link);
			break;
		}

		/*
		 * If the path of the might-be-previous location is not a
		 * prefix of the new path, insert the new location after
		 * the might-be-previous location.
		 */

		if (len < ptr->key_len ||
		    memcmp(ptr->key, lbegin, ptr->key_len) != 0) {
			TAILQ_INSERT_AFTER(&parent->children_tailq, ptr,
			    prefix, children_link);
			break;
		}

		/* 
		 * The new location is a descendant of the
		 * might-be-previous location.
		 */

		lbegin += ptr->key_len;
		parent = ptr;
	}

	if (found_exact_match) {
		TAILQ_INSERT_TAIL(&parent->location_tailq, loc, link);
		loc->prefix = ptr;

	} else {
		RB_INIT(&prefix->children_tree);
		TAILQ_INIT(&prefix->children_tailq);
		TAILQ_INIT(&prefix->location_tailq);
		prefix->server = server;
		KHTTPD_TR("prefix %p, parent %p", prefix, parent);
		prefix->parent = parent;
		loc->prefix = prefix;

		TAILQ_INSERT_TAIL(&prefix->location_tailq, loc, link);

		/*
		 * Let the succeeding elements whose path starts with the
		 * new path descend into the new prefix.
		 */
		khttpd_server_adopt_successors(parent, prefix, lbegin, len);

		/* Insert the new location into the tree. */
		RB_INSERT(khttpd_prefix_tree,
		    &parent->children_tree, prefix);

		khttpd_server_acquire(server);
	}

	rw_wunlock(&server->lock);

	if (found_exact_match)
		khttpd_free(prefix);

	return (loc);
}

static void
khttpd_server_dtor(struct khttpd_server *server)
{

	if (server->costructs_ready)
		khttpd_costruct_call_dtors(khttpd_server_costruct_info,
		    server);
	rw_destroy(&server->lock);
}

struct khttpd_server *
khttpd_server_new(int *error_out)
{
	struct khttpd_server *server;

	server = khttpd_malloc(khttpd_costruct_instance_size
	    (khttpd_server_costruct_info));

	rw_init_flags(&server->lock, "server", RW_NEW);

	RB_INIT(&server->root.children_tree);
	TAILQ_INIT(&server->root.children_tailq);
	TAILQ_INIT(&server->root.location_tailq);
	server->costructs_ready = false;
	server->root.server = server;
	server->root.parent = NULL;
	server->root.key = "";
	server->root.key_len = 0;
	server->root.path[0] = '\0';
	KHTTPD_REFCOUNT1_INIT(khttpd_server, server);

	if ((*error_out = khttpd_costruct_call_ctors
		(khttpd_server_costruct_info, server)) != 0) {
		khttpd_server_release(server);
		return (NULL);
	}

	server->costructs_ready = true;

	return (server);
}

/* 
 * For each element that succeeds 'location' and its path starts with [lbegin,
 * lbegin + len), make it be a child of 'location'.
 */

static void
khttpd_server_adopt_successors(struct khttpd_prefix *parent,
    struct khttpd_prefix *new_parent, char *lbegin, size_t len)
{
	struct khttpd_prefix *next, *ptr;

	KHTTPD_ENTRY("%s(%s)", __func__,
	    khttpd_ktr_printf("%p(%s),%p(%s),%*s", parent, parent->path,
		new_parent, new_parent->path, (int)len, lbegin));

	for (ptr = TAILQ_NEXT(new_parent, children_link);
	     ptr != NULL && len <= ptr->key_len &&
		 memcmp(ptr->key, lbegin, len) == 0;
	     ptr = next) {
		next = TAILQ_NEXT(ptr, children_link);

		RB_REMOVE(khttpd_prefix_tree, &parent->children_tree, ptr);
		TAILQ_REMOVE(&parent->children_tailq, ptr, children_link);

		ptr->parent = new_parent;
		ptr->key += len;
		ptr->key_len -= len;

		RB_INSERT(khttpd_prefix_tree, &new_parent->children_tree,
		    ptr);

		TAILQ_INSERT_TAIL(&new_parent->children_tailq, ptr, 
		    children_link);
	}
}

/* 
 * Notes
 * - This function increments the reference count of the result location.
 */

struct khttpd_location *
khttpd_server_route(struct khttpd_server *server, struct sbuf *target,
    struct khttpd_exchange *exchange, const char **suffix_out,
    struct sbuf *translated_path)
{
	struct khttpd_prefix key;
	struct khttpd_prefix *ptr, *prev, *parent, *root;
	struct khttpd_location *loc, *lastloc;
	const char *cp, *end;

	KHTTPD_ENTRY("%s(%p,\"%s\",%p)", __func__, server,
	    khttpd_ktr_printf("%.*s",
		(int)sbuf_len(target), sbuf_data(target)),
	    exchange);

	cp = sbuf_data(target);
	end = cp + sbuf_len(target);

	rw_rlock(&server->lock);

	parent = root = &server->root;
	while (!RB_EMPTY(&parent->children_tree)) {
		key.key = cp;
		key.key_len = end - cp;
		ptr = RB_NFIND(khttpd_prefix_tree, &parent->children_tree,
		    &key);

		KHTTPD_TR("%s %s", __func__, 
		    khttpd_ktr_printf("ptr %p(\"%s\"), "
			"parent %p(\"%s\"), key \"%.*s\"",
			ptr, ptr == NULL ? "null" : ptr->path,
			parent, parent->path, (int)(end - cp), cp));

		/* If 'ptr' matches the key, */
		if (ptr != NULL && (khttpd_prefix_compare(ptr, &key) == 0 ||
			/* ... or matches except the trailing '/' */
			(end - cp == ptr->key_len - 1 &&
			    memcmp(ptr->key, cp, end - cp) == 0))) {
			KHTTPD_NOTE("'ptr' matches the key");
			parent = ptr;
			cp = MIN(end, cp + ptr->key_len);
			break;
		}

		prev = ptr == NULL ?
		    TAILQ_LAST(&parent->children_tailq, khttpd_prefix_tailq) :
		    TAILQ_PREV(ptr, khttpd_prefix_tailq, children_link);
		KHTTPD_NOTE("prev %p, path \"%s\", key \"%s\"",
		    prev, prev == NULL ? "<null>" :
		    khttpd_ktr_printf("%s", prev->path),
		    prev == NULL ? "<null>" : 
		    khttpd_ktr_printf("%.*s", (int)prev->key_len, prev->key));

		/*
		 * If the path of 'prev' is not a prefix of the target
		 * path, the parent is the result.
		 */

		if (prev == NULL || end - cp < prev->key_len ||
		    memcmp(prev->key, cp, prev->key_len) != 0) {
			KHTTPD_NOTE("prev NULL, prev is not a prefix");
			break;
		}

		/*
		 * We found a location whose path is a prefix of the target
		 * path.  Descend into it.
		 */

		parent = prev;
		cp += prev->key_len;
	}

	KHTTPD_TR("%s prefix %p(\"%s\")", __func__, parent,
	    khttpd_ktr_printf("%s", parent->path));

	loc = lastloc = NULL;
	for (; parent != NULL; parent = parent->parent) {
		for (loc = TAILQ_FIRST(&parent->location_tailq);
		     loc != NULL; loc = TAILQ_NEXT(loc, link)) {
			khttpd_location_acquire(loc);
			rw_runlock(&server->lock);

			khttpd_location_release(lastloc);
			lastloc = NULL;

			if (loc->ops->filter == NULL ||
			    loc->ops->filter(loc, exchange, cp,
				translated_path)) {
				if (suffix_out != NULL)
					*suffix_out = cp;
				return (loc);
			}

			rw_rlock(&server->lock);
			lastloc = loc;
		}
	}

	rw_runlock(&server->lock);
	khttpd_location_release(lastloc);

	return (NULL);
}

/* 
 * Notes
 * - This function increments the reference count of the returned location.
 * - If location 'ptr' has been replaced, this function returns NULL.
 */

static struct khttpd_prefix *
khttpd_server_next_prefix_locked(struct khttpd_server *server,
    struct khttpd_prefix *prefix)
{
	struct khttpd_prefix *next_prefix, *parent;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, server, prefix);

	/* If 'prefix' has a child, the first child is the result. */
	if ((next_prefix = TAILQ_FIRST(&prefix->children_tailq)) != NULL) {
		KHTTPD_NOTE("%s child %p", __func__, next_prefix);
		return (next_prefix);
	}

	/* If 'prefix' is the root, 'prefix' is the last element. */
	if (prefix->parent == NULL) {
		KHTTPD_NOTE("%s root", __func__);
		return (NULL);
	}

	/* If 'ptr' has a next sibling, it's the result. */
	if ((next_prefix = TAILQ_NEXT(prefix, children_link)) != NULL) {
		KHTTPD_NOTE("%s sibling %p", __func__, next_prefix);
		return (next_prefix);
	}

	/* Find the first ancestor which has the next sibling. */
	for (prefix = prefix->parent; (parent = prefix->parent) != NULL;
	     prefix = parent) {
		next_prefix = TAILQ_NEXT(prefix, children_link);
		if (next_prefix != NULL) {
			KHTTPD_NOTE("%s sibling of ancestor %p", __func__,
			    next_prefix);
			return (next_prefix);
		}
	}

	KHTTPD_NOTE("%s finish", __func__);

	return (NULL);
}

static struct khttpd_location *
khttpd_server_next_location_locked(struct khttpd_server *server,
    struct khttpd_location *ptr)
{
	struct khttpd_location *result;
	struct khttpd_prefix *prefix;

	KHTTPD_ENTRY("%s %p", __func__, ptr);

	if ((result = TAILQ_NEXT(ptr, link)) != NULL)
		return (khttpd_location_acquire(result));

	prefix = khttpd_server_next_prefix_locked(server, ptr->prefix);
	return (prefix == NULL ? NULL :
	    khttpd_location_acquire(TAILQ_FIRST(&prefix->location_tailq)));
}

struct khttpd_location *
khttpd_server_first_location(struct khttpd_server *server)
{
	struct khttpd_prefix *prefix;
	struct khttpd_location *result;

	rw_rlock(&server->lock);
	/* The first prefix is next to the root prefix */
	prefix = khttpd_server_next_prefix_locked(server, &server->root);
	result = prefix == NULL ? NULL :
	    khttpd_location_acquire(TAILQ_FIRST(&prefix->location_tailq));
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

	return (location->data);
}

void *
khttpd_location_set_data(struct khttpd_location *location, void *data)
{

	return ((void *)atomic_swap_ptr((volatile u_long *)&location->data,
	    (u_long)data));
}

static int
khttpd_server_register_costructs(void)
{

	KHTTPD_ENTRY("khttpd_server_register_costructs()");
	/* +1 is necessary for server.prefix.path[0].  */
	khttpd_costruct_info_new(&khttpd_server_costruct_info,
	    sizeof(struct khttpd_server) + 1);
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

/*
 * If 'server' is NULL, this function doesn't check whether the location's
 * 'server' field matches 'server'
 */
static int
khttpd_prefix_check_invariants(struct khttpd_prefix *prefix,
	struct khttpd_server *server)
{
	struct khttpd_prefix *locp1, *locp2;
	const char *path, *path_end;

	path = prefix->path;
	path_end = prefix->path + strlen(prefix->path);

	/* 'server' is correct */
	if (server != NULL && prefix->server != server) {
		log(LOG_ERR, "khttpd: wrong 'server' . "
		    "(file: \"%s\", line: %u, prefix: %s, "
		    "expect: %p, actual: %p)", __FILE__, __LINE__,
		    path, server, prefix->server);
		return (EDOOFUS);
	}

	/* 'key' points a character in or the terminator of 'path'. */
	if (prefix->key < path || path_end < prefix->key) {
		log(LOG_ERR, "khttpd: 'key' doesn't point a ch. in 'path'. "
		    "(file: \"%s\", line: %u, prefix: \"%s\")", __FILE__,
		    __LINE__, path);
		return (EDOOFUS);
	}

	/*
	 * 'key_len' of root prefixs must be 0.
	 * 'key_len' of non-root prefixs must be larger than 0.
	 */
	if (prefix->parent != NULL ? prefix->key_len <= 0 :
	    prefix->key_len != 0) {
		log(LOG_ERR, "khttpd: 'key_len' is wrong. "
		    "(file: \"%s\", line: %u, prefix: \"%s\", "
		    "key_len: %zu)", __FILE__, __LINE__, path,
		    prefix->key_len);
		return (EDOOFUS);
	}

	/* 'key' + key_len points a character in 'path' or the terminator */
	if (path_end < prefix->key + prefix->key_len) {
		log(LOG_ERR, "khttpd: 'key_len' is too large. "
		    "(file: \"%s\", line: %u, prefix: \"%s\", "
		    "key_len: \"%zu\")", __FILE__, __LINE__, path,
		    prefix->key_len);
		return (EDOOFUS);
	}

	/* 'key' is not a prefix of the key of a sibling */
	if (prefix->parent != NULL) {
		locp1 = RB_NEXT(khttpd_prefix_tree, &parent->children_tree,
		    prefix);
		if (locp1 != NULL && strncmp(prefix->key, locp1->key,
			prefix->key_len) == 0) {
			log(LOG_ERR, "khttpd: the key is a prefix of "
			    "the key of a sibling "
			    "(file: \"%s\", line: %u, prefix: \"%s\", "
			    "sibling: \"%s\")", __FILE__, __LINE__, path,
			    locp1->path);
			return (EDOOFUS);
		}
	}

	/* All the children's 'parent' is me */
	TAILQ_FOREACH(locp1, &prefix->children_tailq, children_link)
		if (locp1->parent != prefix) {
			log(LOG_ERR, "khttpd: a child does't believe "
			    "I am his father. "
			    "(file: \"%s\", line: %u, prefix: \"%s\", "
			    "child: \"%s\")", __FILE__, __LINE__, path,
			    locp1->path);
			return (EDOOFUS);
		}

	/* The children list is ordered. */
	TAILQ_FOREACH(locp1, &prefix->children_tailq, children_link) {
		locp2 = TAILQ_NEXT(locp1, children_link);
		if (locp2 != NULL && 0 <= strcmp(locp1->path, locp2->path)) {
			log(LOG_ERR, "khttpd: children list is not ordered. "
			    "(file: \"%s\", line: %u, prefix: \"%s\", "
			    "child: \"%s\", next: \"%s\")",
			    __FILE__, __LINE__, path,
			    locp1->path, locp2->path);
			return (EDOOFUS);
		}
	}

	/*
	 * The member sets of the children tree and the children list are
	 * identical with each other.
	 */
	locp2 = TAILQ_FIRST(&prefix->children_tailq);
	RB_FOREACH(locp1, khttpd_prefix_tree, &prefix->children_tree) {
		if (locp1 != locp2) {
			log(LOG_ERR, "khttpd: the children tree and the list "
			    "doesn't match. "
			    "(file: \"%s\", line: %u, prefix: \"%s\", "
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
		    "(file: \"%s\", line: %u, prefix: \"%s\", "
		    "tree element: \"<null>\", tree element: \"%s\")",
		    __FILE__, __LINE__, path, locp2->path);
		return (EDOOFUS);
	}

	/* Check the invariants of all the children. */
	TAILQ_FOREACH(locp1, &prefix->children_tailq, children_link)
	    khttpd_prefix_check_invariants(locp1, server);

	return (0);
}

int
khttpd_server_check_invariants(struct khttpd_server *server)
{

	/* 'root' prefix doesn't have any parents. */
	if (server->root.parent != NULL) {
		log(LOG_ERR, "khttpd: root->parent != NULL "
		    "(file: \"%s\", line: %u, server: %p, "
		    "parent: %p)", __FILE__, __LINE__, server,
		    server->root.parent);
		return (EDOOFUS);
	}

	return (khttpd_prefix_check_invariants(&server->root, server));
}
