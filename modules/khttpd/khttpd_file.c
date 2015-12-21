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

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/hash.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/syscallsubr.h>

#include <machine/stdarg.h>

#include <vm/uma.h>

#include "khttpd.h"
#include "khttpd_private.h"

/* ------------------------------------------------------- type definitions */

struct khttpd_mime_type_rule_set;

struct khttpd_file_route_data {
	struct khttpd_mime_type_rule_set *rule_set;
	char		*path;
	int		dirfd;
};

struct khttpd_file_request_data {
	off_t	xmit_offset;
	off_t	xmit_residual;
	size_t	pathsize;
	int	fd;
	char	path[];
};

struct khttpd_mime_type_rule {
	SLIST_ENTRY(khttpd_mime_type_rule) link;
	const char	*suffix;
	const char	*type;
};

SLIST_HEAD(khttpd_mime_type_rule_slist, khttpd_mime_type_rule);

struct khttpd_mime_type_rule_set {
	char		*buffer;
	uint32_t	hash_mask;
	struct khttpd_mime_type_rule_slist hash_table[];
};

/* -------------------------------------------------- prototype declrations */

static struct khttpd_mime_type_rule_set *khttpd_mime_type_rule_set_alloc
    (uint32_t hash_size, char *buf);
static void khttpd_mime_type_rule_set_free
    (struct khttpd_mime_type_rule_set *rule_set);
static const char *khttpd_mime_type_rule_set_find
    (struct khttpd_mime_type_rule_set *rule_set, const char *path);

static void khttpd_file_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request);

/* --------------------------------------------------- variable definitions */

static struct khttpd_route_type khttpd_route_type_file = {
	.name = "file",
	.received_header = khttpd_file_received_header,
};

static const char *khttpd_index_names[] = {
	"index.html"
};

static uma_zone_t khttpd_mime_type_rule_zone;

/* --------------------------------------------------- function definitions */

static int
khttpd_file_normalize_path(const char *path, char *buf, size_t bufsize)
{
	const char *src, *segend;
	char *dst, *dstend;

	src = path;
	dst = buf;
	dstend = dst + bufsize;

	for (;;) {

		/* consecutive slashes are replaced with a slash */
		if (*src == '/') {
			while (*++src == '/')
				; /* nothing */

			if (dstend <= dst)
				return (ENOMEM);
			*dst++ = '/';
		}

again:
		if (*src == '\0')
			break;

		if (src[0] == '.' && src[1] == '\0') {
			if (buf < dst)
				--dst;
			break;
		}

		if (src[0] == '.' && src[1] == '/') {
			src += 2;
			while (*src == '/')
				++src;
			if (*src == '\0')
				break;
		}

		segend = khttpd_find_ch(src, '/');
		if (segend == NULL)
			segend = src + strlen(src);

		if (segend - src == 2 && 
		    src[0] == '.' && src[1] == '.') {
			if (dst <= buf)
				return (EINVAL);
			--dst;
			while (dst < buf && dst[-1] != '/')
				--dst;

			if (src[2] == '\0') {
				if (dst <= buf)
					return (EINVAL);
				--dst;
				break;
			}

			for (src = segend + 1; *src == '/'; ++src)
				; /* nothing */
			goto again;
		}

		if (dstend - dst < segend - src + 1)
			return (ENOMEM);

		bcopy(src, dst, segend - src);
		dst += segend - src;

		src = segend;
	}

	if (buf == dst) {
		if (dstend <= dst)
			return (ENOMEM);
		*dst++ = '.';
	}

	if (dstend <= dst)
		return (ENOMEM);
	*dst = '\0';

	return (0);
}

static int
khttpd_file_transmit(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    struct mbuf **out)
{
	cap_rights_t rights;
	struct khttpd_file_request_data *data;
	struct file *fp;
	struct thread *td;
	off_t sent;
	int error;

	td = curthread;
	data = khttpd_request_data(request);

	TRACE("enter %d %s", khttpd_socket_fd(socket), data->path);

	error = fget_read(td, data->fd, cap_rights_init(&rights, CAP_PREAD),
	    &fp);
	if (error != 0) {
		TRACE("error fget_read %d", error);
		return (error);
	}

	error = fo_sendfile(fp, khttpd_socket_fd(socket), NULL, NULL,
	    data->xmit_offset, data->xmit_residual, &sent, 0, 0, td);
	if (error != 0)
		TRACE("error sendfile %d", error);

	fdrop(fp, td);

	if (error == 0 || error == EWOULDBLOCK) {
		TRACE("sent=%d, residual=%zd, offset=%zd",
		    sent, data->xmit_residual, data->xmit_offset);
		if ((data->xmit_residual -= sent) == 0)
			khttpd_transmit_finished(socket);
		else
			data->xmit_offset += sent;
	}

	return (error);
}

static struct khttpd_file_request_data *
khttpd_file_request_data_alloc(const char *path)
{
	struct khttpd_file_request_data *data;
	size_t pathsize;

	/* 
	 * This MAX() is necessary because normalizing an empty path can
	 * result in "."
	 */
	pathsize = MAX(2, strlen(path) + 1);
	data = malloc(sizeof(*data) + pathsize, M_KHTTPD, M_WAITOK);
	data->pathsize = pathsize;
	data->fd = -1;

	return (data);
}

static void
khttpd_file_request_data_free(struct khttpd_file_request_data *data)
{
	struct thread *td;

	td = curthread;
	if (data->fd != -1)
		kern_close(td, data->fd);
	free(data, M_KHTTPD);
}

static void
khttpd_file_request_dtor(struct khttpd_request *request, void *data)
{

	khttpd_file_request_data_free(data);
}

static int
khttpd_file_open(int dirfd, const char *path, int *fd_out,
    struct stat *statbuf)
{
	struct thread *td;
	int error, fd;

	td = curthread;

	error = kern_openat(td, dirfd, (char *)path, UIO_SYSSPACE, O_RDONLY,
	    0);
	if (error != 0) {
		TRACE("error open %d", error);
		return (error);
	}

	fd = td->td_retval[0];

	error = kern_fstat(td, fd, statbuf);
	if (error != 0) {
		TRACE("error fstat %d", error);
		kern_close(td, fd);
		return (error);
	}

	if ((statbuf->st_mode & S_IFREG) != 0) {
		*fd_out = fd;
		return (0);
	}

	if ((statbuf->st_mode & S_IFDIR) != 0) {
		*fd_out = fd;
		return (EISDIR);
	}

	kern_close(td, fd);

	return (ENOENT);
}

static void
khttpd_file_redirect_to_index(struct khttpd_socket *socket,
    struct khttpd_request *request, int fd)
{
	struct stat statbuf;
	struct thread *td;
	char *path;
	size_t len, target_len, index_len;
	int error, i, n, tmpfd;

	TRACE("enter %d %s %d", khttpd_socket_fd(socket),
	    ((struct khttpd_file_request_data *)khttpd_request_data(request))
	    ->path, fd);

	td = curthread;

	n = sizeof(khttpd_index_names) / sizeof(khttpd_index_names[0]);
	for (i = 0; i < n; ++i) {
		tmpfd = -1;
		error = khttpd_file_open(fd, khttpd_index_names[i], &tmpfd,
		    &statbuf);
		kern_close(td, tmpfd);
		if (error == 0)
			break;
	}

	if (i == n) {
		khttpd_set_not_found_response(socket, request, FALSE);
		return;
	}

	target_len = strlen(khttpd_request_target(request));
	index_len = strlen(khttpd_index_names[i]);

	path = malloc(target_len + 1 +index_len + 1, M_KHTTPD, M_WAITOK);
	bcopy(khttpd_request_target(request), path, target_len);
	len = target_len;
	if (path[len - 1] != '/')
		path[len++] = '/';
	bcopy(khttpd_index_names[i], path + len, index_len);
	len += index_len;
	path[len] = '\0';

	khttpd_set_moved_permanently_response(socket, request, NULL, path);

	free(path, M_KHTTPD);
}

static void
khttpd_file_get_or_head(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct stat statbuf;
	struct khttpd_file_request_data *data;
	struct khttpd_file_route_data *route_data;
	struct khttpd_response *response;
	struct khttpd_route *route;
	struct thread *td;
	const char *type, *path, *suffix;
	int dirfd, error, fd;

	TRACE("enter %d %s", khttpd_socket_fd(socket),
	    khttpd_request_suffix(request));

	td = curthread;
	route = khttpd_request_route(request);
	route_data = khttpd_route_data(route);
	suffix = khttpd_request_suffix(request);
	data = khttpd_file_request_data_alloc(suffix);

	error = khttpd_file_normalize_path(suffix[0] == '/' ? suffix + 1 :
	    suffix, data->path, data->pathsize);
	if (error != 0) {
		TRACE("error normalize %d", error);
		khttpd_file_request_data_free(data);
		khttpd_set_not_found_response(socket, request, FALSE);
		return;
	}

	khttpd_request_set_data(request, data, khttpd_file_request_dtor);

	dirfd = route_data->dirfd;
	path = data->path;
	TRACE("path %s", path);

	error = khttpd_file_open(dirfd, path, &fd, &statbuf);
	if (error != 0)
		TRACE("error open %d", error);
	switch (error) {

	case 0:
		break;

	case ENAMETOOLONG:
	case ENOENT:
		khttpd_set_not_found_response(socket, request, FALSE);
		return;

	case EACCES:
	case EPERM:
		khttpd_set_conflict_response(socket, request, FALSE);
		return;

	case EISDIR:
		khttpd_file_redirect_to_index(socket, request, fd);
		return;

	default:
		khttpd_set_internal_error_response(socket, request);
		return;
	}

	data->fd = fd;
	data->xmit_offset = 0;
	data->xmit_residual = statbuf.st_size;

	response = khttpd_response_alloc();
	khttpd_response_set_status(response, 200);

	khttpd_response_set_body_proc(response, khttpd_file_transmit,
	    statbuf.st_size);

	type = khttpd_mime_type_rule_set_find(route_data->rule_set,
	    data->path);
	khttpd_response_add_field(response, "Content-Type", "%s", type);

	khttpd_set_response(socket, request, response);
}

static void
khttpd_file_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{

	TRACE("enter %s", khttpd_request_target(request));

	switch (khttpd_request_method(request)) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_file_get_or_head(socket, request);
		break;

	default:
		khttpd_set_not_implemented_response(socket, request, FALSE);
	}
}

static void
khttpd_file_route_dtor(struct khttpd_route *route)
{
	struct khttpd_file_route_data *route_data;

	route_data = khttpd_route_data(route);

	TRACE("enter %s", route_data->path);

	khttpd_mime_type_rule_set_free(route_data->rule_set);
	kern_close(curthread, route_data->dirfd);
	free(route_data->path, M_KHTTPD);
	free(route_data, M_KHTTPD);
}

static int
khttpd_mount_proc(void *data)
{
	struct stat statbuf;
	struct khttpd_mount_args *args;
	struct filedescent *dstfde, *srcfde;
	struct filedesc *fdp;
	struct khttpd_route *route;
	struct khttpd_file_route_data *route_data;
	struct thread *td;
	int error, newfd;

	args = data;
	td = curthread;
	fdp = td->td_proc->p_fd;

	TRACE("enter %s", args->prefix);

	error = khttpd_route_add(&khttpd_route_root, args->prefix,
	    &khttpd_route_type_file);
	if (error != 0)
		goto failed;

	FILEDESC_XLOCK(fdp);

	error = fdalloc(td, 0, &newfd);
	if (error != 0) {
		TRACE("error fdalloc %d", error);
		FILEDESC_XUNLOCK(fdp);
		goto failed;
	}

	srcfde = args->fde;
	dstfde = &fdp->fd_ofiles[newfd];
	dstfde->fde_file = srcfde->fde_file;
	filecaps_move(&srcfde->fde_caps, &dstfde->fde_caps);

	FILEDESC_XUNLOCK(fdp);

	error = kern_fstat(td, newfd, &statbuf);
	if (error != 0) {
		TRACE("error stat %d", error);
		goto failed;
	}

	if ((statbuf.st_mode & S_IFDIR) == 0) {
		TRACE("error nodir");
		error = ENOTDIR;
		goto failed;
	}

	route_data = malloc(sizeof(struct khttpd_file_route_data), M_KHTTPD,
	    M_WAITOK);
	route_data->path = args->prefix;
	route_data->rule_set = khttpd_mime_type_rule_set_alloc(1, NULL);
	route_data->dirfd = newfd;
	args->prefix = NULL;

	route = khttpd_route_find(&khttpd_route_root, route_data->path, NULL);
	khttpd_route_set_data(route, route_data, khttpd_file_route_dtor);

	return (0);

failed:
	fdrop(args->fde->fde_file, td);
	free(args->prefix, M_KHTTPD);

	return (error);
}

int
khttpd_mount(struct khttpd_mount_args *args)
{
	char pathbuf[PATH_MAX];
	struct filedesc *fdp;
	struct file *fp;
	struct filedescent fde, *fdep;
	struct thread *td;
	int error, fd;
	size_t pathlen;

	td = curthread;
	fdp = td->td_proc->p_fd;
	fd = args->dirfd;

	error = copyinstr(args->prefix, pathbuf, sizeof(pathbuf), &pathlen);
	if (error != 0)
		return (error);
	if (pathbuf[0] != '/' || pathbuf[pathlen - 2] == '/')
		return (EINVAL);

	FILEDESC_SLOCK(fdp);

	fdep = &fdp->fd_ofiles[fd];

	if (fd < 0 || fdp->fd_lastfile < fd ||
	    (fp = fdep->fde_file) == NULL) {
		error = EBADF;
		goto out;
	}

	if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
		error = EOPNOTSUPP;
		goto out;
	}

	fhold(fp);

	fde.fde_file = fp;
	filecaps_copy(&fdep->fde_caps, &fde.fde_caps, true);
	FILEDESC_SUNLOCK(fdp);

	args->prefix = strdup(pathbuf, M_KHTTPD);
	args->fde = &fde;

	return (khttpd_run_proc(khttpd_mount_proc, args));

out:
	FILEDESC_SUNLOCK(fdp);

	return (error);
}

static struct khttpd_mime_type_rule_set *
khttpd_mime_type_rule_set_alloc(uint32_t hash_size, char *buf)
{
	struct khttpd_mime_type_rule_set *rule_set;
	uint32_t i;

	rule_set = malloc(sizeof(*rule_set) +
	    sizeof(struct khttpd_mime_type_rule_slist) * hash_size, M_KHTTPD, 
	    M_WAITOK);
	rule_set->buffer = buf;
	rule_set->hash_mask = hash_size - 1;

	for (i = 0; i < hash_size; ++i)
		SLIST_INIT(&rule_set->hash_table[i]);

	return (rule_set);
}

static void
khttpd_mime_type_rule_set_free(struct khttpd_mime_type_rule_set *rule_set)
{
	struct khttpd_mime_type_rule *rule;
	int i;
	uint32_t hash_size;

	TRACE("enter %p", rule_set);

	if (rule_set == NULL)
		return;

	hash_size = rule_set->hash_mask + 1;
	for (i = 0; i < hash_size; ++i)
		while ((rule = SLIST_FIRST(&rule_set->hash_table[i])) !=
		    NULL) {
			SLIST_REMOVE_HEAD(&rule_set->hash_table[i], link);
			uma_zfree(khttpd_mime_type_rule_zone, rule);
		}

	free(rule_set->buffer, M_KHTTPD);
	free(rule_set, M_KHTTPD);
}

static const char *
khttpd_mime_type_rule_set_find(struct khttpd_mime_type_rule_set *rule_set,
    const char *path)
{
	struct khttpd_mime_type_rule *rule;
	const char *cp;
	uint32_t hash;

	TRACE("enter %s", path);

	for (cp = path + strlen(path); path < cp && cp[-1] != '.'; --cp)
		;		/* nothing */

	if (path == cp)
		return ("application/octet-stream");

	hash = khttpd_hash32_str_ci(cp, 0) & rule_set->hash_mask;
	SLIST_FOREACH(rule, &rule_set->hash_table[hash], link)
		if (strcasecmp(cp, rule->suffix) == 0)
			return (rule->type);

	return ("application/octet-stream");
}

static int
khttpd_set_mime_type_rules_proc(void *data)
{
	struct khttpd_set_mime_type_rules_args *args;
	struct khttpd_route *route;
	struct khttpd_file_route_data *route_data;
	const char *suffix;

	args = data;

	TRACE("enter %s", args->mount_point);

	route = khttpd_route_find(&khttpd_route_root, args->mount_point,
	    &suffix);
	if (route == NULL || *suffix != '\0') {
		TRACE("error enoent");
		return (ENOENT);
	}

	if (khttpd_route_type(route) != &khttpd_route_type_file) {
		TRACE("error eopnotsupp");
		return (EOPNOTSUPP);
	}

	route_data = (struct khttpd_file_route_data *)
	    khttpd_route_data(route);
	khttpd_mime_type_rule_set_free(route_data->rule_set);
	route_data->rule_set = args->rule_set;

	return (0);
}

int
khttpd_set_mime_type_rules(struct khttpd_set_mime_type_rules_args *args)
{
	char mount_point[PATH_MAX];
	struct khttpd_mime_type_rule_slist rules;
	struct khttpd_mime_type_rule_set *rule_set;
	struct khttpd_mime_type_rule *rule, *rp;
	char *buf, *cp, *end, *last_end, *next, *suffix, *type;
	size_t bufsize;
	uint32_t rule_count, hash, hash_size;
	int error;
	char dummy;

	rule_set = NULL;

	error = copyinstr(args->mount_point, mount_point, sizeof(mount_point),
	    NULL);
	if (error != 0)
		return (error);

	args->mount_point = mount_point;

	bufsize = args->bufsize;
	buf = malloc(bufsize, M_KHTTPD, M_WAITOK);
	error = copyin(args->buf, buf, bufsize);
	if (error != 0)
		goto out;

	SLIST_INIT(&rules);

	last_end = &dummy;
	end = buf + bufsize;
	rule_count = 0;
	for (cp = buf; cp < end; cp = next + 1) {
		next = khttpd_find_ch_in(cp, end, '\n');
		next = next == NULL ? end : next;

		type = cp = khttpd_skip_whitespace(cp);
		*last_end = '\0';
		last_end = cp = khttpd_find_whitespace(cp, next);

		while (cp < next) {
			suffix = cp = khttpd_skip_whitespace(cp);
			if (*cp == '\n')
				break;
			*last_end = '\0';
			last_end = cp = khttpd_find_whitespace(cp, next);

			++rule_count;
			rule = uma_zalloc(khttpd_mime_type_rule_zone,
			    M_WAITOK);
			rule->type = type;
			rule->suffix = suffix;
			SLIST_INSERT_HEAD(&rules, rule, link);
		}
	}
	*last_end = '\0';

	hash_size = rule_count == 0 ? 1 : 1U << (fls(rule_count) - 1);

	rule_set = khttpd_mime_type_rule_set_alloc(hash_size, buf);
	buf = NULL;
	args->rule_set = rule_set;

	while ((rule = SLIST_FIRST(&rules)) != NULL) {
		SLIST_REMOVE_HEAD(&rules, link);
		hash = khttpd_hash32_str_ci(rule->suffix, 0) & (hash_size - 1);

		SLIST_FOREACH(rp, &rule_set->hash_table[hash], link) {
			if (strcasecmp(rp->suffix, rule->suffix) != 0)
				continue;

			printf("ERROR: there are duplicate entries "
			    "for suffix %s.\n", rule->suffix);
			error = EEXIST;
			goto out;
		}

		SLIST_INSERT_HEAD(&rule_set->hash_table[hash], rule, link);
	}

	error = khttpd_run_proc(khttpd_set_mime_type_rules_proc, args);
	if (error == 0)
		rule_set = NULL;
out:
	khttpd_mime_type_rule_set_free(rule_set);
	free(buf, M_KHTTPD);

	return (error);
}

int khttpd_file_init(void)
{

	khttpd_mime_type_rule_zone = uma_zcreate("khttp-mime-type-rule",
	    sizeof(struct khttpd_mime_type_rule),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);

	return (0);
}

void khttpd_file_fini(void)
{

	uma_zdestroy(khttpd_mime_type_rule_zone);
}
