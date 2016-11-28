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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/hash.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/syscallsubr.h>
#include <sys/syslog.h>

#include <machine/stdarg.h>

#include <vm/uma.h>

#include "khttpd_ctrl.h"
#include "khttpd_http.h"
#include "khttpd_init.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_rewriter.h"
#include "khttpd_refcount.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_webapi.h"

struct khttpd_file_location_data {
	struct khttpd_rewriter *charset_rewriter;
	struct khttpd_rewriter *mime_type_rewriter;
	char		*docroot;
	int		docroot_fd;
	KHTTPD_REFCOUNT1_MEMBERS;
};

struct khttpd_file_get_exchange_data {
	off_t	xmit_offset;
	off_t	xmit_residual;
	int	fd;
	char	path[];
};

static void khttpd_file_get_exchange_dtor(struct khttpd_exchange *, void *);
static int khttpd_file_get_exchange_get(struct khttpd_exchange *, void *,
    struct khttpd_stream *, size_t *);
static void khttpd_file_get(struct khttpd_exchange *);
static void khttpd_file_location_dtor(struct khttpd_location *);
static void khttpd_file_location_data_dtor(struct khttpd_file_location_data *);

static struct khttpd_location_ops khttpd_file_ops = {
	.dtor = khttpd_file_location_dtor,
	.method[KHTTPD_METHOD_GET] = khttpd_file_get,
};

static struct khttpd_exchange_ops khttpd_file_get_exchange_ops = {
	.dtor = khttpd_file_get_exchange_dtor,
	.send = khttpd_file_get_exchange_get,
};

static struct mtx khttpd_file_lock;

MTX_SYSINIT(khttpd_file_lock, &khttpd_file_lock, "khttpd-file", MTX_DEF);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"
KHTTPD_REFCOUNT1_GENERATE_STATIC(khttpd_file_location_data, 
    khttpd_file_location_data, khttpd_file_location_data_dtor, khttpd_free);
#pragma clang diagnostic pop

static int
khttpd_file_normalize_path(const char *path, char *buf, size_t bufsize)
{
	const char *src, *segend;
	char *dst, *dstend;

	KHTTPD_ENTRY("%s(%p,%p,%zu)", __func__, path, buf, bufsize);

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
khttpd_file_open(int dirfd, const char *path, int *fd_out,
    struct stat *statbuf)
{
	struct thread *td;
	int error, fd;

	KHTTPD_ENTRY("%s(%d,%p)", __func__, dirfd, path);

	td = curthread;

	error = kern_openat(td, dirfd, (char *)path, UIO_SYSSPACE, O_RDONLY,
	    0);
	if (error != 0)
		return (error);

	fd = td->td_retval[0];

	error = kern_fstat(td, fd, statbuf);
	if (error != 0) {
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
khttpd_file_get_exchange_dtor(struct khttpd_exchange *exchange, void *arg)
{
	struct khttpd_file_get_exchange_data *data;

	KHTTPD_ENTRY("khttpd_file_get_exchange_dtor(%p,%p)", exchange, arg);

	data = arg;
	if (data->fd != -1)
		kern_close(curthread, data->fd);
	khttpd_free(data);
}

static int
khttpd_file_get_exchange_get(struct khttpd_exchange *exchange, void *arg,
    struct khttpd_stream *stream, size_t *sent_out)
{
	struct khttpd_file_get_exchange_data *data;
	cap_rights_t rights;
	struct file *fp;
	struct thread *td;
	off_t sent;
	int error;

	KHTTPD_ENTRY("khttpd_file_get_exchange_get(%p,%p,%p)",
	    exchange, arg, stream);

	data = arg;
	td = curthread;

	error = fget_read(td, data->fd, cap_rights_init(&rights, CAP_PREAD),
	    &fp);
	if (error != 0)
		return (error);

	error = fo_sendfile(fp, khttpd_stream_get_fd(stream), NULL, NULL,
	    data->xmit_offset, data->xmit_residual, &sent, 0, td);

	fdrop(fp, td);

	if (error != 0 && error != EWOULDBLOCK)
		return (error);

	data->xmit_residual -= sent;
	data->xmit_offset += sent;
	*sent_out = sent;

	return (0);
}

static void
khttpd_file_get(struct khttpd_exchange *exchange)
{
	char buf[64];
	struct sbuf sbuf;
	struct stat statbuf;
	struct khttpd_file_get_exchange_data *data;
	struct khttpd_file_location_data *location_data;
	struct khttpd_location *location;
	struct thread *td;
	const char *suffix;
	size_t pathsize;
	int error;
	int status;

	KHTTPD_ENTRY("khttpd_file_get(%p), target=\"%s\"", exchange,
	    khttpd_ktr_printf("%s", khttpd_exchange_get_target(exchange)));

	td = curthread;
	location = khttpd_exchange_location(exchange);
	mtx_lock(&khttpd_file_lock);
	location_data = khttpd_file_location_data_acquire
	    (khttpd_location_data(location));
	mtx_unlock(&khttpd_file_lock);

	suffix = khttpd_exchange_suffix(exchange);

	/* 
	 * This MAX() is necessary because normalizing an empty path can result
	 * in "."
	 */
	pathsize = MAX(2, strlen(suffix) + 1);
	data = khttpd_malloc(sizeof(*data) + pathsize);
	data->fd = -1;
	data->xmit_offset = 0;
	data->xmit_residual = 0;
	khttpd_exchange_set_ops(exchange, &khttpd_file_get_exchange_ops, data);

	error = khttpd_file_normalize_path(suffix[0] == '/' ? suffix + 1 :
	    suffix, data->path, pathsize);
	if (error != 0) {
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		goto error;
	}

	error = khttpd_file_open(location_data->docroot_fd, data->path,
	    &data->fd, &statbuf);
	switch (error) {

	case 0:
		break;

	default:
		khttpd_exchange_error(exchange, LOG_ERR, "khttpd: "
		    "unexpected error code from khttpd_file_open. "
		    "(error: %d)", error);
		/* FALL THROUGH */

	case EISDIR: /* auto index generation is not implemented yet */

	case ENAMETOOLONG:
	case ENOENT:
	case EACCES:
	case EPERM:
		status = KHTTPD_STATUS_NOT_FOUND;
		khttpd_exchange_set_error_response_body(exchange, status,
		    NULL);
		goto error;

	}

	data->xmit_residual = statbuf.st_size;

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	if (location_data->mime_type_rewriter != NULL)
		khttpd_rewriter_rewrite(location_data->mime_type_rewriter,
		    &sbuf, data->path);

	if (location_data->charset_rewriter != NULL) {
		sbuf_cat(&sbuf, sbuf_len(&sbuf) == 0 ? "charset=" :
		    "; charset=");
		khttpd_rewriter_rewrite(location_data->charset_rewriter,
		    &sbuf, data->path);
	}

	sbuf_finish(&sbuf);

	if (0 < sbuf_len(&sbuf))
		khttpd_exchange_add_response_field(exchange, "Content-Type",
		    "%s", sbuf_data(&sbuf));

	sbuf_delete(&sbuf);

	khttpd_exchange_set_response_content_length(exchange, statbuf.st_size);
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);
	return;

 error:
	khttpd_file_location_data_release(location_data);
	khttpd_exchange_respond(exchange, status);
}

static int
khttpd_file_location_data_new
   (struct khttpd_file_location_data **location_data_out,
    struct khttpd_mbuf_json *output,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_webapi_property prop_spec;
	struct khttpd_file_location_data *location_data;
	struct thread *td;
	const char *docroot_str;
	void *charset_rewriter, *mime_type_rewriter;
	int docroot_fd, error, status;

	KHTTPD_ENTRY("khttpd_file_location_data_new()");

	td = curthread;
	charset_rewriter = NULL;
	mime_type_rewriter = NULL;
	location_data = NULL;
	docroot_fd = -1;

	status = khttpd_obj_type_get_obj_from_property(&khttpd_ctrl_rewriters,
	    &charset_rewriter, "charsetRules", output,
	    input_prop_spec, input, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	status = khttpd_obj_type_get_obj_from_property(&khttpd_ctrl_rewriters,
	    &mime_type_rewriter, "mimeTypeRules", output,
	    input_prop_spec, input, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	status = khttpd_webapi_get_string_property(&docroot_str,
	    "documentRoot", input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	prop_spec.link = input_prop_spec;
	prop_spec.name = "documentRoot";

	if (docroot_str != NULL && docroot_str[0] != '/') {
		khttpd_webapi_set_invalid_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		khttpd_webapi_set_problem_detail(output,
		    "relative path name is not acceptable.");
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}

	error = kern_openat(td, AT_FDCWD, (char *)docroot_str, UIO_SYSSPACE,
	    O_RDONLY | O_DIRECTORY, 0);
	if (error != 0) {
		khttpd_webapi_set_invalid_value_problem(output);
		khttpd_webapi_set_problem_property(output, &prop_spec);
		khttpd_webapi_set_problem_detail(output,
		    "failed to open the document root directory.");
		khttpd_webapi_set_problem_errno(output, error);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}
	docroot_fd = td->td_retval[0];

	location_data = 
	    khttpd_malloc(sizeof(struct khttpd_file_location_data));
	location_data->charset_rewriter =
	    khttpd_rewriter_acquire(charset_rewriter);
	location_data->mime_type_rewriter =
	    khttpd_rewriter_acquire(mime_type_rewriter);
	location_data->docroot = khttpd_strdup(docroot_str);
	location_data->docroot_fd = docroot_fd;
	KHTTPD_REFCOUNT1_INIT(khttpd_file_location_data, location_data);

	*location_data_out = location_data;

	return (KHTTPD_STATUS_OK);

quit:
	if (docroot_fd != -1)
		kern_close(td, docroot_fd);
	khttpd_free(location_data);

	return (status);
}

static void
khttpd_file_location_data_dtor(struct khttpd_file_location_data *data)
{

	KHTTPD_ENTRY("khttpd_file_location_data_dtor(%p)", data);

	khttpd_rewriter_release(data->charset_rewriter);
	khttpd_rewriter_release(data->mime_type_rewriter);
	khttpd_free(data->docroot);
	if (data->docroot_fd != -1)
		kern_close(curthread, data->docroot_fd);
}

static void
khttpd_file_location_dtor(struct khttpd_location *location)
{

	KHTTPD_ENTRY("khttpd_file_location_dtor(%p)", location);
	khttpd_file_location_data_release(khttpd_location_data(location));
}

static void
khttpd_file_location_get(struct khttpd_location *location,
    struct khttpd_mbuf_json *output)
{
	char buf[64];
	struct sbuf sbuf;
	struct khttpd_file_location_data *location_data;

	KHTTPD_ENTRY("khttpd_file_location_get(%p)", location);

	mtx_lock(&khttpd_file_lock);
	KHTTPD_ENTRY("khttpd_file_location_dtor(%p)", location);
	location_data = khttpd_file_location_data_acquire
	    (khttpd_location_data(location));
	mtx_unlock(&khttpd_file_lock);

	khttpd_mbuf_json_object_begin(output);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	if (location_data->charset_rewriter != NULL) {
		khttpd_obj_type_get_id(&khttpd_ctrl_rewriters,
		    location_data->charset_rewriter, &sbuf);
		sbuf_finish(&sbuf);
		khttpd_mbuf_json_property_format(output, "charsetRules", TRUE,
		    "%s", sbuf_data(&sbuf));
	}

	if (location_data->mime_type_rewriter != NULL) {
		sbuf_clear(&sbuf);
		khttpd_obj_type_get_id(&khttpd_ctrl_rewriters,
		    location_data->mime_type_rewriter, &sbuf);
		sbuf_finish(&sbuf);
		khttpd_mbuf_json_property_format(output, "mimeTypeRules", TRUE,
		    "%s", sbuf_data(&sbuf));
	}

	khttpd_mbuf_json_property_format(output, "documentRoot", TRUE,
	    "%s", location_data->docroot);

	khttpd_mbuf_json_object_end(output);

	sbuf_delete(&sbuf);
	khttpd_file_location_data_release(location_data);
}

static int 
khttpd_file_location_put(struct khttpd_location *location, 
    struct khttpd_mbuf_json *output,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_file_location_data *location_data;
	int status;

	KHTTPD_ENTRY("khttpd_file_location_put(%p)", location);

	status = khttpd_file_location_data_new(&location_data, output,
	    input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	mtx_lock(&khttpd_file_lock);
	location_data = khttpd_location_set_data(location, location_data);
	mtx_unlock(&khttpd_file_lock);
	khttpd_file_location_data_release(location_data);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_file_location_create(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path, 
    struct khttpd_mbuf_json *output,
    struct khttpd_webapi_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_file_location_data *location_data;
	int error, status;

	KHTTPD_ENTRY("khttpd_file_location_create(%p)", server);

	status = khttpd_file_location_data_new(&location_data, output,
	    input_prop_spec, input);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	*location_out = khttpd_location_new(&error, server, path,
	    &khttpd_file_ops, location_data);
	if (error != 0) {
		khttpd_file_location_data_release(location_data);
		status = KHTTPD_STATUS_INTERNAL_SERVER_ERROR;
		khttpd_webapi_set_problem(output, status, NULL, NULL);
		khttpd_webapi_set_problem_detail(output,
		    "failed to construct a location");
		khttpd_webapi_set_problem_errno(output, error);
		return (status);
	}

	return (KHTTPD_STATUS_CREATED);
}

static int
khttpd_file_register_location_type(void)
{

	KHTTPD_ENTRY("khttpd_file_register_location_type()");

	khttpd_location_type_register("khttpd_file",
	    khttpd_file_location_create, NULL,
	    khttpd_file_location_get, khttpd_file_location_put);

	return (0);
}

static void
khttpd_file_deregister_location_type(void)
{

	KHTTPD_ENTRY("khttpd_file_deregister_location_type()");
	khttpd_location_type_deregister("khttpd_file");
}

KHTTPD_INIT(khttpd::file, khttpd_file_register_location_type,
    khttpd_file_deregister_location_type,
    KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES);
