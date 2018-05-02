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

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/hash.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rwlock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/sf_buf.h>
#include <sys/kernel.h>
#include <sys/syslog.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/capsicum.h>
#include <sys/vnode.h>
#include <sys/syscallsubr.h>

#include <machine/stdarg.h>

#include <vm/vm.h>
#include <vm/vm_object.h>
#include <vm/vm_page.h>
#include <vm/vm_pager.h>
#include <vm/uma.h>

#include "khttpd_ctrl.h"
#include "khttpd_http.h"
#include "khttpd_init.h"
#include "khttpd_job.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_port.h"
#include "khttpd_problem.h"
#include "khttpd_rewriter.h"
#include "khttpd_refcount.h"
#include "khttpd_server.h"
#include "khttpd_status_code.h"
#include "khttpd_stream.h"
#include "khttpd_string.h"
#include "khttpd_webapi.h"

struct khttpd_file_location_data {
	struct khttpd_rewriter *charset_rewriter;
	struct khttpd_rewriter *mime_type_rewriter;
	char		*docroot;
	int		docroot_fd;
};

/*
 * b	- Both khttpd_file_lock and khttpd_file_get_exchange_data::lock are
 *	  necessary to modify. Only one of the two locks is necessary to read.
 * e	- accessed only by the event handling thread.
 * l	- khttpd_file_get_exchange_data::lock
 * o	- effectively read-only
 * p	- no concurrent access.
 *	  accessed by the event thread if data->in_progress == 0,
 *	  accessed by the event thread or the io_job thread, otherwise.
 *
 * Lock ordering
 * 
 * 1. khttpd_file_get_exchange_data::lock
 * 2. khttpd_file_lock
 */

struct khttpd_file_get_exchange_data {
	struct mtx	lock;
	LIST_ENTRY(khttpd_file_get_exchange_data) orphan_link; /* (b) */
	struct sbuf	path;				       /* (o) */
	off_t		xmit_residual;		     /* (e) */
	off_t		end_offset;		     /* (o) */
	off_t		io_offset;		     /* (p) */
	struct khttpd_exchange *exchange;	     /* (o) */
	struct khttpd_job *io_job;		     /* (o) */

#define khttpd_file_get_exchange_data_zctor_begin fp
	struct file	*fp;	 		     /* (o) */
	struct vm_object *object;    		     /* (o) */
	struct vm_page	*pages[MAXPHYS / PAGE_SIZE]; /* (p) */
	unsigned	io_size;		     /* (p) */
	int		npages;			     /* (p) */
	int		in_progress;		     /* (l) */
	unsigned	paused:1;		     /* (l) */
	unsigned	orphaned:1;		     /* (l) */

#define khttpd_file_get_exchange_data_zctor_end error
	int		error;		/* (l) */
	char		path_buf[128];	/* (o) */
};

static void khttpd_file_get_exchange_dtor(struct khttpd_exchange *, void *);
static int khttpd_file_get_exchange_get(struct khttpd_exchange *, void *,
    ssize_t, struct mbuf **);
static void khttpd_file_get(struct khttpd_exchange *);
static void khttpd_file_location_dtor(struct khttpd_location *);
static bool khttpd_file_filter(struct khttpd_location *, 
    struct khttpd_exchange *, const char *, struct sbuf *);
static void khttpd_file_read_file(void *);

static struct khttpd_location_ops khttpd_file_ops = {
	.dtor = khttpd_file_location_dtor,
	.filter = khttpd_file_filter,
	.method[KHTTPD_METHOD_GET] = khttpd_file_get,
};

static struct khttpd_exchange_ops khttpd_file_get_exchange_ops = {
	.dtor = khttpd_file_get_exchange_dtor,
	.get = khttpd_file_get_exchange_get,
};

static struct mtx khttpd_file_lock;
static uma_zone_t khttpd_file_get_exchange_data_zone;
static LIST_HEAD(, khttpd_file_get_exchange_data) khttpd_file_orphan_get_list =
	LIST_HEAD_INITIALIZER(&khttpd_file_orphan_get_list);

MTX_SYSINIT(khttpd_file_lock, &khttpd_file_lock, "file", MTX_DEF);

static int
khttpd_file_get_exchange_data_init(void *mem, int size, int flags)
{
	struct khttpd_file_get_exchange_data *data;

	KHTTPD_ENTRY("khttpd_file_get_exchange_data_init(%p)", mem);

	data = mem;
	mtx_init(&data->lock, "getxchg", NULL, MTX_DEF);
	sbuf_new(&data->path, data->path_buf, sizeof(data->path_buf),
	    SBUF_AUTOEXTEND);
	data->io_job = khttpd_job_new(khttpd_file_read_file, data, NULL);
	return (0);
}

static void
khttpd_file_get_exchange_data_fini(void *mem, int size)
{
	struct khttpd_file_get_exchange_data *data;

	KHTTPD_ENTRY("khttpd_file_get_exchange_data_fini(%p)", mem);

	data = mem;
	mtx_destroy(&data->lock);
	sbuf_delete(&data->path);
	khttpd_job_delete(data->io_job);
}

static int
khttpd_file_get_exchange_data_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_file_get_exchange_data *data;

	KHTTPD_ENTRY("khttpd_file_get_exchange_data_ctor(%p)", mem);

	data = mem;
	bzero(&data->khttpd_file_get_exchange_data_zctor_begin,
	    sizeof(struct khttpd_file_get_exchange_data) -
	    offsetof(struct khttpd_file_get_exchange_data,
		khttpd_file_get_exchange_data_zctor_begin));

	return (0);
}

static void
khttpd_file_get_exchange_data_dtor(void *mem, int size, void *arg)
{
	struct khttpd_file_get_exchange_data *data;
	struct thread *td;

	KHTTPD_ENTRY("khttpd_file_get_exchange_data_dtor(%p)", mem);

	td = curthread;
	data = mem;
	vm_object_deallocate(data->object);
	if (data->fp != NULL) {
		fdrop(data->fp, td);
	}
	sbuf_clear(&data->path);
}

static void
khttpd_file_get_exchange_dtor(struct khttpd_exchange *exchange, void *arg)
{
	struct khttpd_file_get_exchange_data *data;

	KHTTPD_ENTRY("khttpd_file_get_exchange_dtor(%p,%p)", exchange, arg);

	data = arg;
	mtx_lock(&data->lock);

	if (data->in_progress == 0) {
		mtx_unlock(&data->lock);
		uma_zfree(khttpd_file_get_exchange_data_zone, data);
		return;
	}

	data->orphaned = TRUE;

	mtx_lock(&khttpd_file_lock);
	LIST_INSERT_HEAD(&khttpd_file_orphan_get_list, data, orphan_link);
	mtx_unlock(&khttpd_file_lock);

	mtx_unlock(&data->lock);
}

static int
khttpd_file_open_for_read(int dirfd, 
    struct khttpd_file_get_exchange_data *data)
{
	struct vattr vattr;
	cap_rights_t rights;
	struct file *fp;
	struct thread *td;
	struct vnode *vp;
	struct vm_object *object;
	int error, fd;

	KHTTPD_ENTRY("%s(%d,%p), data={path: \"%s\"}", __func__, dirfd, data,
	    khttpd_ktr_printf("%s", sbuf_data(&data->path)));

	KASSERT(0 < sbuf_len(&data->path) &&
	    sbuf_data(&data->path)[0] == '/', ("path is not absolute"));

	td = curthread;

	if (sbuf_len(&data->path) == 1) {
		KHTTPD_NOTE("eisdir");
		error = EISDIR;
		return (error);
	}

	error = kern_openat(td, dirfd, sbuf_data(&data->path) + 1,
	    UIO_SYSSPACE, O_RDONLY, 0);
	if (error != 0) {
		KHTTPD_BRANCH("kern_openat error=%d", error);
		return (error);
	}
	fd = td->td_retval[0];

	error = fget_read(td, fd, cap_rights_init(&rights, CAP_PREAD), &fp);
	if (error != 0) {
		KHTTPD_BRANCH("fget_read error=%d", error);
		goto error1;
	}

	if (fp->f_type != DTYPE_VNODE) {
		KHTTPD_BRANCH("f_type = %d", fp->f_type);
		error = ENOENT;
		goto error1;
	}

	fhold(fp);
	data->fp = fp;

	vp = fp->f_vnode;
	vn_lock(vp, LK_SHARED | LK_RETRY);

	error = VOP_GETATTR(vp, &vattr, td->td_ucred);
	if (error != 0) {
		KHTTPD_BRANCH("VOP_GETATTR error=%d", error);
		goto error2;
	}

	if (vattr.va_type == VDIR) {
		KHTTPD_BRANCH("is VDIR");
		error = EISDIR;
		goto error1;
	}

	if (vattr.va_type != VREG) {
		KHTTPD_BRANCH("va_type is %d, not VREG", vattr.va_type);
		error = ENOENT;
		goto error1;
	}

	data->end_offset = vattr.va_size;

	object = vp->v_object;
	VM_OBJECT_WLOCK(object);
	if ((object->flags & OBJ_DEAD) != 0) {
		KHTTPD_BRANCH("OBJ_DEAD");
		error = EBADF;
		goto error3;
	}

	vm_object_reference_locked(object);
	data->object = object;

 error3:
	VM_OBJECT_WUNLOCK(object);

 error2:
	VOP_UNLOCK(vp, 0);

 error1:
	fdrop(fp, td);
	kern_close(td, fd);

	return (error);
}

static void
khttpd_file_read_file_done(void *arg, vm_page_t *pages, int count, int error)
{
	struct khttpd_file_get_exchange_data *data;
	int i;
	boolean_t orphaned, need_kick;

	KHTTPD_ENTRY("khttpd_file_read_done(%p,%p,%d,%d)",
	    arg, pages, count, error);

	data = arg;

	for (i = 0; i < count; ++i)
		vm_page_xunbusy(pages[i]);

	mtx_lock(&data->lock);

	if (error != 0)
		data->error = error;

	if (0 < --data->in_progress) {
		mtx_unlock(&data->lock);
		return;
	}

	if ((orphaned = data->orphaned)) {
		mtx_lock(&khttpd_file_lock);

		LIST_REMOVE(data, orphan_link);

		if (LIST_EMPTY(&khttpd_file_orphan_get_list))
			wakeup(&khttpd_file_orphan_get_list);

		mtx_unlock(&khttpd_file_lock);

	} else if ((need_kick = data->paused))
		data->paused = FALSE;

	mtx_unlock(&data->lock);

	if (orphaned)
		uma_zfree(khttpd_file_get_exchange_data_zone, data);
	else if (need_kick)
		khttpd_exchange_continue_receiving(data->exchange);
}

static boolean_t
khttpd_file_is_valid_page(struct vm_page *pg, int pageoff, unsigned io_size,
    int i, int n)
{

	return (i == 0 ? 
	    vm_page_is_valid(pg, pageoff, MIN(PAGE_SIZE - pageoff, io_size)) :
	    i == n - 1 ?
	    vm_page_is_valid(pg, 0, (pageoff + io_size) & PAGE_MASK) :
	    vm_page_is_valid(pg, 0, 0));
}

static void
khttpd_file_read_file(void *arg)
{
	struct thread *td;
	struct khttpd_file_get_exchange_data *data;
	struct vm_object *object;
	struct vnode *vp;
	struct vm_page *pg, **pages;
	off_t io_offset;
	vm_pindex_t si;
	unsigned io_size, pageoff;
	int count, i, j, rahead, after, npages;
	int rv, flags;
	boolean_t no_io;

	KHTTPD_ENTRY("khttpd_file_read_file(%p)", arg);

	td = curthread;
	data = arg;
	object = data->object;
	flags = VM_ALLOC_NORMAL | VM_ALLOC_WIRED;

	io_offset = data->io_offset;
	io_size = data->io_size;
	pages = data->pages;
	pageoff = io_offset & PAGE_MASK;

	if (data->in_progress != 0) {
		no_io = FALSE;
		npages = data->npages;

	} else {
		no_io = TRUE;
		flags |= VM_ALLOC_NOWAIT;
		data->error = 0;
		data->in_progress = 1;
		npages = howmany(pageoff + io_size, PAGE_SIZE);
		KASSERT(npages <  nitems(data->pages),
		    ("npages %d, nitems(data->pages) %zd",
			npages, nitems(data->pages)));
		data->npages = npages;
		bzero(pages, npages * sizeof(struct vm_page *));
	}

	vp = data->fp->f_vnode;
	vn_lock(vp, LK_SHARED | LK_RETRY);

	VM_OBJECT_WLOCK(object);

	si = OFF_TO_IDX(data->io_offset);
	for (i = 0; i < npages; ++i)
		if (pages[i] == NULL) {
			pg = vm_page_grab(object, si + i, flags);
			if (pg == NULL) {
				VM_OBJECT_WUNLOCK(object);
				VOP_UNLOCK(vp, 0);
				khttpd_job_schedule(data->io_job, 0);
				return;
			}
			pages[i] = pg;
		}

	rahead = MIN(MAXPHYS / PAGE_SIZE,
	    howmany(data->end_offset - data->io_offset + pageoff, PAGE_SIZE));

	for (i = 0; i < npages; ) {
		pg = pages[i];
		if (khttpd_file_is_valid_page(pg, pageoff, io_size, i,
			npages)) {
			vm_page_xunbusy(pg);
			++i;
			continue;
		}

		for (j = i + 1; j < npages; ++j)
			if (khttpd_file_is_valid_page(pages[j], pageoff,
				io_size, j, npages))
				break;	/* nothing */

		while (!vm_pager_has_page(object, si + i, NULL, &after) &&
		    i < j) {
			pmap_zero_page(pg);
			pg->valid = VM_PAGE_BITS_ALL;
			pg->dirty = 0;
			vm_page_xunbusy(pg);
			++i;
		}

		if (j < npages)
			after = MIN(after, j - i - 1);
		count = MIN(after + 1, npages - i);

		mtx_lock(&data->lock);
		++data->in_progress;
		mtx_unlock(&data->lock);

		rv = vm_pager_get_pages_async(object, pages + i, count,
		    NULL, i + count == npages ? &rahead : NULL,
		    &khttpd_file_read_file_done, data);
		KASSERT(rv == VM_PAGER_OK,
		    ("vm_pager_get_pages_async(%p,pages + %d,%d,,,,) => %d",
			object, i, count, rv));

		i += count;
	}

	VM_OBJECT_WUNLOCK(object);
	VOP_UNLOCK(vp, 0);

	khttpd_file_read_file_done(data, NULL, 0, 0);
}

static int
khttpd_file_get_exchange_get(struct khttpd_exchange *exchange, void *arg,
    ssize_t space, struct mbuf **data_out)
{
	struct khttpd_mbuf_json logent;
	struct khttpd_file_get_exchange_data *data;
	struct thread *td;
	struct mbuf *hd, *mb, *lmb;
	struct sf_buf *sf;
	struct vm_page **pages;
	unsigned io_size, len;
	int error, i, n, pageoff;

	KHTTPD_ENTRY("khttpd_file_get_exchange_get(%p,%p,%#x)",
	    exchange, arg, space);

	data = arg;
	td = curthread;

	if (data->xmit_residual == 0) {
		*data_out = NULL;
		return (0);
	}

	if (data->io_size == 0) {
		data->io_size = MIN(space, data->xmit_residual);
		khttpd_file_read_file(data);
	}

	mtx_lock(&data->lock);

	if (data->in_progress != 0) {
		data->paused = TRUE;
		mtx_unlock(&data->lock);
		return (EWOULDBLOCK);
	}

	mtx_unlock(&data->lock);

	error = data->error;
	if (error != 0) {
		khttpd_mbuf_json_copy(&logent,
		    khttpd_exchange_log_entry(exchange));
		khttpd_problem_set(&logent, LOG_ERR, "io_error", "I/O error");
		khttpd_problem_set_detail(&logent, "file read failure");
		khttpd_problem_set_errno(&logent, error);

		khttpd_mbuf_json_property(&logent, "path");
		khttpd_mbuf_json_cstr(&logent, TRUE, sbuf_data(&data->path));

		khttpd_mbuf_json_property(&logent, "offset");
		khttpd_mbuf_json_format(&logent, FALSE, "%jd",
		    (intmax_t)data->io_offset);

		khttpd_mbuf_json_property(&logent, "size");
		khttpd_mbuf_json_format(&logent, FALSE, "%jd",
		    (intmax_t)data->io_size);

		khttpd_http_error(&logent);
		return (error);
	}

	pages = data->pages;
	n = data->npages;
	pageoff = data->io_offset & PAGE_MASK;
	io_size = data->io_size;

	hd = lmb = NULL;
	for (i = 0; i < n; ++i) {
retry:
		sf = sf_buf_alloc(pages[i], i == 0 ? 0 : SFB_NOWAIT);
		if (sf == NULL) {
			m_freem(hd);
			i = 0;
			goto retry;
		}

		mb = m_get(M_WAITOK, MT_DATA);
		mb->m_flags |= M_EXT | M_RDONLY;
		mb->m_ext.ext_buf = (char *)sf_buf_kva(sf);
		mb->m_ext.ext_size = PAGE_SIZE;
		mb->m_ext.ext_arg1 = sf;
		mb->m_ext.ext_arg2 = NULL;
		mb->m_ext.ext_type = EXT_SFBUF;
		mb->m_ext.ext_flags = EXT_FLAG_EMBREF;
		mb->m_ext.ext_count = 1;
		mb->m_data = mb->m_ext.ext_buf + (i == 0 ? pageoff : 0);
		mb->m_len = i == 0 ? MIN(PAGE_SIZE - pageoff, io_size) :
		    i < n - 1 ? PAGE_SIZE :
		    ((pageoff + io_size - 1) & PAGE_MASK) + 1;
		if (lmb != NULL)
			lmb->m_next = mb;
		else
			hd = mb;
		lmb = mb;
	}
	*data_out = hd;

	len = data->io_size;
	data->xmit_residual -= len;
	data->io_offset += len;

	KASSERT(0 < len, ("data->io_size == 0"));
	KASSERT(0 < space, ("space is %#zx, is not greater than 0", space));
	KASSERT(m_length(hd, NULL) == len,
	    ("m_length(mbufs[0], NULL)=%#x, data->io_size=%#x",
		m_length(hd, NULL), len));

	if (data->io_offset < data->end_offset) {
		data->io_size = MIN(nitems(data->pages) * PAGE_SIZE,
		    MIN(space, data->end_offset - data->io_offset));
		khttpd_file_read_file(data);
	}

	return (0);
}

static void
khttpd_file_get(struct khttpd_exchange *exchange)
{
	char type_buf[32], charset_buf[32];
	struct sbuf type_sbuf, charset_sbuf;
	struct khttpd_file_get_exchange_data *data;
	struct khttpd_file_location_data *location_data;
	struct khttpd_location *location;
	struct thread *td;
	const char *target, *end;
	int error, status;
	boolean_t mime_type_specified, charset_specified;

	KHTTPD_ENTRY("khttpd_file_get(%p), target=\"%s\"", exchange,
	    khttpd_ktr_printf("%s", khttpd_exchange_target(exchange)));

	td = curthread;

	location = khttpd_exchange_location(exchange);
	mtx_lock(&khttpd_file_lock);
	location_data = khttpd_location_data(location);
	mtx_unlock(&khttpd_file_lock);

	data = uma_zalloc(khttpd_file_get_exchange_data_zone, M_WAITOK);
	bzero(&data->khttpd_file_get_exchange_data_zctor_begin,
	    offsetof(struct khttpd_file_get_exchange_data,
		khttpd_file_get_exchange_data_zctor_end) -
	    offsetof(struct khttpd_file_get_exchange_data,
		khttpd_file_get_exchange_data_zctor_begin));
	data->exchange = exchange;

	khttpd_exchange_set_ops(exchange, &khttpd_file_get_exchange_ops, data);

	target = khttpd_exchange_suffix(exchange);
	KASSERT(khttpd_exchange_target(exchange) < target &&
	    target[-1] == '/', ("target[-1]=%#x", target[-1]));
	--target;

	end = khttpd_string_normalize_request_target(&data->path,
	    target, target + strlen(target), NULL);
	if (*end != '\0')
		goto not_found;
	sbuf_finish(&data->path);

	error = khttpd_file_open_for_read(location_data->docroot_fd, data);
	if (error != 0)
		goto not_found;

	data->io_offset = 0;
	data->xmit_residual = data->end_offset - data->io_offset;

	sbuf_new(&type_sbuf, type_buf, sizeof(type_buf), SBUF_AUTOEXTEND);
	sbuf_new(&charset_sbuf, charset_buf, sizeof(charset_buf), 
	    SBUF_AUTOEXTEND);

	mime_type_specified = charset_specified = FALSE;

	if (location_data->mime_type_rewriter != NULL)
		mime_type_specified = khttpd_rewriter_rewrite
		    (location_data->mime_type_rewriter, &type_sbuf,
			sbuf_data(&data->path));

	if (mime_type_specified && location_data->charset_rewriter != NULL)
		charset_specified = khttpd_rewriter_rewrite
		    (location_data->charset_rewriter, &charset_sbuf,
			sbuf_data(&data->path));

	sbuf_finish(&type_sbuf);
	sbuf_finish(&charset_sbuf);

	if (!mime_type_specified)
		; /* nothing */
	else if (!charset_specified)
		khttpd_exchange_add_response_field(exchange, 
		    "Content-Type", "%s", 
		    sbuf_data(&type_sbuf));
	else
		khttpd_exchange_add_response_field(exchange,
		    "Content-Type", "%s; charset=%s",
		    sbuf_data(&type_sbuf), sbuf_data(&charset_sbuf));

	sbuf_delete(&type_sbuf);
	sbuf_delete(&charset_sbuf);

	khttpd_exchange_set_response_content_length(exchange,
	    data->xmit_residual);
	khttpd_exchange_respond(exchange, KHTTPD_STATUS_OK);

	return;

 not_found:
	status = KHTTPD_STATUS_NOT_FOUND;
	khttpd_exchange_set_error_response_body(exchange, status, NULL);
	khttpd_exchange_respond(exchange, status);
}

static int
khttpd_file_run(void)
{

	KHTTPD_ENTRY("khttpd_file_run()");

	khttpd_file_get_exchange_data_zone = uma_zcreate("getxchg",
	    sizeof(struct khttpd_file_get_exchange_data),
	    khttpd_file_get_exchange_data_ctor,
	    khttpd_file_get_exchange_data_dtor,
	    khttpd_file_get_exchange_data_init,
	    khttpd_file_get_exchange_data_fini,
	    UMA_ALIGN_PTR, 0);

	return (0);
}

static void
khttpd_file_exit(void)
{

	KHTTPD_ENTRY("khttpd_file_exit()");

	mtx_lock(&khttpd_file_lock);
	while (!LIST_EMPTY(&khttpd_file_orphan_get_list))
		mtx_sleep(&khttpd_file_orphan_get_list, &khttpd_file_lock, 0,
		    "fileexit", 0);
	mtx_unlock(&khttpd_file_lock);

	uma_zdestroy(khttpd_file_get_exchange_data_zone);
}

KHTTPD_INIT(khttpd_file, khttpd_file_run, khttpd_file_exit,
    KHTTPD_INIT_PHASE_RUN, khttpd_ctrl);

static int
khttpd_file_location_data_new
   (struct khttpd_file_location_data **location_data_out,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_file_location_data *location_data;
	struct thread *td;
	const char *docroot_str;
	char *docroot_buf;
	void *charset_rewriter, *mime_type_rewriter;
	size_t docroot_len;
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
	    "fsPath", input_prop_spec, input, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		goto quit;

	prop_spec.link = input_prop_spec;
	prop_spec.name = "fsPath";

	if (docroot_str != NULL && docroot_str[0] != '/') {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		khttpd_problem_set_detail(output,
		    "relative path name is not acceptable.");
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}

	error = kern_openat(td, AT_FDCWD, (char *)docroot_str, UIO_SYSSPACE,
	    O_RDONLY | O_DIRECTORY, 0);
	if (error != 0) {
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		khttpd_problem_set_detail(output,
		    "failed to open the document root directory.");
		khttpd_problem_set_errno(output, error);
		status = KHTTPD_STATUS_BAD_REQUEST;
		goto quit;
	}
	docroot_fd = td->td_retval[0];

	/* 
	 * Allocate a copy of docroot path name.  Make sure the last character
	 * of the copied path name is '/'.
	 */
	docroot_len = strlen(docroot_str);
	if (docroot_str[docroot_len - 1] == '/') {
		docroot_buf = khttpd_malloc(docroot_len + 1);
		docroot_buf[docroot_len] = '\0';
	} else {
		docroot_buf = khttpd_malloc(docroot_len + 2);
		docroot_buf[docroot_len] = '/';
		docroot_buf[docroot_len + 1] = '\0';
	}
	bcopy(docroot_str, docroot_buf, docroot_len);

	location_data = 
	    khttpd_malloc(sizeof(struct khttpd_file_location_data));
	location_data->charset_rewriter =
	    khttpd_rewriter_acquire(charset_rewriter);
	location_data->mime_type_rewriter =
	    khttpd_rewriter_acquire(mime_type_rewriter);
	location_data->docroot = docroot_buf;
	location_data->docroot_fd = docroot_fd;

	*location_data_out = location_data;

	return (KHTTPD_STATUS_OK);

quit:
	if (docroot_fd != -1)
		kern_close(td, docroot_fd);

	return (status);
}

static void
khttpd_file_location_data_destroy(struct khttpd_file_location_data *data)
{
	KHTTPD_ENTRY("khttpd_file_location_data_destroy(%p)", data);

	khttpd_rewriter_release(data->charset_rewriter);
	khttpd_rewriter_release(data->mime_type_rewriter);
	khttpd_free(data->docroot);
	if (data->docroot_fd != -1)
		kern_close(curthread, data->docroot_fd);
	khttpd_free(data);
}

static void
khttpd_file_location_dtor(struct khttpd_location *location)
{

	KHTTPD_ENTRY("khttpd_file_location_dtor(%p)", location);
	khttpd_file_location_data_destroy(khttpd_location_data(location));
}

static bool
khttpd_file_filter(struct khttpd_location *location,
    struct khttpd_exchange *exchange, const char *suffix,
    struct sbuf *translated_path)
{
	struct khttpd_file_location_data *loc_data;
	const char *fs_path;

	KHTTPD_ENTRY("%s(%p,%p,%s)", __func__, location, exchange,
	    khttpd_ktr_printf("%s", suffix));

	loc_data = khttpd_location_data(location);
	if (translated_path != NULL) {
		fs_path = loc_data->docroot;
		sbuf_cpy(translated_path, fs_path);
		if (fs_path[strlen(fs_path) - 1] != '/') {
			sbuf_putc(translated_path, '/');
		}
		sbuf_cat(translated_path,
		    suffix[0] != '/' ? suffix : suffix + 1);
	}

	/* No translucent file location yet. */
	return (true);
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
	location_data = khttpd_location_data(location);
	mtx_unlock(&khttpd_file_lock);

	khttpd_mbuf_json_object_begin(output);

	sbuf_new(&sbuf, buf, sizeof(buf), SBUF_AUTOEXTEND);

	if (location_data->charset_rewriter != NULL) {
		khttpd_obj_type_get_id(&khttpd_ctrl_rewriters,
		    location_data->charset_rewriter, &sbuf);
		sbuf_finish(&sbuf);
		khttpd_mbuf_json_property(output, "charsetRules");
		khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&sbuf));
	}

	if (location_data->mime_type_rewriter != NULL) {
		sbuf_clear(&sbuf);
		khttpd_obj_type_get_id(&khttpd_ctrl_rewriters,
		    location_data->mime_type_rewriter, &sbuf);
		sbuf_finish(&sbuf);
		khttpd_mbuf_json_property(output, "mimeTypeRules");
		khttpd_mbuf_json_cstr(output, TRUE, sbuf_data(&sbuf));
	}

	khttpd_mbuf_json_property(output, "fsPath");
	khttpd_mbuf_json_cstr(output, TRUE, location_data->docroot);

	khttpd_mbuf_json_object_end(output);

	sbuf_delete(&sbuf);
}

static int 
khttpd_file_location_put(struct khttpd_location *location, 
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
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

	khttpd_file_location_data_destroy(location_data);

	return (KHTTPD_STATUS_OK);
}

static int
khttpd_file_location_create(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path, 
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input)
{
	struct khttpd_file_location_data *location_data;
	int status;

	KHTTPD_ENTRY("khttpd_file_location_create(%p)", server);

	status = khttpd_file_location_data_new(&location_data, output,
	    input_prop_spec, input);

	return (!KHTTPD_STATUS_IS_SUCCESSFUL(status) ? status :
	    khttpd_location_type_create_location(location_out, server, path,
		output, input_prop_spec, input,
		&khttpd_file_ops, location_data));
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

KHTTPD_INIT(khttpd_file, khttpd_file_register_location_type,
    khttpd_file_deregister_location_type,
    KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES);
