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

#include "khttpd_gcov.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/syscallsubr.h>
#include <machine/stdarg.h>
#include <vm/vm.h>
#include <vm/uma.h>

#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

#define KHTTPD_GCOV_BUFSIZ	PAGE_SIZE

struct khttpd_gcov_fn_node {
	STAILQ_ENTRY(khttpd_gcov_fn_node) stailqe;
	khttpd_gcov_fn	fn;
};

STAILQ_HEAD(khttpd_gcov_fn_stailq, khttpd_gcov_fn_node);

__GLOBL(__start_gcov_ctors);
__GLOBL(__stop_gcov_ctors);

typedef void (*ctor_fn)(void);
extern ctor_fn __weak_symbol __start_gcov_ctors;
extern ctor_fn __weak_symbol __stop_gcov_ctors;

static struct khttpd_gcov_fn_stailq khttpd_gcov_writeout_list;
static struct khttpd_gcov_fn_stailq khttpd_gcov_flush_list;
static off_t khttpd_gcov_buffer_off;
static off_t khttpd_gcov_file_size;
static char *khttpd_gcov_filename;
static char *khttpd_gcov_buffer;
static size_t khttpd_gcov_buffer_size = PAGE_SIZE;
static int khttpd_gcov_fd;
static int khttpd_gcov_cur_pos;
static bool khttpd_gcov_new_file;
static bool khttpd_gcov_buffer_valid;

static void
khttpd_gcov_fail(const char *fmt, ...)
{
	va_list va;

	KHTTPD_ENTRY("%s(%s)", __func__, fmt);

	va_start(va, fmt);
	vlog(LOG_ERR, fmt, va);
	va_end(va);

	panic("break");

	kern_close(curthread, khttpd_gcov_fd);
	khttpd_gcov_fd = -1;
	khttpd_gcov_buffer_valid = false;
}

static void
khttpd_gcov_flush_buffer(void)
{
	struct uio auio;
	struct iovec aiov;
	int error, nwrite;

	KHTTPD_ENTRY("%s()", __func__);

	KASSERT(0 <= khttpd_gcov_cur_pos &&
	    khttpd_gcov_cur_pos <= khttpd_gcov_buffer_size,
	    ("khttpd_gcov_cur_pos %d", khttpd_gcov_cur_pos));

	if (!khttpd_gcov_buffer_valid || (nwrite = khttpd_gcov_cur_pos) <= 0 ||
	    khttpd_gcov_fd == -1) {
		return;
	}

	aiov.iov_base = khttpd_gcov_buffer;
	aiov.iov_len = nwrite;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_resid = nwrite;
	auio.uio_segflg = UIO_SYSSPACE;

	error = kern_pwritev(curthread, khttpd_gcov_fd, &auio, 
	    khttpd_gcov_buffer_off);
	if (error != 0) {
		khttpd_gcov_fail("khttpd: failed to write to %s. "
		    "(error: %d)\n", khttpd_gcov_filename, error);
	}
}

static void
khttpd_gcov_fill_buffer(void)
{
	struct uio auio;
	struct iovec aiov;
	struct thread *td;
	int error, nread;

	KHTTPD_ENTRY("%s()", __func__);

	td = curthread;

	if (khttpd_gcov_buffer_valid) {
		if (khttpd_gcov_cur_pos < khttpd_gcov_buffer_size) {
			return;
		}

		khttpd_gcov_flush_buffer();

		khttpd_gcov_cur_pos = 0;
		khttpd_gcov_buffer_off += khttpd_gcov_buffer_size;
	}

	nread = khttpd_gcov_new_file ||
	    khttpd_gcov_file_size <= khttpd_gcov_buffer_off ? 0 :
	    MIN(khttpd_gcov_buffer_size,
		khttpd_gcov_file_size - khttpd_gcov_buffer_off);

	if (0 < nread && khttpd_gcov_fd != -1) {
		aiov.iov_base = khttpd_gcov_buffer;
		aiov.iov_len = nread;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_resid = nread;
		auio.uio_segflg = UIO_SYSSPACE;

		error = kern_preadv(td, khttpd_gcov_fd, &auio,
		    khttpd_gcov_buffer_off);
		if (error == 0) {
			nread -= auio.uio_resid;
		} else {
			khttpd_gcov_fail("khttpd: failed to read %s."
			    "(error: %d)\n", khttpd_gcov_filename, error);
			nread = 0;
		}
	}

	bzero(khttpd_gcov_buffer + nread, khttpd_gcov_buffer_size - nread);
	khttpd_gcov_buffer_valid = true;
}

static void
khttpd_gcov_write_bytes(const void *data, size_t len)
{
	const char *datap;
	size_t resid;
	int n;

	KHTTPD_ENTRY("%s(%p,%#zx)", __func__, data, len);

	datap = data;
	resid = len;
	while (0 < resid) {
		khttpd_gcov_fill_buffer();
		n = MIN(resid, khttpd_gcov_buffer_size - khttpd_gcov_cur_pos);
		bcopy(datap, khttpd_gcov_buffer + khttpd_gcov_cur_pos, n);
		khttpd_gcov_cur_pos += n;
		datap += n;
		resid -= n;
	}
}

static void
khttpd_gcov_write32(uint32_t value)
{

	khttpd_gcov_write_bytes(&value, sizeof(value));
}

static void
khttpd_gcov_write64(uint64_t value)
{

	khttpd_gcov_write_bytes(&value, sizeof(value));
}

static uint32_t
khttpd_gcov_str_numwords(const char *str)
{

	return (strlen(str) / 4 + 1);
}

static void
khttpd_gcov_write_string(const char *str)
{
	uint32_t n;

	KHTTPD_ENTRY("%s(%p)", __func__, str);

	n = khttpd_gcov_str_numwords(str);
	khttpd_gcov_write32(n);
	khttpd_gcov_write_bytes(str, strlen(str));
	khttpd_gcov_write_bytes("\0\0\0\0", 4 - (strlen(str) % 4));
}

static void
khttpd_gcov_read_bytes(void *data, size_t len)
{
	char *datap;
	size_t resid;
	int n;

	KHTTPD_ENTRY("%s(%p,%#zx)", __func__, data, len);

	if (khttpd_gcov_new_file || khttpd_gcov_file_size <
	    khttpd_gcov_buffer_off + khttpd_gcov_cur_pos + len) {
		memset(data, 0xff, len);
		return;
	}

	datap = data;
	resid = len;
	while (0 < resid) {
		khttpd_gcov_fill_buffer();
		n = MIN(resid, khttpd_gcov_buffer_size - khttpd_gcov_cur_pos);
		bcopy(khttpd_gcov_buffer + khttpd_gcov_cur_pos, datap, n);
		khttpd_gcov_cur_pos += n;
		datap += n;
		resid -= n;
	}
}

static uint32_t
khttpd_gcov_read32(void)
{
	uint32_t value;

	khttpd_gcov_read_bytes(&value, sizeof(value));
	return (value);
}

static uint64_t
khttpd_gcov_read64(void)
{
	uint64_t value;

	khttpd_gcov_read_bytes(&value, sizeof(value));
	return (value);
}

void
llvm_gcda_start_file(const char *orig_filename, const char version[4],
    uint32_t checksum)
{
	struct stat statbuf;
	struct thread *td;
	int fd;
	int error;
	bool new_file;

	KHTTPD_ENTRY("%s(%s,%.4s,%#x)",
	    __func__, orig_filename, version, checksum);
	KASSERT(khttpd_gcov_fd == -1, ("khttpd_gcov_fd %d", khttpd_gcov_fd));
	KASSERT(khttpd_gcov_buffer == NULL,
	    ("khttpd_gcov_buffer %p", khttpd_gcov_buffer));

	td = curthread;
	new_file = false;
	fd = -1;
	khttpd_gcov_filename = khttpd_strdup(orig_filename);

	error = kern_openat(td, AT_FDCWD, khttpd_gcov_filename, UIO_SYSSPACE,
	    O_RDWR, 0);
	if (error == ENOENT) {
		error = kern_openat(td, AT_FDCWD, khttpd_gcov_filename,
		    UIO_SYSSPACE, O_RDWR | O_CREAT, 0666);
		if (error != 0) {
			KHTTPD_NOTE("%s kern_openat %d", __func__, error);
			goto error;
		}
		new_file = true;
	}
	fd = td->td_retval[0];

	error = kern_fstat(td, fd, &statbuf);
	if (error != 0) {
		KHTTPD_NOTE("%s kern_fstat %d", __func__, error);
		goto error;
	}

	if (!S_ISREG(statbuf.st_mode)) {
		KHTTPD_NOTE("%s !S_ISREG", __func__);
		goto error;
	}

	khttpd_gcov_buffer = khttpd_malloc(khttpd_gcov_buffer_size);
	khttpd_gcov_buffer_off = 0;
	khttpd_gcov_file_size = statbuf.st_size;
	khttpd_gcov_fd = fd;
	khttpd_gcov_cur_pos = 0;
	khttpd_gcov_new_file = new_file;
	khttpd_gcov_buffer_valid = false;

	khttpd_gcov_write_bytes("adcg", 4);
	khttpd_gcov_write_bytes(version, 4);
	khttpd_gcov_write32(checksum);

	return;

 error:
	log(LOG_ERR, "khttpd: failed to open %s. (error: %d)\n",
	    khttpd_gcov_filename, error);

	if (fd != -1) {
		kern_close(td, fd);
	}

	khttpd_free(khttpd_gcov_filename);
}

void
llvm_gcda_increment_indirect_counter(uint32_t *predecessor, 
    uint64_t **counters)
{
	uint64_t *counter;
	uint32_t pred;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, predecessor, counters);

	pred = *predecessor;
	if (pred == 0xffffffff) {
		return;
	}

	counter = counters[pred];
	if (counter != NULL) {
		++*counter;
	}
}

void
llvm_gcda_emit_function(uint32_t ident, const char *function_name,
    uint32_t func_checksum, uint8_t use_extra_checksum, uint32_t cfg_checksum)
{
	uint32_t len;

	KHTTPD_ENTRY("%s(%#x,%s,%#x,%#x,%#x)",
	    __func__, ident, function_name, func_checksum, use_extra_checksum,
		cfg_checksum);

	len = use_extra_checksum ? 3 : 2;

	khttpd_gcov_write_bytes("\0\0\0\1", 4);
	if (function_name != NULL) {
		len += 1 + khttpd_gcov_str_numwords(function_name);
	}
	khttpd_gcov_write32(len);
	khttpd_gcov_write32(ident);
	khttpd_gcov_write32(func_checksum);
	if (use_extra_checksum) {
		khttpd_gcov_write32(cfg_checksum);
	}
	if (function_name != NULL) {
		khttpd_gcov_write_string(function_name);
	}
}

void
llvm_gcda_emit_arcs(uint32_t num_counters, uint64_t *counters)
{
	uint64_t *old_ctrs = NULL;
	off_t save_buffer_off;
	int save_cur_pos;
	uint32_t i, tag, len;

	KHTTPD_ENTRY("%s(%#x,%p)", __func__, num_counters, counters);

	save_buffer_off = khttpd_gcov_buffer_off;
	save_cur_pos = khttpd_gcov_cur_pos;

	tag = khttpd_gcov_read32();
	if (tag != ~(uint32_t)0) {
		len = khttpd_gcov_read32();
		if (tag != 0x01a10000 ||
		    len == ~(uint32_t)0 || len / 2 != num_counters) {
			KHTTPD_NOTE("tag %#x, len %#x", tag, len);
			khttpd_gcov_fail("khttpd: corrupt file %s\n",
			    khttpd_gcov_filename);
			return;
		}

		old_ctrs = khttpd_malloc(sizeof(uint64_t) * num_counters);
		for (i = 0; i < num_counters; ++i) {
			old_ctrs[i] = khttpd_gcov_read64();
		}
	}

	khttpd_gcov_buffer_valid = save_buffer_off == khttpd_gcov_buffer_off;
	khttpd_gcov_buffer_off = save_buffer_off;
	khttpd_gcov_cur_pos = save_cur_pos;

	khttpd_gcov_write32(0x01a10000);
	khttpd_gcov_write32(num_counters * 2);
	for (i = 0; i < num_counters; ++i) {
		counters[i] += old_ctrs ? old_ctrs[i] : 0;
		khttpd_gcov_write64(counters[i]);
	}

	khttpd_free(old_ctrs);
}

void
llvm_gcda_summary_info(void)
{
	off_t save_buffer_off;
	int save_cur_pos;
	uint32_t obj_summary_len;
	uint32_t i;
	uint32_t runs;
	uint32_t tag, len;

	KHTTPD_ENTRY("%s()", __func__);

	obj_summary_len = 9;
	runs = 1;
	
	save_cur_pos = khttpd_gcov_cur_pos;
	save_buffer_off = khttpd_gcov_buffer_off;

	tag = khttpd_gcov_read32();
	if (tag != ~(uint32_t)0) {
		len = khttpd_gcov_read32();
		if (tag != 0xa1000000 || len != obj_summary_len) {
			KHTTPD_NOTE("tag %#x, len %#x", tag, len);
			khttpd_gcov_fail("khttpd: corrupt file %s\n",
			    khttpd_gcov_filename);
			return;
		}

		khttpd_gcov_read32();
		khttpd_gcov_read32();
		runs += khttpd_gcov_read32();
	}

	khttpd_gcov_buffer_valid = save_buffer_off == khttpd_gcov_buffer_off;
	khttpd_gcov_cur_pos = save_cur_pos;
	khttpd_gcov_buffer_off = save_buffer_off;

	khttpd_gcov_write32(0xa1000000);
	khttpd_gcov_write32(obj_summary_len);
	khttpd_gcov_write32(0);
	khttpd_gcov_write32(0);
	khttpd_gcov_write32(runs);
	for (i = 3; i < obj_summary_len; ++i) {
		khttpd_gcov_write32(0);
	}

	khttpd_gcov_write32(0xa3000000);
	khttpd_gcov_write32(0);
}

void
llvm_gcda_end_file(void)
{
	KHTTPD_ENTRY("%s()", __func__);

	khttpd_gcov_write64(0);
	khttpd_gcov_flush_buffer();

	if (khttpd_gcov_fd != -1) {
		kern_close(curthread, khttpd_gcov_fd);
		khttpd_gcov_fd = -1;
	}
	khttpd_free(khttpd_gcov_filename);
	khttpd_free(khttpd_gcov_buffer);
	khttpd_gcov_filename = NULL;
	khttpd_gcov_buffer = NULL;
	khttpd_gcov_buffer_valid = false;
}

void
__gcov_flush(void)
{
	struct khttpd_gcov_fn_node *ptr;

	KHTTPD_ENTRY("%s()", __func__);
	STAILQ_FOREACH(ptr, &khttpd_gcov_flush_list, stailqe) {
		ptr->fn();
	}
}

void
llvm_gcov_init(khttpd_gcov_fn wfn, khttpd_gcov_fn ffn)
{
	struct khttpd_gcov_fn_node *new_node;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, wfn, ffn);

	if (wfn != NULL) {
		new_node = khttpd_malloc(sizeof(struct khttpd_gcov_fn_node));
		new_node->fn = wfn;
		STAILQ_INSERT_TAIL(&khttpd_gcov_writeout_list, new_node,
		    stailqe);
	}

	if (ffn != NULL) {
		new_node = khttpd_malloc(sizeof(struct khttpd_gcov_fn_node));
		new_node->fn = ffn;
		STAILQ_INSERT_TAIL(&khttpd_gcov_flush_list, new_node, stailqe);
	}
}

void
khttpd_gcov_init(void)
{
	ctor_fn *fn_ptr;

	KHTTPD_ENTRY("%s()", __func__);

	STAILQ_INIT(&khttpd_gcov_writeout_list);
	STAILQ_INIT(&khttpd_gcov_flush_list);
	khttpd_gcov_fd = -1;

	for (fn_ptr = &__start_gcov_ctors; fn_ptr < &__stop_gcov_ctors;
	     ++fn_ptr) {
		(**fn_ptr)();
	}
}

void
khttpd_gcov_fini(void)
{
	struct khttpd_gcov_fn_node *ptr, *tmpptr;

	KHTTPD_ENTRY("%s()", __func__);

	STAILQ_FOREACH(ptr, &khttpd_gcov_writeout_list, stailqe) {
		ptr->fn();
	}

	STAILQ_FOREACH_SAFE(ptr, &khttpd_gcov_writeout_list, stailqe, tmpptr) {
		khttpd_free(ptr);
	}
	STAILQ_INIT(&khttpd_gcov_writeout_list);

	STAILQ_FOREACH_SAFE(ptr, &khttpd_gcov_flush_list, stailqe, tmpptr) {
		khttpd_free(ptr);
	}
	STAILQ_INIT(&khttpd_gcov_flush_list);
}
