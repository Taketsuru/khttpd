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
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "khttpd_task.h"

#include <sys/param.h>
#include <sys/queue.h>
#include <sys/stack.h>
#include <sys/linker.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/rmlock.h>
#include <sys/systm.h>
#include <sys/smp.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/syslog.h>
#include <machine/stdarg.h>
#include <crypto/siphash/siphash.h>
#include <vm/vm.h>
#include <vm/uma.h>

#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

#define KHTTPD_TASK_DEBUG

struct khttpd_task_worker;

struct khttpd_task {
	STAILQ_ENTRY(khttpd_task) stqe;
	struct khttpd_task_queue *queue;
	khttpd_task_fn_t fn;
	void		*arg;
#ifdef KHTTPD_TASK_DEBUG
	struct stack	stack;
#endif

	union {
		struct {
			khttpd_task_fn_t	fn;
			void			*arg;
		} run;
		struct {
			struct khttpd_task_worker *destination;
			khttpd_task_fn_t	notify;
			void			*arg;
		} take_over;
	};

	bool		scheduled;
	char		name[16];
};

STAILQ_HEAD(khttpd_task_stq, khttpd_task);

struct khttpd_internal_task;
STAILQ_HEAD(khttpd_internal_task_stq, khttpd_internal_task);

struct khttpd_task_queue {
	struct rmlock	lock;
	struct khttpd_task_worker *worker;
	bool		take_over_in_progress;
	char		name[16];
};

struct khttpd_task_worker {
	struct khttpd_task_stq queue;
	struct mtx	lock;
	struct thread	*thread;
	struct khttpd_task_queue *current_queue;
	bool		busy;
};

extern int uma_align_cache;

static struct mtx khttpd_task_lock;
static struct khttpd_task_worker **khttpd_task_workers;
static long volatile khttpd_task_siphash_counter;
static uma_zone_t khttpd_task_zone;
static uma_zone_t khttpd_task_queue_zone;
static int khttpd_task_worker_count;
static bool volatile khttpd_task_ready;
static char khttpd_task_siphash_key[SIPHASH_KEY_LENGTH];

MTX_SYSINIT(task_mtx, &khttpd_task_lock, "task", MTX_DEF);

#ifdef KHTTPD_KTR_LOGGING

static const char *
khttpd_task_queue_ktr_print(struct khttpd_task_queue *queue)
{

	return (queue == NULL ? "NULL" :
	    khttpd_ktr_printf("%p(%s)", queue, queue->name));
}

static const char *
khttpd_task_worker_ktr_print(struct khttpd_task_worker *worker)
{

	return (worker == NULL ? "NULL" : 
	    khttpd_ktr_printf("%p(%s)", worker, worker->thread->td_name));
}

static const char *
khttpd_task_ktr_print(struct khttpd_task *task)
{

	return (task == NULL ? "NULL" :
	    khttpd_ktr_printf("%p(%s)", task, task->name));
}

#endif /* KHTTPD_KTR_LOGGING */

static void
khttpd_task_worker_main(void *arg)
{
	struct khttpd_task *task;
	struct khttpd_task_worker *worker;
	khttpd_task_fn_t fn;
	void *fn_arg;
	int id;

	KHTTPD_ENTRY("%s(%p)", __func__, arg);

	worker = khttpd_malloc(roundup2(sizeof(struct khttpd_task_worker), 
		    uma_align_cache + 1));
	STAILQ_INIT(&worker->queue);
	mtx_init(&worker->lock, "taskwrkr", NULL, MTX_DEF | MTX_NEW);
	worker->thread = curthread;
	worker->current_queue = NULL;
	worker->busy = true;

	mtx_lock(&khttpd_task_lock);
	id = (intptr_t)arg;
	khttpd_task_workers[id] = worker;
	wakeup(&khttpd_task_workers[id]);
	mtx_unlock(&khttpd_task_lock);

	for (;;) {
		mtx_lock(&worker->lock);

		while ((task = STAILQ_FIRST(&worker->queue)) == NULL) {
			KHTTPD_NOTE("%s idle", __func__);
			worker->busy = false;
			worker->current_queue = NULL;

			if (!khttpd_task_ready) {
				goto quit;
			}

			mtx_sleep(&worker->queue, &worker->lock, 0,
			    "taskidle", 0);
		}

		STAILQ_REMOVE_HEAD(&worker->queue, stqe);
		task->scheduled = false;

		fn = task->fn;
		fn_arg = task->arg;
		worker->current_queue = task->queue;

		mtx_unlock(&worker->lock);

		KHTTPD_NOTE("%s run %s", __func__,
		    khttpd_task_ktr_print(task));
		fn(fn_arg);
	}
quit:
	mtx_destroy(&worker->lock);
	khttpd_free(worker);

	mtx_lock(&khttpd_task_lock);
	khttpd_task_workers[id] = NULL;
	wakeup(&khttpd_task_workers[id]);
	mtx_unlock(&khttpd_task_lock);

	kthread_exit();
}

static void
khttpd_task_exit(void)
{
	int i, n;

	KHTTPD_ENTRY("%s()", __func__);

	mtx_lock(&khttpd_task_lock);

	khttpd_task_ready = false;
	n = khttpd_task_worker_count;

	for (i = 0; i < n; ++i) {
		wakeup(&khttpd_task_workers[i]->queue);
	}

	for (i = 0; i < n; ++i) {
		while (khttpd_task_workers[i] != NULL) {
			mtx_sleep(&khttpd_task_workers[i],
			    &khttpd_task_lock, 0, "taskexit", 0);
		}
	}

	mtx_unlock(&khttpd_task_lock);

	khttpd_free(khttpd_task_workers);
}

static int
khttpd_task_run(void)
{
	size_t size;
	int error, i, n;

	KHTTPD_ENTRY("%s()", __func__);

	arc4rand(khttpd_task_siphash_key, sizeof(khttpd_task_siphash_key),
	    false);
	khttpd_task_ready = true;

	n = mp_ncpus;
	KASSERT(n < 256, ("n %d", n)); /* "task%02x" assumes this. */
	size = n * sizeof(struct khttpd_task_worker *);
	khttpd_task_workers = khttpd_malloc(size);
	bzero(khttpd_task_workers, size);

	for (i = 0; i < n; ++i) {
		error = kthread_add(khttpd_task_worker_main,
		    (void *)(intptr_t)i, curproc, NULL, 0, 0, "task%02x", i);
		if (error != 0) {
			log(LOG_ERR, "khttpd: kthread_add() failed "
			    "(error: %d, file: %s, line: %u)",
			    error, __FILE__, __LINE__);
			break;
		}

		mtx_lock(&khttpd_task_lock);
		while (khttpd_task_workers[i] == NULL) {
			mtx_sleep(&khttpd_task_workers[i],
			    &khttpd_task_lock, 0, "taskrun", 0);
		}
		mtx_unlock(&khttpd_task_lock);
	}

	khttpd_task_worker_count = i;

	if (error != 0) {
		khttpd_task_exit();
	}

	return (error);
}

KHTTPD_INIT(khttpd_task, khttpd_task_run, khttpd_task_exit,
    KHTTPD_INIT_PHASE_RUN);

#ifdef KHTTPD_TRACE_MALLOC

static int
khttpd_task_ctor(void *mem, int size, void *arg, int flags)
{

	KHTTPD_TR_ALLOC(mem, size);
	return (0);
}

static void
khttpd_task_dtor(void *mem, int size, void *arg)
{

	KHTTPD_TR_FREE(mem);
}

#endif	/* KHTTPD_TRACE_MALLOC */

static int
khttpd_task_queue_ctor(void *mem, int size, void *arg, int flags)
{
	static SIPHASH_CTX siphash_ctx;
	u_long count, hash;
	struct khttpd_task_queue *queue;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);
	KASSERT(0 < khttpd_task_worker_count,
	    ("khttpd_task_worker_count %d", khttpd_task_worker_count));

	KHTTPD_TR_ALLOC(mem, size);

	queue = mem;
	count = atomic_fetchadd_long(&khttpd_task_siphash_counter, 1);
	hash = SipHash24(&siphash_ctx, khttpd_task_siphash_key, &count,
	    sizeof(count));
	queue->worker = khttpd_task_workers[hash % khttpd_task_worker_count];
	queue->take_over_in_progress = false;

	return (0);
}

#ifdef KHTTPD_TRACE_MALLOC

static void
khttpd_task_queue_dtor(void *mem, int size, void *arg)
{

	KHTTPD_TR_FREE(mem);
}

#endif	/* KHTTPD_TRACE_MALLOC */

static int
khttpd_task_queue_init(void *mem, int size, int flags)
{
	struct khttpd_task_queue *queue;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size, flags);

	queue = mem;
	rm_init(&queue->lock, "taskq");
	return (0);
}

static void
khttpd_task_queue_fini(void *mem, int size)
{
	struct khttpd_task_queue *queue;

	KHTTPD_ENTRY("%s(%p,%#x,%#x)", __func__, mem, size);

	queue = mem;
	rm_destroy(&queue->lock);
}

static void
khttpd_task_local_fini(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	uma_zdestroy(khttpd_task_queue_zone);
	uma_zdestroy(khttpd_task_zone);
}

static int
khttpd_task_local_init(void)
{

	KHTTPD_ENTRY("%s()", __func__);

	khttpd_task_zone = uma_zcreate("task",
	    sizeof(struct khttpd_task),
#ifdef KHTTPD_TRACE_MALLOC
	    khttpd_task_ctor, khttpd_task_dtor,
#else
	    NULL, NULL,
#endif
	    NULL, NULL, UMA_ALIGN_CACHE, 0);

	khttpd_task_queue_zone = uma_zcreate("taskq",
	    sizeof(struct khttpd_task_queue), khttpd_task_queue_ctor,
#ifdef KHTTPD_TRACE_MALLOC
	    khttpd_task_queue_dtor,
#else
	    NULL,
#endif
	    khttpd_task_queue_init, khttpd_task_queue_fini,
	    UMA_ALIGN_CACHE, 0);

	return (0);
}

KHTTPD_INIT(khttpd_task, khttpd_task_local_init, khttpd_task_local_fini,
    KHTTPD_INIT_PHASE_LOCAL);

struct khttpd_task *
khttpd_task_new(struct khttpd_task_queue *queue,
    khttpd_task_fn_t fn, void *arg, const char *name_fmt, ...)
{
	struct khttpd_task *task;
	va_list va;

	KHTTPD_ENTRY("%s(%s,%s,%p)", __func__, 
	    khttpd_task_queue_ktr_print(queue), khttpd_ktr_printsym(fn), arg);

	task = uma_zalloc(khttpd_task_zone, M_WAITOK);
	task->fn = fn;
	task->arg = arg;
	task->queue = queue;
	task->scheduled = false;

	if (name_fmt == NULL) {
		task->name[0] = '\0';
	} else {
		va_start(va, name_fmt);
		vsnprintf(task->name, sizeof(task->name), name_fmt, va);
		va_end(va);
	}

	return (task);
}

void
khttpd_task_delete(struct khttpd_task *task)
{

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_ktr_print(task));
	uma_zfree(khttpd_task_zone, task);
}

bool
khttpd_task_is_active(struct khttpd_task *task)
{

	return (task->scheduled);
}

void
khttpd_task_set_queue(struct khttpd_task *task,
    struct khttpd_task_queue *queue)
{

	KASSERT(!khttpd_task_is_active(task), ("active"));
	task->queue = queue;
}

bool
khttpd_task_schedule(struct khttpd_task *task)
{
	struct rm_priotracker trkr;
	struct khttpd_task_queue *queue;
	struct khttpd_task_worker *worker;
	bool scheduled;

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_ktr_print(task));
	KASSERT(khttpd_task_ready, ("not ready"));

	queue = task->queue;

	rm_rlock(&queue->lock, &trkr);
	worker = queue->worker;

	mtx_lock(&worker->lock);

	if (!(scheduled = task->scheduled)) {
#ifdef KHTTPD_TASK_DEBUG
		stack_save(&task->stack);
#endif
		task->scheduled = true;
		STAILQ_INSERT_TAIL(&worker->queue, task, stqe);

		if (!worker->busy) {
			worker->busy = true;
			wakeup(&worker->queue);
		}
	}

	mtx_unlock(&worker->lock);
	rm_runlock(&queue->lock, &trkr);

	return (scheduled);
}

bool
khttpd_task_cancel(struct khttpd_task *task)
{
	struct rm_priotracker trkr;
	struct khttpd_task_queue *queue;
	struct khttpd_task_worker *worker;
	bool result;

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_ktr_print(task));

	queue = task->queue;

	rm_rlock(&queue->lock, &trkr);
	worker = queue->worker;
	KASSERT(curthread == worker->thread,
	    ("worker %p, thread %p", worker, worker->thread));

	mtx_lock(&worker->lock);
	KHTTPD_NOTE("%s scheduled %d", __func__, task->scheduled);
	if ((result = task->scheduled)) {
		STAILQ_REMOVE(&worker->queue, task, khttpd_task, stqe);
		task->scheduled = false;
	}
	mtx_unlock(&worker->lock);

	rm_runlock(&queue->lock, &trkr);

	return (result);
}

static struct khttpd_task_worker *
khttpd_task_current_worker(void)
{
	struct khttpd_task_worker *worker;
	struct thread *td;
	const char *cp;
	int ch, s, id;

	td = curthread;
	cp = td->td_name + 4;
	id = 0;
	for (s = 4; s >= 0; s -= 4) {
		ch = *cp++;
		if ('0' <= ch && ch <= '9') {
			id |= (ch - '0') << s;
		} else if ('a' <= ch && ch <= 'f') {
			id |= (ch - 'a' + 10) << s;
		} else {
			return (NULL);
		}
	}

	if (khttpd_task_worker_count <= id) {
		return (NULL);
	}

	worker = khttpd_task_workers[id];

	return (worker->thread == td ? worker : NULL);
}

bool
khttpd_task_queue_on_worker_thread(struct khttpd_task_queue *queue)
{
	struct rm_priotracker trkr;
	struct khttpd_task_worker *worker;
	bool result;

	rm_rlock(&queue->lock, &trkr);
	worker = queue->worker;
	result = curthread == worker->thread;
	rm_runlock(&queue->lock, &trkr);

	return (result);
}

struct khttpd_task_queue *
khttpd_task_queue_current(void)
{
	struct khttpd_task_worker *worker;

	worker = khttpd_task_current_worker();
	return (worker == NULL ? NULL : worker->current_queue);
}

struct khttpd_task_queue *
khttpd_task_queue_new(const char *name_fmt, ...)
{
	struct khttpd_task_queue *queue;
	va_list va;

	KHTTPD_ENTRY("%s()", __func__);

	queue = uma_zalloc(khttpd_task_queue_zone, M_WAITOK);

	if (name_fmt == NULL) {
		queue->name[0] = '\0';
	} else {
		va_start(va, name_fmt);
		vsnprintf(queue->name, sizeof(queue->name), name_fmt, va);
		va_end(va);
	}

	return (queue);
}

void
khttpd_task_queue_delete(struct khttpd_task_queue *queue)
{

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_queue_ktr_print(queue));
	uma_zfree(khttpd_task_queue_zone, queue);
}

bool
khttpd_task_queue_is_active(struct khttpd_task_queue *queue)
{
	struct rm_priotracker trkr;
	struct khttpd_task *task;
	struct khttpd_task_worker *worker;
	bool result;

	rm_rlock(&queue->lock, &trkr);

	if (!(result = queue->take_over_in_progress)) {
		worker = queue->worker;

		mtx_lock(&worker->lock);
		STAILQ_FOREACH(task, &worker->queue, stqe) {
			if (task->queue == queue) {
				result = true;
				break;
			}
		}
		mtx_unlock(&worker->lock);
	}

	rm_runlock(&queue->lock, &trkr);

	return (result);
}

void
khttpd_task_queue_assign_random_worker(struct khttpd_task_queue *queue)
{
	static SIPHASH_CTX siphash_ctx;
	u_long count, hash;

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_queue_ktr_print(queue));

	KASSERT(0 < khttpd_task_worker_count,
	    ("khttpd_task_worker_count %d", khttpd_task_worker_count));
	KASSERT(!khttpd_task_queue_is_active(queue), ("queue is active"));

	count = atomic_fetchadd_long(&khttpd_task_siphash_counter, 1);
	hash = SipHash24(&siphash_ctx, khttpd_task_siphash_key, &count,
	    sizeof(count));
	queue->worker = khttpd_task_workers[hash % khttpd_task_worker_count];
}

static void
khttpd_task_queue_do_run(void *arg)
{
	struct khttpd_task *task;
	khttpd_task_fn_t fn;
	void	*fn_arg;

	task = arg;
	fn = task->run.fn;
	fn_arg = task->run.arg;

	KHTTPD_ENTRY("%s(%s), fn %s, arg %p", __func__,
	    khttpd_task_ktr_print(task), khttpd_ktr_printsym(fn), fn_arg);

	uma_zfree(khttpd_task_zone, task);

	fn(fn_arg);
}

void
khttpd_task_queue_run(struct khttpd_task_queue *queue, khttpd_task_fn_t fn,
    void *arg)
{
	struct khttpd_task *task;

	KHTTPD_ENTRY("%s(%s,%s,%p)", __func__, 
	    khttpd_task_queue_ktr_print(queue), khttpd_ktr_printsym(fn), arg);

	task = uma_zalloc(khttpd_task_zone, M_WAITOK);
	task->fn = khttpd_task_queue_do_run;
	task->arg = task;
	task->queue = queue;
	task->run.fn = fn;
	task->run.arg = arg;
	task->scheduled = false;

	khttpd_task_schedule(task);
}

static void
khttpd_task_remove(struct khttpd_task_worker *worker,
    struct khttpd_task_stq *tasks, struct khttpd_task_queue *queue)
{
	struct khttpd_task *task, *prev;

	KHTTPD_ENTRY("%s(%p,,%s)", __func__,
	    khttpd_task_worker_ktr_print(worker), 
	    khttpd_task_queue_ktr_print(queue));

	for (;;) {
		task = STAILQ_FIRST(&worker->queue);

		if (task == NULL) {
			return;
		}

		if (task->queue != queue) {
			break;
		}

		STAILQ_REMOVE_HEAD(&worker->queue, stqe);
		STAILQ_INSERT_TAIL(tasks, task, stqe);
	}

	prev = task;
	for (;;) {
		task = STAILQ_NEXT(prev, stqe);

		if (task == NULL) {
			return;
		}

		if (task->queue != queue) {
			prev = task;
			continue;
		}

		STAILQ_REMOVE_AFTER(&worker->queue, prev, stqe);
		STAILQ_INSERT_TAIL(tasks, task, stqe);
	}
}

void
khttpd_task_queue_hand_over(struct khttpd_task_queue *subject,
    struct khttpd_task_queue *destination)
{
	struct rm_priotracker trkr;
	struct khttpd_task_stq tasks;
	struct khttpd_task_queue *current_queue;
	struct khttpd_task_worker *current_worker, *destination_worker;

	KHTTPD_ENTRY("%s(%s,%s)", __func__,
	    khttpd_task_queue_ktr_print(subject),
	    khttpd_task_queue_ktr_print(destination));
	KASSERT(khttpd_task_ready, ("not ready"));

	current_worker = khttpd_task_current_worker();
	current_queue = subject;
	KASSERT(current_worker == subject->worker,
	    ("current worker %p, subject->worker %p",
	     current_worker, subject->worker));

	rm_rlock(&destination->lock, &trkr);
	destination_worker = destination->worker;
	rm_runlock(&destination->lock, &trkr);

	if (current_worker == destination_worker) {
		return;
	}

	STAILQ_INIT(&tasks);

	rm_wlock(&subject->lock);
	KASSERT(!subject->take_over_in_progress,
	    ("take_over_in_progress"));

	mtx_lock(&current_worker->lock);
	khttpd_task_remove(current_worker, &tasks, subject);
	mtx_unlock(&current_worker->lock);

	if (!STAILQ_EMPTY(&tasks)) {
		mtx_lock(&destination_worker->lock);
		STAILQ_CONCAT(&destination_worker->queue, &tasks);
		if (!destination_worker->busy) {
			destination_worker->busy = true;
			wakeup(&destination_worker->queue);
		}
		mtx_unlock(&destination_worker->lock);
	}

	subject->worker = destination_worker;
	rm_wunlock(&subject->lock);
}

static void
khttpd_task_do_take_over_finalize_task(void *arg)
{
	struct khttpd_task *task;
	struct khttpd_task_queue *queue;
	khttpd_task_fn_t notify;
	void *notify_arg;

	task = arg;
	queue = task->queue;
	notify = task->take_over.notify;
	notify_arg = task->take_over.arg;

	KHTTPD_ENTRY("%s(%s), notify %s, arg %p", __func__,
	    khttpd_task_ktr_print(task), khttpd_ktr_printsym(notify),
	    notify_arg);
	
	uma_zfree(khttpd_task_zone, task);

	rm_wlock(&queue->lock);
	queue->take_over_in_progress = false;
	rm_wunlock(&queue->lock);

	if (notify != NULL) {
		notify(notify_arg);
	}
}

static void
khttpd_task_do_take_over_task(void *arg)
{
	struct khttpd_task_stq tasks;
	struct khttpd_task *task;
	struct khttpd_task_worker *source, *destination;
	struct khttpd_task_queue *queue;

	KHTTPD_ENTRY("%s(%s)", __func__, khttpd_task_ktr_print(arg));

	STAILQ_INIT(&tasks);

	source = khttpd_task_current_worker();

	task = arg;
	queue = task->queue;
	destination = task->take_over.destination;

	rm_wlock(&queue->lock);

	mtx_lock(&source->lock);
	khttpd_task_remove(source, &tasks, queue);
	mtx_unlock(&source->lock);

	task->fn = khttpd_task_do_take_over_finalize_task;

	mtx_lock(&destination->lock);
	STAILQ_INSERT_HEAD(&destination->queue, task, stqe);
	STAILQ_CONCAT(&destination->queue, &tasks);
	if (!destination->busy) {
		destination->busy = true;
		wakeup(&destination->queue);
	}
	mtx_unlock(&destination->lock);

	queue->worker = destination;
	rm_wunlock(&queue->lock);
}

void
khttpd_task_queue_take_over(struct khttpd_task_queue *source,
    khttpd_task_fn_t notify, void *arg)
{
	struct khttpd_task_stq tasks;
	struct khttpd_task_worker *current_worker, *source_worker;
	struct khttpd_task *tmp_task;

	KHTTPD_ENTRY("%s(%s,%s,%p)", __func__,
	    khttpd_task_queue_ktr_print(source), khttpd_ktr_printsym(notify),
		arg);
	KASSERT(khttpd_task_ready, ("not ready"));

	current_worker = khttpd_task_current_worker();
	tmp_task = NULL;

 retry:
	rm_wlock(&source->lock);

	KASSERT(!source->take_over_in_progress, ("take over in progress"));

	source_worker = source->worker;
	if (source_worker != current_worker) {
		mtx_lock(&source_worker->lock);

		if (!source_worker->busy) {
			mtx_unlock(&source_worker->lock);
			source->worker = current_worker;

		} else if (source_worker->current_queue != source) {
			STAILQ_INIT(&tasks);
			khttpd_task_remove(source_worker, &tasks, source);
			mtx_unlock(&source_worker->lock);

			mtx_lock(&current_worker->lock);
			STAILQ_CONCAT(&current_worker->queue, &tasks);
			mtx_unlock(&current_worker->lock);

			source->worker = current_worker;

		} else if (tmp_task == NULL) {
			mtx_unlock(&source_worker->lock);
			rm_wunlock(&source->lock);

			tmp_task = uma_zalloc(khttpd_task_zone, M_WAITOK);
			tmp_task->fn = khttpd_task_do_take_over_task;
			tmp_task->arg = tmp_task;
			tmp_task->queue = source;
			tmp_task->take_over.destination = current_worker;
			tmp_task->take_over.notify = notify;
			tmp_task->take_over.arg = arg;

			goto retry;

		} else {
			STAILQ_INSERT_HEAD(&source_worker->queue, 
			    tmp_task, stqe);
			mtx_unlock(&source_worker->lock);

			source->take_over_in_progress = true;
			rm_wunlock(&source->lock);

			return;
		}
	}

	rm_wunlock(&source->lock);

	uma_zfree(khttpd_task_zone, tmp_task);

	if (notify != NULL) {
		notify(arg);
	}
}

#ifdef DDB

#include <ddb/ddb.h>
#include <ddb/db_sym.h>

DB_SHOW_COMMAND(task, khttpd_task_show)
{
	struct khttpd_task *task;
	struct khttpd_task_worker *dst_worker;

	if (!have_addr) {
		db_printf("usage: ddb> show task <addr>\n");
		return;
	}

	task = (struct khttpd_task *)addr;

	db_printf("Task at %#lx:\n", addr);

	if (task->name[0] != '\0') {
		db_printf(" name: %.*s\n",
		    (int)sizeof(task->name), task->name);
	}

	if (task->queue == NULL || task->queue->name[0] == '\0') {
		db_printf(" queue: %p\n", task->queue);
	} else {
		db_printf(" queue: %p (name %.*s)\n", task->fn,
		    (int)sizeof(task->queue->name), task->queue->name);
	}

	db_printf(" function: ");
	db_printsym((db_expr_t)task->fn, DB_STGY_PROC);
	db_printf("\n arg: %p\n", task->arg);
	db_printf(" flags: %s\n",
	    task->scheduled ? "scheduled" : "!scheduled");

	if (task->fn == khttpd_task_queue_do_run) {
		db_printf(" run.fn: ");
		db_printsym((db_expr_t)task->run.fn, DB_STGY_PROC);
		db_printf("\n run.arg: %p\n", task->run.arg);

	} else if (task->fn == khttpd_task_do_take_over_task) {
		dst_worker = task->take_over.destination;
		db_printf(" take_over.destination: %p (tid %d)\n",
		    dst_worker, dst_worker->thread->td_tid);
		db_printf(" take_over.notify: ");
		db_printsym((db_expr_t)task->take_over.notify, DB_STGY_PROC);
		db_printf("\n take_over.arg: %p\n", task->take_over.arg);
	}
}

DB_SHOW_COMMAND(task_queue, khttpd_task_queue_show)
{
	struct khttpd_task_queue *queue;

	if (!have_addr) {
		db_printf("usage: ddb> show task_queue <addr>\n");
		return;
	}

	queue = (struct khttpd_task_queue *)addr;

	db_printf("Task queue at %#lx:\n", addr);

	if (queue->name[0] != '\0') {
		db_printf(" name: %.*s\n",
		    (int)sizeof(queue->name), queue->name);
	}

	db_printf(" worker: %p (thread %p, tid %d)", queue->worker,
	    queue->worker->thread, queue->worker->thread->td_tid);
	db_printf(" flags: %s\n",
	    queue->take_over_in_progress ? "take_over_in_progress" :
	    "!take_over_in_progress");
}

DB_SHOW_COMMAND(task_worker, khttpd_task_worker_show)
{
	struct khttpd_task *task;
	struct khttpd_task_worker *worker, *dst_worker;
	int i;

	if (!have_addr) {
		db_printf("usage: ddb> show task_worker <addr>\n");
		return;
	}

	worker = (struct khttpd_task_worker *)addr;

	db_printf("Task worker at %#lx:\n", addr);

	db_printf(" thread %p (tid %d)", worker->thread,
	    worker->thread->td_tid);

	if (worker->current_queue == NULL ||
	    worker->current_queue->name[0] == '\0') {
		db_printf(" current_queue: %p\n", worker->current_queue);
	} else {
		db_printf(" current_queue: %p (name %.*s)\n",
		    worker->current_queue,
		    (int)sizeof(worker->current_queue->name),
		    worker->current_queue->name);
	}

	db_printf(" flags: %s\n", worker->busy ? "busy" : "!busy");

	db_printf(" queue: \n");
	i = 0;
	STAILQ_FOREACH(task, &worker->queue, stqe) {
		if (task->name[0] == '\0') {
			db_printf(" #%d %p\n", ++i, task);
		} else {
			db_printf(" #%d %p (name %.*s)\n",
			    ++i, task, (int)sizeof(task->name), task->name);
		}

		if (task->queue == NULL || task->queue->name[0] == '\0') {
			db_printf("  queue: %p\n", task->queue);
		} else {
			db_printf("  queue: %p (name %.*s)\n", task->queue,
			    (int)sizeof(task->queue->name), task->queue->name);
		}

		db_printf("  function: ");
		db_printsym((db_expr_t)task->fn, DB_STGY_PROC);
		db_printf("\n  arg: %p\n", task->arg);

		if (task->fn == khttpd_task_queue_do_run) {
			db_printf("  run.fn: ");
			db_printsym((db_expr_t)task->run.fn, DB_STGY_PROC);
			db_printf("\n  run.arg: %p\n", task->run.arg);

		} else if (task->fn == khttpd_task_do_take_over_task) {
			dst_worker = task->take_over.destination;
			db_printf("  take_over.destination: %p (tid %d)\n",
			    dst_worker, dst_worker->thread->td_tid);
			db_printf("  take_over.notify: ");
			db_printsym((db_expr_t)task->take_over.notify,
			    DB_STGY_PROC);
			db_printf("\n  take_over.arg: %p\n",
			    task->take_over.arg);
		}

#ifdef KHTTPD_TASK_DEBUG
		db_printf("  stack:\n");
		for (i = 0; i < task->stack.depth; i++) {
			linker_symval_t symval;
			c_linker_sym_t sym;
			vm_offset_t pc;
			long offset;

			pc = task->stack.pcs[i];
			if (linker_ddb_search_symbol((caddr_t)pc, &sym,
				&offset) == 0 &&
			    linker_ddb_symbol_values(sym, &symval) == 0 &&
			    symval.name != NULL) {
				db_printf("  #%d %#lx at %s+%#lx\n", i, pc,
				    symval.name, offset);
			} else {
				db_printf("  #%d %#lx\n", i, pc);
			}
		}
#endif
	}
}

DB_SHOW_ALL_COMMAND(task_worker, khttpd_task_worker_show_all)
{
	struct khttpd_task_worker *worker;
	int i;

	if (khttpd_task_workers == NULL) {
		return;
	}

	for (i = 0; i < khttpd_task_worker_count; ++i) {
		worker = khttpd_task_workers[i];
		if (worker == NULL) {
			continue;
		}

		db_printf("#%d %p (thread %p, id %d):\n", i, worker,
		    worker->thread, worker->thread->td_tid);
	}
}

#endif	/* DDB */
