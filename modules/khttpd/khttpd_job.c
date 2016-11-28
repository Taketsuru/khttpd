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

#include "khttpd_job.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/linker_set.h>
#include <sys/queue.h>
#include <sys/smp.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/eventhandler.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/event.h>
#include <sys/module.h>
#include <sys/conf.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/syscallsubr.h>
#include <sys/sysproto.h>
#include <sys/random.h>
#include <crypto/siphash/siphash.h>

extern int uma_align_cache;

#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

struct khttpd_job {
	STAILQ_ENTRY(khttpd_job) link;
	struct khttpd_job_queue *queue;
	khttpd_job_fn_t	handler;
	void		*arg;
};

STAILQ_HEAD(khttpd_job_stq, khttpd_job);

struct khttpd_job_worker {
	TAILQ_ENTRY(khttpd_job_worker) link;
	struct khttpd_job *job;
};

TAILQ_HEAD(khttpd_job_worker_tq, khttpd_job_worker);

struct khttpd_job_queue {
	struct mtx	lock;
	struct khttpd_job_worker_tq idle_workers;
	struct khttpd_job_stq jobs;
	int		id;
	int		worker_count;
	int		worker_count_max;
};

static void khttpd_job_worker_main(void *arg);

/* 
 * Below is a key of locks used to protect each variables.  The lock is
 * indicated by a reference to a specific character in parens in the
 * associated comment.
 *
 *	a - atomic
 *	l - khttpd_job_lock
 */

static struct mtx khttpd_job_lock;
static char khttpd_job_siphash_key[SIPHASH_KEY_LENGTH];
static struct khttpd_job_queue **khttpd_job_queues;
static uma_zone_t khttpd_job_zone;
static uma_zone_t khttpd_job_queue_zone;
static int khttpd_job_queue_count;
static int khttpd_job_active_queue_count;
static boolean_t khttpd_job_exiting;

MTX_SYSINIT(khttpd_job_lock, &khttpd_job_lock, "khttpd-job", MTX_DEF);

static void
khttpd_job_decrement_worker_count(struct khttpd_job_queue *queue)
{
	boolean_t active;

	mtx_lock(&queue->lock);
	active = 0 < --queue->worker_count;
	mtx_unlock(&queue->lock);

	if (active)
		return;

	mtx_lock(&khttpd_job_lock);
	if (khttpd_job_exiting && --khttpd_job_active_queue_count == 0)
		wakeup(&khttpd_job_active_queue_count);
	mtx_unlock(&khttpd_job_lock);
}

static int
khttpd_job_spawn_and_unlock(struct khttpd_job_queue *queue)
{
	int error, worker_id;

	mtx_assert(&queue->lock, MA_OWNED);

	worker_id = queue->worker_count++;
	mtx_unlock(&queue->lock);

	KHTTPD_TR("%s spawn %d", __func__, worker_id);

	error = kthread_add(khttpd_job_worker_main, queue, curproc, NULL, 0,
	    0, "worker%d-%d", queue->id, worker_id);
	if (error != 0)
		log(LOG_WARNING, "khttpd: kthread_add failed "
		    "(error: %d, file: %s, line: %u)",
		    error, __FILE__, __LINE__);

	if (error != 0)
		khttpd_job_decrement_worker_count(queue);

	return (error);
}

static void
khttpd_job_kick_and_unlock(struct khttpd_job_queue *queue)
{
	struct khttpd_job_worker *worker;

	KHTTPD_TR("%s(%d)", __func__, queue->id);

	mtx_assert(&queue->lock, MA_OWNED);
	KASSERT(0 < queue->worker_count_max,
	    ("queue(%d)->worker_count_max <= 0", queue->id,
		queue->worker_count_max));

	if ((worker = TAILQ_FIRST(&queue->idle_workers)) != NULL)
		wakeup(worker);

	else if (queue->worker_count < queue->worker_count_max) {
		khttpd_job_spawn_and_unlock(queue);
		return;
	}

	mtx_unlock(&queue->lock);
}

static void
khttpd_job_worker_main(void *arg)
{
	struct khttpd_job_worker self;
	struct khttpd_job *job;
	struct khttpd_job_queue *queue;
	int error;

	queue = arg;

	mtx_lock(&queue->lock);

	for (;;) {
		job = STAILQ_FIRST(&queue->jobs);
		if (job == NULL) {
			if (khttpd_job_exiting)
				break;

			TAILQ_INSERT_HEAD(&queue->idle_workers, &self, link);
			error = mtx_sleep(&self, &queue->lock, 0, "worker",
			    hz);
			TAILQ_REMOVE(&queue->idle_workers, &self, link);
			if (error != 0 && 1 < queue->worker_count)
				break;

			continue;
		}

		KHTTPD_TR("%s %d job job=%p", __func__, queue->id, job);

		STAILQ_REMOVE_HEAD(&queue->jobs, link);
		if (!STAILQ_EMPTY(&queue->jobs))
			khttpd_job_kick_and_unlock(queue);
		else
			mtx_unlock(&queue->lock);

		job->handler(job->arg);
		mtx_lock(&queue->lock);
	}

	mtx_unlock(&queue->lock);

	KHTTPD_TR("%s %d exiting", __func__, queue->id);
	khttpd_job_decrement_worker_count(queue);

	kthread_exit();
}

struct khttpd_job *
khttpd_job_new(khttpd_job_fn_t handler, void *arg, struct khttpd_job *sibling)
{
	static volatile uint64_t counter;

	static SIPHASH_CTX khttpd_siphash_ctx;
	struct khttpd_job *job;
	struct khttpd_job_queue *queue;
	uint64_t hash, count;

	KASSERT(KHTTPD_INIT_PHASE_REGISTER_EVENTS <= khttpd_init_get_phase(),
	    ("phase=%d", khttpd_init_get_phase()));

	if (sibling != NULL) {
		queue = sibling->queue;

	} else {
		count = atomic_fetchadd_long(&counter, 1);
		hash = SipHash24(&khttpd_siphash_ctx, khttpd_job_siphash_key,
		    &count, sizeof(count));
		queue = khttpd_job_queues[hash % khttpd_job_queue_count];
	}

	job = uma_zalloc(khttpd_job_zone, M_WAITOK);
	job->handler = handler;
	job->arg = arg;
	job->queue = queue;

	return (job);
}

/*
 * This function doesn't sleep in it.  This guarantee is necessary because
 * callout functions of khttpd_port calls this function.
 *
 * BUG
 *
 * Even though this function is expected to be non-sleeping, it does sleep
 * when it try to spawn a worker thread.  FIX IT!
 */
void
khttpd_job_schedule(struct khttpd_job *job)
{
	struct khttpd_job_queue *queue;

	queue = job->queue;
	mtx_lock(&queue->lock);

	STAILQ_INSERT_TAIL(&queue->jobs, job, link);
	khttpd_job_kick_and_unlock(queue);
}

void
khttpd_job_delete(struct khttpd_job *job)
{
	if (job == NULL)
		return;

#ifdef INVARIANTS
	struct khttpd_job *j;
	struct khttpd_job_queue *queue;

	queue = job->queue;
	mtx_lock(&queue->lock);
	STAILQ_FOREACH(j, &queue->jobs, link)
		KASSERT(j != job, ("job %p is busy", job));
	mtx_unlock(&queue->lock);
#endif	/* ifdef INVARIANTS */

	uma_zfree(khttpd_job_zone, job);
}

static void
khttpd_job_terminate(void)
{
	struct khttpd_job_queue *queue;
	struct khttpd_job_worker *worker;
	int i, n;

	KHTTPD_TR("%s", __func__);

	mtx_lock(&khttpd_job_lock);
	khttpd_job_exiting = TRUE;
	mtx_unlock(&khttpd_job_lock);

	n = khttpd_job_queue_count;
	for (i = 0; i < n; ++i) {
		queue = khttpd_job_queues[i];
		if (queue == NULL)
			continue;

		mtx_lock(&queue->lock);
		TAILQ_FOREACH(worker, &queue->idle_workers, link)
			wakeup(worker);
		mtx_unlock(&queue->lock);
	}

	mtx_lock(&khttpd_job_lock);
	while (0 < khttpd_job_active_queue_count)
		mtx_sleep(&khttpd_job_active_queue_count, &khttpd_job_lock, 0,
		    "trmjob", 0);
	mtx_unlock(&khttpd_job_lock);

	KHTTPD_TR("%s terminate finished", __func__);
}

static int
khttpd_job_load(void)
{
	struct khttpd_job_queue *queue, **queues;
	struct thread *td;
	struct proc *p;
	int error, i, n;

	td = curthread;

	arc4rand(khttpd_job_siphash_key, sizeof(khttpd_job_siphash_key),
	    FALSE);
	khttpd_job_queue_count = n = mp_ncpus;
	khttpd_job_queues = queues =
	    khttpd_malloc(n * sizeof(struct khttpd_job_queue *));

	khttpd_job_queue_zone = uma_zcreate("khttpd-jobq"
	    , sizeof(struct khttpd_job_queue), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_CACHE, 0);

	for (i = 0; i < n; ++i) {
		queues[i] = queue = 
		    uma_zalloc(khttpd_job_queue_zone, M_WAITOK | M_ZERO);

		TAILQ_INIT(&queue->idle_workers);
		STAILQ_INIT(&queue->jobs);
		mtx_init(&queue->lock, "queue", NULL, MTX_DEF);
		queue->id = i;
		queue->worker_count = 0;
		queue->worker_count_max = 16;
	}

	khttpd_job_zone = uma_zcreate("khttpd-job", sizeof(struct khttpd_job),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_CACHE, 0);

	p = td->td_proc;
	error = 0;
	for (i = 0; i < n && error == 0; ++i) {
		mtx_lock(&khttpd_job_lock);
		++khttpd_job_active_queue_count;
		mtx_unlock(&khttpd_job_lock);

		queue = queues[i];
		mtx_lock(&queue->lock);
		error = khttpd_job_spawn_and_unlock(queue);
	}

	if (error != 0)
		khttpd_job_terminate();

	return (error);
}

static void
khttpd_job_unload(void)
{
	struct khttpd_job_queue *queue, **queues;
	struct thread *td;
	int i, n;

	khttpd_job_terminate();

	td = curthread;
	queues = khttpd_job_queues;
	n = khttpd_job_queue_count;
	for (i = 0; i < n; ++i) {
		queue = queues[i];
		mtx_destroy(&queue->lock);
		uma_zfree(khttpd_job_queue_zone, queue);
	}
	khttpd_free(khttpd_job_queues);
	uma_zdestroy(khttpd_job_zone);
	uma_zdestroy(khttpd_job_queue_zone);
}

KHTTPD_INIT(khttpd::job, khttpd_job_load, khttpd_job_unload, 
    KHTTPD_INIT_PHASE_REGISTER_EVENTS - 1);
