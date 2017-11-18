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

#include "khttpd_event.h"

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

#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

struct khttpd_event;
SLIST_HEAD(khttpd_event_slist, khttpd_event);

struct khttpd_event_queue {
	struct mtx	lock;
	struct khttpd_event_slist changes;
	struct thread   *owner;
	int		kq;
	int		id;
};

struct khttpd_event {
	SLIST_ENTRY(khttpd_event) link;
	struct kevent	kevent;
	struct khttpd_event_queue *queue;
	khttpd_event_fn_t handler;
	void		*arg;
	char		tmsg[16];
};

struct khttpd_kevent_args {
	const struct kevent *changelist;
	struct kevent	    *eventlist;
};

static struct sx khttpd_event_lock;
static char khttpd_event_siphash_key[SIPHASH_KEY_LENGTH];
static struct khttpd_event_queue **khttpd_event_queues;
static uma_zone_t khttpd_event_zone;
static uintptr_t khttpd_event_next_ident;
static int khttpd_event_thread_count;
static int khttpd_event_queue_count;
static boolean_t khttpd_event_exiting;

SX_SYSINIT(khttpd_event_lock, &khttpd_event_lock, "khttpd-event");

static int
khttpd_kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args;

	args = arg;
	bcopy(kevp, args->eventlist, count * sizeof(*kevp));
	args->eventlist += count;

	return (0);
}

static int
khttpd_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args;

	args = arg;
	bcopy(args->changelist, kevp, count * sizeof(*kevp));
	args->changelist += count;

	return (0);
}

static int
khttpd_kevent(int kq, struct kevent *changes, int nchanges,
    struct kevent *eventlist, int nevents, int *nevent_out,
    const struct timespec *timeout)
{
	struct thread *td;
	int error;

	struct khttpd_kevent_args args = {
		.changelist = changes,
		.eventlist  = eventlist
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	KHTTPD_ENTRY("khttpd_kevent(%d,,nchanges=%d,,nevent=%d,"
	    "timeout=%d.%09d)", kq, nchanges, nevents,
	    timeout == NULL ? 0 : timeout->tv_sec,
	    timeout == NULL ? 0 : timeout->tv_nsec);

	td = curthread;
	error = kern_kevent(td, kq, nchanges, nevents, &k_ops, timeout);
	if (nevent_out != NULL)
		*nevent_out = td->td_retval[0];

	return (error);
}

static void
khttpd_event_main(void *arg)
{
	struct kevent events[16];
	struct thread *td;
	struct khttpd_event *event;
	struct khttpd_event_queue *queue;
	int error, i, evasize, nevents, nchanges;

	queue = arg;
	KHTTPD_ENTRY("khttpd_event_main(%p{id=%d})", queue, queue->id);

	td = curthread;
	queue->owner = td;
	evasize = sizeof(events) / sizeof(events[0]);
	error = 0;

	while (!khttpd_event_exiting) {
		nchanges = 0;
		SLIST_FOREACH(event, &queue->changes, link) {
			bcopy(&event->kevent, &events[nchanges++],
			    sizeof(events[0]));
			if (nchanges == evasize && error == 0) {
				error = khttpd_kevent(queue->kq, events,
				    evasize, NULL, 0, NULL, NULL);
				nchanges = 0;
			}
		}

		SLIST_INIT(&queue->changes);

		if (error == 0)
			error = khttpd_kevent(queue->kq, events, nchanges,
			    events, evasize, &nevents, NULL);

		if (error != 0)
			break;

		for (i = 0; i < nevents; ++i)
			if ((event = events[i].udata) != NULL)
				event->handler(event->arg);
	}

	if (error != 0)
		log(LOG_ERR, "khttpd: kevent() failed "
		    "(error: %d, file: %s, line: %u)",
		    error, __FILE__, __LINE__);

	sx_xlock(&khttpd_event_lock);
	if (--khttpd_event_thread_count == 0)
		wakeup(&khttpd_event_thread_count);
	sx_xunlock(&khttpd_event_lock);

	kthread_exit();
}

static struct khttpd_event *
khttpd_event_new(khttpd_event_fn_t handler, void *arg, uintptr_t ident,
    short filter, u_short flags, u_int fflags, intptr_t data,
    struct khttpd_event *sibling)
{
	static SIPHASH_CTX khttpd_siphash_ctx;
	static volatile uint64_t counter;
	struct khttpd_event *event;
	struct khttpd_event_queue *queue;
	uint64_t hash, count;
	int error;

	KASSERT(KHTTPD_INIT_PHASE_REGISTER_EVENTS <= khttpd_init_get_phase(),
	    ("phase=%d", khttpd_init_get_phase()));

	if (sibling != NULL) {
		queue = sibling->queue;

	} else {
		count = atomic_fetchadd_long(&counter, 1);
		hash = SipHash24(&khttpd_siphash_ctx, khttpd_event_siphash_key,
		    &count, sizeof(count));
		queue = khttpd_event_queues[hash % khttpd_event_queue_count];
	}

	event = uma_zalloc(khttpd_event_zone, M_WAITOK);
	EV_SET(&event->kevent, ident, filter, flags | EV_ADD | EV_DISPATCH,
	    fflags, data, event);
	event->queue = queue;
	event->handler = handler;
	event->arg = arg;
	strcpy(event->tmsg, "<unknown>");

	if ((flags & EV_ENABLE) != 0 && queue->owner == curthread) {
		SLIST_INSERT_HEAD(&queue->changes, event, link);
		return (event);
	}

	error = khttpd_kevent(queue->kq, &event->kevent, 1, NULL, 0, NULL,
	    NULL);
	if (error != 0) {
		uma_zfree(khttpd_event_zone, event);
		log(LOG_ERR, "khttpd: kevent() failed "
		    "(error: %d, file: %s, line: %u)",
		    error, __FILE__, __LINE__);
		return (NULL);
	}

	return (event);
}

struct khttpd_event *
khttpd_event_new_read(khttpd_event_fn_t handler, void *arg, int fd,
    boolean_t enable, struct khttpd_event *sibling)
{
	struct khttpd_event *event;
	u_short flags;

	KHTTPD_ENTRY("khttpd_event_new_read(,%p,%d,%s,%p)",
	    arg, fd, enable ? "enable" : "disable", sibling);
	flags = enable ? 0 : EV_DISABLE;
	event = khttpd_event_new(handler, arg, fd, EVFILT_READ, flags, 0, 0,
		sibling);
	snprintf(event->tmsg, sizeof(event->tmsg), "read %d", fd);
	KHTTPD_NOTE("event %p{tmsg=%s}", event,
	    khttpd_ktr_printf("%s", event->tmsg));

	return (event);
}

struct khttpd_event *
khttpd_event_new_write(khttpd_event_fn_t handler, void *arg, int fd,
    boolean_t enable, struct khttpd_event *sibling)
{
	struct khttpd_event *event;
	u_short flags;

	KHTTPD_ENTRY("khttpd_event_new_write(,%p,%d,%s,%p)",
	    arg, fd, enable ? "enable" : "disable", sibling);
	flags = enable ? 0 : EV_DISABLE;
	event = khttpd_event_new(handler, arg, fd, EVFILT_WRITE, flags, 0, 0,
	    sibling);
	snprintf(event->tmsg, sizeof(event->tmsg), "write %d", fd);
	KHTTPD_NOTE("event %p{tmsg=%s}", event,
	    khttpd_ktr_printf("%s", event->tmsg));

	return (event);
}

struct khttpd_event *
khttpd_event_new_user(khttpd_event_fn_t handler, void *arg,
    boolean_t enable, struct khttpd_event *sibling)
{
	struct khttpd_event *event;
	u_short flags;
	uintptr_t ident;

	KHTTPD_ENTRY("khttpd_event_new_user(,%p,%s,%p)",
	    arg, enable ? "enable" : "disable", sibling);

	/* This code assumes uintptr_t counter never wraps around. */
	ident = atomic_fetchadd_long(&khttpd_event_next_ident, 1);
	flags = enable ? EV_CLEAR : EV_CLEAR | EV_DISABLE;
	event = khttpd_event_new(handler, arg, ident, EVFILT_USER, flags, 0, 0,
		sibling);
	snprintf(event->tmsg, sizeof(event->tmsg), "user %ld", ident);
	KHTTPD_NOTE("event %p{tmsg=%s}", event,
	    khttpd_ktr_printf("%s", event->tmsg));

	return (event);
}

struct khttpd_event *
khttpd_event_new_timer(khttpd_event_fn_t handler, void *arg,
    intptr_t timeout, boolean_t enable, boolean_t oneshot,
    struct khttpd_event *sibling)
{
	struct khttpd_event *event;
	u_short flags;
	uintptr_t ident;

	KHTTPD_ENTRY("khttpd_event_new_timer(,%p,%#lx,%s,%s,%p)",
	    arg, timeout, enable ? "enable" : "disable",
	    oneshot ? "oneshot" : "-oneshot", sibling);

	/* This code assumes uintptr_t counter never wraps around. */
	ident = atomic_fetchadd_long(&khttpd_event_next_ident, 1);
	flags = 0;
	if (!enable)
		flags |= EV_DISABLE;
	if (oneshot)
		flags |= EV_ONESHOT;
	event = khttpd_event_new(handler, arg, ident, EVFILT_TIMER, flags, 0,
	    timeout, sibling);
	snprintf(event->tmsg, sizeof(event->tmsg), "timer %ld", ident);
	KHTTPD_NOTE("event %p{tmsg=%s}", event,
	    khttpd_ktr_printf("%s", event->tmsg));

	return (event);
}

/*
 * Don't call khttpd_event_enable / khttpd_event_delete on the same
 * khttpd_event instance concurrently.
 */

void
khttpd_event_enable(struct khttpd_event *event)
{
	struct khttpd_event_queue *queue;
	int error;

	KHTTPD_ENTRY("khttpd_event_enable(%p{tmsg=%s})", event,
	    event == NULL ? "<null>" : khttpd_ktr_printf("%s", event->tmsg));

	queue = event->queue;

	error = 0;
	event->kevent.flags = EV_ENABLE;
	if (queue->owner == curthread) {
		SLIST_INSERT_HEAD(&queue->changes, event, link);
		return;
	}

	error = khttpd_kevent(queue->kq, &event->kevent, 1, NULL, 0,
	    NULL, NULL);
	if (error != 0)
		log(LOG_ERR, "khttpd: kevent(EV_ENABLE) failed "
		    "(error: %d, file: %s, line: %u)",
		    error, __FILE__, __LINE__);
}

/*
 * Don't call khttpd_event_enable / khttpd_event_trigger /
 * khttpd_event_delete on the same khttpd_event instance concurrently.
 *
 * The caller must guarantee that the event is not delivering.
 */

void
khttpd_event_delete(struct khttpd_event *event)
{
	struct khttpd_event_queue *queue;
	int error;

	KHTTPD_ENTRY("khttpd_event_delete(%p{tmsg=%s})", event,
	    event == NULL ? "<null>" : khttpd_ktr_printf("%s", event->tmsg));

	if (event == NULL)
		return;

	queue = event->queue;

#ifdef INVARIANTS
	struct khttpd_event *ptr;
	SLIST_FOREACH(ptr, &queue->changes, link)
		if (ptr == event)
			panic("%p is deleted while it's in the change list",
				event);
#endif

	event->kevent.flags = EV_DELETE;
	error = khttpd_kevent(queue->kq, &event->kevent, 1, NULL, 0, NULL,
	    NULL);
	if (error != 0)
		log(LOG_ERR, "khttpd: kevent() failed "
		    "(error: %d, file: %s, line: %u, filter: %d)",
		    error, __FILE__, __LINE__, event->kevent.filter);

	uma_zfree(khttpd_event_zone, event);
}

/*
 * Don't call khttpd_event_enable / khttpd_event_trigger /
 * khttpd_event_delete on the same khttpd_event instance concurrently.
 */

void
khttpd_event_trigger(struct khttpd_event *event)
{
	int error;

	KHTTPD_ENTRY("khttpd_event_trigger(%p{tmsg=%s})", event,
	    event == NULL ? "<null>" : khttpd_ktr_printf("%s", event->tmsg));
	KASSERT(event->kevent.filter == EVFILT_USER,
	    ("event %p, ident %d", event, event->kevent.filter));
	KASSERT(queue->owner == curthread || &event->owner == 0, ("busy"));

	event->kevent.flags = EV_ENABLE;
	event->kevent.fflags = NOTE_TRIGGER;
	error = khttpd_kevent(event->queue->kq, &event->kevent, 1, NULL, 0,
	    NULL, NULL);
	if (error != 0)
		log(LOG_ERR, "khttpd: kevent() failed "
		    "(error: %d, file: %s, line: %u)",
		    error, __FILE__, __LINE__);
}

/*
 * This function doesn't delete any events.  The caller should guarantee
 * that they are deleted to avoid resource leaks.
 */

static void
khttpd_event_terminate(void)
{
	struct kevent change;
	struct khttpd_event_queue *queue;
	int i, n;

	KHTTPD_ENTRY("khttpd_event_terminate()");

	sx_xlock(&khttpd_event_lock);

	khttpd_event_exiting = TRUE;

	n = khttpd_event_queue_count;
	for (i = 0; i < n; ++i) {
		queue = khttpd_event_queues[i];
		if (queue != NULL) {
			KHTTPD_BRANCH("khttpd_event_terminate %d trigger", i);
			EV_SET(&change, i, EVFILT_USER, EV_ENABLE,
			    NOTE_TRIGGER, 0, NULL);
			khttpd_kevent(queue->kq, &change, 1, NULL, 0, NULL,
			    NULL);
		}
	}

	while (0 < khttpd_event_thread_count) {
		KHTTPD_BRANCH("khttpd_event_terminate wait %d",
		    khttpd_event_thread_count);
		sx_sleep(&khttpd_event_thread_count, &khttpd_event_lock, 0,
		    "wait", 0);
	}

	sx_xunlock(&khttpd_event_lock);

	KHTTPD_NOTE("khttpd_event_terminate leave");
}

static int
khttpd_event_init(void)
{
	struct kevent change;
	struct khttpd_event_queue *queue, **queues;
	struct thread *td;
	struct proc *p;
	int error, i, n, kq;

	KHTTPD_ENTRY("khttpd_event_init()");
	td = curthread;

	arc4rand(khttpd_event_siphash_key, sizeof(khttpd_event_siphash_key),
	    FALSE);
	khttpd_event_queue_count = n = mp_ncpus;
	khttpd_event_queues = queues =
	    khttpd_malloc(n * sizeof(struct khttpd_event_queue *));

	for (i = 0; i < n; ++i) {
		error = sys_kqueue(td, NULL);
		if (error != 0) {
			log(LOG_ERR, "khttpd: kqueue() failed. "
			    "(error: %d, file: %s, line: %u)",
			    error, __FILE__, __LINE__);
			goto error;
		}
		kq = td->td_retval[0];

		EV_SET(&change, i, EVFILT_USER, EV_ADD | EV_DISPATCH, 0, 0,
		    NULL);

		error = khttpd_kevent(kq, &change, 1, NULL, 0, NULL, NULL);
		if (error != 0) {
			log(LOG_ERR, "khttpd: kevent() failed "
			    "(error: %d, file: %s, line: %u)", 
			    error, __FILE__, __LINE__);
			kern_close(td, kq);
			goto error;
		}

		queues[i] = queue = 
		    khttpd_malloc(sizeof(struct khttpd_event_queue));

		queue->kq = kq;
		queue->id = i;
		SLIST_INIT(&queue->changes);
	}

	khttpd_event_next_ident = i;

	khttpd_event_zone = uma_zcreate("khttpd-event",
	    sizeof(struct khttpd_event), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	p = td->td_proc;
	for (i = 0; i < n; ++i) {
		sx_xlock(&khttpd_event_lock);
		++khttpd_event_thread_count;
		sx_xunlock(&khttpd_event_lock);

		error = kthread_add(khttpd_event_main, queues[i], p, NULL, 0,
		    0, "event%d", i);
		if (error != 0) {
			--khttpd_event_thread_count;
			log(LOG_ERR, "khttpd: kthread_add() failed "
			    "(error: %d, file: %s, line: %u)",
			    error, __FILE__, __LINE__);
			break;
		}
	}

	if (error != 0)
		khttpd_event_terminate();

	return (error);

 error:
	for (; 0 < i; --i) {
		queue = queues[i - 1];
		kern_close(td, queue->kq);
		khttpd_free(queue);
	}
	khttpd_free(queues);

	return (error);
}

static void
khttpd_event_fini(void)
{
	struct khttpd_event_queue *queue, **queues;
	struct thread *td;
	int i, n;

	KHTTPD_ENTRY("khttpd_event_fini()");
	khttpd_event_terminate();

	td = curthread;
	queues = khttpd_event_queues;
	n = khttpd_event_queue_count;
	for (i = 0; i < n; ++i) {
		queue = queues[i];
		kern_close(td, queue->kq);
		khttpd_free(queue);
	}
	khttpd_free(khttpd_event_queues);
	uma_zdestroy(khttpd_event_zone);
}

KHTTPD_INIT(, khttpd_event_init, khttpd_event_fini,
    KHTTPD_INIT_PHASE_REGISTER_EVENTS - 1);
