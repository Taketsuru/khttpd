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

#include "khttpd_main.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/linker_set.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/sbuf.h>
#include <sys/malloc.h>
#include <sys/eventhandler.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/filedesc.h>
#include <sys/file.h>
#include <sys/capsicum.h>
#include <sys/module.h>
#include <sys/syslog.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/conf.h>

#include "khttpd.h"
#include "khttpd_init.h"
#include "khttpd_test.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

#ifndef KHTTPD_MAIN_TEST_FILTER_SIZE_MAX
#define KHTTPD_MAIN_TEST_FILTER_SIZE_MAX	(1024ul*1024)
#endif

static int khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td);

enum khttpd_main_state {
	KHTTPD_MAIN_DORMANT,
	KHTTPD_MAIN_INITIALIZING,
	KHTTPD_MAIN_READY,
	KHTTPD_MAIN_TERMINATING,
};

struct khttpd_main_ioctl {
	SLIST_ENTRY(khttpd_main_ioctl) link;
	u_long	cmd;
	khttpd_main_ioctl_fn_t handler;
};

SLIST_HEAD(khttpd_main_ioctl_slist, khttpd_main_ioctl);

static struct cdevsw khttpd_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl   = khttpd_ioctl,
	.d_name	   = "khttpd"
};

static struct mtx khttpd_main_lock;
static struct khttpd_main_ioctl_slist khttpd_main_ioctls = 
    SLIST_HEAD_INITIALIZER(&khttpd_main_ioctls);
static struct cdev *khttpd_main_dev;
static struct khttpd_main_command *khttpd_main_command;
static struct module *khttpd_main_module_self;
static eventhandler_tag khttpd_main_shutdown_tag;
static pid_t khttpd_main_pid;
static enum khttpd_main_state khttpd_main_state;

MTX_SYSINIT(khttpd_main_lock, &khttpd_main_lock, "khttpd", MTX_DEF);

static void
khttpd_main_command_loop(int error)
{

	KHTTPD_ENTRY("%s(%d)", __func__, error);

	mtx_lock(&khttpd_main_lock);

	if (error == 0)
		khttpd_main_state = KHTTPD_MAIN_READY;
	else {
		khttpd_main_command->error = error;
		khttpd_main_command = NULL;
	}
	wakeup(&khttpd_main_state);

	while (khttpd_main_state == KHTTPD_MAIN_READY) {
		while (khttpd_main_command == NULL &&
		    khttpd_main_state == KHTTPD_MAIN_READY)
			mtx_sleep(&khttpd_main_state, &khttpd_main_lock, 0,
			    "khttpd-idle", 0);

		if (khttpd_main_command != NULL) {
			mtx_unlock(&khttpd_main_lock);
			khttpd_main_command->handler(khttpd_main_command);
			mtx_lock(&khttpd_main_lock);
			khttpd_main_command = NULL;
			wakeup(&khttpd_main_state);
		}
	}

	mtx_unlock(&khttpd_main_lock);
}

static void
khttpd_main_entrypoint(void *arg)
{
	struct thread *td;
	int error;

	KHTTPD_ENTRY("%s()", __func__);

	td = curthread;
	khttpd_main_pid = td->td_proc->p_pid;
	error = khttpd_init_run(khttpd_main_command_loop);
	KASSERT(error == 0, ("error=%d", error));
	kproc_exit(0);
}

static void
khttpd_main_shutdown(void *arg)
{
	struct proc *p;
	int state;

	KHTTPD_ENTRY("%s()", __func__);

	mtx_lock(&khttpd_main_lock);

	for (;;) {
		state = khttpd_main_state;

		if (khttpd_main_command == NULL &&
		    (state == KHTTPD_MAIN_READY ||
		     state == KHTTPD_MAIN_DORMANT))
			break;

		mtx_sleep(&khttpd_main_state, &khttpd_main_lock, 0, "main", 0);
	}

	if (state == KHTTPD_MAIN_DORMANT) {
		mtx_unlock(&khttpd_main_lock);
		return;
	}

	khttpd_main_state = KHTTPD_MAIN_TERMINATING;
	wakeup(&khttpd_main_state);

	mtx_unlock(&khttpd_main_lock);

	while ((p = pfind(khttpd_main_pid)) != NULL) {
		PROC_UNLOCK(p);
		pause("khttpd-down", hz / 10);
	}

	mtx_lock(&khttpd_main_lock);

	khttpd_main_state = KHTTPD_MAIN_DORMANT;
	wakeup(&khttpd_main_state);

	mtx_unlock(&khttpd_main_lock);
}

void
khttpd_main_call(struct khttpd_main_command *cmd)
{
	struct proc *p;
	int error, state;

	KHTTPD_ENTRY("%s(%p)", __func__, cmd);
	cmd->error = -1;

	mtx_lock(&khttpd_main_lock);

	for (;;) {
		state = khttpd_main_state;

		if (khttpd_main_command == NULL &&
		    (state == KHTTPD_MAIN_READY ||
		     state == KHTTPD_MAIN_DORMANT))
			break;

		mtx_sleep(&khttpd_main_state, &khttpd_main_lock, 0,
		    "khttpd-state", 0);
	}

	khttpd_main_command = cmd;
	wakeup(&khttpd_main_state);

	if (state == KHTTPD_MAIN_DORMANT) {
		khttpd_main_state = KHTTPD_MAIN_INITIALIZING;
		mtx_unlock(&khttpd_main_lock);

		error = kproc_create(khttpd_main_entrypoint, NULL, NULL, 0, 0,
		    "khttpd");
		if (error != 0) {
			mtx_lock(&khttpd_main_lock);
			khttpd_main_command = NULL;
			khttpd_main_state = KHTTPD_MAIN_DORMANT;
			wakeup(&khttpd_main_state);
			mtx_unlock(&khttpd_main_lock);

			log(LOG_ERR, "khttpd: failed to fork.  "
			    "(error: %d)", error);

			cmd->error = error;
			return;
		}

		mtx_lock(&khttpd_main_lock);
	}

	while (cmd->error == -1)
		mtx_sleep(&khttpd_main_state, &khttpd_main_lock, 0,
		    "khttpd-cmd", 0);

	if (khttpd_main_state == KHTTPD_MAIN_INITIALIZING) {
		mtx_unlock(&khttpd_main_lock);

		while ((p = pfind(khttpd_main_pid)) != NULL) {
			PROC_UNLOCK(p);
			pause("khttpd-term", hz / 10);
		}

		mtx_lock(&khttpd_main_lock);

		khttpd_main_state = KHTTPD_MAIN_DORMANT;
		wakeup(&khttpd_main_state);
	}

	mtx_unlock(&khttpd_main_lock);
}

int
khttpd_main_register_ioctl(u_long cmd, khttpd_main_ioctl_fn_t handler)
{
	struct khttpd_main_ioctl *new_entry, *ptr;

	KHTTPD_ENTRY("%s(%#lx,%p)", __func__, cmd, handler);

	new_entry = khttpd_malloc(sizeof(*new_entry));
	new_entry->cmd = cmd;
	new_entry->handler = handler;

	mtx_lock(&khttpd_main_lock);

	SLIST_FOREACH(ptr, &khttpd_main_ioctls, link)
	    if (ptr->cmd == cmd)
		    break;

	if (ptr == NULL)
		SLIST_INSERT_HEAD(&khttpd_main_ioctls, new_entry, link);

	mtx_unlock(&khttpd_main_lock);

	if (ptr != NULL) {
		log(LOG_ERR, "khttpd: ioctl conflict %#lx", cmd);
		return (EINVAL);
	}

	return (0);
}

void 
khttpd_main_deregister_ioctl(u_long cmd)
{
	struct khttpd_main_ioctl *entry;

	KHTTPD_ENTRY("%s(%#lx)", __func__, cmd);

	mtx_lock(&khttpd_main_lock);

	SLIST_FOREACH(entry, &khttpd_main_ioctls, link)
	    if (entry->cmd == cmd)
		    break;

	if (entry != NULL)
		SLIST_REMOVE(&khttpd_main_ioctls, entry, khttpd_main_ioctl, 
		    link);

	mtx_unlock(&khttpd_main_lock);

	khttpd_free(entry);

	if (entry == NULL)
		log(LOG_ERR, "khttpd: try to deregister unknown ioctl %#lx",
		    cmd);
}

#ifdef KHTTPD_TEST_ENABLE

static int
khttpd_main_test(struct khttpd_ioctl_test_args *args)
{
	struct sbuf report;
	char *filter;
	size_t flen;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, args);

	filter = NULL;
	sbuf_new(&report, NULL, 0, SBUF_AUTOEXTEND | SBUF_INCLUDENUL);

	flen = MIN(KHTTPD_MAIN_TEST_FILTER_SIZE_MAX, args->filter_len);
	filter = malloc(flen, M_TEMP, M_WAITOK);
	error = copyinstr(args->filter, filter, flen, NULL);
	if (error != 0)
		goto quit;

	khttpd_test_run(&report, filter);

	sbuf_finish(&report);
	error = copyout(sbuf_data(&report), args->buf,
	    MIN(args->buf_size, sbuf_len(&report)));

quit:
	args->buf_size = sbuf_len(&report);

	free(filter, M_TEMP);
	sbuf_delete(&report);

	return (error);
}

#endif	/* ifdef KHTTPD_TEST_ENABLE */

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	struct khttpd_main_ioctl *entry;
	khttpd_main_ioctl_fn_t fn;
	static boolean_t loaded;
	int error;

	KHTTPD_ENTRY("%s(%#lx,%p)", __func__, cmd, data);

	if (!loaded) {
		khttpd_init_wait_load_completion(khttpd_main_module_self);
		loaded = TRUE;
	}

	switch (cmd) {

	case KHTTPD_IOC_STOP:
		khttpd_main_shutdown(NULL);
		error = 0;
		break;

#ifdef KHTTPD_TEST_ENABLE
	case KHTTPD_IOC_TEST:
		error = khttpd_main_test((struct khttpd_ioctl_test_args *)data);
		break;
#endif
	default:
		mtx_lock(&khttpd_main_lock);

		fn = NULL;
		SLIST_FOREACH(entry, &khttpd_main_ioctls, link)
			if (entry->cmd == cmd) {
				fn = entry->handler;
				break;
			}

		mtx_unlock(&khttpd_main_lock);

		error = fn == NULL ? ENOIOCTL : fn(dev, cmd, data, fflag, td);
	}

	return (error);
}

static int
khttpd_loader(struct module *m, int what, void *arg)
{
	int error;

	KHTTPD_ENTRY("%s(%p,%d,%p)", __func__, m, what, arg);

	switch (what) {

	case MOD_LOAD:
		khttpd_main_module_self = m;

		khttpd_main_shutdown_tag = 
		    EVENTHANDLER_REGISTER(khttpd_init_shutdown, 
			khttpd_main_shutdown, NULL, 0);

		error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK,
		    &khttpd_main_dev, &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL,
		    0600, "khttpd");
		if (error != 0)
			log(LOG_ERR, "khttpd: failed to create "
			    "device \"khttpd\" (error: %d)", error);

		return (error);

	case MOD_QUIESCE:
		return (khttpd_init_quiesce());

	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		if (khttpd_main_dev != NULL)
			destroy_dev(khttpd_main_dev);

		khttpd_init_unload(m);
		KASSERT(SLIST_EMPTY(&khttpd_main_ioctls),
		    ("incomplete ioctl deregistration"));

		EVENTHANDLER_DEREGISTER(khttpd_init_shutdown, 
		    khttpd_main_shutdown_tag);

		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

MODULE_VERSION(khttpd, 1);
DEV_MODULE(khttpd, khttpd_loader, NULL);
