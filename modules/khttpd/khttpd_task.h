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

#pragma once

#ifndef _KERNEL
#error This file is not for userland code.
#endif

#include <sys/types.h>

struct khttpd_task;
struct khttpd_task_queue;

typedef void (*khttpd_task_fn_t)(void *arg);

struct khttpd_task *
	khttpd_task_new(struct khttpd_task_queue *_queue,
	    khttpd_task_fn_t _fn, void *_arg, const char *name_fmt, ...);
void	khttpd_task_delete(struct khttpd_task *_task);
bool	khttpd_task_is_active(struct khttpd_task *_task);
void	khttpd_task_set_queue(struct khttpd_task *_task,
	    struct khttpd_task_queue *_queue);
bool	khttpd_task_schedule(struct khttpd_task *_task);
bool	khttpd_task_cancel(struct khttpd_task *_task);
bool	khttpd_task_queue_on_worker_thread(struct khttpd_task_queue *_queue);
struct khttpd_task_queue *
	khttpd_task_queue_current(void);
struct khttpd_task_queue *
	khttpd_task_queue_new(const char *name_fmt, ...);
void	khttpd_task_queue_delete(struct khttpd_task_queue *_queue);
bool	khttpd_task_queue_is_active(struct khttpd_task_queue *_queue);
void	khttpd_task_queue_assign_random_worker
	(struct khttpd_task_queue *_queue);
void	khttpd_task_queue_run(struct khttpd_task_queue *_queue,
	    khttpd_task_fn_t _fn, void *_arg);
void	khttpd_task_queue_hand_over(struct khttpd_task_queue *_subject,
	    struct khttpd_task_queue *_destination);
void	khttpd_task_queue_take_over(struct khttpd_task_queue *_source,
	    khttpd_task_fn_t _notify, void *_arg);
