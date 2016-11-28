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

#ifdef _KERNEL

#include <sys/types.h>

struct khttpd_event;

typedef void (*khttpd_event_fn_t)(void *arg);

struct khttpd_event *khttpd_event_new_read(khttpd_event_fn_t handler,
    void *arg, int fd, boolean_t enable, struct khttpd_event *sibling);
struct khttpd_event *khttpd_event_new_write(khttpd_event_fn_t handler,
    void *arg, int fd, boolean_t enable, struct khttpd_event *sibling);
struct khttpd_event *khttpd_event_new_user(khttpd_event_fn_t handler,
    void *arg, boolean_t enable, struct khttpd_event *sibling);
struct khttpd_event *khttpd_event_new_timer(khttpd_event_fn_t handler,
    void *arg, intptr_t time, boolean_t enable, boolean_t oneshot,
    struct khttpd_event *sibling);
void khttpd_event_delete(struct khttpd_event *event);
void khttpd_event_enable(struct khttpd_event *event);
void khttpd_event_trigger(struct khttpd_event *event);

#endif	/* _KERNEL */
