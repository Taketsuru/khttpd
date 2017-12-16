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

#ifndef _KERNEL
#error This file is not for userland code.
#endif

#include <sys/param.h>
#include <sys/systm.h>

#include "khttpd_init.h"

struct khttpd_costruct_info;

typedef size_t khttpd_costruct_key_t;
typedef int (*khttpd_costruct_ctor_t)(void *, void *);
typedef void (*khttpd_costruct_dtor_t)(void *, void *);

void khttpd_costruct_info_new(struct khttpd_costruct_info **, size_t);
void khttpd_costruct_info_destroy(struct khttpd_costruct_info *);
khttpd_costruct_key_t khttpd_costruct_register(struct khttpd_costruct_info *,
    size_t, khttpd_costruct_ctor_t, khttpd_costruct_dtor_t, void *);
int khttpd_costruct_call_ctors(struct khttpd_costruct_info *, void *);
void khttpd_costruct_call_dtors(struct khttpd_costruct_info *, void *);
size_t khttpd_costruct_instance_size(struct khttpd_costruct_info *);

inline void *
khttpd_costruct_get(void *host, khttpd_costruct_key_t key)
{

	KASSERT(KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS < khttpd_init_get_phase(),
	    ("%s is called in init phase %d",
		__func__, khttpd_init_get_phase()));

	return ((char *)host + key);
}

inline void *
khttpd_costruct_host_of(void *costruct, khttpd_costruct_key_t key)
{

	KASSERT(KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS < khttpd_init_get_phase(),
	    ("%s is called in init phase %d",
		__func__, khttpd_init_get_phase()));

	return ((char *)costruct - key);
}
