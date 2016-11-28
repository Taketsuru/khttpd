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

#include "khttpd_costruct.h"

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_ktr.h"
#include "khttpd_malloc.h"

#define KHTTPD_COSTRUCT_INITIAL_ARRAY_SIZE	4

struct khttpd_costruct_callback {
	int	(*ctor)(void *, void *);
	void	(*dtor)(void *, void *);
	void	*arg;
};

struct khttpd_costruct_info {
	struct sx	lock;
	struct khttpd_costruct_callback *callbacks;
	size_t		instance_size;
	size_t		callbacks_size;
	unsigned	costruct_count;
};

static int
khttpd_costruct_null_ctor(void *host, void *arg)
{

	return (0);
}

static void
khttpd_costruct_null_dtor(void *host, void *arg)
{
}

void
khttpd_costruct_info_new(struct khttpd_costruct_info **info_out,
    size_t host_size)
{
	struct khttpd_costruct_info *info;

	KHTTPD_ENTRY("%s(,%#zx)", __func__, host_size);
	KASSERT(khttpd_init_get_phase() < KHTTPD_INIT_PHASE_DEFINE_COSTRUCT,
	    ("%s is called in phase %d", __func__, khttpd_init_get_phase()));

	info = khttpd_malloc(sizeof(*info));
	sx_init(&info->lock, "costruct");
	info->callbacks = khttpd_malloc(KHTTPD_COSTRUCT_INITIAL_ARRAY_SIZE *
	    sizeof(struct khttpd_costruct_callback));
	info->instance_size = host_size;
	info->callbacks_size = KHTTPD_COSTRUCT_INITIAL_ARRAY_SIZE;
	info->costruct_count = 0;
	*info_out = info;
}

void
khttpd_costruct_info_destroy(struct khttpd_costruct_info *info)
{

	KHTTPD_ENTRY("%s(%p)", __func__, info);

	khttpd_free(info->callbacks);
	sx_destroy(&info->lock);
	khttpd_free(info);
}

khttpd_costruct_key_t
khttpd_costruct_register(struct khttpd_costruct_info *info,
    size_t costruct_size, khttpd_costruct_ctor_t ctor,
    khttpd_costruct_dtor_t dtor, void *arg)
{
	struct khttpd_costruct_callback *array, *tmp_array;
	khttpd_costruct_key_t key;
	size_t new_size;
	unsigned count;

	KHTTPD_ENTRY("%s(%p,%#zx,%p,%p,%p)", __func__, info, costruct_size,
	    ctor, dtor, arg);
	KASSERT(khttpd_init_get_phase() == KHTTPD_INIT_PHASE_DEFINE_COSTRUCT,
	    ("%s is called in phase %d", __func__, khttpd_init_get_phase()));

	if (ctor == NULL)
		ctor = khttpd_costruct_null_ctor;
	if (dtor == NULL)
		dtor = khttpd_costruct_null_dtor;

	sx_xlock(&info->lock);

	tmp_array = NULL;
	array = info->callbacks;
	count = info->costruct_count;

	if (info->callbacks_size < count + 1) {
		info->callbacks_size = new_size = count + 1;
		info->callbacks = array = khttpd_realloc(array, new_size *
		    sizeof(struct khttpd_costruct_callback));
	}

	array[count].ctor = ctor;
	array[count].dtor = dtor;
	array[count].arg = arg;
	info->costruct_count = count + 1;

	key = roundup(info->instance_size, sizeof(void *));
	info->instance_size = key + costruct_size;

	sx_xunlock(&info->lock);

	return (key);
}

int
khttpd_costruct_call_ctors(struct khttpd_costruct_info *info, void *host)
{								
	unsigned n, i;
	int error;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, info, host);
	KASSERT(KHTTPD_INIT_PHASE_DEFINE_COSTRUCT <
	    khttpd_init_get_phase(), ("%s is called in init phase %d",
		__func__, khttpd_init_get_phase()));

	error = 0;
	n = info->costruct_count;
	for (i = 0; i < n && error == 0; ++i)
		error = info->callbacks[i].ctor(host, info->callbacks[i].arg);

	if (error != 0)
		for (; 0 < i; --i)
			info->callbacks[i - 1].dtor
			    (host, info->callbacks[i - 1].arg);

	return (error);							
}

void
khttpd_costruct_call_dtors(struct khttpd_costruct_info *info, void *host)
{
	unsigned i;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, info, host);

	for (i = info->costruct_count; 0 < i; --i)
		info->callbacks[i - 1].dtor
		    (host, info->callbacks[i - 1].arg);
}

size_t
khttpd_costruct_instance_size(struct khttpd_costruct_info *info)
{

	KASSERT(KHTTPD_INIT_PHASE_DEFINE_COSTRUCT < khttpd_init_get_phase(),
	    ("%s is called in init phase %d",
		__func__, khttpd_init_get_phase()));

	return (info->instance_size);
}

extern void *
khttpd_costruct_get(void *host, khttpd_costruct_key_t key);

extern void *
khttpd_costruct_host_of(void *costruct, khttpd_costruct_key_t key);
