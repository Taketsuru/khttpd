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

#include <sys/types.h>
#include <sys/lock.h>
#include <sys/refcount.h>
#include <machine/atomic.h>

#include "khttpd_ktr.h"

/*
 * Don't change the name of the member because several definitions such as
 * khttpd_request_zctor_end depend on it.
 */
#define KHTTPD_REFCOUNT1_MEMBERS volatile u_int refcount

#define KHTTPD_REFCOUNT1_INIT(type, obj)		\
	do {						\
		struct type *ptr1_ = (obj);		\
		refcount_init(&ptr1_->refcount, 1);	\
	} while (0)

#define KHTTPD_REFCOUNT1_ACQUIRE_(type, obj)			\
	({							\
		struct type *ptr2_ = (obj);			\
		if (ptr2_ != NULL) {				\
			refcount_acquire(&(obj)->refcount);	\
		}						\
		ptr2_;						\
	})

#define KHTTPD_REFCOUNT1_RELEASE_(type, obj, dtor, free)		\
	do {								\
		struct type *ptr4_ = (obj);				\
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,		\
		    "%s is called", __func__);				\
		if (ptr4_ != NULL &&					\
		    refcount_release(&ptr4_->refcount)) {		\
			(dtor)(ptr4_);					\
			(free)(ptr4_);					\
		}							\
	} while (0)

#define KHTTPD_REFCOUNT1_PROTOTYPE_(decl, type)				\
	decl struct type *type ## _acquire(struct type *ptr);		\
	decl struct type *type ## _acquire_checked(struct type *ptr);	\
	decl void type ## _release(struct type *ptr)			\

#define KHTTPD_REFCOUNT1_GENERATE_(decl, type, dtor, free)		\
	decl struct type *type ## _acquire(struct type *ptr)		\
	{								\
		KHTTPD_ENTRY("%s(%p), refcount=%d",			\
		    __func__, ptr, ptr == NULL ? 0 : ptr->refcount);	\
		return (KHTTPD_REFCOUNT1_ACQUIRE_(type, ptr));		\
	}								\
	decl struct type *type ## _acquire_checked(struct type *ptr)	\
	{								\
		KHTTPD_ENTRY("%s(%p), refcount=%d",			\
		    __func__, ptr, ptr == NULL ? 0 : ptr->refcount);	\
		return (KHTTPD_REFCOUNT1_ACQUIRE_(type, ptr));		\
	}								\
	decl void type ## _release(struct type *ptr)			\
	{								\
		KHTTPD_ENTRY("%s(%p), refcount=%d",			\
		    __func__, ptr, ptr == NULL ? 0 : ptr->refcount);	\
		KHTTPD_REFCOUNT1_RELEASE_(type, ptr, dtor, free);	\
	}

#define KHTTPD_REFCOUNT1_GENERATE(type, dtor, free)	\
	KHTTPD_REFCOUNT1_GENERATE_(, type, dtor, free)

#define KHTTPD_REFCOUNT1_GENERATE_STATIC(type, dtor, free)	\
	KHTTPD_REFCOUNT1_GENERATE_(static, type, dtor, free)

#define KHTTPD_REFCOUNT1_PROTOTYPE(type)	\
	KHTTPD_REFCOUNT1_PROTOTYPE_(, type)

#define KHTTPD_REFCOUNT1_PROTOTYPE_STATIC(type)		\
	KHTTPD_REFCOUNT1_PROTOTYPE_(static, type)
