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

#include <sys/types.h>
#include <sys/lock.h>
#include <sys/refcount.h>
#include <machine/atomic.h>

#include "khttpd_ktr.h"

/*
 * Don't change the name of the member because several definitions such as
 * khttpd_request_zctor_end depend on it.
 */
#define KHTTPD_REFCOUNT1_MEMBERS		\
	volatile u_int refcount			\

#define KHTTPD_REFCOUNT1_INIT(type, obj)		\
	do {						\
		struct type *ptr1_ = (obj);		\
		refcount_init(&ptr1_->refcount, 1);	\
	} while (0)

#define KHTTPD_REFCOUNT1_ACQUIRE(type, obj)			\
	({							\
		struct type *ptr2_ = (obj);			\
		if (ptr2_ != NULL)				\
			refcount_acquire(&(obj)->refcount);	\
		ptr2_;						\
	})

#define KHTTPD_REFCOUNT1_RELEASE(type, obj, dtor, free)			\
	do {								\
		struct type *ptr4_ = (obj);				\
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,		\
		    "%s is called", __func__);				\
		if (ptr4_ != NULL && refcount_release(&ptr4_->refcount)) { \
			(dtor)(ptr4_);					\
			(free)(ptr4_);					\
		}							\
	} while (0)

#define KHTTPD_REFCOUNT1_PROTOTYPE(name, type)				\
	struct type *name ## _acquire(struct type *ptr);		\
	struct type *name ## _acquire_checked(struct type *ptr);	\
	void name ## _release(struct type *ptr)				\

#define KHTTPD_REFCOUNT1_GENERATE(name, type, dtor, free)		\
	struct type *name ## _acquire(struct type *ptr)			\
	{								\
		KHTTPD_ENTRY(#name "_acquire(%p), refcount=%d",		\
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		return (KHTTPD_REFCOUNT1_ACQUIRE(type, ptr));		\
	}								\
	struct type *name ## _acquire_checked(struct type *ptr)		\
	{								\
		KHTTPD_ENTRY(#name "_acquire_checked(%p), refcount=%d", \
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		return (KHTTPD_REFCOUNT1_ACQUIRE(type, ptr));		\
	}								\
	void name ## _release(struct type *ptr)				\
	{								\
		KHTTPD_ENTRY(#name "_release(%p), refcount=%d",		\
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		KHTTPD_REFCOUNT1_RELEASE(type, ptr, dtor, free);	\
	}

#define KHTTPD_REFCOUNT1_PROTOTYPE_STATIC(name, type)			\
	static struct type *name ## _acquire(struct type *ptr);		\
	static struct type *name ## _acquire_checked(struct type *ptr);	\
	static void name ## _release(struct type *ptr)			\

#define KHTTPD_REFCOUNT1_GENERATE_STATIC(name, type, dtor, free)	\
	static struct type *name ## _acquire(struct type *ptr)		\
	{								\
		KHTTPD_ENTRY(#name "_acquire(%p), refcount=%d",		\
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		return (KHTTPD_REFCOUNT1_ACQUIRE(type, ptr));		\
	}								\
	static struct type *name ## _acquire_checked(struct type *ptr)	\
	{								\
		KHTTPD_ENTRY(#name "_acquire_checked(%p), refcount=%d", \
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		return (KHTTPD_REFCOUNT1_ACQUIRE(type, ptr));		\
	}								\
	static void name ## _release(struct type *ptr)			\
	{								\
		KHTTPD_ENTRY(#name "_release(%p), refcount=%d",		\
		    ptr, ptr == NULL ? 0 : ptr->refcount);		\
		KHTTPD_REFCOUNT1_RELEASE(type, ptr, dtor, free);	\
	}

/*
 * Don't change the name 'refcount'.  It must be the first member.
 * Users of this code may depend on it.  It's a necessary rule to use
 * offsetof on KHTTPD_REFCOUNT2_MEMBERS.
 */
#define KHTTPD_REFCOUNT2_MEMBERS		\
	volatile u_int		refcount;	\
	volatile u_int		weakcount

#define KHTTPD_REFCOUNT2_INIT(type, obj)		\
	do {						\
		struct type *ptr1_ = (obj);		\
		refcount_init(&ptr1_->refcount, 1);	\
		refcount_init(&ptr1_->weakcount, 1);	\
	} while (0)

#define KHTTPD_REFCOUNT2_ACQUIRE(type, obj)			\
	({							\
		struct type *ptr2_ = (obj);			\
		if (ptr2_ != NULL)				\
			refcount_acquire(&(obj)->refcount);	\
		ptr2_;						\
	})

#define KHTTPD_REFCOUNT2_ACQUIRE_CHECKED(type, obj)			\
	({								\
		struct type *ptr3_ = (obj);				\
		u_int refcount_;					\
		if (ptr3_ != NULL)					\
			do {						\
				refcount_ = ptr3_->refcount;		\
				if (refcount_ == 0)			\
					break;				\
			} while (!atomic_cmpset_int(&ptr3_->refcount,	\
				refcount_, refcount_ + 1));		\
		ptr3_ != NULL && refcount_ != 0 ? ptr3_ : NULL;		\
	})

#define KHTTPD_REFCOUNT2_RELEASE(type, obj, dtor, free)			\
	do {								\
		struct type *ptr4_ = (obj);				\
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,		\
		    "%s is called", __func__);				\
		if (ptr4_ != NULL && refcount_release(&ptr4_->refcount)) { \
			(dtor)(ptr4_);					\
			KHTTPD_REFCOUNT2_RELEASE_WEAK(type, ptr4_, free); \
		}							\
	} while (0)

#define KHTTPD_REFCOUNT2_ACQUIRE_WEAK(type, obj)		\
	({							\
		struct type *ptr5_ = (obj);			\
		if (ptr5_ != NULL)				\
			refcount_acquire(&(obj)->weakcount);	\
		ptr5_;						\
	})

#define KHTTPD_REFCOUNT2_RELEASE_WEAK(type, obj, free)			\
	do {								\
		struct type *ptr6_ = (obj);				\
		WITNESS_WARN(WARN_GIANTOK | WARN_SLEEPOK, NULL,		\
		    "%s is called", __func__);				\
		if (ptr6_ != NULL && refcount_release(&ptr6_->weakcount)) { \
			KASSERT(ptr6_->refcount == 0,			\
			    ("invalid refcount: object=%p, refcount=%d", \
				ptr6_, ptr6_->refcount));		\
			(free)(ptr6_);					\
		}							\
	} while (0)

#define KHTTPD_REFCOUNT2_PROTOTYPE(name, type)				\
	struct type *name ## _acquire(struct type *ptr);		\
	struct type *name ## _acquire_checked(struct type *ptr);	\
	struct type *name ## _acquire_weak(struct type *ptr);		\
	void name ## _release(struct type *ptr);			\
	void name ## _release_weak(struct type *ptr)

#define KHTTPD_REFCOUNT2_GENERATE(name, type, dtor, free)		\
	struct type *name ## _acquire(struct type *ptr)			\
	{								\
		KHTTPD_ENTRY(#name "_acquire(%p), refcount=%d,%d",	\
		    ptr, ptr == NULL ? 0 : ptr->refcount,		\
		    ptr == NULL ? 0 : ptr->weakcount);			\
		return (KHTTPD_REFCOUNT2_ACQUIRE(type, ptr));		\
	}								\
	struct type *name ## _acquire_checked(struct type *ptr)		\
	{								\
		KHTTPD_ENTRY(#name "_acquire_checked(%p), "		\
		    "refcount=%d,%d",					\
		    ptr, ptr == NULL ? 0 : ptr->refcount,		\
		    ptr == NULL ? 0 : ptr->weakcount);			\
		return (KHTTPD_REFCOUNT2_ACQUIRE_CHECKED(type, ptr));	\
	}								\
	struct type *name ## _acquire_weak(struct type *ptr)		\
	{								\
		KHTTPD_ENTRY(#name "_acquire_weak(%p), refcount=%d,%d", \
		    ptr, ptr == NULL ? 0 : ptr->refcount,		\
		    ptr == NULL ? 0 : ptr->weakcount);			\
		return (KHTTPD_REFCOUNT2_ACQUIRE_WEAK(type, ptr));	\
	}								\
	void name ## _release(struct type *ptr)				\
	{								\
		KHTTPD_ENTRY(#name "_release(%p), refcount=%d,%d",	\
		    ptr, ptr == NULL ? 0 : ptr->refcount,		\
		    ptr == NULL ? 0 : ptr->weakcount);			\
		KHTTPD_REFCOUNT2_RELEASE(type, ptr, dtor, free);	\
	}								\
	void name ## _release_weak(struct type *ptr)			\
	{								\
		KHTTPD_ENTRY(#name "_release_weak(%p), refcount=%d,%d", \
		    ptr, ptr == NULL ? 0 : ptr->refcount,		\
		    ptr == NULL ? 0 : ptr->weakcount);			\
		KHTTPD_REFCOUNT2_RELEASE_WEAK(type, ptr, free);		\
	}								\
