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
#include <sys/linker_set.h>
#include <sys/eventhandler.h>

struct module;

enum {
	KHTTPD_INIT_PHASE_LOCAL = 1,

	/* define costructs */
	KHTTPD_INIT_PHASE_REGISTER_COSTRUCTS = 4,

	/* call khttpd_event_new_* / khttpd_job_new */
	KHTTPD_INIT_PHASE_REGISTER_EVENTS = 7,

	/* call khttpd_event_new_* / khttpd_job_new */
	KHTTPD_INIT_PHASE_REGISTER_LOCATION_TYPES = 10,

	/* start */
	KHTTPD_INIT_PHASE_RUN = 13
};

typedef int	(*khttpd_init_fn_t)(void);
typedef void	(*khttpd_fini_fn_t)(void);
typedef void	(*khttpd_init_shutdown_fn_t)(void *);

struct khttpd_init {
	const char		*name;
	const char		*file;
	khttpd_init_fn_t	init;
	khttpd_fini_fn_t	fini;
	int			phase;
	const char		*dependee[];
};

#define KHTTPD_INIT_LEN_(_d, _1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N
#define KHTTPD_INIT_LEN(dum, ...) KHTTPD_INIT_LEN_(dum, ## __VA_ARGS__, \
	    9, 8, 7, 6, 5, 4, 3, 2, 1, 0)

#define KHTTPD_INIT_DEP_0() NULL
#define KHTTPD_INIT_DEP_1(x) #x, NULL
#define KHTTPD_INIT_DEP_2(x, ...) #x, KHTTPD_INIT_DEP_1(__VA_ARGS__)
#define KHTTPD_INIT_DEP_3(x, ...) #x, KHTTPD_INIT_DEP_2(__VA_ARGS__)
#define KHTTPD_INIT_DEP_4(x, ...) #x, KHTTPD_INIT_DEP_3(__VA_ARGS__)
#define KHTTPD_INIT_DEP_5(x, ...) #x, KHTTPD_INIT_DEP_4(__VA_ARGS__)
#define KHTTPD_INIT_DEP_6(x, ...) #x, KHTTPD_INIT_DEP_5(__VA_ARGS__)
#define KHTTPD_INIT_DEP_7(x, ...) #x, KHTTPD_INIT_DEP_6(__VA_ARGS__)
#define KHTTPD_INIT_DEP_8(x, ...) #x, KHTTPD_INIT_DEP_7(__VA_ARGS__)
#define KHTTPD_INIT_DEP_9(x, ...) #x, KHTTPD_INIT_DEP_8(__VA_ARGS__)

#define KHTTPD_INIT(name, init, fini, phase, ...)			\
	static struct khttpd_init __CONCAT(khttpd_init_, __LINE__) = {	\
		#name, __FILE__, (init), (fini), (phase), {		\
			__CONCAT(KHTTPD_INIT_DEP_,			\
			    KHTTPD_INIT_LEN(dum, ##__VA_ARGS__))(__VA_ARGS__) \
		}							\
	};								\
	SET_ENTRY(khttpd_init_set, __CONCAT(khttpd_init_, __LINE__))

EVENTHANDLER_DECLARE(khttpd_init_shutdown, khttpd_init_shutdown_fn_t);

int	khttpd_init_get_phase(void);
int	khttpd_init_quiesce(void);
int	khttpd_init_run_focusing(void (*_fn)(int), const char **_files,
	    int _nfiles);
void	khttpd_init_unload(struct module *_mod);
void	khttpd_init_wait_load_completion(struct module *_mod);

inline int
khttpd_init_run(void (*_fn)(int))
{

	return (khttpd_init_run_focusing(_fn, NULL, 0));
}
