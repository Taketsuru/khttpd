/*-
 * Copyright (c) 2016 Taketsuru <taketsuru11@gmail.com>.
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
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
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
#include <sys/malloc.h>

#include "khttpd.h"

#ifdef _KERNEL

struct filedescent;
struct khttpd_mime_type_rule_set;

#ifdef KHTTPD_DEBUG
#define	DTR0(d)				CTR0(KTR_GEN, d)
#define	DTR1(d, p1)			CTR1(KTR_GEN, d, p1)
#define	DTR2(d, p1, p2)			CTR2(KTR_GEN, d, p1, p2)
#define	DTR3(d, p1, p2, p3)		CTR3(KTR_GEN, d, p1, p2, p3)
#define	DTR4(d, p1, p2, p3, p4)		CTR4(KTR_GEN, d, p1, p2, p3, p4)
#define	DTR5(d, p1, p2, p3, p4, p5)	CTR5(KTR_GEN, d, p1, p2, p3, p4, p5)
#define	DTR6(d, p1, p2, p3, p4, p5, p6)	\
	CTR6(KTR_GEN, d, p1, p2, p3, p4, p5, p6)
#else
#define	DTR0(d)				(void)0
#define	DTR1(d, p1)			(void)0
#define	DTR2(d, p1, p2)			(void)0
#define	DTR3(d, p1, p2, p3)		(void)0
#define	DTR4(d, p1, p2, p3, p4)		(void)0
#define	DTR5(d, p1, p2, p3, p4, p5)	(void)0
#define	DTR6(d, p1, p2, p3, p4, p5, p6)	(void)0
#endif

#define KHTTPD_DEBUG_TRACE	0x00000001
#define KHTTPD_DEBUG_ALL	0x00000001

#ifdef KHTTPD_DEBUG

#define DEBUG_ENABLED(mask)					\
	((khttpd_debug_mask & KHTTPD_DEBUG_ ## mask) != 0)
#define DEBUG(fmt, ...)					\
	khttpd_msgbuf_put(__func__, fmt, ## __VA_ARGS__)
#define TRACE(fmt, ...) \
	if (DEBUG_ENABLED(TRACE)) DEBUG(fmt, ## __VA_ARGS__)

extern int khttpd_debug_mask;

#else

#define DEBUG_ENABLED(mask) 0
#define DEBUG(fmt, ...)
#define TRACE(fmt, ...)

#endif

extern struct proc *khttpd_proc;

#define KHTTPD_ASSERT_CURPROC_IS_KHTTPD()				\
	KASSERT(curproc == khttpd_proc,					\
	    ("curproc %d is not the khttpd process", curproc->p_pid))

void *khttpd_malloc(size_t size);
void khttpd_free(void *mem);
void *khttpd_realloc(void *mem, size_t size);
char *khttpd_strdup(const char *str);

void khttpd_msgbuf_put(const char *func, const char *fmt, ...)
	__attribute__ ((__format__ (__printf__, 2, 3)));

void khttpd_access(struct khttpd_server *server, struct khttpd_socket *socket,
    struct khttpd_request *request);
void khttpd_error(struct khttpd_server *server, int severity,
    const char *fmt, ...) __attribute__ ((__format__ (__printf__, 3, 4)));
void khttpd_logger_suspend(void);
void khttpd_logger_resume(void);

char *khttpd_find_ch(const char *begin, const char search);
char *khttpd_find_ch_in(const char *begin, const char *end, char ch);
char *khttpd_skip_whitespace(const char *ptr);
char *khttpd_rskip_whitespace(const char *ptr);
char *khttpd_find_whitespace(const char *ptr, const char *end);
char *khttpd_dup_first_line(const char *str);
char *khttpd_find_list_item_end(const char *begin, const char **sep);
char *khttpd_unquote_uri(char *begin, char *end);
boolean_t khttpd_is_token(const char *start, const char *end);
uint32_t khttpd_hash32_buf_ci(const void *begin, const void *end, 
    uint32_t hash);
uint32_t khttpd_hash32_str_ci(const void *str, uint32_t hash);

int khttpd_json_init(void);
void khttpd_json_fini(void);

int khttpd_sysctl_route(struct khttpd_route *root);

void khttpd_mime_type_rule_set_free(struct khttpd_mime_type_rule_set *);
struct khttpd_mime_type_rule_set *
    khttpd_parse_mime_type_rules(const char *description);
int khttpd_file_mount(const char *path, struct khttpd_route *root,
    int rootdirfd, struct khttpd_mime_type_rule_set *rules);
int khttpd_file_init(void);
void khttpd_file_fini(void);

int khttpd_sdt_mount(struct khttpd_route *root, const char *prefix);
int khttpd_sdt_load(void);
void khttpd_sdt_unload(void);
int khttpd_sdt_quiesce(void);

int khttpd_ktr_logging_init(void);
void khttpd_ktr_logging_fini(void);

#endif	/* _KERNEL */
