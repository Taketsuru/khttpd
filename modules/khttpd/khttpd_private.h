/*-
 * Copyright (c) 2015 Taketsuru <taketsuru11@gmail.com>.
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

#ifdef _KERNEL

MALLOC_DECLARE(M_KHTTPD);

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

#define ERROR(fmt, ...) \
	khttpd_log(KHTTPD_LOG_ERROR, fmt, ## __VA_ARGS__)

#ifdef KHTTPD_DEBUG

#define DEBUG_ENABLED(MASK)				\
	((khttpd_log_state[KHTTPD_LOG_DEBUG].mask &	\
	    KHTTPD_LOG_DEBUG_ ## MASK) != 0)
#define DEBUG(fmt, ...) \
	khttpd_log(KHTTPD_LOG_DEBUG, fmt, __func__, ## __VA_ARGS__)
#define TRACE(fmt, ...) \
	if (DEBUG_ENABLED(TRACE)) DEBUG(fmt, ## __VA_ARGS__)

#else

#define DEBUG_ENABLED(MASK) 0
#define DEBUG(fmt, ...)
#define TRACE(fmt, ...)

#endif

struct khttpd_log_state {
	u_int	mask;
	int	fd;
};

extern struct khttpd_log_state khttpd_log_state[];

void khttpd_log(int type, const char *fmt, ...);

char *khttpd_find_ch(const char *begin, const char search);
char *khttpd_find_ch_in(const char *begin, const char *end, char ch);
char *khttpd_skip_whitespace(const char *ptr);
char *khttpd_rskip_whitespace(const char *ptr);
char *khttpd_find_whitespace(const char *ptr, const char *end);
char *khttpd_dup_first_line(const char *str);
char *khttpd_find_list_item_end(const char *begin, const char **sep);
char *khttpd_unquote_uri(char *begin, char *end);
boolean_t khttpd_is_token(const char *start, const char *end);
uint32_t khttpd_hash32_buf_ci(const char *begin, const char *end);
uint32_t khttpd_hash32_str_ci(const char *str);

int khttpd_json_init(void);
void khttpd_json_fini(void);

int khttpd_sysctl_load(void);
void khttpd_sysctl_unload(void);

int khttpd_mount(struct khttpd_mount_args *data);
int khttpd_set_mime_type_rules(struct khttpd_set_mime_type_rules_args *args);
int khttpd_file_init(void);
void khttpd_file_fini(void);

int khttpd_sdt_load(void);
void khttpd_sdt_unload(void);
int khttpd_sdt_quiesce(void);

#endif	/* _KERNEL */
