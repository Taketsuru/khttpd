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

typedef void (*khttpd_gcov_fn)(void);

void	llvm_gcda_start_file(const char *_filename, const char _version[4],
	    uint32_t _checksum);
void	llvm_gcda_increment_indirect_counter(uint32_t *_predecessor,
	    uint64_t **_counters);
void	llvm_gcda_emit_function(uint32_t _ident, const char *_function_name,
	    uint32_t _func_checksum, uint8_t _use_extra_checksum,
	    uint32_t _cfg_checksum);
void	llvm_gcda_emit_arcs(uint32_t _num_counters, uint64_t *_counters);
void	llvm_gcda_summary_info(void);
void	llvm_gcda_end_file(void);
void	__gcov_flush(void);
void	llvm_gcov_init(khttpd_gcov_fn _wfn, khttpd_gcov_fn _ffn);
void	khttpd_gcov_init(void);
void	khttpd_gcov_fini(void);
