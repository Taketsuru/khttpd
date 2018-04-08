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

#include <sys/param.h>
#include <sys/socket.h>

#include "khttpd_refcount.h"

struct mbuf;
struct khttpd_costruct_info;
struct khttpd_port;
struct khttpd_socket;
struct khttpd_stream;
struct khttpd_stream_down_ops;

struct khttpd_socket_config {
	struct khttpd_stream	*stream;
	sbintime_t		timeout;
};

typedef int (*khttpd_socket_config_fn_t)(struct khttpd_socket *, void *,
    struct khttpd_socket_config *);

extern struct khttpd_costruct_info *khttpd_port_costruct_info;

KHTTPD_REFCOUNT1_PROTOTYPE(khttpd_port, khttpd_port);

const struct sockaddr *
	khttpd_socket_name(struct khttpd_socket *_sock);
const struct sockaddr *
	khttpd_socket_peer_address(struct khttpd_socket *_sock);
void	khttpd_socket_set_smesg(struct khttpd_socket *_sock,
	    const char *_smesg);
int	khttpd_socket_connect(struct sockaddr *_peeraddr,
	    struct sockaddr *_bindaddr,
	    khttpd_socket_config_fn_t _fn, void *_arg);
void	khttpd_socket_reset(struct khttpd_socket *_sock);
void	khttpd_socket_run_later(struct khttpd_socket *_sock,
	    void (*_fn)(void *), void *_arg);
int	khttpd_socket_set_affinity(struct khttpd_socket *_target,
	    struct khttpd_socket *_source,
	    void (*_notify)(void *), void *_arg);
int	khttpd_port_new(struct khttpd_port **_port_out);
int	khttpd_port_start(struct khttpd_port *_port, struct sockaddr *_addr,
	    khttpd_socket_config_fn_t _fn, void *_arg,
	    const char **_detail_out);
void	khttpd_port_stop(struct khttpd_port *_port);
