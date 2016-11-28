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

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/socket.h>
#include <machine/stdarg.h>

#include "khttpd_event.h"
#include "khttpd_refcount.h"

struct mbuf;
struct khttpd_port;
struct khttpd_socket;
struct khttpd_stream;
struct khttpd_stream_down_ops;

extern struct khttpd_stream_down_ops khttpd_socket_ops;
extern struct khttpd_costruct_info *khttpd_port_costruct_info;

KHTTPD_REFCOUNT1_PROTOTYPE(khttpd_port, khttpd_port);

int khttpd_port_new(struct khttpd_port **port_out);
int khttpd_port_start(struct khttpd_port *port, struct sockaddr *addr,
    khttpd_event_fn_t accept_handler, const char **detail_out);
void khttpd_port_stop(struct khttpd_port *port);

struct khttpd_socket *khttpd_socket_new(void);
int khttpd_socket_start(struct khttpd_socket *socket,
    struct khttpd_stream *stream, struct khttpd_port *port,
    const char **detail_out);
const struct sockaddr *khttpd_socket_peer_address
    (struct khttpd_socket *socket);

/*
 * XXX This is a tentative hack.  This function assumes the down side of the
 * stream is a socket.
 */
int khttpd_stream_get_fd(struct khttpd_stream *stream);

#endif	/* _KERNEL */
