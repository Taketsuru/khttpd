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

#ifdef _KERNEL

struct khttpd_mbuf_json;
struct khttpd_json;
struct khttpd_port;
struct khttpd_server;
struct khttpd_server_name;
struct khttpd_vhost_tie;

struct khttpd_server_name *khttpd_vhost_server_name_new(void);
void khttpd_vhost_server_name_delete(struct khttpd_server_name *name);

void khttpd_vhost_set_canonical_name(struct khttpd_server_name *name,
    const char *value);
const char *khttpd_vhost_get_canonical_name(struct khttpd_server_name *name);
void khttpd_vhost_set_exact_alias_list(struct khttpd_server_name *name,
    const char **aliases, int n);
int khttpd_vhost_get_exact_alias_list_length(struct khttpd_server_name *name);
const char *khttpd_vhost_get_exact_alias(struct khttpd_server_name *name,
    int index);

void khttpd_vhost_set_server_name(struct khttpd_server *server,
    struct khttpd_server_name *name);
struct khttpd_server_name *
khttpd_vhost_copy_server_name(struct khttpd_server *server);

void khttpd_vhost_set_port_list(struct khttpd_server *server,
    struct khttpd_port **port_list, int len);
void khttpd_vhost_set_server_list(struct khttpd_port *port,
    struct khttpd_server **server_list, int len);
void khttpd_vhost_clear_port_list(struct khttpd_server *server);
void khttpd_vhost_clear_server_list(struct khttpd_port *port);
struct khttpd_server *khttpd_vhost_find_server(struct khttpd_port *port,
    const char *host);
struct khttpd_vhost_tie *
khttpd_vhost_port_iterator(struct khttpd_server *server);
struct khttpd_vhost_tie *
khttpd_vhost_port_iterator_next(struct khttpd_vhost_tie *iterator,
    struct khttpd_port **port_out);

#endif	/* _KERNEL */
