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

#include <sys/types.h>

struct mbuf;
struct sbuf;

struct khttpd_exchange;
struct khttpd_json;
struct khttpd_location;
struct khttpd_location_ops;
struct khttpd_mbuf_json;
struct khttpd_obj_type;
struct khttpd_server;
struct khttpd_problem_property;

extern struct khttpd_obj_type khttpd_ctrl_rewriters;
extern struct khttpd_obj_type khttpd_ctrl_ports;
extern struct khttpd_obj_type khttpd_ctrl_servers;
extern struct khttpd_obj_type khttpd_ctrl_locations;

int khttpd_ctrl_parse_json(struct khttpd_json **value_out,
    struct khttpd_mbuf_json *response, struct mbuf *input);

void khttpd_obj_type_get_id(struct khttpd_obj_type *type,
    void *object, struct sbuf *output);
int khttpd_obj_type_get_obj_from_property(struct khttpd_obj_type *type,
    void **obj_out, const char *name, struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, boolean_t may_not_exist);

typedef int (*khttpd_ctrl_location_create_fn_t)
    (struct khttpd_location **location_out, struct khttpd_server *server,
     const char *path, struct khttpd_mbuf_json *output,
     struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input);
typedef int (*khttpd_ctrl_location_delete_fn_t)
    (struct khttpd_location *location, struct khttpd_mbuf_json *output);
typedef void (*khttpd_ctrl_location_get_fn_t)
    (struct khttpd_location *location, struct khttpd_mbuf_json *output);
typedef int (*khttpd_ctrl_location_put_fn_t)
    (struct khttpd_location *location, struct khttpd_mbuf_json *output,
     struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input);

int khttpd_location_type_create_location(struct khttpd_location **location_out,
    struct khttpd_server *server, const char *path,
    struct khttpd_mbuf_json *output,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, struct khttpd_location_ops *ops, void *arg);
void khttpd_location_type_register(const char *name, 
    khttpd_ctrl_location_create_fn_t create, 
    khttpd_ctrl_location_delete_fn_t delete, khttpd_ctrl_location_get_fn_t get,
    khttpd_ctrl_location_put_fn_t put);
void khttpd_location_type_deregister(const char *name);

#endif	/* _KERNEL */
