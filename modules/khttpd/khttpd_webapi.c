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
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "khttpd_webapi.h"

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/hash.h>
#include <sys/mbuf.h>
#include <sys/sbuf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>

#include <netinet/in.h>

#include "khttpd_json.h"
#include "khttpd_ktr.h"
#include "khttpd_log.h"
#include "khttpd_mbuf.h"
#include "khttpd_problem.h"
#include "khttpd_status_code.h"
#include "khttpd_string.h"
#include "khttpd_strtab.h"

int
khttpd_webapi_get_string_property(const char **value_out, const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = NULL;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_problem_no_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_STRING) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = khttpd_json_string_data(value_j);

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_integer_property(int64_t *value_out, const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = 0;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_problem_no_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_INTEGER) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = khttpd_json_integer_value(value_j);

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_object_property(struct khttpd_json **value_out,
    const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = 0;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_problem_no_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_OBJECT) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = value_j;

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_array_property(struct khttpd_json **value_out,
    const char *name,
    struct khttpd_problem_property *input_prop_spec, struct khttpd_json *input,
    struct khttpd_mbuf_json *output, boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec;
	struct khttpd_json *value_j;

	KASSERT(khttpd_json_type(input) == KHTTPD_JSON_OBJECT,
	    ("wrong type %d", khttpd_json_type(input)));

	prop_spec.link = input_prop_spec;
	prop_spec.name = name;
	value_j = khttpd_json_object_get(input, name);
	if (value_j == NULL) {
		if (may_not_exist) {
			*value_out = 0;
			return (KHTTPD_STATUS_NO_CONTENT);
		}
		khttpd_problem_no_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (khttpd_json_type(value_j) != KHTTPD_JSON_ARRAY) {
		khttpd_problem_wrong_type_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	*value_out = value_j;

	return (KHTTPD_STATUS_OK);
}

int
khttpd_webapi_get_sockaddr_property(struct sockaddr *addr, socklen_t len,
    const char *name,
    struct khttpd_problem_property *input_prop_spec,
    struct khttpd_json *input, struct khttpd_mbuf_json *output,
    boolean_t may_not_exist)
{
	struct khttpd_problem_property prop_spec[2];
	struct sockaddr_un *un;
	struct sockaddr_in *in;
	struct sockaddr_in6 *in6;
	struct khttpd_json *obj_j;
	const char *family, *address;
	uint32_t ipaddr;
	in_port_t *port_field;
	size_t alen;
	int64_t port;
	int status;

	status = khttpd_webapi_get_object_property(&obj_j, name, 
	    input_prop_spec, input, output, may_not_exist);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	prop_spec[0].name = name;
	prop_spec[0].link = input_prop_spec;

	status = khttpd_webapi_get_string_property(&family, "family",
	    &prop_spec[0], obj_j, output, FALSE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	status = khttpd_webapi_get_string_property(&address, "address",
	    &prop_spec[0], obj_j, output, TRUE);
	if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
		return (status);

	port_field = NULL;

	prop_spec[1].name = "address";
	prop_spec[1].link = &prop_spec[0];

	if (strcmp(family, "unix") == 0) {
		if (address == NULL) {
			khttpd_problem_no_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec[1]);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		if (address[0] != '/') {
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_detail(output, 
			    "absolute path only");
			khttpd_problem_set_property(output, &prop_spec[1]);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		un = (struct sockaddr_un *)addr;
		alen = offsetof(struct sockaddr_un, sun_path) + strlen(address)
		    + 1;
		if (len < MIN(sizeof(struct sockaddr_un), alen)) {
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec[1]);
			khttpd_problem_set_detail(output, "too long");
			return (KHTTPD_STATUS_BAD_REQUEST);
		}
		un->sun_len = alen;
		un->sun_family = AF_UNIX;
		strlcpy(un->sun_path, address,
		    len - offsetof(struct sockaddr_un, sun_path));

	} else if (strcmp(family, "inet") == 0) {
		in = (struct sockaddr_in *)addr;
		port_field = &in->sin_port;
		in->sin_len = sizeof(struct sockaddr_in);
		in->sin_family = AF_INET;
		if (address == NULL) {
			in->sin_addr.s_addr = htonl(INADDR_ANY);
		} else if (khttpd_parse_ip_addresss(&ipaddr, address) == 0) {
			in->sin_addr.s_addr = htonl(ipaddr);
		} else {
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec[1]);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

	} else if (strcmp(family, "inet6") == 0) {
		in6 = (struct sockaddr_in6 *)addr;
		port_field = &in6->sin6_port;
		bzero(in6, sizeof(*in6));
		in6->sin6_len = sizeof(struct sockaddr_in6);
		in6->sin6_family = AF_INET6;
		if (address == NULL) {
			in6->sin6_addr = in6addr_any;
		} else if (khttpd_parse_ipv6_address(in6->sin6_addr.s6_addr,
			address) != 0) {
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec[1]);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

	} else {
		prop_spec[1].name = "family";
		khttpd_problem_invalid_value_response_begin(output);
		khttpd_problem_set_property(output, &prop_spec[1]);
		return (KHTTPD_STATUS_BAD_REQUEST);
	}

	if (port_field != NULL) {
		status = khttpd_webapi_get_integer_property(&port, "port",
		    &prop_spec[0], obj_j, output, FALSE);
		if (!KHTTPD_STATUS_IS_SUCCESSFUL(status))
			return (status);

		if (port < 1 || IPPORT_MAX < port) {
			prop_spec[1].name = "port";
			khttpd_problem_invalid_value_response_begin(output);
			khttpd_problem_set_property(output, &prop_spec[1]);
			return (KHTTPD_STATUS_BAD_REQUEST);
		}

		*port_field = htons(port);
	}

	return (KHTTPD_STATUS_OK);
}
