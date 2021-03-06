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

enum {
	KHTTPD_STATUS_CONTINUE = 100,
	KHTTPD_STATUS_SWITCHING_PROTOCOLS = 101,
	KHTTPD_STATUS_OK = 200,
	KHTTPD_STATUS_CREATED = 201,
	KHTTPD_STATUS_ACCEPTED = 202,
	KHTTPD_STATUS_NON_AUTHORITATIVE_INFORMATION = 203,
	KHTTPD_STATUS_NO_CONTENT = 204,
	KHTTPD_STATUS_RESET_CONTENT = 205,
	KHTTPD_STATUS_PARTIAL_CONTENT = 206,
	KHTTPD_STATUS_MULTIPLE_CHOICES = 300,
	KHTTPD_STATUS_MOVED_PERMANENTLY = 301,
	KHTTPD_STATUS_FOUND = 302,
	KHTTPD_STATUS_SEE_OTHER = 303,
	KHTTPD_STATUS_NOT_MODIFIED = 304,
	KHTTPD_STATUS_USE_PROXY = 305,
	KHTTPD_STATUS_TEMPORARY_REDIRECT = 307,
	KHTTPD_STATUS_BAD_REQUEST = 400,
	KHTTPD_STATUS_UNAUTHORIZED = 401,
	KHTTPD_STATUS_PAYMENT_REQUIRED = 402,
	KHTTPD_STATUS_FORBIDDEN = 403,
	KHTTPD_STATUS_NOT_FOUND = 404,
	KHTTPD_STATUS_METHOD_NOT_ALLOWED = 405,
	KHTTPD_STATUS_NOT_ACCEPTABLE = 406,
	KHTTPD_STATUS_PROXY_AUTHENTICATION_REQUIRED = 407,
	KHTTPD_STATUS_REQUEST_TIMEOUT = 408,
	KHTTPD_STATUS_CONFLICT = 409,
	KHTTPD_STATUS_GONE = 410,
	KHTTPD_STATUS_LENGTH_REQUIRED = 411,
	KHTTPD_STATUS_PRECONDITION_FAILED = 412,
	KHTTPD_STATUS_REQUEST_ENTITY_TOO_LARGE = 413,
	KHTTPD_STATUS_REQUEST_URI_TOO_LONG = 414,
	KHTTPD_STATUS_UNSUPPORTED_MEDIA_TYPE = 415,
	KHTTPD_STATUS_REQUESTED_RANGE_NOT_SATISFIABLE = 416,
	KHTTPD_STATUS_EXPECTATION_FAILED = 417,
	KHTTPD_STATUS_UPGRADE_REQUIRED = 426,
	KHTTPD_STATUS_REQUEST_HEADER_FIELDS_TOO_LARGE = 431,
	KHTTPD_STATUS_INTERNAL_SERVER_ERROR = 500,
	KHTTPD_STATUS_NOT_IMPLEMENTED = 501,
	KHTTPD_STATUS_BAD_GATEWAY = 502,
	KHTTPD_STATUS_SERVICE_UNAVAILABLE = 503,
	KHTTPD_STATUS_GATEWAY_TIMEOUT = 504,
	KHTTPD_STATUS_HTTP_VERSION_NOT_SUPPORTED = 505,
};

#define KHTTPD_STATUS_IS_INFORMATIONAL(x) ((x) / 100 == 1)
#define KHTTPD_STATUS_IS_SUCCESSFUL(x) ((x) / 100 == 2)
#define KHTTPD_STATUS_IS_REDIRECTION(x) ((x) / 100 == 3)
#define KHTTPD_STATUS_IS_CLIENT_ERROR(x) ((x) / 100 == 4)
#define KHTTPD_STATUS_IS_SERVER_ERROR(x) ((x) / 100 == 5)

const char *khttpd_status_default_reason(int _status);
