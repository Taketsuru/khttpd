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
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sysexits.h>

#include "../../modules/khttpd/khttpd.h"

int main(int argc, char **argv)
{
	struct sockaddr_storage addr;
	struct addrinfo ai_hint, *ai_list, *ai_ptr;
	struct khttpd_log_conf log_conf;
	struct khttpd_address_info kai;
	int fd, gai_error;

	fd = open("/dev/khttpd", O_RDWR);
	if (fd == -1)
		err(EX_UNAVAILABLE, "failed to open /dev/khttpd");

	log_conf.type = KHTTPD_LOG_DEBUG;
	log_conf.mask = KHTTPD_LOG_DEBUG_ALL;
	log_conf.path = "/home/taketsuru/work/khttpd/debug.log";
	if (ioctl(fd, KHTTPD_IOC_CONFIGURE_LOG, &log_conf) == -1)
		err(EX_UNAVAILABLE, "failed to configure debug log");

	bzero(&ai_hint, sizeof(ai_hint));
	ai_hint.ai_flags = AI_PASSIVE;
	ai_hint.ai_family = PF_UNSPEC;
	ai_hint.ai_socktype = SOCK_STREAM;
	ai_hint.ai_protocol = 0;

	gai_error = getaddrinfo(NULL, "http", &ai_hint, &ai_list);
	if (gai_error != 0)
		errx(EX_UNAVAILABLE, "failed to get address info: %s",
		    gai_strerror(gai_error));

	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		if (sizeof(kai.ai_addr) < ai_ptr->ai_addrlen)
			errx(EX_CONFIG, "address length too long: "
			    "addrlen=%d, family=%d, socktype=%d, protocol=%d",
			    ai_ptr->ai_addrlen, ai_ptr->ai_family,
			    ai_ptr->ai_socktype, ai_ptr->ai_protocol);

		bzero(&kai, sizeof(kai));
		bcopy(ai_ptr->ai_addr, &kai.ai_addr, ai_ptr->ai_addrlen);
		kai.ai_family = ai_ptr->ai_family;
		kai.ai_protocol = ai_ptr->ai_protocol;
		kai.ai_socktype = ai_ptr->ai_socktype;

		if (ioctl(fd, KHTTPD_IOC_ADD_SERVER_PORT, &kai) == -1)
			err(EX_UNAVAILABLE, "failed to add server port");
	}

	freeaddrinfo(ai_list);

	return (0);
}
