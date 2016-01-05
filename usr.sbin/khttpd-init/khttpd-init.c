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
#include <sys/un.h>
#include <sys/stat.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>

#include "../../modules/khttpd/khttpd.h"

static int debug_level;

struct fdvec {
	int *memory;
	int len;
	int storage;
};

static void
add_element(struct fdvec *fdvec, int elem)
{
	if (fdvec->storage < fdvec->len + 1) {
		fdvec->storage += fdvec->storage >> 1;
		if (fdvec->storage < 8)
			fdvec->storage = 8;
		fdvec->memory = realloc(fdvec->memory,
		    sizeof(int) * fdvec->storage);
		if (fdvec->memory == NULL)
			errc(EX_OSERR, ENOMEM, "too many file descriptors");
	}
	fdvec->memory[fdvec->len++] = elem;
}

static void
open_server_port(struct fdvec *fdvec, int family, const char *name)
{
	struct addrinfo ai_hint, *ai_list, *ai_ptr;
	int fd, gai_error;

	bzero(&ai_hint, sizeof(ai_hint));
	ai_hint.ai_flags = AI_PASSIVE;
	ai_hint.ai_family = family;
	ai_hint.ai_socktype = SOCK_STREAM;
	ai_hint.ai_protocol = 0;

	gai_error = getaddrinfo(name, "http", &ai_hint, &ai_list);
	if (gai_error != 0)
		errx(EX_NOHOST, "failed to get address info: %s",
		    gai_strerror(gai_error));

	for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
		fd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype,
		    ai_ptr->ai_protocol);
		if (fd == -1)
			err(EX_OSERR, "failed to open a socket");

		if (bind(fd, ai_ptr->ai_addr, ai_ptr->ai_addrlen) == -1)
			err(EX_NOHOST, "failed to bind socket.");

		add_element(fdvec, fd);
	}

	freeaddrinfo(ai_list);
}

int main(int argc, char **argv)
{
	struct sockaddr_un unix_addr;
	struct khttpd_config_admin_args args;
	struct fdvec fdvec;
	const char *passwd_file;
	const char *admin_root_path;
	size_t len;
	int ch, devfd, sockfd;

	bzero(&fdvec, sizeof(fdvec));

	admin_root_path = "/usr/share/khttpd/admin_docs";
	passwd_file = NULL;

	while ((ch = getopt(argc, argv, "4::6::a:dr:u:")) != -1) {
		switch (ch) {

		case '4':	/* -4 <address>: open IPv4 socket */
			if (0 < debug_level)
				printf("open an IPv4 socket: '%s'\n",
				    optarg == NULL ? "<anonymous>" : optarg);
			open_server_port(&fdvec, PF_INET, optarg);
			break;

		case '6':	/* -6 <address>: open IPv6 socket */
			if (0 < debug_level)
				printf("open an IPv6 socket: '%s'\n",
				    optarg == NULL ? "<anonymous>" : optarg);
			open_server_port(&fdvec, PF_INET6, optarg);
			break;

		case 'a':	/* -a <passwd file>: require authentication */
			if (0 < debug_level)
				printf("require authentication: '%s'\n",
				    optarg == NULL ? "<none>" : optarg);
			passwd_file = optarg;
			break;

		case 'd':
			++debug_level;
			break;

		case 'r':
			if (0 < debug_level)
				printf("admin root directory: '%s'\n",
				    optarg == NULL ? "<none>" : optarg);
			admin_root_path = optarg;
			break;

		case 'u':	/* -u <path>: UNIX domain socket */
			if (0 < debug_level)
				printf("Open a UNIX domain socket: '%s'\n",
				    optarg == NULL ? "<null>" : optarg);
			len = strlcpy(unix_addr.sun_path, optarg,
			    sizeof(unix_addr.sun_path));
			if (sizeof(unix_addr.sun_path) <= len)
				errc(EX_USAGE, ENAMETOOLONG,
				    "failed to create a UNIX domain socket");
			unix_addr.sun_len =
			    offsetof(struct sockaddr_un, sun_path) + len;
			unix_addr.sun_family = AF_UNIX;

			sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
			if (sockfd == -1)
				err(EX_OSERR, "failed to open a socket");

			unlink(unix_addr.sun_path);
			if (bind(sockfd, (struct sockaddr *)&unix_addr,
				unix_addr.sun_len) == -1)
				err(EX_NOHOST, "failed to bind socket.");

			if (chmod(unix_addr.sun_path, 0600) == -1)
				err(EX_NOHOST, "failed to chmod the socket.");

			add_element(&fdvec, sockfd);
			break;

		default:
			err(EX_USAGE, "");
		}
	}

	devfd = open("/dev/khttpd", O_RDWR);
	if (devfd == -1)
		err(EX_UNAVAILABLE, "failed to open /dev/khttpd");

	args.rootfd = open(admin_root_path, O_DIRECTORY|O_EXEC);
	if (args.rootfd == -1)
		err(EX_NOINPUT, "failed to open admin root directory.");

	args.fds = fdvec.memory;
	args.nfds = fdvec.len;

	if (ioctl(devfd, KHTTPD_IOC_CONFIG_ADMIN, &args) == -1)
		err(EX_OSERR, "failed to ioctl().");

	return (0);
}
