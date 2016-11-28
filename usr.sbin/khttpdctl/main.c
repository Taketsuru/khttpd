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

#include "khttpd.h"

#include <sys/types.h>
#include <sys/sbuf.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

struct command {
	const char *name;
	void (*handler)(int argc, char **argv, int *index);
};

static void do_load_command(int argc, char **argv, int *index);
static void do_stop_command(int argc, char **argv, int *index);

static struct command command_table[] = {
	{
		.name = "load",
		.handler = do_load_command
	},
	{
		.name = "stop",
		.handler = do_stop_command
	}
};

static int dev_fd;

static void
do_load_command(int argc, char **argv, int *index)
{
	struct sbuf sbuf;
	struct khttpd_ioctl_start_args ioctl_args;
	char *buf;
	const char *config;
	size_t bufsize;
	ssize_t rsize;
	int fd;

	if (argc <= ++*index)
		err(EX_USAGE, "configuration file name is expected");

	config = argv[*index++];

	if (strcmp(config, "-") == 0)
		fd = STDIN_FILENO;
	else {
		fd = open(config, O_RDONLY);
		if (fd == -1)
			err(EX_NOINPUT, "can't open configuration file \"%s\"",
			    config);
	}

	bufsize = 65536;
	buf = malloc(bufsize);
	sbuf_new(&sbuf, NULL, 0, SBUF_AUTOEXTEND);

	for (;;) {
		rsize = read(fd, buf, bufsize);
		if (rsize == -1)
			err(EX_IOERR, "failed to read configuration file "
			    "\"%s\"", config);
		if (rsize == 0)
			break;
		sbuf_bcat(&sbuf, buf, rsize);
	}
	sbuf_finish(&sbuf);

	ioctl_args.data = sbuf_data(&sbuf);
	ioctl_args.size = sbuf_len(&sbuf);
	if (ioctl(dev_fd, KHTTPD_IOC_START, &ioctl_args) == -1)
		err(EX_DATAERR, "configuration error");

	sbuf_delete(&sbuf);
	free(buf);
}

static void
do_stop_command(int argc, char **argv, int *index)
{

	++*index;

	if (ioctl(dev_fd, KHTTPD_IOC_STOP, 0) == -1)
		err(EX_DATAERR, "failed to stop the server");
}

static struct command *
find_command(const char *name)
{
	int i;

	for (i = 0; i < sizeof(command_table) / sizeof(command_table[0]); ++i)
		if (strcmp(command_table[i].name, name) == 0)
			return (&command_table[i]);
	return (NULL);
}

int
main(int argc, char **argv)
{
	struct command *cmd;
	int i;

	dev_fd = open("/dev/khttpd", O_RDWR);
	if (dev_fd == -1)
		err(EX_CONFIG, "Can't find /dev/khttpd.  Is khttpd running?");

	for (i = 1; i < argc; ++i) {
		cmd = find_command(argv[i]);
		if (cmd == NULL)
			err(EX_USAGE, "Unknown command \"%s\"", argv[i]);

		cmd->handler(argc, argv, &i);
	}

	return (0);
}
