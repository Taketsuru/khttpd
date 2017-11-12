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
#include <sys/mman.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#ifndef KHTTPD_TEST_REPORT_PATH
#define KHTTPD_TEST_REPORT_PATH "report.xml"
#endif

#ifndef KHTTPD_TEST_REPORT_SIZE_MAX
#define KHTTPD_TEST_REPORT_SIZE_MAX	(256ul*1024*1024)
#endif

struct command {
	const char *name;
	void (*handler)(int argc, char **argv);
};

static void do_load_command(int argc, char **argv);
static void do_test_command(int argc, char **argv);
static void do_stop_command(int argc, char **argv);

static struct command command_table[] = {
	{
		.name = "stop",
		.handler = do_stop_command
	},
	{
		.name = "test",
		.handler = do_test_command
	},
	{
		.name = "load",
		.handler = do_load_command
	}
};

static int dev_fd;

static void
do_load_command(int argc, char **argv)
{
	struct sbuf sbuf;
	struct khttpd_ioctl_start_args ioctl_args;
	char *buf;
	const char *config;
	size_t bufsize;
	ssize_t rsize;
	int fd;

	if (argc != 3) {
		fprintf(stderr, "usage) %s load file\n", argv[0]);
		exit(EX_USAGE);
	}

	config = argv[2];

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
do_test_command(int argc, char **argv)
{
	struct sbuf sbuf;
	struct khttpd_ioctl_test_args ioctl_args;
	void *buf;
	size_t buf_size;
	int error, fd, i;

	sbuf_new(&sbuf, NULL, 0, SBUF_AUTOEXTEND | SBUF_INCLUDENUL);
	for (i = 2; i < argc; ++i) {
		if (2 < i)
			sbuf_putc(&sbuf, ',');
		sbuf_cat(&sbuf, argv[i]);
	}

	fd = open(KHTTPD_TEST_REPORT_PATH, O_RDWR | O_TRUNC | O_CREAT, 0666);
	if (fd == -1)
		err(EX_CANTCREAT, "failed to create %s",
		    KHTTPD_TEST_REPORT_PATH);

	error = ftruncate(fd, KHTTPD_TEST_REPORT_SIZE_MAX);
	if (error == -1)
		err(EX_IOERR, "failed to write to %s",
		    KHTTPD_TEST_REPORT_PATH);

	buf = mmap(NULL, KHTTPD_TEST_REPORT_SIZE_MAX, PROT_READ | PROT_WRITE,
	    MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		err(EX_OSERR, "failed to allocate a buffer");

	sbuf_finish(&sbuf);
	ioctl_args.filter = sbuf_data(&sbuf);
	ioctl_args.filter_len = sbuf_len(&sbuf);
	ioctl_args.buf = buf;
	ioctl_args.buf_size = KHTTPD_TEST_REPORT_SIZE_MAX;

	if (ioctl(dev_fd, KHTTPD_IOC_TEST, &ioctl_args) == -1)
		err(EX_DATAERR, "failed to run tests");

	sbuf_delete(&sbuf);

	buf_size = ioctl_args.buf_size;
	if (ioctl_args.buf[buf_size - 1] == '\0')
		--buf_size;

	munmap(ioctl_args.buf, KHTTPD_TEST_REPORT_SIZE_MAX);

	ftruncate(fd, buf_size);
	close(fd);
}

static void
do_stop_command(int argc, char **argv)
{

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

	dev_fd = open("/dev/khttpd", O_RDWR);
	if (dev_fd == -1)
		err(EX_CONFIG, "Can't find /dev/khttpd.  Is khttpd running?");

	cmd = find_command(argv[1]);
	if (cmd == NULL) {
		fprintf(stderr, "Unknown command \"%s\"\n", argv[1]);
		exit(EX_USAGE);
	}

	cmd->handler(argc, argv);

	return (0);
}
