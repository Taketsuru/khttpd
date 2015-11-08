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
 * DISCLAIMED.	IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/hash.h>
#include <sys/refcount.h>
#include <sys/syslimits.h>
#include <sys/eventhandler.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#include <sys/fcntl.h>
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>

#include <vm/uma.h>

#include <netinet/in.h>

#include <machine/stdarg.h>

#include "khttpd.h"

#ifndef KHTTPD_LISTEN_BACKLOG
#define KHTTPD_LISTEN_BACKLOG 128
#endif

/* The maximum size of a line in a header-field and a start-line */
#ifndef KHTTPD_LINE_MAX
#define KHTTPD_LINE_MAX 4096
#endif

#ifndef KHTTPD_METHOD_HASH_SIZE
#define KHTTPD_METHOD_HASH_SIZE	64
#endif

#ifndef KHTTPD_HEADER_HASH_SIZE
#define KHTTPD_HEADER_HASH_SIZE 8
#endif

/* The maximum size of a message excluding message body */
#ifndef KHTTPD_MAX_HEADER_SIZE
#define KHTTPD_MAX_HEADER_SIZE \
	(8192 - (sizeof(void *) * (KHTTPD_HEADER_HASH_SIZE * 2 + 2)))
#endif

#ifndef KHTTPD_SYS_PREFIX
#define KHTTPD_SYS_PREFIX "/sys"
#endif

#ifndef KHTTPD_SYSCTL_PREFIX
#define KHTTPD_SYSCTL_PREFIX KHTTPD_SYS_PREFIX "/sysctl"
#endif

#ifndef KHTTPD_JSON_EMBEDDED_DATA_SIZE
#define KHTTPD_JSON_EMBEDDED_DATA_SIZE	(128 - 32)
#endif

#ifndef KHTTPD_JSON_DEPTH_MAX
#define KHTTPD_JSON_DEPTH_MAX	16
#endif

#ifndef KHTTPD_SYSCTL_PUT_MAX
#define KHTTPD_SYSCTL_PUT_MAX	4096
#endif

#ifdef KHTTPD_DEBUG
#define	DTR0(d)				CTR0(KTR_GEN, d)
#define	DTR1(d, p1)			CTR1(KTR_GEN, d, p1)
#define	DTR2(d, p1, p2)			CTR2(KTR_GEN, d, p1, p2)
#define	DTR3(d, p1, p2, p3)		CTR3(KTR_GEN, d, p1, p2, p3)
#define	DTR4(d, p1, p2, p3, p4)		CTR4(KTR_GEN, d, p1, p2, p3, p4)
#define	DTR5(d, p1, p2, p3, p4, p5)	CTR5(KTR_GEN, d, p1, p2, p3, p4, p5)
#define	DTR6(d, p1, p2, p3, p4, p5, p6)	CTR6(KTR_GEN, d, p1, p2, p3, p4, p5, p6)
#else
#define	DTR0(d)				(void)0
#define	DTR1(d, p1)			(void)0
#define	DTR2(d, p1, p2)			(void)0
#define	DTR3(d, p1, p2, p3)		(void)0
#define	DTR4(d, p1, p2, p3, p4)		(void)0
#define	DTR5(d, p1, p2, p3, p4, p5)	(void)0
#define	DTR6(d, p1, p2, p3, p4, p5, p6)	(void)0
#endif

#define ERROR(fmt, ...) \
	khttpd_log(KHTTPD_LOG_ERROR, fmt, ## __VA_ARGS__)

#ifdef KHTTPD_DEBUG

#define DEBUG_ENABLED(MASK)				\
	((khttpd_log_state[KHTTPD_LOG_DEBUG].mask &	\
	    KHTTPD_LOG_DEBUG_ ## MASK) != 0)
#define DEBUG(fmt, ...) \
	khttpd_log(KHTTPD_LOG_DEBUG, fmt, __func__, ## __VA_ARGS__)
#define TRACE(fmt, ...) \
	if (DEBUG_ENABLED(TRACE)) DEBUG(fmt, ## __VA_ARGS__)

#else

#define DEBUG_ENABLED(MASK) 0
#define DEBUG(fmt, ...)
#define TRACE(fmt, ...)

#endif

/* --------------------------------------------------------- Type definitions */

/* possible values of khttpd_state */
enum {
	/* the server process has not finished its initialization yet */
	KHTTPD_LOADING = 0,

	/* the server process is exiting. */
	KHTTPD_UNLOADING,

	/* failed to initialize and the requester has not noticed it yet. */
	KHTTPD_FAILED,

	/* the server is ready to serve http requests.	*/
	KHTTPD_READY,
};

enum {
	KHTTPD_NO_SKIP = '\377'
};

struct khttpd_command;
typedef int (*khttpd_command_proc_t)(void *);

struct khttpd_command {
	STAILQ_ENTRY(khttpd_command) link;
	khttpd_command_proc_t command;
	void		*argument;
	int		status;
};

struct khttpd_kevent_args {
	const struct kevent *changelist;
	struct kevent	    *eventlist;
};

typedef void (*khttpd_handle_event_t)(struct kevent *);

struct khttpd_event_type {
	khttpd_handle_event_t handle_event;
};

struct khttpd_server_port {
	/* must be &event_type == &<this struct> */
	struct khttpd_event_type	event_type;
	SLIST_ENTRY(khttpd_server_port)	link;
	struct khttpd_address_info	addrinfo;
	int		fd;
};

typedef int (*khttpd_receive_t)(struct kevent *);
typedef int (*khttpd_transmit_t)(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

struct khttpd_socket {
	/* must be &event_type == &<this struct> */
	struct khttpd_event_type event_type;
	LIST_ENTRY(khttpd_socket) link;
	STAILQ_HEAD(, khttpd_request) requests;
	struct sockaddr_storage peer_addr;
	struct iovec	xmit_iov[8];
	struct uio	xmit_uio;
	khttpd_receive_t receive;
	khttpd_transmit_t transmit;
	char		*recv_getp;
	char		*recv_putp;
	uint64_t	recv_residual;
	int		fd;
	u_int		refcount;
	unsigned	xmit_busy:1;
	unsigned	eof:1;
	unsigned	recv_chunked:1;
	char		recv_skip;
	char		recv_buf[KHTTPD_LINE_MAX + 1];
	char		recv_line[KHTTPD_LINE_MAX + 1];
	char		xmit_line[KHTTPD_LINE_MAX];
};

struct khttpd_header_field {
	STAILQ_ENTRY(khttpd_header_field) hash_link;
	char	*name;
	char	*colon;
	char	*end;
};

struct khttpd_header {
	STAILQ_HEAD(, khttpd_header_field) index[KHTTPD_HEADER_HASH_SIZE];
	char		*trailer_begin;
	char		*end;
	char		buffer[KHTTPD_MAX_HEADER_SIZE];
};

struct khttpd_request {
	STAILQ_ENTRY(khttpd_request) link;
	STAILQ_HEAD(, khttpd_response) responses;
	khttpd_request_dtor_t	dtor;
	khttpd_received_body_t	received_body;
	khttpd_end_of_message_t	end_of_message;
	struct khttpd_header	*header;
	struct khttpd_route	*route;
	void		*data[2];
	char		*target;
	const char	*target_suffix;
	char		*query;
	uint64_t	content_length;
	int		method;
	char		version_minor;
};

struct khttpd_response {
	STAILQ_ENTRY(khttpd_response) link;
	uint64_t		content_length;
	khttpd_response_dtor_t	dtor;
	khttpd_transmit_body_t	transmit_body;
	struct khttpd_header	*header;
	void		*data[2];
	unsigned	chunked:1;
	short		status;
	char		version_minor;
};

struct khttpd_route;
SPLAY_HEAD(khttpd_route_tree, khttpd_route);
LIST_HEAD(khttpd_route_list, khttpd_route);

struct khttpd_route {
	LIST_ENTRY(khttpd_route)	children_link;
	SPLAY_ENTRY(khttpd_route)	children_node;
	struct khttpd_route_tree	children_tree;
	struct khttpd_route_list	children_list;
	khttpd_route_dtor_t		dtor;
	khttpd_received_header_t	received_header;
	struct khttpd_route		*parent;
	const char	*label;
	const char	*path;
	void		*data[2];
	u_int		refcount;
	int		label_len;
};

struct khttpd_json {
	int		type;
	u_int		refcount;
	size_t		size;
	size_t		storage_size;
	union {
		int64_t		ivalue;
		char		*storage;
	};
	char		data[KHTTPD_JSON_EMBEDDED_DATA_SIZE];
};		

struct khttpd_sysctl_put_leaf_request {
	struct mbuf	*head;
	struct mbuf	*tail;
	size_t		limit;
	u_int		kind;
	int		oidlen;
	int		oid[CTL_MAXNAME];
};

struct khttpd_log_state {
	u_int	mask;
	int	fd;
};

/* ---------------------------------------------------- prototype declrations */

static int khttpd_route_compare(struct khttpd_route *x, struct khttpd_route *y);

static void khttpd_kevent_nop(struct kevent *event);

static int khttpd_transmit_status_line_and_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

static int khttpd_receive_chunk(struct kevent *event);
static int khttpd_receive_body(struct kevent *event);
static int khttpd_receive_header_or_trailer(struct kevent *event);
static int khttpd_receive_request_line(struct kevent *event);

static void khttpd_handle_socket_event(struct kevent *event);

static int khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
	       struct thread *td);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

SPLAY_PROTOTYPE(khttpd_route_tree, khttpd_route, children_node,
    khttpd_route_compare);
SPLAY_GENERATE(khttpd_route_tree, khttpd_route, children_node,
    khttpd_route_compare);

#pragma clang diagnostic pop

/* ----------------------------------------------------- Variable definitions */

/*
 * module variables
 */

MALLOC_DEFINE(M_KHTTPD, "khttpd", "khttpd buffer");

STAILQ_HEAD(khttpd_command_list, khttpd_command);
static struct khttpd_command_list khttpd_command_queue = 
    STAILQ_HEAD_INITIALIZER(khttpd_command_queue);

static struct khttpd_json khttpd_json_null = {
	.type = KHTTPD_JSON_NULL,
	.refcount = 1
};

static struct khttpd_json khttpd_json_true = {
	.type = KHTTPD_JSON_BOOL,
	.refcount = 1,
	.ivalue = 1
};

static struct khttpd_json khttpd_json_false = {
	.type = KHTTPD_JSON_BOOL,
	.refcount = 1,
	.ivalue = 0
};

static struct khttpd_log_state khttpd_log_state[] = {
	{ /* KHTTPD_LOG_DEBUG */
		.mask = 0,
		.fd = -1
	},
	{ /* KHTTPD_LOG_ERROR */
		.mask = 0,
		.fd = -1
	},
	{ /* KHTTPD_LOG_ACCESS */
		.mask = 0,
		.fd = -1
	},
};

static const u_int khttpd_log_conf_valid_masks[] = {
	KHTTPD_LOG_DEBUG_ALL,	/* KHTTPD_LOG_DEBUG */
	0,			/* KHTTPD_LOG_ERROR */
	0,			/* KHTTPD_LOG_ACCESS */
};

static struct khttpd_method {
	const char	name[24];
	SLIST_ENTRY(khttpd_method) link;
} khttpd_methods[] = {
	{ "ACL" },
	{ "BASELINE-CONTROL" },
	{ "BIND" },
	{ "CHECKIN" },
	{ "CHECKOUT" },
	{ "CONNECT" },
	{ "COPY" },
	{ "DELETE" },
	{ "GET" },
	{ "HEAD" },
	{ "LABEL" },
	{ "LINK" },
	{ "LOCK" },
	{ "MERGE" },
	{ "MKACTIVITY" },
	{ "MKCALENDAR" },
	{ "MKCOL" },
	{ "MKREDIRECTREF" },
	{ "MKWORKSPACE" },
	{ "MOVE" },
	{ "OPTIONS" },
	{ "ORDERPATCH" },
	{ "PATCH" },
	{ "POST" },
	{ "PRI" },
	{ "PROPFIND" },
	{ "PROPPATCH" },
	{ "PUT" },
	{ "REBIND" },
	{ "REPORT" },
	{ "SEARCH" },
	{ "TRACE" },
	{ "UNBIND" },
	{ "UNCHECKOUT" },
	{ "UNLINK" },
	{ "UNLOCK" },
	{ "UPDATE" },
	{ "UPDATEREDIRECTREF" },
	{ "VERSION-CONTROL" },
};

SLIST_HEAD(khttpd_method_list, khttpd_method);
static struct khttpd_method_list
    khttpd_method_hash_table[KHTTPD_METHOD_HASH_SIZE];

static struct mtx khttpd_lock;
static struct cdev *khttpd_dev;
static struct proc *khttpd_proc;
static pid_t khttpd_pid;
static int khttpd_listen_backlog = KHTTPD_LISTEN_BACKLOG;
static int khttpd_state;
static int khttpd_server_status;
static boolean_t khttpd_log_writing, khttpd_log_waiting;
static char khttpd_log_buffer[1024];

static char khttpd_crlf[] = { '\r', '\n' };

static struct cdevsw khttpd_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl   = khttpd_ioctl,
	.d_name	   = "khttpd"
};

static const struct {
	const char     *token;
	int		index;
} khttpd_transfer_codings[] = {
	{ "chunked", KHTTPD_TRANSFER_CODING_CHUNKED },
	{ "compress", KHTTPD_TRANSFER_CODING_COMPRESS },
	{ "x-compress", KHTTPD_TRANSFER_CODING_COMPRESS },
	{ "deflate", KHTTPD_TRANSFER_CODING_DEFLATE },
	{ "gzip", KHTTPD_TRANSFER_CODING_GZIP },
	{ "x-gzip", KHTTPD_TRANSFER_CODING_GZIP },
};

#define KHTTPD_TRANSFER_CODING_TABLE_SIZE \
    (sizeof khttpd_transfer_codings / sizeof khttpd_transfer_codings[0])

static const char *khttpd_sysctl_types[] = {
	"node",
	"int",
	"string",
	"s64",
	"opaque",
	"uint",
	"long",
	"ulong",
	"u64"
};

static const size_t khttpd_sysctl_types_end =
    sizeof(khttpd_sysctl_types) / sizeof(khttpd_sysctl_types[0]);

static const struct {
	u_int		flag;
	const char	*field_name;
} khttpd_sysctl_flags[] = {
	{ CTLFLAG_RD,		"rd" },
	{ CTLFLAG_WR,		"wr" },
	{ CTLFLAG_ANYBODY,	"anybody" },
	{ CTLFLAG_PRISON,	"prison" },
	{ CTLFLAG_DYN,		"dyn" },
	{ CTLFLAG_SKIP,		"skip" },
	{ CTLFLAG_TUN,		"tun" },
	{ CTLFLAG_MPSAFE,	"mpsafe" },
	{ CTLFLAG_VNET,		"vnet" },
	{ CTLFLAG_DYING,	"dying" },
	{ CTLFLAG_CAPRD,	"caprd" },
	{ CTLFLAG_CAPWR,	"capwr" },
	{ CTLFLAG_STATS,	"stats" },
	{ CTLFLAG_NOFETCH,	"nofetch" }
};

static const size_t khttpd_sysctl_flags_count =
    sizeof(khttpd_sysctl_flags) / sizeof(khttpd_sysctl_flags[0]);

/*
 * khttpd process-local variables
 */

static struct khttpd_event_type khttpd_stop_request_type = {
	.handle_event = khttpd_kevent_nop
};

static struct khttpd_route khttpd_route_root = {
	.children_tree = SPLAY_INITIALIZER(khttpd_route_root.children_tree),
	.children_list = LIST_HEAD_INITIALIZER(khttpd_route_root.children_list),
	.parent = NULL,
	.refcount = 1,
};

static SLIST_HEAD(khttpd_server_port_list, khttpd_server_port)
    khttpd_server_ports = SLIST_HEAD_INITIALIZER(khttpd_server_port_list);

static LIST_HEAD(, khttpd_socket) khttpd_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static uma_zone_t khttpd_json_zone;
static uma_zone_t khttpd_route_zone;
static uma_zone_t khttpd_socket_zone;
static uma_zone_t khttpd_request_zone;
static uma_zone_t khttpd_response_zone;
static uma_zone_t khttpd_header_zone;
static uma_zone_t khttpd_header_field_zone;
static int khttpd_kqueue;

/* ----------------------------------------------------- Function definitions */

static
void khttpd_log(int type, const char *fmt, ...)
{
	struct uio auio;
	struct iovec iov[2];
	struct timeval tv;
	va_list vl;
	int len;

	mtx_lock(&khttpd_lock);
	while (khttpd_log_writing) {
		khttpd_log_waiting = TRUE;
		mtx_sleep(&khttpd_log_writing, &khttpd_lock, 0, "khttpd-log",
		    0);
	}
	khttpd_log_writing = TRUE;
	mtx_unlock(&khttpd_lock);

	microuptime(&tv);

	va_start(vl, fmt);
	len = type == KHTTPD_LOG_DEBUG
	    ? snprintf(khttpd_log_buffer, sizeof(khttpd_log_buffer),
		"%ld.%06ld %d %s ",
		tv.tv_sec, tv.tv_usec, curthread->td_tid, va_arg(vl, char *))
	    : snprintf(khttpd_log_buffer, sizeof(khttpd_log_buffer),
		"%ld.%06ld ", tv.tv_sec, tv.tv_usec);

	len += vsnprintf((char *)khttpd_log_buffer + len,
	    sizeof(khttpd_log_buffer) - len, fmt, vl);
	va_end(vl);

	iov[0].iov_base = (void *)khttpd_log_buffer;
	iov[0].iov_len = len;

	iov[1].iov_base = khttpd_crlf + 1;
	iov[1].iov_len = 1;

	auio.uio_iov = iov;
	auio.uio_iovcnt = 2;
	auio.uio_resid = iov[0].iov_len + 1;
	auio.uio_segflg = UIO_SYSSPACE;
	kern_writev(curthread, khttpd_log_state[KHTTPD_LOG_DEBUG].fd, &auio);

	mtx_lock(&khttpd_lock);
	khttpd_log_writing = FALSE;
	if (khttpd_log_waiting) {
		khttpd_log_waiting = FALSE;
		wakeup(&khttpd_log_writing);
	}
	mtx_unlock(&khttpd_lock);
}

/*
 * string manipulation functions
 */

static char *
khttpd_find_ch(const char *begin, const char search)
{
	const char *ptr;
	char ch;

	for (ptr = begin; (ch = *ptr) != '\0'; ++ptr)
		if (ch == search)
			return ((char *)ptr);

	return (NULL);
}

static char *
khttpd_find_ch_in(const char *begin, const char *end, char ch)
{
	const char *ptr;

	for (ptr = begin; ptr < end; ++ptr)
		if (*ptr == ch)
			return ((char *)ptr);

	return (NULL);
}

static char *
khttpd_skip_whitespace(const char *ptr)
{
	const char *cp;

	for (cp = ptr; *cp == ' ' || *cp == '\t'; ++cp)
		;		/* nothing */

	return ((char *)cp);
}

static char *
khttpd_rskip_whitespace(const char *ptr)
{
	const char *cp;

	for (cp = ptr; cp[-1] == ' ' || cp[-1] == '\t'; --cp)
		;		/* nothing */

	return ((char *)cp);
}

static char *
khttpd_dup_first_line(const char *str)
{
	char *buf;
	const char *end;

	end = khttpd_find_ch(str, '\n');
	if (end == NULL)
		return (NULL);

	if (str < end && end[-1] == '\r')
		--end;

	buf = malloc(end - str + 1, M_KHTTPD, M_WAITOK);
	bcopy(str, buf, end - str);
	buf[end - str] = '\0';

	return (buf);
}

static char *
khttpd_find_list_item_end(const char *begin, const char **sep)
{
	const char *ptr;
	char *result;
	char ch;

	result = (char *)begin;
	for (ptr = begin; (ch = *ptr) != ',' && ch != '\n' && ch != '\r'; ++ptr)
		if (ch != ' ' && ch != '\t')
			result = (char *)(ptr + 1);

	*sep = ptr;

	return (result);
}

static char *
khttpd_unquote_uri(char *begin, char *end)
{
	char *dstp, *srcp;
	int code, i;
	char ch;

	dstp = begin;
	for (srcp = begin; srcp < end; ++srcp) {
		KASSERT(dstp <= srcp, ("srcp=%p, dstp=%p", srcp, dstp));

		ch = *srcp;

		if (ch == '\0')
			return (NULL);

		if (ch == '%' && 2 < end - srcp) {
			code = 0;
			for (i = 0; i < 2; ++i) {
				code <<= 4;

				if ('0' <= ch && ch <= '9')
					code |= ch - '0';

				else if ('A' <= ch && ch <= 'F')
					code |= ch - 'A' + 10;

				else if ('a' <= ch && ch <= 'f')
					code |= ch - 'a' + 10;

				else
					return (NULL);
			}

			if (code == 0)
				return (NULL);

			*dstp++ = code;
			continue;
		}

		*dstp++ = ch;
	}

	return (dstp);
}

static boolean_t
khttpd_is_token(const char *start, const char *end)
{
	static const char is_tchar[] = {
		/*	    4		8	    c */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x00 */
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 0x10 */
		0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, /* 0x20 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /* 0x30 */
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, /* 0x50 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, /* 0x70 */
	};

	const char *cp;
	unsigned char ch;

	for (cp = start; cp < end; ++cp) {
		ch = (unsigned char)*cp;
		if (sizeof(is_tchar) <= ch || is_tchar[ch] == 0)
			return (FALSE);
	}

	return (TRUE);
}

static uint32_t
khttpd_hash32_buf_ci(const char *begin, const char *end)
{
	const char *bp;
	uint32_t hash;
	unsigned char ch;

	hash = 0;
	for (bp = begin; bp < end; ++bp) {
		ch = *bp;
		hash = HASHSTEP(hash, tolower(ch));
	}

	return (hash);
}

static uint32_t
khttpd_hash32_str_ci(const char *str)
{
	const char *bp;
	uint32_t hash;
	char ch;

	hash = 0;
	for (bp = str; ((ch = *bp) != '\0'); ++bp)
		hash = HASHSTEP(hash, tolower(ch));

	return (hash);
}

/*
 * method name lookup
 */

static void
khttpd_method_init(void)
{
	uint32_t h;
	int i, n;

	for (i = 0; i < KHTTPD_METHOD_HASH_SIZE; ++i)
		SLIST_INIT(&khttpd_method_hash_table[i]);

	n = sizeof(khttpd_methods) / sizeof(khttpd_methods[0]);
	for (i = 0; i < n; ++i) {
		h = hash32_str(khttpd_methods[i].name, 0) %
		    KHTTPD_METHOD_HASH_SIZE;
		SLIST_INSERT_HEAD(&khttpd_method_hash_table[h],
		    &khttpd_methods[i], link);
	}
}

static int
khttpd_method_find(const char *begin, const char *end)
{
	struct khttpd_method *ptr;

	uint32_t h = hash32_buf(begin, end - begin, 0) % KHTTPD_METHOD_HASH_SIZE;
	SLIST_FOREACH(ptr, &khttpd_method_hash_table[h], link) {
		if (strncmp(begin, ptr->name, end - begin) == 0)
			return (ptr - khttpd_methods);
	}

	return (-1);
}

/*
 * mbuf
 */

void
khttpd_mbuf_vprintf(struct mbuf *output, const char *fmt, va_list vl)
{
	struct mbuf *buf;
	int req, buflen;

	buf = m_get(M_WAITOK, MT_DATA);
	buflen = M_TRAILINGSPACE(buf);
	req = vsnprintf(mtod(buf, char *), buflen, fmt, vl);
	if (buflen < req)
		panic("%s: result is too long", __func__);
	buf->m_len = req;
	m_cat(output, buf);
}

void
khttpd_mbuf_printf(struct mbuf *output, const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	khttpd_mbuf_vprintf(output, fmt, vl);
	va_end(vl);
}

struct mbuf *
khttpd_mbuf_append(struct mbuf *output, const char *begin, const char *end)
{
	struct mbuf *ptr;
	const char *cp;
	size_t space, len;

	ptr = output;
	cp = begin;
	while (cp < end && 0 < (space = M_TRAILINGSPACE(ptr))) {
		len = MIN(end - cp, space);
		bcopy(cp, mtod(ptr, char *) + ptr->m_len, len);
		ptr->m_len += len;
		cp += len;
	}

	if (end <= cp)
		return (ptr);

	for (ptr = m_getm2(ptr, end - cp, M_WAITOK, MT_DATA, 0); cp < end;
	     ptr = ptr->m_next) {
		len = MIN(end - cp, M_TRAILINGSPACE(ptr));
		bcopy(cp, mtod(ptr, void *), len);
		ptr->m_len = len;
		cp += len;
	}

	return (ptr);
}

void
khttpd_base64_encode_to_mbuf(struct mbuf *output, const char *buf, size_t size)
{
	struct mbuf *tail;
	char *encbuf;
	size_t i, j, n;
	unsigned q, v;
	int space;

	TRACE("enter %p %#zx", buf, size);

	m_length(output, &tail);
	encbuf = mtod(tail, char *) + tail->m_len;

	n = size / 3 * 3;
	for (i = 0; i < n; i += 3) {
		space = M_TRAILINGSPACE(tail);
		if (space < 4) {
			tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
			encbuf = mtod(tail, char *);
		}

		q = ((int)buf[i] << 16) | ((int)buf[i + 1] << 8) |
		    (int)buf[i + 2];
		for (j = 0; j < 4; ++j) {
			v = (q >> 18) & 0x3f;
			if (v < 26)
				encbuf[j] = 'A' + v;
			else if (v < 52)
				encbuf[j] = 'a' + (v - 26);
			else if (v < 62)
				encbuf[j] = '0' + (v - 52);
			else if (v == 62)
				encbuf[j] = '+';
			else
				encbuf[j] = '/';
			q <<= 6;
		}

		encbuf += 4;
		tail->m_len += 4;
	}

	q = 0;
	switch (size - n) {
	case 0:
		break;

	case 2:
		q = ((int)buf[i + 1] << 8);
		/* FALLTHROUGH */

	case 1:
		q |= ((int)buf[i] << 16);

		space = M_TRAILINGSPACE(tail);
		if (space < 4) {
			tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
			encbuf = mtod(tail, char *);
		}

		for (j = 0; j < 1 + (size - n); ++j) {
			v = (q >> 18) & 0x3f;
			if (v < 26)
				encbuf[j] = 'A' + v;
			else if (v < 52)
				encbuf[j] = 'a' + (v - 26);
			else if (v < 62)
				encbuf[j] = '0' + (v - 52);
			else if (v == 62)
				encbuf[j] = '+';
			else
				encbuf[j] = '/';
			q <<= 6;
		}
		for (; j < 4; ++j)
			encbuf[j] = '=';

		tail->m_len += 4;
	}
}

int
khttpd_base64_decode_from_mbuf(struct khttpd_mbuf_iter *iter, void **buf_out,
    size_t *size_out)
{
	unsigned char *buf;
	size_t bufsize, size;
	int ch, code, equals, i;

	size = 0;
	bufsize = 128;
	buf = malloc(bufsize, M_KHTTPD, M_WAITOK);

	while ((ch = khttpd_mbuf_getc(iter)) != -1) {
		code = 0;
		equals = 0;
		for (i = 0; i < 4; ++i) {
			code <<= 6;
			if ('A' <= ch && ch <= 'Z')
				code |= ch - 'A';
			else if ('a' <= ch && ch <= 'z')
				code |= ch - 'a' + 26;
			else if ('0' <= ch && ch <= '9')
				code |= ch - '0' + 52;
			else if (ch == '+')
				code |= 62;
			else if (ch == '/')
				code |= 63;
			else if (ch == '=')
				++equals;
			else
				return (EINVAL);
			ch = khttpd_mbuf_getc(iter);
		}
		khttpd_mbuf_ungetc(iter, ch);

		if (bufsize < size + 3 - equals) {
			bufsize = bufsize < 65536 ? bufsize <<= 1
			    : bufsize + 65536;
			buf = realloc(buf, bufsize, M_KHTTPD, M_WAITOK);
		}

		for (i = 2; equals <= i; --i)
			buf[size++] = (code >> (i * 8)) & 0xff;

		if (0 < equals)
			break;
	}

	*buf_out = buf;
	*size_out = size;

	return (0);
}

void
khttpd_mbuf_iter_init(struct khttpd_mbuf_iter *iter, struct mbuf *ptr, int off)
{
	iter->unget = -1;
	iter->ptr = ptr;
	iter->off = off;
}

int
khttpd_mbuf_getc(struct khttpd_mbuf_iter *iter)
{
	int result;

	TRACE("enter");

	if (0 < iter->unget) {
		result = iter->unget;
		iter->unget = -1;
		return (result);
	}

	while (iter->ptr != NULL && iter->ptr->m_len <= iter->off) {
		iter->off = 0;
		iter->ptr = iter->ptr->m_next;
	}

	if (iter->ptr == NULL)
		return (-1);
	
	result = mtod(iter->ptr, unsigned char *)[iter->off];
	++iter->off;

	return (result);
}

void
khttpd_mbuf_ungetc(struct khttpd_mbuf_iter *iter, int ch)
{
	TRACE("enter '%c'", ch);

	KASSERT(iter->unget == -1, ("unget=%#02x", iter->unget));
	iter->unget = ch;
}

void
khttpd_mbuf_skip_json_ws(struct khttpd_mbuf_iter *iter)
{
	struct mbuf *ptr;
	const char *cp;
	int ch, len, off;

	TRACE("enter");

	if (iter->unget != -1) {
		ch = iter->unget;
		if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
			return;
		iter->unget = -1;
	}

	for (ptr = iter->ptr, off = iter->off; ptr != NULL;
	     ptr = ptr->m_next, off = 0) {
		len = ptr->m_len;
		for (cp = mtod(ptr, char *) + off; off < len; ++cp, ++off) {
			ch = *cp;
			if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
				goto quit;
		}
	}
quit:
	iter->ptr = ptr;
	iter->off = off;
}

/*
 * JSON
 */

void
khttpd_json_hold(struct khttpd_json *value)
{
	TRACE("enter %p", value);
	refcount_acquire(&value->refcount);
}

void
khttpd_json_free(struct khttpd_json *value)
{
	struct khttpd_json *ptr, *child, **stack;
	size_t stacksize, depth;

	TRACE("enter %p", value);

	if (value == NULL || !refcount_release(&value->refcount))
		return;

	depth = 0;
	stacksize = 0;
	stack = NULL;

	ptr = value;
	for (;;) {
		while (0 < ptr->size &&
		    (ptr->type == KHTTPD_JSON_ARRAY ||
			ptr->type == KHTTPD_JSON_OBJECT)) {

			for (;;) {
				child = ((struct khttpd_json **)
				    (ptr->storage + ptr->size))[-1];
				if (refcount_release(&child->refcount))
					break;
				ptr->size -= sizeof(struct khttpd_json *);
				if (ptr->size == 0)
					goto no_children;
			}

			if (stacksize <= depth) {
				stacksize = stacksize < 8 ? 8 : stacksize << 1;
				stack = realloc(stack,
				    stacksize * sizeof(struct khttpd_json *),
				    M_KHTTPD, M_WAITOK);
			}

			stack[depth++] = ptr;
			ptr = child;
		}

no_children:
		if (ptr->type != KHTTPD_JSON_INTEGER &&
		    ptr->storage != ptr->data)
			free(ptr->storage, M_KHTTPD);
		uma_zfree(khttpd_json_zone, ptr);
		if (depth == 0)
			break;
		ptr = stack[--depth];
		ptr->size -= sizeof(struct khttpd_json *);
	}

	free(stack, M_KHTTPD);
}

static void
khttpd_json_resize(struct khttpd_json *value, size_t newsize)
{
	void *storage;
	size_t size, ssize;

	KASSERT(value->type == KHTTPD_JSON_ARRAY ||
	    value->type == KHTTPD_JSON_OBJECT ||
	    value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	size = value->size;
	ssize = value->storage_size;
	if (ssize == 0) {
		ssize = sizeof(value->data);
		storage = NULL;
	} else
		storage = value->storage;

	if (newsize < ssize)
		return;

	while (ssize < newsize)
		ssize = sizeof(value->data) << 1;
	value->storage_size = ssize;

	value->storage = realloc(storage, ssize, M_KHTTPD, M_WAITOK);
	if (storage == NULL)
		bcopy(value->data, value->storage, size);
}

struct khttpd_json *
khttpd_json_integer_new(int64_t value)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_INTEGER;
	refcount_init(&result->refcount, 1);
	result->size = result->storage_size = 0;
	result->ivalue = value;

	return (result);
}

int64_t
khttpd_json_integer_value(struct khttpd_json *value)
{
	return (value->ivalue);
}

struct khttpd_json *
khttpd_json_string_new(void)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_STRING;
	refcount_init(&result->refcount, 1);
	result->size = 0;
	result->storage_size = 0;
	result->storage = result->data;

	return (result);
}

int
khttpd_json_string_size(struct khttpd_json *value)
{
	KASSERT(value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	return (value->size);
}

const char *
khttpd_json_string_data(struct khttpd_json *value)
{
	KASSERT(value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	if (value->size == value->storage_size == 0 ? sizeof(value->data)
	    : value->storage_size)
		khttpd_json_resize(value, value->size + 1);
	value->storage[value->size] = '\0';

	return (value->storage);
}

void
khttpd_json_string_append(struct khttpd_json *value, const char *begin,
    const char *end)
{
	size_t size;

	KASSERT(value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	size = value->size;
	khttpd_json_resize(value, size + (end - begin));
	bcopy(begin, value->storage + size, end - begin);
	value->size = size + (end - begin);
}

void
khttpd_json_string_append_char(struct khttpd_json *value, int ch)
{
	KASSERT(value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	if (value->size == value->storage_size == 0 ? sizeof(value->data)
	    : value->storage_size)
		khttpd_json_resize(value, value->size + 1);
	value->storage[value->size++] = ch;
}

void
khttpd_json_string_append_utf8(struct khttpd_json *value, int code)
{
	KASSERT(0 <= code && code <= 0x200000, ("code %#x", code));

	if (code < 0x80)
		khttpd_json_string_append_char(value, code);
	else if (code < 0x800) {
		khttpd_json_string_append_char(value, 0xc0 | (code >> 6));
		khttpd_json_string_append_char(value, 0x80 | (code & 0x3f));
	} else if (code < 0x10000) {
		khttpd_json_string_append_char(value, 0xe0 | (code >> 12));
		khttpd_json_string_append_char(value,
		    0x80 | ((code >> 6) & 0x3f));
		khttpd_json_string_append_char(value, 0x80 | (code & 0x3f));
	} else {
		khttpd_json_string_append_char(value, 0xf0 | (code >> 18));
		khttpd_json_string_append_char(value,
		    0x80 | ((code >> 12) & 0x3f));
		khttpd_json_string_append_char(value,
		    0x80 | ((code >> 6) & 0x3f));
		khttpd_json_string_append_char(value, 0x80 | (code & 0x3f));
	}
}

struct khttpd_json *
khttpd_json_array_new(void)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_ARRAY;
	refcount_init(&result->refcount, 1);
	result->size = 0;
	result->storage_size = 0;
	result->storage = result->data;

	return (result);
}

int khttpd_json_array_size(struct khttpd_json *value)
{
	KASSERT(value->type == KHTTPD_JSON_ARRAY,
	    ("invalid type %d", value->type));

	return (value->size / sizeof(struct khttpd_json *));
}

void
khttpd_json_array_add(struct khttpd_json *value, struct khttpd_json *elem)
{
	size_t size, newsize;

	KASSERT(value->type == KHTTPD_JSON_ARRAY,
	    ("invalid type %d", value->type));

	size = value->size;
	newsize = size + sizeof(elem);
	khttpd_json_resize(value, newsize);
	*(struct khttpd_json **)(value->storage + size) = elem;
	value->size = newsize;
	refcount_acquire(&elem->refcount);
}

struct khttpd_json *
khttpd_json_array_get(struct khttpd_json *value, int index)
{
	KASSERT(value->type == KHTTPD_JSON_ARRAY,
	    ("invalid type %d", value->type));

	return (value->size <= (size_t)index * sizeof(value)
	    ? NULL : ((struct khttpd_json **)value->storage)[index]);
}

struct khttpd_json *
khttpd_json_object_new(int size_hint)
{
	struct khttpd_json *result;
	size_t len;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_OBJECT;
	refcount_init(&result->refcount, 1);
	result->size = 0;
	len = size_hint * sizeof(struct khttpd_json *) * 2;
	if (len <= sizeof(result->data)) {
		result->storage_size = 0;
		result->storage = result->data;
	} else {
		result->storage_size = len;
		result->storage = malloc(len, M_KHTTPD, M_WAITOK);
	}

	return result;
}

void
khttpd_json_object_add(struct khttpd_json *value, struct khttpd_json *name,
    struct khttpd_json *elem)
{
	struct khttpd_json **ptr;
	size_t size, newsize;

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	khttpd_json_hold(name);
	khttpd_json_hold(elem);
	size = value->size;
	newsize = size + sizeof(struct khttpd_json *) * 2;
	khttpd_json_resize(value, newsize);
	ptr = (struct khttpd_json **)(value->storage + size);
	ptr[0] = name;
	ptr[1] = elem;
	value->size = newsize;
}

struct khttpd_json *
khttpd_json_object_get(struct khttpd_json *value, const char *name)
{
	struct khttpd_json **end, **ptr;

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	end = (struct khttpd_json **)(value->storage + value->size);
	ptr = (struct khttpd_json **)value->storage;
	for (; ptr < end; ptr += 2) {
		KASSERT(ptr[0]->type == KHTTPD_JSON_STRING,
		    ("invalid type %d", ptr[0]->type));
		if (strcmp(name, (const char *)ptr[0]->storage) == 0)
			return (ptr[1]);
	}

	return (NULL);
}

struct khttpd_json *
khttpd_json_object_get_at(struct khttpd_json *value, int index,
    struct khttpd_json **name_out)
{
	struct khttpd_json **ptr;

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	if (value->size <= index * sizeof(struct khttpd_json *) * 2)
		return (NULL);

	ptr = (struct khttpd_json **)value->storage + (index * 2L);
	KASSERT(ptr[0]->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", ptr[0]->type));

	if (name_out != NULL)
		*name_out = ptr[0];

	return (ptr[1]);
}

int
khttpd_json_object_size(struct khttpd_json *value)
{
	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	return (value->size / (sizeof(struct khttpd_json *) * 2));
}

static boolean_t
khttpd_json_parse_expect_char(struct khttpd_mbuf_iter *iter, char expected)
{
	char ch;

	ch = khttpd_mbuf_getc(iter);
	if (ch == expected)
		return (TRUE);
	khttpd_mbuf_ungetc(iter, ch);
	return (FALSE);
}

static int
khttpd_json_parse_string(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out)
{
	struct khttpd_json *value;
	int ch, code, error, i, surrogate;

	TRACE("enter");

	khttpd_mbuf_skip_json_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '\"'))
		return (EINVAL);

	error = 0;
	value = khttpd_json_string_new();
	surrogate = 0;

	for (;;) {
		ch = khttpd_mbuf_getc(iter);

		if (ch != '\\' && surrogate != 0) {
			khttpd_json_string_append_utf8(value, surrogate);
			surrogate = 0;
		}

		switch (ch) {

		case '\"':
			goto quit;

		case '\\':
			ch = khttpd_mbuf_getc(iter);

			if (ch != 'u' && surrogate != 0) {
				khttpd_json_string_append_utf8(value,
				    surrogate);
				surrogate = 0;
			}

			switch (ch) {
			case 'b':
				khttpd_json_string_append_char(value, '\b');
				break;
			case 'f':
				khttpd_json_string_append_char(value, '\f');
				break;
			case 'n':
				khttpd_json_string_append_char(value, '\n');
				break;
			case 'r':
				khttpd_json_string_append_char(value, '\r');
				break;
			case 't':
				khttpd_json_string_append_char(value, '\t');
				break;
			case 'u':
				code = 0;
				for (i = 0; i < 4; ++i) {
					ch = khttpd_mbuf_getc(iter);
					if (!isxdigit(ch)) {
						error = EINVAL;
						goto quit;
					}
					code <<= 4;
					if (isdigit(ch))
						code |= ch - '0';
					else if ('a' <= ch && ch <= 'f')
						code |= ch - 'a' + 10;
					else
						code |= ch - 'A' + 10;
				}

				if (surrogate != 0) {
					if (0xdc00 <= code && code < 0xe000) {
						code = 0x10000 |
						    ((surrogate - 0xd800)
							<< 10) |
						    (code - 0xdc00);
						khttpd_json_string_append_utf8
						    (value, code);
						surrogate = 0;
						break;
					}
					khttpd_json_string_append_utf8
					    (value, surrogate);
					surrogate = 0;
				}

				if (0xd800 <= code && code < 0xdc00)
					surrogate = code;
				else
					khttpd_json_string_append_utf8(value,
					    code);
				break;

			default:
				khttpd_json_string_append_char(value, ch);
			}
			break;

		default:
			khttpd_json_string_append_char(value, ch);
		}
	}
quit:
	if (error == 0)
		*value_out = value;
	else
		khttpd_json_free(value);

	return (error);
}

static int
khttpd_json_parse_object(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *name, *elem;
	int error;

	TRACE("enter");

	khttpd_mbuf_skip_json_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '{'))
		return (EINVAL);

	error = 0;
	value = khttpd_json_object_new(0);

	khttpd_mbuf_skip_json_ws(iter);
	if (khttpd_json_parse_expect_char(iter, '}')) {
		*value_out = value;
		return (0);
	}

	for (;;) {
		error = khttpd_json_parse_string(iter, &name);
		if (error != 0)
			break;

		khttpd_mbuf_skip_json_ws(iter);
		if (!khttpd_json_parse_expect_char(iter, ':')) {
			error = EINVAL;
			break;
		}

		error = khttpd_json_parse(iter, &elem, depth_limit - 1);
		if (error != 0)
			break;

		khttpd_json_object_add(value, name, elem);
		khttpd_json_free(name);
		khttpd_json_free(elem);

		khttpd_mbuf_skip_json_ws(iter);
		if (khttpd_json_parse_expect_char(iter, '}'))
			break;
		if (!khttpd_json_parse_expect_char(iter, ',')) {
			error = EINVAL;
			break;
		}
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_free(value);

	return (error);
}

static int
khttpd_json_parse_array(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *elem;
	int error;

	TRACE("enter");

	khttpd_mbuf_skip_json_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '['))
		return (EINVAL);

	error = 0;
	value = khttpd_json_array_new();

	khttpd_mbuf_skip_json_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, ']')) {
		*value_out = value;
		return (0);
	}

	for (;;) {
		error = khttpd_json_parse(iter, &elem, depth_limit - 1);
		if (error != 0)
			break;

		khttpd_json_array_add(value, elem);
		khttpd_json_free(elem);

		khttpd_mbuf_skip_json_ws(iter);
		if (khttpd_json_parse_expect_char(iter, ']'))
			break;
		if (!khttpd_json_parse_expect_char(iter, ',')) {
			error = EINVAL;
			break;
		}
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_free(value);

	return (error);
}

static int
khttpd_json_parse_expect_seq(struct khttpd_mbuf_iter *iter,
    const char *symbol)
{
	const char *cp;
	int ch;

	for (cp = symbol; (ch = *cp) != '\0'; ++cp)
		if (!khttpd_json_parse_expect_char(iter, ch))
			return (EINVAL);
	return (0);
}

static int
khttpd_json_parse_integer(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out)
{
	int ch;
	int64_t value;
	boolean_t negative;

	negative = FALSE;

	khttpd_mbuf_skip_json_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	if (ch == '-')
		negative = TRUE;
	else
		khttpd_mbuf_ungetc(iter, ch);

	ch = khttpd_mbuf_getc(iter);
	if (ch == '0') {
		*value_out = 0;
		return (0);
	}
	if (!isdigit(ch))
		return (EINVAL);

	value = ch - '0';
	for (;;) {
		ch = khttpd_mbuf_getc(iter);
		if (!isdigit(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			break;
		}

		/* -2^63 need not be handled */
		if (value * 10 < value)
			return (EOVERFLOW);
		value = value * 10 + (ch - '0');
	}

	*value_out = khttpd_json_integer_new(negative ? -value : value);

	return (0);
}

int
khttpd_json_parse(struct khttpd_mbuf_iter *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value;
	int ch, error;

	TRACE("enter");

	if (depth_limit <= 0)
		return (ELOOP);

	value = NULL;
	error = 0;

	khttpd_mbuf_skip_json_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	switch (ch) {

	case '{':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_object(iter, &value,
		    KHTTPD_JSON_DEPTH_MAX);
		break;

	case '[':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_array(iter, &value,
		    KHTTPD_JSON_DEPTH_MAX);
		break;

	case '\"':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_string(iter, &value);
		break;

	case '-':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_integer(iter, &value);
		break;

	case 't':
		error = khttpd_json_parse_expect_seq(iter, "rue");
		if (error == 0) {
			value = &khttpd_json_true;
			khttpd_json_hold(value);
		}
		break;

	case 'f':
		error = khttpd_json_parse_expect_seq(iter, "alse");
		if (error == 0) {
			value = &khttpd_json_false;
			khttpd_json_hold(value);
		}
		break;

	case 'n':
		error = khttpd_json_parse_expect_seq(iter, "ull");
		if (error == 0) {
			value = &khttpd_json_null;
			khttpd_json_hold(value);
		}
		break;

	default:
		if (isdigit(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			error = khttpd_json_parse_integer(iter, &value);
		} else if (ch == -1)
			error = ENOMSG;
		else if (!isdigit(ch))
			error = EINVAL;
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_free(value);

	return (error);
}

/*
 * kevent
 */

static void
khttpd_kevent_nop(struct kevent *event)
{
}

static int
khttpd_kevent_copyout(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args = (struct khttpd_kevent_args *)arg;
	bcopy(kevp, args->eventlist, count * sizeof *kevp);
	args->eventlist += count;

	return (0);
}

static int
khttpd_kevent_copyin(void *arg, struct kevent *kevp, int count)
{
	struct khttpd_kevent_args *args = (struct khttpd_kevent_args *)arg;
	bcopy(args->changelist, kevp, count * sizeof *kevp);
	args->changelist += count;

	return (0);
}

static int
khttpd_kevent_add_read(int kq, int fd, struct khttpd_event_type *etype)
{
	TRACE("enter %d", fd);

	struct kevent change = {
		.ident	     = fd,
		.filter	     = EVFILT_READ,
		.flags	     = EV_ADD,
		.fflags	     = 0,
		.data	     = 0,
		.udata	     = etype
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_add_read_write(int kq, int fd, struct khttpd_event_type *etype)
{
	TRACE("enter %d", fd);

	struct kevent changes[] = {
		{
			.ident	     = fd,
			.filter	     = EVFILT_READ,
			.flags	     = EV_ADD,
			.fflags	     = 0,
			.data	     = 0,
			.udata	     = etype
		},
		{
			.ident	     = fd,
			.filter	     = EVFILT_WRITE,
			.flags	     = EV_ADD|EV_DISABLE,
			.fflags	     = 0,
			.data	     = 0,
			.udata	     = etype
		}
	};

	struct khttpd_kevent_args args = {
		.changelist = changes,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, sizeof changes / sizeof changes[0],
	    0, &k_ops, NULL));
}

static int
khttpd_kevent_enable_write(int kq, int fd, boolean_t enable,
    struct khttpd_event_type *etype)
{
	TRACE("enter %d", fd);

	struct kevent change = {
		.ident	= fd,
		.filter	= EVFILT_WRITE,
		.flags	= enable ? EV_ENABLE : EV_DISABLE,
		.fflags	= 0,
		.udata	= etype
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_delete_read(int kq, int fd)
{
	TRACE("enter %d", fd);

	struct kevent change = {
		.ident	= fd,
		.filter	= EVFILT_READ,
		.flags	= EV_DELETE,
		.fflags	= 0,
		.data	= 0,
		.udata	= NULL
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_add_signal(int kq, int signo, struct khttpd_event_type *etype)
{
	TRACE("enter");

	struct kevent change = {
		.ident	= signo,
		.filter = EVFILT_SIGNAL,
		.flags	= EV_ADD,
		.fflags = 0,
		.data	= 0,
		.udata	= &khttpd_stop_request_type
	};

	struct khttpd_kevent_args args = {
		.changelist = &change,
		.eventlist  = NULL,
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	return (kern_kevent(curthread, kq, 1, 0, &k_ops, NULL));
}

static int
khttpd_kevent_get(int kq, struct kevent *event)
{
	int error;

	TRACE("enter");

	struct khttpd_kevent_args args = {
		.changelist = NULL,
		.eventlist  = event
	};

	struct kevent_copyops k_ops = {
		&args,
		khttpd_kevent_copyout,
		khttpd_kevent_copyin	
	};

	error = kern_kevent(curthread, kq, 0, 1, &k_ops, NULL);

	if (error == 0 && curthread->td_retval[0] == 0)
		error = ETIMEDOUT;

	return (error);
}

/*
 * route
 */

static void
khttpd_route_dtor_null(struct khttpd_route *route)
{
}

static int
khttpd_route_init(void *mem, int size, int flags)
{
	struct khttpd_route *route;

	route = (struct khttpd_route *)mem;
	LIST_INIT(&route->children_list);
	SPLAY_INIT(&route->children_tree);

	return (0);
}

static int
khttpd_route_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_route *route;

	route = (struct khttpd_route *)mem;
	route->dtor = khttpd_route_dtor_null;
	route->received_header = (khttpd_received_header_t)arg;
	route->refcount = 1;

	return (0);
}

static void
khttpd_route_dtor(void *mem, int size, void *arg)
{
	struct khttpd_route *route;

	route = (struct khttpd_route *)mem;

	TRACE("enter %s", route->path);

	KASSERT(route->refcount == 0,
	    ("%p->refcount == %d", route, route->refcount));
	KASSERT(SPLAY_EMPTY(&route->children_tree),
	    ("%p->children_tree not empty", route));
	KASSERT(LIST_EMPTY(&route->children_list),
	    ("%p->children_list not empty", route));
	route->dtor(route);
}

static void
khttpd_route_hold(struct khttpd_route *route)
{
	++route->refcount;
}

static void
khttpd_route_free(struct khttpd_route *route)
{
	if (--route->refcount == 0)
		uma_zfree(khttpd_route_zone, route);
}

static int
khttpd_route_compare(struct khttpd_route *x, struct khttpd_route *y)
{
	int len, result;

	len = MIN(x->label_len, y->label_len);
	result = strncmp(x->label, y->label, len);
	return (result != 0 ? result : x->label_len - y->label_len);
}

static struct khttpd_route *
khttpd_route_find(struct khttpd_route *root,
    const char *target, const char **suffix)
{
	struct khttpd_route key;
	struct khttpd_route *ptr, *parent;
	const char *cp, *end;

	TRACE("enter %s", target);

	KASSERT(curproc == khttpd_proc,
	    ("curproc = %p, khttpd_proc = %p", curproc, khttpd_proc));

	parent = root;
	cp = target;
	end = target + strlen(cp);
	while (!SPLAY_EMPTY(&parent->children_tree)) {
		key.label = cp;
		key.label_len = end - cp;
		ptr = SPLAY_FIND(khttpd_route_tree, &parent->children_tree, &key);
		if (ptr != NULL) {
			if (suffix != NULL)
				*suffix = end;
			return (ptr);
		}

		ptr = SPLAY_ROOT(&parent->children_tree);
		if (0 < khttpd_route_compare(ptr, &key))
			ptr = LIST_PREV(ptr, &parent->children_list,
			    khttpd_route, children_link);

		if (ptr == NULL ||
		    strncmp(ptr->label, cp, ptr->label_len) != 0 ||
		    (cp + ptr->label_len < end && cp[ptr->label_len] != '/'))
			break;

		parent = ptr;
		cp += ptr->label_len;
	}

	if (parent == root)
		return (NULL);

	if (suffix != NULL)
		*suffix = cp;

	return (parent);
}

static int
khttpd_route_add(struct khttpd_route *root, char *path,
    khttpd_received_header_t received_header_fn)
{
	struct khttpd_route key;
	struct khttpd_route *next, *parent, *ptr, *prev, *route;
	const char *lbegin, *lend;
	size_t len;

	TRACE("enter %s", path);

	route = uma_zalloc_arg(khttpd_route_zone, received_header_fn, M_WAITOK);
	lbegin = route->path = path;
	len = strlen(lbegin);
	lend = lbegin + len;
	route->label = lbegin;
	route->label_len = len;

	parent = root;

	for (;;) {
		if (SPLAY_EMPTY(&parent->children_tree)) {
			LIST_INSERT_HEAD(&parent->children_list,
			    route, children_link);
			break;
		}

		len = lend - lbegin;
		key.label = lbegin;
		key.label_len = len;
		ptr = SPLAY_FIND(khttpd_route_tree, &parent->children_tree, &key);
		if (ptr == NULL) {
			ptr = SPLAY_ROOT(&parent->children_tree);
			if (0 < khttpd_route_compare(ptr, &key))
				ptr = LIST_PREV(ptr, &parent->children_list,
				    khttpd_route, children_link);

			if (ptr == NULL ||
			    strncmp(ptr->label, lbegin, ptr->label_len) != 0 ||
			    (lbegin + ptr->label_len < lend &&
				lbegin[ptr->label_len] != '/')) {
				if (ptr == NULL)
					LIST_INSERT_HEAD(&parent->children_list,
					    route, children_link);
				else
					LIST_INSERT_AFTER(ptr, route,
					    children_link);

				for (ptr = LIST_NEXT(route, children_link),
					 prev = NULL;
				     ptr != NULL &&
					 strncmp(ptr->label, lbegin, len) == 0;
				     prev = ptr, ptr = next) {
					next = LIST_NEXT(ptr, children_link);

					SPLAY_REMOVE(khttpd_route_tree,
					    &parent->children_tree, next);
					LIST_REMOVE(ptr, children_link);

					ptr->parent = route;
					ptr->label += len;
					ptr->label_len -= len;

					SPLAY_INSERT(khttpd_route_tree,
					    &route->children_tree, ptr);
					if (prev == NULL)
						LIST_INSERT_AFTER(prev, ptr,
						    children_link);
					else
						LIST_INSERT_HEAD
						    (&route->children_list, ptr,
							children_link);
					prev = ptr;
				}

				break;
			}
		}

		lbegin += len;

		if (lbegin == lend) {
			khttpd_route_free(route);
			return (EEXIST);
		}

		parent = ptr;
	}

	route->parent = parent;
	SPLAY_INSERT(khttpd_route_tree, &parent->children_tree, route);

	return (0);
}

static void
khttpd_route_remove(struct khttpd_route *route)
{
	struct khttpd_route *parent, *ptr;
	size_t len;

	TRACE("enter %s", route->path);

	len = route->label_len;
	parent = route->parent;
	SPLAY_REMOVE(khttpd_route_tree, &parent->children_tree, route);

	SPLAY_INIT(&route->children_tree);
	while ((ptr = LIST_FIRST(&route->children_list)) != NULL) {
		LIST_REMOVE(ptr, children_link);

		ptr->parent = parent;
		ptr->label -= len;
		ptr->label_len += len;

		SPLAY_INSERT(khttpd_route_tree, &parent->children_tree, ptr);
		LIST_INSERT_AFTER(route, ptr, children_link);
	}

	LIST_REMOVE(route, children_link);

	khttpd_route_free(route);
}

static void
khttpd_route_clear_all(struct khttpd_route *root)
{
	struct khttpd_route *parent, *ptr;

	TRACE("enter");

	SPLAY_INIT(&root->children_tree);
	parent = root;
	for (;;) {
		if ((ptr = LIST_FIRST(&parent->children_list)) != NULL) {
			SPLAY_INIT(&ptr->children_tree);
			LIST_REMOVE(ptr, children_link);
			parent = ptr;
			continue;
		}

		ptr = parent;
		parent = ptr->parent;
		if (parent == NULL)
			break;

		khttpd_route_free(ptr);
	}
}

/*
 * header
 */

static int
khttpd_header_init(void *mem, int size, int flags)
{
	struct khttpd_header *header;
	int i;

	header = (struct khttpd_header *)mem;
	for (i = 0; i < KHTTPD_HEADER_HASH_SIZE; ++i)
		STAILQ_INIT(&header->index[i]);

	return (0);
}

static int
khttpd_header_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_header *header;

	header = (struct khttpd_header *)mem;
	header->end = header->buffer;
	header->trailer_begin = header->buffer + sizeof(header->buffer);

	return (0);
}

static void
khttpd_header_dtor(void *mem, int size, void *arg)
{
	struct khttpd_header *header;
	struct khttpd_header_field *field;
	int i;

	header = (struct khttpd_header *)mem;
	for (i = 0; i < KHTTPD_HEADER_HASH_SIZE; ++i)
		while ((field = STAILQ_FIRST(&header->index[i])) != NULL) {
			STAILQ_REMOVE_HEAD(&header->index[i], hash_link);
			uma_zfree(khttpd_header_field_zone, field);
		}
}

static struct khttpd_header_field *
khttpd_header_find(struct khttpd_header *header, char *field_name,
    boolean_t include_trailer)
{
	struct khttpd_header_field *field;
	char *name;
	size_t len;
	uint32_t hash;

	TRACE("enter");

	hash = khttpd_hash32_str_ci(field_name);
	len = strlen(field_name);

	STAILQ_FOREACH(field, &header->index[hash % KHTTPD_HEADER_HASH_SIZE],
	    hash_link) {
		name = field->name;
		if (!include_trailer && header->trailer_begin <= name)
			return (NULL);
		if (name[len] == ':' && strncasecmp(field_name, name, len) == 0)
			return (field);
	}

	return (NULL);
}

static struct khttpd_header_field *
khttpd_header_find_next(struct khttpd_header *header,
    struct khttpd_header_field *current, boolean_t include_trailer)
{
	struct khttpd_header_field *field;
	char *field_name, *name;
	size_t len;

	TRACE("enter");

	field_name = current->name;
	len = current->colon - field_name + 1;

	field = current;
	while ((field = STAILQ_NEXT(field, hash_link)) != NULL) {
		name = field->name;
		if (!include_trailer && header->trailer_begin <= name)
			return (NULL);
		if (name[len] == ':' && strncasecmp(field_name, name, len) == 0)
			return (field);
	}

	return (NULL);
}

static boolean_t
khttpd_header_value_includes(struct khttpd_header *header,
    char *field_name, char *token, boolean_t include_trailer)
{
	struct khttpd_header_field *field;
	const char *begin, *end, *ptr, *sep;
	size_t name_len, token_len;

	TRACE("enter");

	name_len = strlen(field_name);
	token_len = strlen(token);

	for (field = khttpd_header_find(header, field_name, include_trailer);
	     field != NULL;
	     field = khttpd_header_find_next(header, field, include_trailer))
		for (ptr = field->colon + 1; *ptr != '\n'; ptr = sep) {
			begin = khttpd_skip_whitespace(ptr + 1);
			end = khttpd_find_list_item_end(begin, &sep);
			if (end - begin == token_len &&
			    strncasecmp(token, begin, token_len) == 0)
				return (TRUE);
		}

	return (FALSE);
}

static int
khttpd_header_addv(struct khttpd_header *header,
    struct iovec *iov, int iovcnt)
{
	struct khttpd_header_field *field;
	char *line, *colon, *end;
	char *bufp;
	size_t space, len;
	uint32_t hash;
	int i;

	TRACE("enter");

	space = sizeof(header->buffer) - (header->end - header->buffer);
	line = bufp = header->end;
	for (i = 0; i < iovcnt; ++i) {
		len = iov[i].iov_len;
		if (space < len) {
			TRACE("emsgsize");
			return (EMSGSIZE);
		}
		bcopy(iov[i].iov_base, bufp, len);
		bufp += len;
		space -= len;
	}

	if (bufp[-1] != '\n') {
		TRACE("ebadmsg lf");
		return (EBADMSG);
	}

	if (*line == ' ' || *line == '\t') {
		TRACE("ebadmsg bws");
		return (EBADMSG);
	}

	end = line <= bufp - 2 && bufp[-2] == '\r' ? bufp - 2 : bufp - 1;
	if (line == end) {
		TRACE("enomsg");
		return (ENOMSG);
	}

	colon = khttpd_find_ch_in(line, end, ':');
	if (colon == line || !khttpd_is_token(line, colon)) {
		TRACE("ebadmsg token");
		return (EBADMSG);
	}

	header->end = bufp;

	field = uma_zalloc(khttpd_header_field_zone, M_WAITOK);
	field->name = line;
	field->colon = colon;
	field->end = end;

	hash = khttpd_hash32_buf_ci(line, colon);
	STAILQ_INSERT_TAIL(&header->index[hash % KHTTPD_HEADER_HASH_SIZE],
	    field, hash_link);

	return (0);
}

static int
khttpd_header_add(struct khttpd_header *header, char *field)
{
	TRACE("enter");

	struct iovec iov[2] = {
		{
			.iov_base = (void *)field,
			.iov_len = strlen(field)
		},
		{
			.iov_base = (void *)khttpd_crlf,
			.iov_len = sizeof(khttpd_crlf)
		}
	};

	return khttpd_header_addv(header, iov, 2);
}

static void
khttpd_header_add_allow(struct khttpd_header *header,
    const char *allowed_methods)
{
	struct iovec iov[3];
	static const char allow[] = "Allow: ";

	iov[0].iov_base = (void *)allow;
	iov[0].iov_len = sizeof(allow) - 1;
	iov[1].iov_base = (void *)allowed_methods;
	iov[1].iov_len = strlen(allowed_methods);
	iov[2].iov_base = (void *)khttpd_crlf;
	iov[2].iov_len = sizeof(khttpd_crlf);

	khttpd_header_addv(header, iov, sizeof(iov) / sizeof(iov[0]));
}

static void
khttpd_header_add_content_length(struct khttpd_header *header, uint64_t size)
{
	char buf[48];

	snprintf(buf, sizeof(buf), "Content-Length: %jd", (uintmax_t)size);
	khttpd_header_add(header, buf);
}

static void
khttpd_header_start_trailer(struct khttpd_header *header)
{
	TRACE("enter");
	header->trailer_begin = header->end;
}

static int
khttpd_header_list_iter_init(struct khttpd_header *header,
    char *name, struct khttpd_header_field **fp_out, char **cp_out,
    boolean_t include_trailer)
{
	TRACE("enter %s", name);

	struct khttpd_header_field *fp;

	fp = khttpd_header_find(header, name, include_trailer);
	if (fp == NULL) {
		TRACE("enoent");
		return (ENOENT);
	}

	*fp_out = fp;
	*cp_out = fp->colon + 1;

	return (0);
}

static int
khttpd_header_list_iter_next(struct khttpd_header *header,
    struct khttpd_header_field **fp_inout, char **cp_inout,
    char **begin_out, char **end_out, boolean_t include_trailer)
{
	TRACE("enter");

	struct khttpd_header_field *fp;
	char *cp, *begin, *end;

	fp = *fp_inout;
	cp = *cp_inout;
	for (;;) {
		cp = khttpd_skip_whitespace(cp);
		if (*cp == '\r' && cp[1] == '\n') {
			fp = khttpd_header_find_next(header, fp,
			    include_trailer);
			if (fp == NULL) {
				TRACE("enoent");
				return (ENOENT);
			}

			cp = khttpd_find_ch(fp->name, ':') + 1;
			continue;
		}

		if (*cp == ',') {
			++cp;
			continue;
		}

		begin = cp;
		do {
			++cp;
		} while (*cp != '\n' && *cp != ',');
		if (*cp == '\n' && begin < cp && cp[-1] == '\r')
			--cp;
		end = khttpd_rskip_whitespace(cp);

		*fp_inout = fp;
		*cp_inout = cp;
		*begin_out = begin;
		*end_out = end;

		return (0);
	}
}

static int
khttpd_header_get_uint64(struct khttpd_header *header,
    char *name, uint64_t *value_out, boolean_t include_trailer)
{
	uint64_t value, digit, result;
	struct khttpd_header_field *fp;
	char *buf, *cp, *begin, *end;
	int error;
	boolean_t found;

	TRACE("enter %p %s", header, name);

	error = khttpd_header_list_iter_init(header, name, &fp, &cp, FALSE);
	if (error != 0) {
		TRACE("error init %d", error);
		return (error);
	}

	found = FALSE;
	for (;;) {
		error = khttpd_header_list_iter_next(header, &fp, &cp,
		    &begin, &end, FALSE);
		if (error == ENOENT)
			break;

		value = 0;
		for (cp = begin; cp < end; ++cp) {
			if (!isdigit(*cp)) {
				if (DEBUG_ENABLED(TRACE)) {
					buf = khttpd_dup_first_line(cp);
					TRACE("error isdigit: %s", buf);
					free(buf, M_KHTTPD);
				}
				return (EINVAL);
			}
			digit = *cp - '0';
			if (value * 10 + digit < value) {
				TRACE("error range");
				return (found ? EINVAL : ERANGE);
			}
			value = value * 10 + digit;
		}

		if (!found) {
			result = value;
			found = TRUE;
		} else if (result != value) {
			TRACE("error match");
			return (EINVAL);
		}
	}

	if (!found)
		return (ENOENT);

	*value_out = result;

	return (0);
}

/*
 * Note: This function returns ENOENT if there is no Content-Length: header
 * field.  If there is a Content-Length: header field but the list is empty,
 * this function returns 0 and set 0 to *array_size.
 */
static int
khttpd_header_get_transfer_encoding(struct khttpd_header *header,
    char *array, int *array_size)
{
	struct khttpd_header_field *fp;
	char *cp, *begin, *end;
	int error;
	int i, max, size;

	TRACE("enter %p %d", header, *array_size);

	error = khttpd_header_list_iter_init(header, "Transfer-Encoding",
	    &fp, &cp, FALSE);
	if (error != 0) {
		TRACE("error init %d", error);
		return (error);
	}

	size = 0;
	max = *array_size;
	for (;;) {
		error = khttpd_header_list_iter_next(header, &fp, &cp,
		    &begin, &end, FALSE);
		if (error != 0) {
			TRACE("error next %d", error);
			break;
		}

		if (max <= size) {
			TRACE("enobufs");
			return (ENOBUFS);
		}

		for (i = 0; i < KHTTPD_TRANSFER_CODING_TABLE_SIZE; ++i)
			if (strncasecmp(khttpd_transfer_codings[i].token,
			    begin, end - begin) == 0)
				break;

		if (i == KHTTPD_TRANSFER_CODING_TABLE_SIZE) {
			TRACE("einval");
			return (EINVAL);
		}

		array[size++] = khttpd_transfer_codings[i].index;
	}

	*array_size = size;

	return (0);
}

static int
khttpd_header_is_continue_expected(struct khttpd_header *header,
    boolean_t *value_out)
{
	struct khttpd_header_field *fp;
	char *cp, *begin, *end;
	int error;

	TRACE("enter");

	error = khttpd_header_list_iter_init(header, "Expect", &fp, &cp, FALSE);
	if (error == ENOENT) {
		*value_out = FALSE;
		return (0);
	}
	if (error != 0) {
		TRACE("error init %d", error);
		return (error);
	}

	for (;;) {
		error = khttpd_header_list_iter_next(header, &fp, &cp,
		    &begin, &end, FALSE);
		if (error == ENOENT)
			break;
		if (error != 0)
			return (error);
		if (strncasecmp(begin, "100-continue", end - begin) == 0) {
			*value_out = TRUE;
			return (0);
		}
	}

	*value_out = FALSE;

	return (0);
}

/*
 * request
 */

static void
khttpd_request_dtor_null(struct khttpd_request *request)
{
}

static void
khttpd_received_body_null(struct khttpd_socket *socket,
    struct khttpd_request *request, const char *begin, const char *end)
{
}

static void
khttpd_end_of_message_null(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
}

static int
khttpd_request_init(void *mem, int size, int flags)
{
	struct khttpd_request *request;

	request = (struct khttpd_request *)mem;
	STAILQ_INIT(&request->responses);

	return (0);
}

static int
khttpd_request_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_request *request;

	request = (struct khttpd_request *)mem;
	request->dtor = khttpd_request_dtor_null;
	request->received_body = khttpd_received_body_null;
	request->end_of_message = khttpd_end_of_message_null;
	request->header = uma_zalloc(khttpd_header_zone, M_WAITOK);
	request->route = NULL;
	request->target = NULL;
	request->query = NULL;

	return (0);
}

static void
khttpd_request_dtor(void *mem, int size, void *arg)
{
	struct khttpd_request *request = (struct khttpd_request *)mem;
	struct khttpd_response *response;
	struct khttpd_route *route;

	while ((response = STAILQ_FIRST(&request->responses)) != NULL) {
		STAILQ_REMOVE_HEAD(&request->responses, link);
		uma_zfree(khttpd_response_zone, response);
	}

	request->dtor(request);

	route = request->route;
	if (route != NULL)
		khttpd_route_free(route);

	free(request->target, M_KHTTPD);
	free(request->query, M_KHTTPD);
	uma_zfree(khttpd_header_zone, request->header);
}

/*
 * response
 */

static void
khttpd_response_dtor_null(struct khttpd_response *response)
{
}

static int
khttpd_response_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_response *response;

	response = (struct khttpd_response *)mem;
	response->dtor = khttpd_response_dtor_null;
	response->transmit_body = NULL;
	response->header = uma_zalloc(khttpd_header_zone, M_WAITOK);
	bzero(response->data, sizeof(response->data));
	response->status = -1;
	response->version_minor = 1;
	return (0);
}

static void
khttpd_response_dtor(void *mem, int size, void *arg)
{
	struct khttpd_response *response;

	response = (struct khttpd_response *)mem;
	response->dtor(response);
	uma_zfree(khttpd_header_zone, response->header);
}

/*
 * socket
 */

void
khttpd_socket_hold(struct khttpd_socket *socket)
{
	TRACE("enter %d", socket->fd);
	++socket->refcount;
}

void
khttpd_socket_free(struct khttpd_socket *socket)
{
	TRACE("enter %d", socket->fd);
	if (--socket->refcount == 0)
		uma_zfree(khttpd_socket_zone, socket);
}

static void
khttpd_socket_clear_all_requests(struct khttpd_socket *socket)
{
	struct khttpd_request *request;

	TRACE("enter %d", socket->fd);

	while ((request = STAILQ_FIRST(&socket->requests)) != NULL) {
		STAILQ_REMOVE_HEAD(&socket->requests, link);
		uma_zfree(khttpd_request_zone, request);
	}
}

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket = (struct khttpd_socket *)mem;

	TRACE("enter");

	socket->event_type.handle_event = khttpd_handle_socket_event;
	STAILQ_INIT(&socket->requests);
	socket->xmit_uio.uio_resid = 0;
	socket->receive = khttpd_receive_request_line;
	socket->transmit = khttpd_transmit_status_line_and_header;
	socket->recv_getp = socket->recv_putp = socket->recv_buf;
	socket->recv_residual = 0;
	socket->fd = -1;
	socket->refcount = 1;
	socket->xmit_busy = FALSE;
	socket->eof = FALSE;
	socket->recv_chunked = FALSE;
	socket->recv_skip = KHTTPD_NO_SKIP;

	return (0);
}

static void
khttpd_socket_dtor(void *mem, int size, void *arg)
{
	struct khttpd_socket *socket = (struct khttpd_socket *)mem;

	TRACE("enter %d", socket->fd);

	KASSERT(STAILQ_EMPTY(&socket->requests), ("orphan request"));
	KASSERT(socket->refcount == 0, ("refcount=%d", socket->refcount));

	if (socket->fd != -1) {
		kern_close(curthread, socket->fd);
		socket->fd = -1;
	}
}

static void
khttpd_socket_reset(struct khttpd_socket *socket)
{
	TRACE("enter %d", socket->fd);

	kern_close(curthread, socket->fd);
	socket->fd = -1;
	socket->eof = TRUE;

	khttpd_socket_clear_all_requests(socket);

	LIST_REMOVE(socket, link);
	khttpd_socket_free(socket);
}

static int
khttpd_socket_drain(struct kevent *event)
{
	struct iovec aiov;
	struct uio auio;
	struct khttpd_socket *socket;
	struct thread *td;
	int error;

	TRACE("enter %td", event->ident);

	td = curthread;
	socket = (struct khttpd_socket *)event->udata;

	aiov.iov_base = socket->recv_buf;
	aiov.iov_len = sizeof socket->recv_buf;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;

	do {
		auio.uio_resid = sizeof socket->recv_buf;
		error = kern_readv(td, socket->fd, &auio);
	} while (error == 0 && td->td_retval[0] != 0);

	if (error == 0)
		khttpd_socket_reset(socket);

	return (error);
}

static void
khttpd_socket_shutdown(struct khttpd_socket *socket)
{
	struct shutdown_args args;

	TRACE("enter %d", socket->fd);

	args.s = socket->fd;
	args.how = SHUT_WR;
	sys_shutdown(curthread, &args);

	socket->recv_getp = socket->recv_putp = socket->recv_buf;
	socket->recv_skip = KHTTPD_NO_SKIP;
	socket->receive = khttpd_socket_drain;

	khttpd_socket_clear_all_requests(socket);
}

/*
 * The pointers and the lengthes of the returned string in socket->recv_buf is
 * set to linev and linevcnt.
 *
 * The string includes the terminator character.
 *
 * The maximum number of characters returned is
 * KHTTPD_LINE_MAX.
 *
 * ERRORS
 *	This function will succeed unless:
 *
 *	[ECONNRESET]	The socket end is forcibly closed.
 *
 *	[EWOULDBLOCK]	Not enough data were ready to be read from the socket.
 */
static int
khttpd_socket_skip(struct khttpd_socket *socket)
{
	struct uio auio;
	struct iovec iov;
	struct thread *td;
	char *end, *bufend;
	int error, size;
	char skip;

	td = curthread;
	skip = socket->recv_skip;

	TRACE("enter %d %#x", socket->fd, skip);

	bufend = socket->recv_buf + sizeof(socket->recv_buf);

	for (;;) {
		if (socket->recv_getp <= socket->recv_putp)
			end = khttpd_find_ch_in(socket->recv_getp,
			    socket->recv_putp, skip);

		else {
			end = khttpd_find_ch_in(socket->recv_getp,
			    bufend, skip);
			if (end == NULL)
				end = khttpd_find_ch_in(socket->recv_buf,
				    socket->recv_putp, skip);
		}

		if (end != NULL) {
			socket->recv_getp = end + 1 < bufend
			    ? end + 1
			    : socket->recv_buf;
			socket->recv_skip = KHTTPD_NO_SKIP;
			break;
		}

		socket->recv_getp = socket->recv_putp = socket->recv_buf;

		auio.uio_iov = &iov;
		auio.uio_iovcnt = 1;
		auio.uio_resid = sizeof(socket->recv_buf) - 1;
		auio.uio_segflg = UIO_SYSSPACE;

		iov.iov_base = socket->recv_buf;
		iov.iov_len = auio.uio_resid;

		if ((error = kern_readv(td, socket->fd, &auio)) != 0) {
			TRACE("error readv %d", error);
			return (error);
		}

		size = td->td_retval[0];
		if (size == 0) {
			socket->eof = TRUE;
			socket->recv_skip = KHTTPD_NO_SKIP;
			TRACE("eof");
			break;
		}

		socket->recv_putp = socket->recv_buf + size;
	}

	return (0);
}

/*
 * The pointers and the lengthes of the returned string in socket->recv_buf is
 * set to linev and linevcnt.
 *
 * The string includes the terminator character.
 *
 * The maximum number of characters returned is
 * KHTTPD_LINE_MAX.
 *
 * ERRORS
 *	This function will succeed unless:
 *
 *	[ENOBUFS]	There are more than KHTTPD_LINE_MAX characters before
 *			terminator character appears.
 *
 *	[EBADMSG]	The last line is not terminated by CRLF.
 *
 *	[ECONNRESET]	The socket end is forcibly closed.
 *
 *	[EWOULDBLOCK]	Not enough data were ready to be read from the socket.
 */
static int
khttpd_socket_read(struct khttpd_socket *socket, char terminator,
    struct iovec *linev, int *linevcnt)
{
	struct uio auio;
	struct iovec iov[2];
	struct thread *td;
	char *bufend, *end, *new_putp;
	int error, size, space;

	TRACE("enter %d %#x", socket->fd, terminator);

	td = curthread;
	bufend = socket->recv_buf + sizeof(socket->recv_buf);

	for (;;) {
		if (socket->recv_skip != KHTTPD_NO_SKIP)
			khttpd_socket_skip(socket);

		if (socket->recv_getp <= socket->recv_putp)
			end = khttpd_find_ch_in(socket->recv_getp,
			    socket->recv_putp, terminator);

		else {
			end = khttpd_find_ch_in(socket->recv_getp,
			    bufend, terminator);
			if (end == NULL)
				end = khttpd_find_ch_in(socket->recv_buf,
				    socket->recv_putp, terminator);
		}

		if (end != NULL)
			break;

		space = socket->recv_getp - socket->recv_putp - 1;
		if (space < 0)
			space += sizeof(socket->recv_buf);
		if (space == 0) {
			socket->recv_skip = terminator;
			socket->recv_getp = socket->recv_putp =
			    socket->recv_buf;
			TRACE("error enobufs");
			return (ENOBUFS);
		}

		auio.uio_iov = iov;
		auio.uio_resid = space;
		auio.uio_segflg = UIO_SYSSPACE;

		if (socket->recv_putp < socket->recv_getp) {
			iov[0].iov_base = socket->recv_putp;
			iov[0].iov_len = space;
			auio.uio_iovcnt = 1;

		} else {
			iov[0].iov_base = socket->recv_putp;
			iov[0].iov_len = bufend - socket->recv_putp;
			iov[1].iov_base = socket->recv_buf;
			iov[1].iov_len =
			    socket->recv_getp - socket->recv_buf - 1;
			auio.uio_iovcnt = 2;

		}

		if ((error = kern_readv(td, socket->fd, &auio)) != 0) {
			TRACE("readv error %d", error);
			return (error);
		}

		size = td->td_retval[0];
		if (size == 0) {
			socket->eof = TRUE;
			end = NULL;
			break;
		}

		new_putp = socket->recv_putp + size;
		if (bufend <= new_putp)
			new_putp -= sizeof(socket->recv_buf);
		socket->recv_putp = new_putp;
	}

	end = end == NULL ? socket->recv_putp : end + 1;

	if (socket->recv_getp <= end) { 
		linev[0].iov_base = socket->recv_getp;
		linev[0].iov_len = end - socket->recv_getp;
		*linevcnt = 1;

	} else {
		linev[0].iov_base = socket->recv_getp;
		linev[0].iov_len = bufend - socket->recv_getp;
		linev[1].iov_base = socket->recv_buf;
		linev[1].iov_len = end - socket->recv_buf;
		*linevcnt = 2;

	}

	socket->recv_getp = end == bufend ? socket->recv_buf : end;

	return (0);
}

/*
 * The output string includes CRLF if they exist in the input stream.
 *
 * The output string is NUL-terminated by this function.
 * 
 * The size of the given buffer must be KHTTPD_LINE_MAX + 1 bytes.
 *
 * ERRORS
 *	This function will succeed unless:
 *
 *	[EBADMSG]	The last line of the input is not terminated by CRLF.
 *
 *	Others		khttpd_socket_read() failed.
 */
static int
khttpd_socket_readline(struct khttpd_socket *socket, char *buf)
{
	struct iovec iov[2];
	char *end;
	size_t len;
	int error, i, iovcnt;

	error = khttpd_socket_read(socket, '\n', iov, &iovcnt);
	if (error != 0)
		return (error);
	if (socket->eof)
		return (EBADMSG);

	end = buf;
	for (i = 0; i < iovcnt; ++i) {
		len = iov[i].iov_len;
		bcopy(iov[i].iov_base, end, len);
		end += len;
	}
	if (buf < end && end[-1] == '\n')
		--end;
	else
		return (EBADMSG);
	if (buf < end && end[-1] == '\r')
		--end;
	*end = '\0';

	if (DEBUG_ENABLED(MESSAGE))
		DEBUG("< '%s'", buf);

	return (0);
}

void
khttpd_send_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	int error, transfer_codings_count;
	char transfer_codings[KHTTPD_TRANSFER_CODING_COUNT];

	TRACE("enter %d %s", socket->fd, request->target);

	KASSERT(response->status != -1,
	    ("status for %p has not been set.", response));

	if (response->status / 100 == 1 ||
	    response->status == 204 ||
	    response->status == 304 ||
	    request->method == KHTTPD_METHOD_HEAD) {
		response->content_length = 0;
		response->chunked = FALSE;
		goto body_fixed;
	}

	transfer_codings_count = sizeof(transfer_codings) /
	    sizeof(transfer_codings[0]);
	error = khttpd_header_get_transfer_encoding(response->header,
	    transfer_codings, &transfer_codings_count);
	switch (error) {

	case 0:
		if (transfer_codings_count == 0)
			break;

		if (2 <= transfer_codings_count ||
		    (transfer_codings_count == 1 &&
			transfer_codings[0] != KHTTPD_TRANSFER_CODING_CHUNKED))
			panic("%s: unsupported transfer coding: %p(%d)",
			    __func__, transfer_codings, transfer_codings_count);

		error = khttpd_header_get_uint64(response->header,
		    "Content-Length", &response->content_length, FALSE);
		if (error != ENOENT)
			panic("%s: both Transfer-Encoding and Content-Length "
			    "fields are specified.", __func__);

		response->content_length = 0;
		response->chunked = TRUE;
		goto body_fixed;

	case ENOENT:
		break;

	case EINVAL:
	case ENOBUFS:
		panic("%s: invalid Transfer-Encoding field. "
		    "route=%p, request=%p, response=%p",
		    __func__, request->route, request, response);

	default:
		panic("%s: unknown error: %d", __func__, error);
	}

	error = khttpd_header_get_uint64(response->header, "Content-Length",
	    &response->content_length, FALSE);
	switch (error) {

	case 0:
		break;

	case ENOENT:
		panic("%s: Content-Length field required", __func__);

	default:
		panic("%s: invalid Content-Length field", __func__);
	}

	response->chunked = FALSE;

body_fixed:
	STAILQ_INSERT_TAIL(&request->responses, response, link);

	if (STAILQ_FIRST(&socket->requests) == request)
		khttpd_ready_to_send(socket);
}

void
khttpd_ready_to_send(struct khttpd_socket *socket)
{
	TRACE("enter");

	if (socket->xmit_busy)
		return;

	socket->xmit_busy = TRUE;
	khttpd_kevent_enable_write(khttpd_kqueue, socket->fd, TRUE,
	    &socket->event_type);
}

static int
khttpd_transmit_end(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	boolean_t continue_response;
	boolean_t close;

	TRACE("enter %d", socket->fd);

	continue_response = 100 <= response->status && response->status < 200;

	close = !continue_response &&
	    khttpd_header_value_includes(response->header,
		"Connection", "close", FALSE);

	STAILQ_REMOVE_HEAD(&request->responses, link);
	uma_zfree(khttpd_response_zone, response);

	if (!continue_response) {
		STAILQ_REMOVE_HEAD(&socket->requests, link);
		uma_zfree(khttpd_request_zone, request);

		if (close)
			khttpd_socket_shutdown(socket);
	}

	socket->transmit = khttpd_transmit_status_line_and_header;

	return (0);
}

static int
khttpd_transmit_trailer(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	const char *cp, *end, *lf;
	char *buf;
	size_t len;

	TRACE("enter %d", socket->fd);

	socket->xmit_iov[0].iov_base = response->header->trailer_begin;
	len = socket->xmit_iov[1].iov_len = response->header->end -
	    response->header->trailer_begin;

	socket->xmit_iov[1].iov_base = (void *)khttpd_crlf;
	len += socket->xmit_iov[1].iov_len = sizeof(khttpd_crlf);

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = 2;
	socket->xmit_uio.uio_resid = len;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	socket->transmit = khttpd_transmit_end;

	if (DEBUG_ENABLED(MESSAGE)) {
		end = response->header->end;
		for (cp = response->header->trailer_begin;
		     cp < end; cp = lf + 1) {
			lf = khttpd_find_ch(cp, '\n');
			buf = khttpd_dup_first_line(cp);
			DEBUG("> '%s'", buf);
			free(buf, M_KHTTPD);
		}

		DEBUG("> ''");
	}

	return (0);
}

static int
khttpd_transmit_chunk(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	void *base, *last_base;
	char *line;
	size_t last_len, len, size;
	int error, i, n;

	TRACE("enter %d", socket->fd);

	error = response->transmit_body(socket, request, response);
	if (error != 0) {
		TRACE("error transmit_body %d", error);
		return (error);
	}

	n = socket->xmit_uio.uio_iovcnt;
	KASSERT(n + 2 <= sizeof(socket->xmit_iov) / sizeof(socket->xmit_iov[0]),
	    ("iovec overflow"));

	last_base = socket->xmit_line;
	last_len = 0;
	size = 0;
	for (i = 0; i < n; ++i) {
		base = socket->xmit_iov[i].iov_base;
		size += len = socket->xmit_iov[i].iov_len;
		socket->xmit_iov[i].iov_base = last_base;
		socket->xmit_iov[i].iov_len = last_len;
		last_base = base;
		last_len = len;
	}
	socket->xmit_iov[i].iov_base = last_base;
	socket->xmit_iov[i].iov_len = last_len;
	socket->xmit_iov[i + 1].iov_base = khttpd_crlf;
	socket->xmit_iov[i + 1].iov_len = sizeof(khttpd_crlf);
	socket->xmit_uio.uio_iovcnt = n + 2;

	socket->xmit_iov[0].iov_len = 
	    snprintf(socket->xmit_line, sizeof(socket->xmit_line),
		"%jx\r\n", (uintmax_t)size);

	if (DEBUG_ENABLED(MESSAGE)) {
		line = khttpd_dup_first_line(socket->xmit_line);
		DEBUG("> '%s'", line);
		free(line, M_KHTTPD);
	}

	if (size == 0)
		socket->transmit = khttpd_transmit_trailer;

	return (0);
}

static int
khttpd_transmit_mbuf_data(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	struct mbuf *mbuf, *ptr;
	size_t resid;
	int i, n;

	TRACE("enter %d", socket->fd);

	ptr = (struct mbuf *)response->data[0];
	mbuf = (struct mbuf *)response->data[1];
	while (ptr != mbuf)
		ptr = m_free(ptr);
	response->data[0] = ptr;
	if (ptr == NULL) {
		socket->transmit = khttpd_transmit_end;
		return (khttpd_transmit_end(socket, request, response));
	}

	i = 0;
	n = sizeof(socket->xmit_iov) / sizeof(socket->xmit_iov[0]);
	resid = 0;
	for (ptr = mbuf; ptr != NULL && i < n; ptr = ptr->m_next, ++i) {
		socket->xmit_iov[i].iov_base = mtod(ptr, void *);
		resid += socket->xmit_iov[i].iov_len = ptr->m_len;
	}
	response->data[1] = ptr;

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = i;
	socket->xmit_uio.uio_resid = resid;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	return (0);
}

static int
khttpd_transmit_static_data(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	size_t len;

	TRACE("enter %d", socket->fd);

	socket->xmit_iov[0].iov_base = response->data[0];
	socket->xmit_iov[0].iov_len = len = strlen(response->data[0]);

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = 1;
	socket->xmit_uio.uio_resid = len;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	socket->transmit = khttpd_transmit_end;

	return (0);
}

static int
khttpd_transmit_body(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	int error;

	TRACE("enter %d", socket->fd);

	error = response->transmit_body(socket, request, response);
	if (error != 0)
		TRACE("error transmit_body %d", error);

	return (error);
}

static int
khttpd_transmit_status_line_and_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	const char *cp, *ep, *lf;
	char *line;
	size_t len;

	TRACE("enter %d", socket->fd);

	len = snprintf(socket->xmit_line, sizeof(socket->xmit_line),
	    "HTTP/1.%d %d n/a\r\n",
	    response->version_minor, response->status);

	socket->xmit_iov[0].iov_base = socket->xmit_line;
	socket->xmit_iov[0].iov_len = len;

	socket->xmit_iov[1].iov_base = response->header->buffer;
	len += socket->xmit_iov[1].iov_len =
	    MIN(response->header->end, response->header->trailer_begin) -
	    response->header->buffer;

	socket->xmit_iov[2].iov_base = (void *)khttpd_crlf;
	len += socket->xmit_iov[2].iov_len = sizeof(khttpd_crlf);

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = 3;
	socket->xmit_uio.uio_resid = len;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	if (DEBUG_ENABLED(MESSAGE)) {
		line = khttpd_dup_first_line(socket->xmit_line);
		DEBUG("> '%s'", line);
		free(line, M_KHTTPD);

		ep = MIN(response->header->end,
		    response->header->trailer_begin);
		for (cp = response->header->buffer; cp < ep; cp = lf + 1) {
			lf = khttpd_find_ch(cp, '\n');
			line = khttpd_dup_first_line(cp);
			DEBUG("> '%s'", line);
			free(line, M_KHTTPD);
		}

		DEBUG("> ''");
	}

	if (response->chunked)
		socket->transmit = khttpd_transmit_chunk;
	else if (0 < response->content_length)
		socket->transmit = khttpd_transmit_body;
	else
		socket->transmit = khttpd_transmit_end;

	return (0);
}

void
khttpd_send_continue_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	TRACE("enter");

	if (response == NULL)
		response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	response->status = 100;
	khttpd_send_response(socket, request, response);
}

void
khttpd_send_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *content, boolean_t close)
{
	size_t len;

	TRACE("enter %d %d", status, close);

	if (response == NULL)
		response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	response->status = status;

	if (close) {
		khttpd_header_add(response->header, "Connection: close");
		socket->receive = khttpd_socket_drain;
	}

	if (content != NULL) {
		response->data[0] = (void *)content;
		len = strlen(content);

		khttpd_header_add_content_length(response->header, len);
		khttpd_header_add(response->header,
		    "Content-Type: text/html; charset=US-ASCII");

		response->transmit_body = khttpd_transmit_static_data;
	}

	khttpd_send_response(socket, request, response);
}

void
khttpd_send_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    int status, const char *reason, const char *description, boolean_t close)
{
	static const char fmt[] = "<!DOCTYPE html>"
	    "<html lang='en'>"
		"<head>"
		    "<meta charset='US-ASCII' />"
		    "<title>%d %s</title>"
		"</head>"
		"<body>"
		    "<h1>%s</h1>"
		    "<p>%s</p>"
		"</body>"
	    "</html>";

	struct mbuf *mbuf;

	if (response == NULL)
		response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	KASSERT(response->transmit_body == NULL,
	    ("transmit_body has already been set %p", response->transmit_body));

	response->status = status;

	response->transmit_body = khttpd_transmit_mbuf_data;
	response->data[0] = response->data[1] = mbuf = m_get(M_WAITOK, MT_DATA);
	khttpd_mbuf_printf(mbuf, fmt, status, reason, reason, description);

	khttpd_header_add_content_length(response->header,
	    m_length(mbuf, NULL));
	khttpd_header_add(response->header,
	    "Content-Type: text/html; charset=US-ASCII");

	if (close)
		khttpd_header_add(response->header, "Connection: close");

	khttpd_send_response(socket, request, response);
}

void
khttpd_send_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 400,
	    "Bad Reqeust",
	    "A request that this server could not understand was sent.", TRUE);
}

void
khttpd_send_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 413,
	    "Payload Too Large",
	    "The request payload is larger than this server could handle.",
	    TRUE);
}

void
khttpd_send_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 501,
	    "Not Implemented",
	    "The server does not support the requested functionality.", close);
}

void
khttpd_send_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 404,
	    "Not Found",
	    "The server does not have the requested resource.", close);
}

void
khttpd_send_method_not_allowed_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close,
    const char *allowed_methods)
{
	struct khttpd_response *response;

	TRACE("enter");
	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
	khttpd_header_add_allow(response->header, allowed_methods);
	khttpd_send_error_response(socket, request, response, 405,
	    "Method Not Allowed",
	    "The requested method is not supported by the target resource.",
	    close);
}

void
khttpd_send_conflict_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 404,
	    "Conflict",
	    "The request could not be completed due to a conflict with the "
	    "current state of the target resource.", close);
}

void
khttpd_send_request_header_field_too_large_response
(struct khttpd_socket *socket, struct khttpd_request *request)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 431,
	    "Request Header Fields Too Large",
	    "The header fields in the request is too large.", TRUE);
}

void
khttpd_send_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter");
	khttpd_send_error_response(socket, request, NULL, 500,
	    "Internal Server Error",
	    "The server encountered an unexpected condition "
	    "that prevent it from fulfilling the reqeust.", TRUE);
}

void
khttpd_send_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods)
{
	TRACE("enter \"%s\"", allowed_methods);

	if (response == NULL)
		response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	response->status = 200;

	/* RFC7231 section 4.3.7 mandates to send Content-Length: 0 */
	response->data[0] = (void *)"";
	response->transmit_body = khttpd_transmit_static_data;
	khttpd_header_add(response->header, "Content-Length: 0");

	khttpd_header_add_allow(response->header, allowed_methods);

	khttpd_send_response(socket, request, response);
}

static int
khttpd_receive_crlf_following_chunk_data(struct kevent *event)
{
	struct khttpd_request *request;
	struct khttpd_socket  *socket;
	int error;

	socket = (struct khttpd_socket *)event->udata;
	request = STAILQ_LAST(&socket->requests, khttpd_request, link);

	TRACE("enter %td", event->ident);

	KASSERT(socket->recv_chunked, ("recv_chunked must be TRUE"));

	error = khttpd_socket_readline(socket, socket->recv_line);
	if (error == EBADMSG) {
		khttpd_send_bad_request_response(socket, request);
		return (0);
	}
	if (error != 0) {
		TRACE("error %td", event->ident);
		return (error);
	}

	if (socket->recv_line[0] != '\0')
		khttpd_send_bad_request_response(socket, request);
	else
		socket->receive = khttpd_receive_chunk;

	return (0);
}

static int
khttpd_receive_chunk(struct kevent *event)
{
	struct khttpd_request *request;
	struct khttpd_socket  *socket;
	uint64_t chunk_length;
	char *sep, *cp;
	int error, nibble;
	char ch;

	socket = (struct khttpd_socket *)event->udata;
	request = STAILQ_LAST(&socket->requests, khttpd_request, link);

	TRACE("enter %td", event->ident);

	KASSERT(socket->recv_chunked, ("recv_chunked must be TRUE"));

	error = khttpd_socket_readline(socket, socket->recv_line);
	if (error == EBADMSG) {
		khttpd_send_bad_request_response(socket, request);
		return (0);
	}
	if (error != 0) {
		TRACE("readline %td", event->ident);
		return (error);
	}

	sep = khttpd_find_ch(socket->recv_line, ';');
	if (sep != NULL)
		*sep = '\0';

	chunk_length = 0;
	for (cp = socket->recv_line; (ch = *cp) != '\0'; ++cp) {
		if (!isxdigit(ch)) {
			khttpd_send_bad_request_response(socket, request);
			return (0);
		}

		nibble = isdigit(ch) ? ch - '0'
		    : 'a' <= ch && ch <= 'f' ? ch - 'a'
		    : ch - 'A';

		if ((chunk_length << 4) + nibble < chunk_length) {
			khttpd_send_payload_too_large_response(socket, request);
			return (0);
		}

		chunk_length = (nibble << 4) + nibble;
	}

	if (chunk_length == 0)
		socket->receive = khttpd_receive_header_or_trailer;

	else {
		socket->recv_residual = chunk_length;
		socket->receive = khttpd_receive_body;

	}

	return (0);
}

static int
khttpd_receive_body(struct kevent *event)
{
	struct iovec aiov;
	struct uio auio;
	struct khttpd_request *request;
	struct khttpd_socket *socket;
	struct thread *td;
	char *bufend, *end;
	int error, size;
	boolean_t wrapped;

	td = curthread;
	socket = (struct khttpd_socket *)event->udata;
	request = STAILQ_LAST(&socket->requests, khttpd_request, link);

	TRACE("enter %td %#jx %d", event->ident,
	    (uintmax_t)socket->recv_residual, socket->recv_chunked);

	if (socket->recv_skip != KHTTPD_NO_SKIP)
		khttpd_socket_skip(socket);

	bufend = socket->recv_buf + sizeof(socket->recv_buf);

	size = socket->recv_putp - socket->recv_getp;
	if (size != 0) {
		if (size < 0)
			size += sizeof(socket->recv_buf);
		if (socket->recv_residual < size)
			size = socket->recv_residual;

		end = socket->recv_getp + size;
		wrapped = bufend < end;

		request->received_body(socket, request, socket->recv_getp,
		    wrapped ? bufend : end);

		if (wrapped) {
			end -= sizeof(socket->recv_buf);
			request->received_body(socket, request,
			    socket->recv_buf, end);
		}

		if ((socket->recv_residual -= size) == 0)
			socket->recv_getp = bufend == end
			    ? socket->recv_buf : end;
		else
			socket->recv_getp = socket->recv_putp =
			    socket->recv_buf;
	}

	while (0 < socket->recv_residual) {
		TRACE("recv_residual %#lx", socket->recv_residual);

		aiov.iov_base = socket->recv_buf;
		aiov.iov_len = MIN(socket->recv_residual,
		    sizeof socket->recv_buf);

		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_resid = aiov.iov_len;

		error = kern_readv(td, socket->fd, &auio);
		if (error != 0) {
			TRACE("kern_readv %d", error);
			return (error);
		}

		size = td->td_retval[0];
		if (size == 0) {
			TRACE("eof");
			socket->eof = TRUE;
			khttpd_socket_reset(socket);
			return (0);
		}

		socket->recv_residual -= size;

		request->received_body(socket, request, socket->recv_buf,
		    socket->recv_buf + size);
	}

	if (socket->recv_chunked)
		socket->receive = khttpd_receive_crlf_following_chunk_data;

	else {
		request->end_of_message(socket, request);
		socket->receive = khttpd_receive_request_line;
	}

	return (0);
}

static void
khttpd_dispatch_request(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct khttpd_route *route;
	int error;
	int transfer_codings_count;
	char transfer_codings[KHTTPD_TRANSFER_CODING_COUNT];
	boolean_t chunked;
	boolean_t content_length_specified;
	boolean_t continue_expected;

	TRACE("enter");

	error = khttpd_header_get_uint64(request->header, "Content-Length",
	    &request->content_length, FALSE);
	if (error != 0)
		TRACE("error get_content_length %d", error);
	switch (error) {

	case 0:
		content_length_specified = TRUE;
		break;

	case ENOENT:
		content_length_specified = FALSE;
		break;

	case EINVAL:
		khttpd_send_bad_request_response(socket, request);
		return;

	case ERANGE:
		khttpd_send_payload_too_large_response(socket, request);
		return;

	default:
		khttpd_send_internal_error_response(socket, request);
		return;
	}

	transfer_codings_count = sizeof transfer_codings /
	    sizeof transfer_codings[0];
	error = khttpd_header_get_transfer_encoding(request->header,
	    transfer_codings, &transfer_codings_count);
	if (error != 0)
		TRACE("error get_transfer_encoding %d", error);
	switch (error) {

	case 0:
		/*
		 * The server doesn't support transfer encodings other than
		 * 'chunked'.
		 */
		if (2 <= transfer_codings_count ||
		    (transfer_codings_count == 1 &&
		     transfer_codings[0] != KHTTPD_TRANSFER_CODING_CHUNKED)) {
			TRACE("error unsupported");
			khttpd_send_not_implemented_response(socket, request,
			    TRUE);
			return;
		}

		chunked = 0 < transfer_codings_count &&
		    transfer_codings[transfer_codings_count - 1] ==
		    KHTTPD_TRANSFER_CODING_CHUNKED;

		content_length_specified = FALSE;
		break;

	case ENOENT:
		chunked = FALSE;
		break;

	case EINVAL:
	case ENOBUFS:
		khttpd_send_not_implemented_response(socket, request, TRUE);
		return;

	default:
		khttpd_send_internal_error_response(socket, request);
		return;
	}

	socket->recv_chunked = chunked;

	if (chunked) {
		khttpd_header_start_trailer(request->header);
		socket->receive = khttpd_receive_chunk;
		request->content_length = 0;

	} else if (content_length_specified && 0 < request->content_length) {
		socket->receive = khttpd_receive_body;
		socket->recv_residual = request->content_length;

	} else {
		socket->receive = khttpd_receive_request_line;
		request->content_length = 0;

	}

	route = khttpd_route_find(&khttpd_route_root, request->target,
	    &request->target_suffix);
	if (route == NULL) {
		TRACE("no route");
		khttpd_send_not_found_response(socket, request,
		    chunked || request->content_length != 0);
		return;
	}

	khttpd_route_hold(route);
	request->route = route;

	(*route->received_header)(socket, request);

	if (STAILQ_EMPTY(&request->responses) && 1 <= request->version_minor) {
		error = khttpd_header_is_continue_expected(request->header,
		    &continue_expected);
		if (error != 0) {
			TRACE("error is_continue_expected %d", error);
			khttpd_send_internal_error_response(socket, request);
			return;
		}

		if (continue_expected)
			khttpd_send_continue_response(socket, request, NULL);
	}

	if (!chunked &&
	    !(content_length_specified && 0 < request->content_length))
		request->end_of_message(socket, request);
}

static int
khttpd_receive_header_or_trailer(struct kevent *event)
{
	struct iovec iov[2];
	struct khttpd_request *request;
	struct khttpd_socket  *socket;
	char *buf, *end;
	size_t len;
	int error, i, iovcnt;

	TRACE("enter %td", event->ident);

	socket = (struct khttpd_socket *)event->udata;
	request = STAILQ_LAST(&socket->requests, khttpd_request, link);

	error = khttpd_socket_read(socket, '\n', iov, &iovcnt);
	if (error != 0)
		TRACE("read %d", error);
	if (error == ENOBUFS) {
		khttpd_send_request_header_field_too_large_response(socket,
		    request);
		return (0);
	}
	if (error != 0)
		return (error);

	if (DEBUG_ENABLED(MESSAGE)) {
		len = (0 < iovcnt ? iov[0].iov_len : 0) +
		    (1 < iovcnt ? iov[1].iov_len : 0) + 1;
		buf = malloc(len, M_KHTTPD, M_WAITOK);

		end = buf;
		for (i = 0; i < iovcnt; ++i) {
			len = iov[i].iov_len;
			bcopy(iov[i].iov_base, end, len);
			end += len;
		}
		if (buf < end && end[-1] == '\n')
			--end;
		if (buf < end && end[-1] == '\r')
			--end;
		*end = '\0';

		DEBUG("< '%s'", buf);

		free(buf, M_KHTTPD);
	}

	error = khttpd_header_addv(request->header, iov, iovcnt);
	switch (error) {

	case ENOMSG:
		if (socket->recv_chunked) {
			request->end_of_message(socket, request);
			socket->receive = khttpd_receive_request_line;
			socket->recv_chunked = FALSE;
		} else
			khttpd_dispatch_request(socket, request);
		return (0);

	case EBADMSG:
		khttpd_send_bad_request_response(socket, request);
		return (0);

	case EMSGSIZE:
		khttpd_send_request_header_field_too_large_response(socket,
		    request);
		return (0);

	default:
		; 		/* nothing */
	}

	return (error);
}

static int
khttpd_receive_request_line(struct kevent *event)
{
	struct khttpd_request *request;
	struct khttpd_socket *socket;
	char *query, *query_end, *sep, *target, *target_end, *version;
	int error;

	TRACE("enter %td", event->ident);

	socket = (struct khttpd_socket *)event->udata;

	KASSERT(!socket->recv_chunked, ("recv_chunked must be FALSE"));

	request = uma_zalloc_arg(khttpd_request_zone, event->udata, M_WAITOK);

	error = khttpd_socket_readline(socket, socket->recv_line);
	if (error != 0)
		TRACE("error readline %d", error);
	if (error == EWOULDBLOCK)
		goto out;
	if (error != 0)
		goto reject;

	sep = khttpd_find_ch(socket->recv_line, ' ');
	if (sep == NULL || sep == socket->recv_line) {
		TRACE("error method-separator");
		goto reject;
	}
	request->method = khttpd_method_find(socket->recv_line, sep);
	TRACE("method %d", request->method);

	target = sep + 1;
	sep = khttpd_find_ch(target, ' ');
	if (sep == NULL || sep == target) {
		TRACE("error request-target-separator");
		goto reject;
	}

	version = sep + 1;

	query = khttpd_find_ch(target, '?');
	if (query == NULL) {
		target_end = sep;

	} else  {
		target_end = query++;
		query_end = khttpd_unquote_uri(query, sep);
		if (query_end == NULL) {
			TRACE("error unquote_uri1");
			goto reject;
		}

		request->query =
		    malloc(query_end - query + 1, M_KHTTPD, M_WAITOK);
		bcopy(query, request->query, query_end - query);
		request->query[query_end - query] = '\0';
	}

	target_end = khttpd_unquote_uri(target, target_end);
	if (target_end == NULL) {
		TRACE("error unquote_uri2");
		goto reject;
	}

	request->target = malloc(target_end - target + 1, M_KHTTPD, M_WAITOK);
	bcopy(target, request->target, target_end - target);
	request->target[target_end - target] = '\0';

	if (strlen(version) != 8 || strncmp(version, "HTTP/1.", 7) != 0 ||
	    !isdigit(version[7])) {
		TRACE("error HTTP-version %zd %s", strlen(version), version);
		goto reject;
	}
	request->version_minor = version[7] - '0';

	socket->receive = khttpd_receive_header_or_trailer;
	STAILQ_INSERT_TAIL(&socket->requests, request, link);

	return (0);

reject:
	khttpd_socket_reset(socket);
	error = 0;

out:
	uma_zfree(khttpd_request_zone, request);

	return (error);
}

static void
khttpd_accept_client(struct kevent *event)
{
	struct sockaddr *name;
	struct khttpd_server_port *port;
	struct khttpd_socket *socket;
	struct thread *td;
	socklen_t namelen;
	int error, fd;

	TRACE("enter %td", event->ident);

	td = curthread;
	port = (struct khttpd_server_port *)event->udata;

	error = kern_accept4(td, port->fd, &name, &namelen, SOCK_NONBLOCK,
	    NULL);
	if (error != 0) {
		TRACE("error accept %d", error);
		return;
	}
	fd = td->td_retval[0];

	TRACE("ident %d", fd);

	socket = (struct khttpd_socket *)
	    uma_zalloc(khttpd_socket_zone, M_WAITOK);
	socket->fd = fd;
	bcopy(name, &socket->peer_addr, namelen);

	error = khttpd_kevent_add_read_write(khttpd_kqueue, socket->fd,
	    (struct khttpd_event_type *)socket);
	if (error != 0) {
		TRACE("error kevent_add_read_write %d", error);
		khttpd_socket_free(socket);
		return;
	}

	LIST_INSERT_HEAD(&khttpd_sockets, socket, link);
}

static void
khttpd_handle_socket_event(struct kevent *event)
{
	struct khttpd_socket *socket;
	struct khttpd_request *request;
	struct khttpd_response *response;
	struct thread *td;
	int error;
	boolean_t enable_new, enable_old;

	TRACE("enter %td %d", event->ident, event->filter);

	td = curthread;
	socket = (struct khttpd_socket *)event->udata;

	switch (event->filter) {

	case EVFILT_READ:
		while (!socket->eof && (error = socket->receive(event)) == 0)
			;	/* nothing */

		if (error != 0 && error != EWOULDBLOCK) {
			TRACE("error receive %d", error);
			khttpd_socket_reset(socket);
		}

		if (socket->eof && socket->fd != -1) {
			TRACE("error receive EOF");
			khttpd_kevent_delete_read(khttpd_kqueue, socket->fd);
		}

		break;

	case EVFILT_WRITE:
		error = 0;
		for (;;) {
			if (0 < socket->xmit_uio.uio_resid) {
				error = kern_writev(td, socket->fd,
				    &socket->xmit_uio);
				if (error != 0) {
					TRACE("error writev %d", error);
					break;
				}
				if (0 < socket->xmit_uio.uio_resid) {
					TRACE("error writev EWOULDBLOCK %zd",
					    socket->xmit_uio.uio_resid);
					error = EWOULDBLOCK;
					break;
				}
			}

			request = STAILQ_FIRST(&socket->requests);
			if (request == NULL)
				break;

			response = STAILQ_FIRST(&request->responses);
			if (response == NULL)
				break;

			error = socket->transmit(socket, request, response);
			if (error == EWOULDBLOCK) {
				error = 0;
				break;
			}
			if (error != 0) {
				TRACE("error transmit %d", error);
				break;
			}
		}

		enable_old = socket->xmit_busy;
		socket->xmit_busy = enable_new = error == EWOULDBLOCK;

		if (enable_old != enable_new)
			khttpd_kevent_enable_write(khttpd_kqueue, socket->fd,
			    enable_new, (struct khttpd_event_type *)&socket);

		if (error != 0 && error != EWOULDBLOCK)
			khttpd_socket_reset(socket);

		break;

	default:
		panic("%s: unknown filter %d", __func__, event->filter);
	}
}

/*-------------------------------------------------------------------- sysctl */

static void
khttpd_sysctl_get_or_head_index(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	int cur_oid[CTL_MAXNAME], next_oid[CTL_MAXNAME + 2];
	char *strbuf;
	struct mbuf *body, *itembuf;
	struct khttpd_response *response;
	struct thread *td;
	size_t cur_oidlen, next_oidlen, strbuflen;
	u_int kind;
	int error, i, flag_count, item_count, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	TRACE("enter");

	td = curthread;
	strbuf = NULL;
	body = m_get(M_WAITOK, MT_DATA);
	response = NULL;

	khttpd_mbuf_printf(body, "[");

	item_count = FALSE;
	cur_oid[0] = 1;
	cur_oidlen = sizeof(int);
	next_oidlen = 0;
	for (;;) {
		/* Find the next entry of the entry named by cur_oid. */
		next_oid[0] = 0; /* sysctl internal magic */
		next_oid[1] = 2; /* next */
		bcopy(cur_oid, next_oid + 2, cur_oidlen);
		next_oidlen = CTL_MAXNAME * sizeof(int);
		error = kernel_sysctl(td, next_oid,
		    cur_oidlen / sizeof(int) + 2,
		    next_oid + 2, &next_oidlen, NULL, 0, &next_oidlen, 0);
		if (error != 0) {
			TRACE("next %d", error);
			break;
		}

		itembuf = m_get(M_WAITOK, MT_DATA);

		/* Print { "href":"/sys/sysctl/1.1" */
		khttpd_mbuf_printf(itembuf, "%s{\"href\":\"%s",
		    0 < item_count ? ",\n" : "\n", KHTTPD_SYSCTL_PREFIX);
		for (i = 0; i < next_oidlen / sizeof(int); ++i)
			khttpd_mbuf_printf(itembuf, i == 0 ? "%x": ".%x",
			    next_oid[i + 2]);
		khttpd_mbuf_printf(itembuf, "\"");

		/* Get the name of the next entry. */
		next_oid[1] = 1; /* name */
		error = kernel_sysctl(td, next_oid, next_oidlen / sizeof(int) +
		    2, NULL, 0, NULL, 0, &strbuflen, 0);
		if (error != 0) {
			TRACE("error name1 %d", error);
			goto again;
		}
		strbuf = realloc(strbuf, strbuflen, M_KHTTPD, M_WAITOK);
		error = kernel_sysctl(td, next_oid, next_oidlen / sizeof(int) +
		    2, strbuf, &strbuflen, NULL, 0, NULL, 0);
		if (error != 0) {
			TRACE("error name2 %d", error);
			goto again;
		}

		/* Print ,"name":"kern.ostype", */
		khttpd_mbuf_printf(itembuf, ",\n \"name\":\"%s\"", strbuf);

		/* Get the kind and the format of the next entry. */
		next_oid[1] = 4; /* oidfmt */
		error = kernel_sysctl(td, next_oid, next_oidlen / sizeof(int) +
		    2, NULL, 0, NULL, 0, &strbuflen, 0);
		if (error != 0) {
			TRACE("error oidfmt1 %d", error);
			goto again;
		}
		strbuf = realloc(strbuf, strbuflen, M_KHTTPD, M_WAITOK);
		error = kernel_sysctl(td, next_oid, next_oidlen / sizeof(int) +
		    2, strbuf, &strbuflen, NULL, 0, NULL, 0);
		if (error != 0) {
			TRACE("error oidfmt2 %d", error);
			goto again;
		}

		kind = *(u_int *)strbuf;

		khttpd_mbuf_printf(itembuf, ",\n \"flags\":[");
		flag_count = 0;
		for (i = 0; i < khttpd_sysctl_flags_count; ++i) {
			if ((kind & khttpd_sysctl_flags[i].flag) == 0)
				continue;
			khttpd_mbuf_printf(itembuf, "%s\"%s\"",
			    0 < flag_count ? ", " : "",
			    khttpd_sysctl_flags[i].field_name);
			++flag_count;
		}
		khttpd_mbuf_printf(itembuf, "]");

		if ((kind & CTLFLAG_SECURE) != 0) {
			khttpd_mbuf_printf(itembuf, ",\n \"securelevel\":%d",
			    (kind & CTLMASK_SECURE) >> CTLSHIFT_SECURE);
		}

		type = kind & CTLTYPE;
		if (type < khttpd_sysctl_types_end) {
			khttpd_mbuf_printf(itembuf, ",\n \"type\":\"%s\"",
			    khttpd_sysctl_types[type - 1]);
		}

		khttpd_mbuf_printf(itembuf, ",\n \"format\":\"%s\" }",
		    strbuf + sizeof(kind));

		m_cat(body, itembuf);
		++item_count;
		itembuf = NULL;

		bcopy(next_oid + 2, cur_oid, next_oidlen);
		cur_oidlen = next_oidlen;

again:
		m_freem(itembuf);
		itembuf = NULL;
	}

	khttpd_mbuf_printf(body, 0 < item_count ? "\n]" : "]");

	response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	response->transmit_body = khttpd_transmit_mbuf_data;
	response->data[0] = response->data[1] = body;

	khttpd_header_add_content_length(response->header,
	    m_length(body, NULL));

	khttpd_header_add(response->header, "Content-Type: application/json");

	response->status = 200;
	khttpd_send_response(socket, request, response);

	if (itembuf != NULL)
		m_freem(itembuf);
	free(strbuf, M_KHTTPD);
}

static struct mbuf *
khttpd_sysctl_entry_to_json(struct khttpd_socket *socket,
    struct khttpd_request *request, int *oid, int oidlen, int *error_out)
{
	int tmpoid[CTL_MAXNAME + 2];
	struct thread *td;
	struct mbuf *result;
	char *valbuf;
	size_t vallen;
	u_int kind;
	int error, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	TRACE("enter");

	td = curthread;
	result = m_get(M_WAITOK, MT_DATA);
	valbuf = NULL;

	tmpoid[0] = 0;		/* sysctl internal magic */
	tmpoid[1] = 4;		/* oidfmt */
	bcopy(oid, tmpoid + 2, oidlen * sizeof(oid[0]));
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    NULL, 0, NULL, 0, &vallen, 0);
	if (error != 0) {
		TRACE("error oidfmt1 %d", error);
		goto out;
	}

	valbuf = malloc(vallen, M_KHTTPD, M_WAITOK);
	error = kernel_sysctl(td, tmpoid, oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	if (error != 0) {
		TRACE("error oidfmt2 %d", error);
		goto out;
	}
	bcopy(valbuf, &kind, sizeof(kind));
	type = kind & CTLTYPE;

	if (type == CTLTYPE_NODE) {
		TRACE("error node");
		error = ENOENT;
		goto out;
	}

	error = kernel_sysctl(td, oid, oidlen, NULL, 0, NULL, 0, &vallen, 0);
	if (error != 0) {
		TRACE("error get1 %d", error);
		goto out;
	}
	valbuf = realloc(valbuf, vallen, M_KHTTPD, M_WAITOK);
	error = kernel_sysctl(td, oid, oidlen,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	if (error != 0) {
		TRACE("error get2 %d", error);
		goto out;
	}

	switch (type) {

	case CTLTYPE_INT:
		khttpd_mbuf_printf(result, "%d", *(int *)valbuf);
		break;

	case CTLTYPE_STRING:
		khttpd_mbuf_printf(result, "\"%s\"", (char *)valbuf);
		break;

	case CTLTYPE_S64:
		khttpd_mbuf_printf(result, "%jd", (intmax_t)*(int64_t *)valbuf);
		break;

	case CTLTYPE_UINT:
		khttpd_mbuf_printf(result, "%u", *(u_int *)valbuf);
		break;

	case CTLTYPE_LONG:
		khttpd_mbuf_printf(result, "%ld", *(long *)valbuf);
		break;

	case CTLTYPE_ULONG:
		khttpd_mbuf_printf(result, "%lu", *(u_long *)valbuf);
		break;

	case CTLTYPE_U64:
		khttpd_mbuf_printf(result, "%ju",
		    (uintmax_t)*(uint64_t *)valbuf);
		break;

	default:
		khttpd_mbuf_printf(result, "\"");
		khttpd_base64_encode_to_mbuf(result, valbuf, vallen);
		khttpd_mbuf_printf(result, "\"");
	}

out:
	free(valbuf, M_KHTTPD);

	if (error != 0) {
		m_freem(result);
		result = NULL;
	}

	*error_out = error;

	return (result);
}

static int
khttpd_sysctl_parse_oid(const char *name, int *oid)
{
	const char *cp;
	int i;
	u_int value;
	char ch;

	TRACE("enter %s", name);

	cp = name;
	i = 0;
	for (i = 0; i < CTL_MAXNAME; ++i) {
		if (*cp == '\0') {
			TRACE("terminated by '.'");
			return (-1);
		}

		value = 0;
		for (;;) {
			ch = *cp++;
			if (!isxdigit(ch))
				break;
			if (value << 4 < value) {
				TRACE("overflow");
				return (-1);
			}
			value <<= 4;
			if (isdigit(ch))
				value |= ch - '0';
			else if ('a' <= ch && ch <= 'f')
				value |= ch - 'a' + 10;
			else
				value |= ch - 'A' + 10;
		}

		if (ch != '.' && ch != '\0') {
			TRACE("invalid ch %#02x", ch);
			return (-1);
		}

		oid[i] = value;

		if (ch == '\0')
			return (i + 1);
	}

	TRACE("too long");

	return (-1);
}

static void
khttpd_sysctl_get_or_head_leaf(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	int oid[CTL_MAXNAME];
	struct mbuf *body;
	struct khttpd_response *response;
	const char *name;
	size_t oidlen;
	int error;

	TRACE("enter %s", request->target_suffix);

	name = request->target_suffix + 1;
	oidlen = khttpd_sysctl_parse_oid(name, oid);
	if (oidlen == -1) {
		TRACE("error parse_oid");
		khttpd_send_not_found_response(socket, request, FALSE);
		return;
	}

	body = khttpd_sysctl_entry_to_json(socket, request, oid, oidlen,
	    &error);
	if (body == NULL) {
		TRACE("error entry_to_json %d", error);
		if (error == ENOENT)
			khttpd_send_not_found_response(socket, request, FALSE);
		else
			khttpd_send_internal_error_response(socket, request);
		return;
	}

	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
	response->transmit_body = khttpd_transmit_mbuf_data;
	response->data[0] = response->data[1] = body;

	khttpd_header_add_content_length(response->header,
	    m_length(body, NULL));
	khttpd_header_add(response->header, "Content-Type: application/json");

	response->status = 200;
	khttpd_send_response(socket, request, response);
}

static void
khttpd_sysctl_get_or_head(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	const char *suffix;

	TRACE("enter %d %s", socket->fd, request->target_suffix);

	suffix = request->target_suffix;
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		khttpd_sysctl_get_or_head_index(socket, request);
	else
		khttpd_sysctl_get_or_head_leaf(socket, request);
}

static void
khttpd_sysctl_put_leaf_request_dtor(struct khttpd_request *request)
{
	struct khttpd_sysctl_put_leaf_request *auxdata;

	TRACE("enter");

	auxdata = request->data[0];
	m_freem(auxdata->head);
	free(auxdata, M_KHTTPD);
}

static void
khttpd_sysctl_put_leaf_end(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct khttpd_mbuf_iter iter;
	struct khttpd_sysctl_put_leaf_request *auxdata;
	struct khttpd_response	*response;
	struct khttpd_json *value;
	struct thread *td;
	const char *name;
	char *valbuf;
	size_t vallen;
	long lval;
	u_int kind;
	int error, ival;

	TRACE("enter %s", request->target_suffix);

	name = request->target_suffix + 1;
	td = curthread;
	auxdata = (struct khttpd_sysctl_put_leaf_request *)request->data[0];
	kind = auxdata->kind;
	value = NULL;

	khttpd_mbuf_iter_init(&iter, auxdata->head, 0);
	if ((kind & CTLTYPE) == CTLTYPE_OPAQUE) {
		error = khttpd_base64_decode_from_mbuf(&iter, (void **)&valbuf,
		    &vallen);
		if (error != 0) {
			TRACE("error decode %d", error);
			goto out;
		}
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, valbuf, vallen, NULL, 0);
		free(valbuf, M_KHTTPD);
		goto out;
	}

	error = khttpd_json_parse(&iter, &value, KHTTPD_JSON_DEPTH_MAX);
	if (error != 0) {
		TRACE("error parse %d", error);
		goto out;
	}

	khttpd_mbuf_skip_json_ws(&iter);
	if (iter.ptr != NULL) {
		TRACE("error trailing-garbage");
		error = EINVAL;
		goto out;
	}

	switch (kind & CTLTYPE) {

	case CTLTYPE_INT:
		if (value->type != KHTTPD_JSON_INTEGER ||
		    value->ivalue < INT_MIN || INT_MAX < value->ivalue) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		ival = value->ivalue;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &ival, sizeof(ival), NULL, 0);
		break;

	case CTLTYPE_STRING:
		if (value->type != KHTTPD_JSON_STRING) {
			TRACE("error string");
			error = EINVAL;
			break;
		}
		khttpd_json_string_append_char(value, '\0');
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, value->storage, value->size, NULL, 0);
		break;

	case CTLTYPE_S64:
		if (value->type != KHTTPD_JSON_INTEGER) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &value->ivalue, sizeof(value->ivalue), NULL, 0);
		break;

	case CTLTYPE_UINT:
		if (value->type != KHTTPD_JSON_INTEGER ||
		    value->ivalue < 0 || UINT_MAX < value->ivalue) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		ival = value->ivalue;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &ival, sizeof(ival), NULL, 0);
		break;

	case CTLTYPE_LONG:
		if (value->type != KHTTPD_JSON_INTEGER ||
		    value->ivalue < LONG_MIN || LONG_MAX < value->ivalue) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		lval = value->ivalue;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &lval, sizeof(lval), NULL, 0);
		break;

	case CTLTYPE_ULONG:
		if (value->type != KHTTPD_JSON_INTEGER ||
		    value->ivalue < 0 || ULONG_MAX < value->ivalue) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		lval = value->ivalue;
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &lval, sizeof(lval), NULL, 0);
		break;

	case CTLTYPE_U64:
		if (value->type != KHTTPD_JSON_INTEGER) {
			TRACE("error int");
			error = EINVAL;
			break;
		}
		error = kernel_sysctl(td, auxdata->oid, auxdata->oidlen,
		    NULL, 0, &value->ivalue, sizeof(value->ivalue), NULL, 0);
		break;

	default:
		error = EINVAL;
	}

out:
	switch (error) {

	case 0:
		response = uma_zalloc(khttpd_response_zone, M_WAITOK);
		response->status = 204;
		khttpd_send_response(socket, request, response);
		break;

	case EINVAL:
	case ELOOP:
	case ENOMSG:
	case EOVERFLOW:
		khttpd_send_conflict_response(socket, request, FALSE);
		break;

	case ENOENT:
		khttpd_send_not_found_response(socket, request, FALSE);
		break;

	default:
		khttpd_send_internal_error_response(socket, request);
	}

	khttpd_json_free(value);
}

static void
khttpd_sysctl_put_leaf_received_body(struct khttpd_socket *socket,
    struct khttpd_request *request, const char *begin, const char *end)
{
	struct khttpd_sysctl_put_leaf_request *auxdata;

	auxdata = (struct khttpd_sysctl_put_leaf_request *)request->data[0];

	if (auxdata->limit < end - begin) {
		khttpd_send_payload_too_large_response(socket, request);
		return;
	}

	auxdata->limit -= end - begin;
	auxdata->tail = khttpd_mbuf_append(auxdata->tail, begin, end);
}

static void
khttpd_sysctl_put_leaf(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	int oid[CTL_MAXNAME + 2];
	struct khttpd_sysctl_put_leaf_request *auxdata;
	struct thread *td;
	char *valbuf;
	size_t vallen;
	int error;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) ==
	    sizeof(auxdata->kind));

	TRACE("enter");

	td = curthread;
	valbuf = NULL;
	request->data[0] = auxdata =
	    malloc(sizeof(*auxdata), M_KHTTPD, M_WAITOK);

	auxdata->oidlen = khttpd_sysctl_parse_oid(request->target_suffix + 1,
	    auxdata->oid);
	if (auxdata->oidlen == -1) {
		TRACE("error parse_oid");
		error = ENOENT;
		goto out;
	}

	oid[0] = 0;		/* sysctl internal magic */
	oid[1] = 4;		/* oidfmt */
	bcopy(auxdata->oid, oid + 2, auxdata->oidlen * sizeof(auxdata->oid[0]));
	error = kernel_sysctl(td, oid, auxdata->oidlen + 2,
	    NULL, 0, NULL, 0, &vallen, 0);
	if (error == ENOENT) {
		TRACE("error oidfmt1 %d", error);
		goto out;
	}

	valbuf = malloc(vallen, M_KHTTPD, M_WAITOK);
	error = kernel_sysctl(td, oid, auxdata->oidlen + 2,
	    valbuf, &vallen, NULL, 0, NULL, 0);
	if (error != 0) {
		TRACE("error oidfmt2 %d", error);
		goto out;
	}
	bcopy(valbuf, &auxdata->kind, sizeof(auxdata->kind));

	if ((auxdata->kind & CTLFLAG_WR) == 0) {
		error = EPERM;
		goto out;
	}

	auxdata->head = auxdata->tail = m_get(M_WAITOK, MT_DATA);
	auxdata->limit = KHTTPD_SYSCTL_PUT_MAX;

	request->dtor = khttpd_sysctl_put_leaf_request_dtor;
	request->received_body = khttpd_sysctl_put_leaf_received_body;
	request->end_of_message = khttpd_sysctl_put_leaf_end;
	request->data[0] = auxdata;
	auxdata = NULL;

out:
	free(valbuf, M_KHTTPD);
	free(auxdata, M_KHTTPD);

	switch (error) {

	case 0:
		break;

	case ENOENT:
		khttpd_send_not_found_response(socket, request, FALSE);
		break;

	case EPERM:
		khttpd_send_method_not_allowed_response(socket, request, FALSE,
		    "OPTIONS, HEAD, GET");
		break;

	default:
		khttpd_send_internal_error_response(socket, request);
	}
}

static void
khttpd_sysctl_put(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	const char *suffix;

	TRACE("enter");

	suffix = request->target_suffix;
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		khttpd_send_method_not_allowed_response(socket, request, FALSE,
		    "OPTIONS, HEAD, GET");
	else
		khttpd_sysctl_put_leaf(socket, request);
}

static void
khttpd_sysctl_options(struct khttpd_socket *socket, 
    struct khttpd_request *request)
{
	int oid[CTL_MAXNAME];
	struct thread *td;
	const char *suffix;
	char *buf;
	size_t buflen, oidlen;
	u_int kind;
	int error;
	boolean_t writeable;

	TRACE("enter");

	td = curthread;
	writeable = FALSE;

	suffix = request->target_suffix;
	if (*suffix == '\0' || strcmp(suffix, "/") == 0)
		/* target is "/sys/sysctl/" */
		writeable = FALSE;

	else {
		/* the target is "/sys/sysctl/<oid>" */
		oidlen = khttpd_sysctl_parse_oid(suffix + 1, oid + 2);
		if (oidlen == -1) {
			khttpd_send_not_found_response(socket, request, FALSE);
			return;
		}

		oid[0] = 0;	/* sysctl internal magic */
		oid[1] = 4;	/* oidfmt */
		error = kernel_sysctl(td, oid, oidlen + 2,
		    NULL, 0, NULL, 0, &buflen, 0);
		if (error == ENOENT) {
			khttpd_send_not_found_response(socket, request, FALSE);
			return;
		}

		buf = malloc(buflen, M_KHTTPD, M_WAITOK);
		error = kernel_sysctl(td, oid, oidlen + 2,
		    buf, &buflen, NULL, 0, NULL, 0);
		bcopy(buf, &kind, sizeof(kind));
		free(buf, M_KHTTPD);
		if (error != 0) {
			TRACE("error oidfmt %d", error);
			khttpd_send_internal_error_response(socket, request);
			return;
		}

		writeable = (kind & CTLFLAG_WR) != 0;
	}

	khttpd_send_options_response(socket, request, NULL,
	    writeable ? "OPTIONS, HEAD, GET, PUT" : "OPTIONS, HEAD, GET");
}

static void
khttpd_sysctl_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %d", socket->fd);

	switch (request->method) {

	case KHTTPD_METHOD_GET:
	case KHTTPD_METHOD_HEAD:
		khttpd_sysctl_get_or_head(socket, request);
		break;

	case KHTTPD_METHOD_PUT:
		khttpd_sysctl_put(socket, request);
		break;

	case KHTTPD_METHOD_OPTIONS:
		khttpd_sysctl_options(socket, request);
		break;

	default:
		khttpd_send_not_implemented_response(socket, request, FALSE);
	}
}

/* ----------------------------------------------------------------- asterisc */

static void
khttpd_asterisc_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %d", socket->fd);

	switch (request->method) {

	case KHTTPD_METHOD_OPTIONS:
		khttpd_send_not_implemented_response(socket, request, FALSE);
		break;

	default:
		khttpd_send_options_response(socket, request, NULL,
		    "OPTIONS, HEAD, GET, PUT, POST, DELETE");
	}
}

/* ------------------------------------------------------------ khttpd daemon */

static void
khttpd_set_state(int state)
{
	int old_state;

	mtx_assert(&khttpd_lock, MA_OWNED);

	old_state = khttpd_state;
	if (old_state == state)
		return;
	if (old_state == KHTTPD_READY && khttpd_proc != NULL) {
		PROC_LOCK(khttpd_proc);
		kern_psignal(khttpd_proc, SIGUSR1);
		PROC_UNLOCK(khttpd_proc);
	}
	khttpd_state = state;
	wakeup(&khttpd_state);
}

static void
khttpd_main(void *arg)
{
	struct khttpd_command_list worklist;
	sigset_t sigmask;
	struct sigaction sigact;
	struct kevent event;
	struct khttpd_command *command;
	struct khttpd_socket *socket;
	struct khttpd_server_port *port;
	struct thread *td;
	int debug_fd, error, i;

	TRACE("enter %p", arg);

	STAILQ_INIT(&worklist);
	td = curthread;
	error = 0;

	khttpd_method_init();

	khttpd_json_zone = uma_zcreate("khttp-json",
	    sizeof(struct khttpd_json),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);

	khttpd_route_zone = uma_zcreate("khttp-route",
	    sizeof(struct khttpd_route),
	    khttpd_route_ctor, khttpd_route_dtor, khttpd_route_init, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_header_field_zone = uma_zcreate("khttpd-header-field",
	    sizeof(struct khttpd_header_field),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);

	khttpd_header_zone = uma_zcreate("khttpd-header",
	    sizeof(struct khttpd_header),
	    khttpd_header_ctor, khttpd_header_dtor, khttpd_header_init, NULL,
	    UMA_ALIGN_PTR, UMA_ZONE_OFFPAGE | UMA_ZONE_VTOSLAB);

	khttpd_response_zone = uma_zcreate("khttpd-response",
	    sizeof(struct khttpd_response),
	    khttpd_response_ctor, khttpd_response_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_request_zone = uma_zcreate("khttpd-request",
	    sizeof(struct khttpd_request),
	    khttpd_request_ctor, khttpd_request_dtor, khttpd_request_init, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_socket_zone = uma_zcreate("khttpd-socket",
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, 0);

	khttpd_kqueue = -1;

	error = kern_open(td, "/dev/console", UIO_SYSSPACE, O_WRONLY, 0666);
	if (error != 0) {
		printf("khttpd: failed to open the console: %d\n", error);
		goto cont;
	}
	debug_fd = td->td_retval[0];

	khttpd_log_state[KHTTPD_LOG_DEBUG].mask = KHTTPD_LOG_DEBUG_ALL;
	khttpd_log_state[KHTTPD_LOG_DEBUG].fd = debug_fd;

	do_dup(td, 0, debug_fd, 0, td->td_retval);
	khttpd_log_state[KHTTPD_LOG_ERROR].fd = td->td_retval[0];

	do_dup(td, 0, debug_fd, 0, td->td_retval);
	khttpd_log_state[KHTTPD_LOG_ACCESS].fd = td->td_retval[0];

	bzero(&sigact, sizeof(sigact));
	sigact.sa_handler = SIG_IGN;
	error = kern_sigaction(td, SIGUSR1, &sigact, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigaction(SIGUSR1) failed: %d\n", error);
		goto cont;
	}

	error = kern_sigaction(td, SIGPIPE, &sigact, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigaction(SIGPIPE) failed: %d\n", error);
		goto cont;
	}

	SIGEMPTYSET(sigmask);
	SIGADDSET(sigmask, SIGUSR1);
	error = kern_sigprocmask(td, SIG_UNBLOCK, &sigmask, NULL, 0);
	if (error != 0) {
		printf("khttpd: sigprocmask() failed: %d\n", error);
		goto cont;
	}

	error = sys_kqueue(td, NULL);
	if (error != 0) {
		printf("khttpd: kqueue() failed: %d\n", error);
		goto cont;
	}
	khttpd_kqueue = td->td_retval[0];

	error = khttpd_kevent_add_signal(khttpd_kqueue, SIGUSR1,
	    &khttpd_stop_request_type);
	if (error != 0) {
		printf("khttpd: kevent(EVFILT_SIGNAL, SIGUSR1) failed: %d\n",
		    error);
		goto cont;
	}

	error = khttpd_route_add(&khttpd_route_root, "*",
	    khttpd_asterisc_received_header);
	if (error != 0) {
		printf("khttpd: failed to add route '*': %d\n", error);
		goto cont;
	}

	error = khttpd_route_add(&khttpd_route_root, KHTTPD_SYSCTL_PREFIX, 
	    khttpd_sysctl_received_header);
	if (error != 0) {
		printf("khttpd: failed to add route '"
		    KHTTPD_SYSCTL_PREFIX "': %d\n", error);
		goto cont;
	}

cont:
	mtx_lock(&khttpd_lock);
	khttpd_server_status = error;
	khttpd_set_state(error == 0 ? KHTTPD_READY : KHTTPD_FAILED);

	while (khttpd_state != KHTTPD_UNLOADING) {
		if (khttpd_state == KHTTPD_FAILED) {
			mtx_sleep(&khttpd_state, &khttpd_lock, 0,
			    "khttpd-failed", 0);
			continue;
		}

		STAILQ_SWAP(&worklist, &khttpd_command_queue, khttpd_command);

		mtx_unlock(&khttpd_lock);

		while ((command = STAILQ_FIRST(&worklist)) != NULL) {
			STAILQ_REMOVE_HEAD(&worklist, link);
			command->status = command->command(command->argument);
			wakeup(command);
		}

		error = khttpd_kevent_get(khttpd_kqueue, &event);
		if (error == 0)
			((struct khttpd_event_type *)event.udata)->
			    handle_event(&event);

		KASSERT(error == 0 || error == EINTR || error == ETIMEDOUT,
		    ("kevent_get error=%d", error));

		mtx_lock(&khttpd_lock);
	}

	mtx_unlock(&khttpd_lock);

	while (!LIST_EMPTY(&khttpd_sockets)) {
		socket = LIST_FIRST(&khttpd_sockets);
		LIST_REMOVE(socket, link);
		khttpd_socket_clear_all_requests(socket);
		khttpd_socket_free(socket);
	}

	while ((port = SLIST_FIRST(&khttpd_server_ports)) != NULL) {
		SLIST_REMOVE_HEAD(&khttpd_server_ports, link);
		if (port->fd != -1)
			kern_close(td, port->fd);
		free(port, M_KHTTPD);
	}

	if (khttpd_kqueue != -1)
		kern_close(td, khttpd_kqueue);

	khttpd_route_clear_all(&khttpd_route_root);

	for (i = 0; i < KHTTPD_LOG_END; ++i)
		if (khttpd_log_state[i].fd != -1) {
			kern_close(td, khttpd_log_state[i].fd);
			khttpd_log_state[i].fd = -1;
		}

	uma_zdestroy(khttpd_socket_zone);
	uma_zdestroy(khttpd_request_zone);
	uma_zdestroy(khttpd_response_zone);
	uma_zdestroy(khttpd_header_zone);
	uma_zdestroy(khttpd_header_field_zone);
	uma_zdestroy(khttpd_route_zone);
	uma_zdestroy(khttpd_json_zone);

	kproc_exit(0);
}

/* ----------------------------------------------------------- ioctl handlers */

static int
khttpd_run_proc(khttpd_command_proc_t proc, void *argument)
{
	struct khttpd_command *command;
	int error;

	command = malloc(sizeof(*command), M_KHTTPD, M_WAITOK);
	command->command = proc;
	command->argument = argument;
	command->status = -1;

	mtx_lock(&khttpd_lock);

	if (STAILQ_EMPTY(&khttpd_command_queue)) {
		PROC_LOCK(khttpd_proc);
		kern_psignal(khttpd_proc, SIGUSR1);
		PROC_UNLOCK(khttpd_proc);
	}

	STAILQ_INSERT_TAIL(&khttpd_command_queue, command, link);

	while ((error = command->status) == -1)
		mtx_sleep(command, &khttpd_lock, 0, "khttpd-cmd", 0);

	mtx_unlock(&khttpd_lock);

	free(command, M_KHTTPD);

	return (error);
}

static int
khttpd_open_server_port(void *arg)
{
	struct socket_args socket_args;
	struct listen_args listen_args;
	struct khttpd_server_port *port;
	struct thread *td;
	int error;

	TRACE("enter");

	KASSERT(curproc == khttpd_proc,
	    ("curproc=%p, khttpd_proc=%p", curproc, khttpd_proc));

	port = (struct khttpd_server_port *)arg;
	td = curthread;

	KASSERT(port->fd == -1, ("port->fd=%d", port->fd));

	socket_args.domain = port->addrinfo.ai_family;
	socket_args.type = port->addrinfo.ai_socktype;
	socket_args.protocol = port->addrinfo.ai_protocol;
	error = sys_socket(td, &socket_args);
	if (error != 0) {
		TRACE("error socket %d", error);
		return (error);
	}
	port->fd = td->td_retval[0];
	TRACE("fd %d", port->fd);

	error = kern_bind(td, port->fd,
	    (struct sockaddr *)&port->addrinfo.ai_addr);
	if (error != 0) {
		TRACE("error bind %d", error);
		goto bad;
	}

	listen_args.s = port->fd;
	listen_args.backlog = khttpd_listen_backlog;
	error = sys_listen(td, &listen_args);
	if (error != 0) {
		TRACE("error listen %d", error);
		goto bad;
	}

	error = khttpd_kevent_add_read(khttpd_kqueue, port->fd,
	    &port->event_type);
	if (error != 0) {
		TRACE("error kevent %d", error);
		goto bad;
	}

	SLIST_INSERT_HEAD(&khttpd_server_ports, port, link);

	return (0);

bad:
	kern_close(td, port->fd);
	port->fd = -1;

	return (error);
}

static int
khttpd_add_port(struct khttpd_address_info *ai)
{
	struct khttpd_server_port *port;
	int error;

	port = malloc(sizeof(*port), M_KHTTPD, M_WAITOK);
	port->event_type.handle_event = khttpd_accept_client;
	bcopy(ai, &port->addrinfo, sizeof(port->addrinfo));
	port->fd = -1;

	error = khttpd_run_proc(khttpd_open_server_port, port);

	if (error != 0)
		free(port, M_KHTTPD);

	return (error);
}

static int
khttpd_set_log_conf(void *argument)
{
	struct filedesc *fdp;
	struct filedescent *srcfde, *dstfde;
	struct khttpd_log_conf *conf;
	struct khttpd_log_state *state;
	struct thread *td;
	int error, newfd;

	conf = (struct khttpd_log_conf *)argument;

	TRACE("enter %d %#x", conf->type, conf->mask);

	KASSERT(curproc == khttpd_proc,
	    ("curproc=%p, khttpd_proc=%p", curproc, khttpd_proc));

	td = curthread;
	fdp = td->td_proc->p_fd;

	FILEDESC_XLOCK(fdp);

	error = fdalloc(td, 0, &newfd);
	if (error != 0) {
		TRACE("error fdalloc %d", error);
		fdrop(conf->fde->fde_file, td);
		FILEDESC_XUNLOCK(fdp);
		return (error);
	}

	srcfde = conf->fde;
	dstfde = &fdp->fd_ofiles[newfd];
	dstfde->fde_file = srcfde->fde_file;
	filecaps_move(&srcfde->fde_caps, &dstfde->fde_caps);

	FILEDESC_XUNLOCK(fdp);

	state = &khttpd_log_state[conf->type];
	if (state->fd != -1)
		kern_close(curthread, state->fd);
	state->mask = conf->mask;
	state->fd = newfd;

	TRACE("fd %d", newfd);

	return (0);
}

static int
khttpd_configure_log(struct khttpd_log_conf *conf)
{
	struct filedesc *fdp;
	struct file *fp;
	struct filedescent fde, *fdep;
	struct thread *td;
	u_int mask;
	int error, fd, type;

	type = conf->type;
	if (type < KHTTPD_LOG_DEBUG || KHTTPD_LOG_ACCESS < type)
		return (EINVAL);

	mask = conf->mask;
	if ((mask & khttpd_log_conf_valid_masks[type]) != mask)
		return (EINVAL);

	td = curthread;
	fd = conf->fd;
	fdp = td->td_proc->p_fd;

	FILEDESC_SLOCK(fdp);

	fdep = &fdp->fd_ofiles[conf->fd];

	if (fd < 0 || fdp->fd_lastfile < fd || (fp = fdep->fde_file) == NULL) {
		error = EBADF;
		goto out;
	}

	if (!(fp->f_ops->fo_flags & DFLAG_PASSABLE)) {
		error = EOPNOTSUPP;
		goto out;
	}

	fhold(fp);

	fde.fde_file = fp;
	filecaps_copy(&fdep->fde_caps, &fde.fde_caps);
	FILEDESC_SUNLOCK(fdp);

	conf->fde = &fde;

	return (khttpd_run_proc(khttpd_set_log_conf, conf));

out:
	FILEDESC_SUNLOCK(fdp);

	return (error);
}

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	switch (cmd) {

	case KHTTPD_IOC_CONFIGURE_LOG:
		return (khttpd_configure_log((struct khttpd_log_conf *)data));

	case KHTTPD_IOC_ADD_PORT:
		return (khttpd_add_port((struct khttpd_address_info *)data));

	default:
		return (ENOIOCTL);
	}
}

static void
khttpd_unload(void)
{
	struct khttpd_command_list worklist;
	struct khttpd_command *command;
	struct proc *proc;

	if (khttpd_dev != NULL)
		destroy_dev(khttpd_dev);

	STAILQ_INIT(&worklist);

	mtx_lock(&khttpd_lock);

	/* khttpd_state is UNLOADING if load has been failed */
	while (khttpd_state != KHTTPD_UNLOADING && khttpd_state != KHTTPD_READY)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-unload", 0);

	if (khttpd_state == KHTTPD_READY)
		khttpd_set_state(KHTTPD_UNLOADING);

	STAILQ_SWAP(&worklist, &khttpd_command_queue, khttpd_command);
	mtx_unlock(&khttpd_lock);

	while ((command = STAILQ_FIRST(&worklist)) != NULL) {
		STAILQ_REMOVE_HEAD(&worklist, link);
		command->status = ECANCELED;
		wakeup(command);
	}

	/* khttpd_pid is 0 if fork has been failed. */
	while ((proc = pfind(khttpd_pid)) != NULL) {
		PROC_UNLOCK(proc);
		pause("khttpd-exit", hz);
	}

	mtx_destroy(&khttpd_lock);
}

static int
khttpd_load(void)
{
	int error;

	mtx_init(&khttpd_lock, "khttpd", NULL, MTX_DEF);

	error = kproc_create(khttpd_main, NULL, &khttpd_proc, 0, 0, "khttpd");
	if (error != 0) {
		printf("khttpd: failed to fork khttpd: %d\n", error);
		goto bad;
	}

	khttpd_pid = khttpd_proc->p_pid;

	mtx_lock(&khttpd_lock);
	while (khttpd_state == KHTTPD_LOADING)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-load", 0);
	if (khttpd_state == KHTTPD_FAILED) {
		error = khttpd_server_status;
		goto bad;
	}
	mtx_unlock(&khttpd_lock);

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &khttpd_dev,
	    &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "khttpd");
	if (error != 0) {
		printf("khttpd: failed to create /dev/khttpd: %d\n", error);
		goto bad;
	}

	return (0);

bad:
	khttpd_set_state(KHTTPD_UNLOADING);
	mtx_unlock(&khttpd_lock);
	khttpd_unload();

	return (error);
}

static int
khttpd_loader(struct module *m, int what, void *arg)
{
	switch (what) {

	case MOD_LOAD:
		return (khttpd_load());

	case MOD_UNLOAD:
		khttpd_unload();
		return (0);

	default:
		return (EOPNOTSUPP);
	}
}

DEV_MODULE(khttpd, khttpd_loader, NULL);
