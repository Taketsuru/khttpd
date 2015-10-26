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
#include <sys/conf.h>
#include <sys/ioccom.h>
#include <sys/socket.h>
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

/* The maximum size of a message excluding message body */
#ifndef KHTTPD_MAX_HEADER_SIZE
#define KHTTPD_MAX_HEADER_SIZE 8192
#endif

#ifndef KHTTPD_HEADER_HASH_SIZE
#define KHTTPD_HEADER_HASH_SIZE 8
#endif

#ifndef KHTTPD_PREFIX
#define KHTTPD_PREFIX "/sys"
#endif

#ifndef KHTTPD_SYSCTL_PREFIX
#define KHTTPD_SYSCTL_PREFIX KHTTPD_PREFIX "/sysctl"
#endif

#if 0
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

#define LOG(type, fmt, ...) \
	do {								\
		struct timeval tv;					\
		microuptime(&tv);					\
		printf("[khttpd] " #type " %ld.%06ld %d %s " fmt "\n",	\
		    tv.tv_sec, tv.tv_usec, curthread->td_tid,		\
		    __func__, ## __VA_ARGS__);				\
	} while (0)

#define ERROR(fmt, ...) LOG(error, fmt, ## __VA_ARGS__)
#define DEBUG(fmt, ...) LOG(debug, fmt, ## __VA_ARGS__)

#define STATE_LOG(fmt, ...)				\
	if ((khttpd_debug & KHTTPD_DEBUG_STATE) != 0)	\
		DEBUG(fmt, ## __VA_ARGS__)

#define TRACE(fmt, ...)					\
	if ((khttpd_debug & KHTTPD_DEBUG_TRACE) != 0)	\
		DEBUG(fmt, ## __VA_ARGS__)

/* possible values of khttpd_state */
enum {
	/* the server process has not finished its initialization yet */
	KHTTPD_LOADING,

	KHTTPD_DORMANT,

	/* enabled but not ready yet */
	KHTTPD_STARTING,

	/* the server is ready to serve http requests.	*/
	KHTTPD_ACTIVE,

	/* failed to start and the requester has not noticed it yet. */
	KHTTPD_FAILED,

	/* server shutdown is in progress */
	KHTTPD_STOPPING,

	/* the server process is exiting. */
	KHTTPD_UNLOADING,
};

enum {
	KHTTPD_NO_SKIP = '\377'
};

/* --------------------------------------------------------- Type definitions */

struct khttpd_kevent_args {
	const struct kevent *changelist;
	struct kevent	    *eventlist;
};

typedef void (*khttpd_handle_event_t)(struct kevent *);

struct khttpd_event_type {
	khttpd_handle_event_t handle_event;
};

struct khttpd_server_port {
	/*
	 * event_type is the first member so that (this struct *)&event_type
	 * is valid.
	 */
	struct khttpd_event_type	event_type;
	SLIST_ENTRY(khttpd_server_port)	link;
	struct khttpd_address_info	addrinfo;
	int		fd;
};

typedef int (*khttpd_receive_t)(struct kevent *);
typedef int (*khttpd_transmit_t)(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

struct khttpd_socket {
	/*
	 * event_type is the first member so that (this struct *)&event_type
	 * is valid.
	 */
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
	u_int		ref_count;
	unsigned	xmit_busy:1;
	unsigned	eof:1;
	unsigned	recv_chunked:1;
	char		recv_skip;
	char		recv_buf[KHTTPD_LINE_MAX + 1];
	char		recv_line[KHTTPD_LINE_MAX];
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
	struct khttpd_header	header;
	khttpd_request_dtor_t	dtor;
	khttpd_received_body_t	received_body;
	khttpd_end_of_message_t	end_of_message;
	struct khttpd_route	*route;
	void		*data[2];
	char		*target;
	uint64_t	content_length;
	int		transfer_codings_count;
	char		version_major;
	char		version_minor;
	char		transfer_codings[KHTTPD_TRANSFER_CODING_COUNT];
	char		request_line[KHTTPD_LINE_MAX + 1];
};

struct khttpd_response {
	STAILQ_ENTRY(khttpd_response) link;
	struct khttpd_header	header;
	uint64_t		content_length;
	khttpd_response_dtor_t	dtor;
	khttpd_transmit_body_t	transmit_body;
	void		*data[2];
	unsigned	chunked:1;
	short		status;
	char		version_major;
	char		version_minor;
};

struct khttpd_route {
	TAILQ_ENTRY(khttpd_route)	list_entry;
	SPLAY_ENTRY(khttpd_route)	tree_entry;
	khttpd_route_dtor_t		dtor;
	khttpd_received_header_t	received_header;
	void		*data[2];
	char		*path;
	u_int		ref_count;
};

struct khttpd_route_tree;

/* ---------------------------------------------------- prototype declrations */

static char *khttpd_find_ch(const char *begin, const char ch);
static char *khttpd_find_ch_in(const char *begin, const char *end, char ch);
static char *khttpd_skip_whitespace(const char *ptr);
static char *khttpd_rskip_whitespace(const char *ptr);
static char *khttpd_dup_first_line(const char *str);
static char *khttpd_find_list_item_end(const char *begin, const char **sep);
static char *khttpd_unquote_uri(char *begin, char *end);
static boolean_t khttpd_is_token(const char *begin, const char *end);
static uint32_t khttpd_hash32_buf_ci(const char *begin, const char *end);
static uint32_t khttpd_hash32_str_ci(const char *str);

static void khttpd_kevent_nop(struct kevent *event);
static int khttpd_kevent_copyout(void *arg, struct kevent *kevp, int count);
static int khttpd_kevent_copyin(void *arg, struct kevent *kevp, int count);
static int khttpd_kevent_add_read(int kq, int fd,
    struct khttpd_event_type *etype);
static int khttpd_kevent_add_read_write(int kq, int fd,
    struct khttpd_event_type *etype);
static int khttpd_kevent_enable_write(int kq, int fd, boolean_t enable,
    struct khttpd_event_type *etype);
static int khttpd_kevent_delete_read(int kq, int fd);
static int khttpd_kevent_add_signal(int kq, int signo,
    struct khttpd_event_type *etype);
static int khttpd_kevent_get(int kq, struct kevent *event);

static int  khttpd_route_ctor(void *mem, int size, void *arg, int flags);
static void khttpd_route_dtor(void *mem, int size, void *arg);
static void khttpd_route_dtor_null(struct khttpd_route *route);
static int khttpd_route_compare(struct khttpd_route *x, struct khttpd_route *y);

static int  khttpd_header_ctor(struct khttpd_header *header);
static void khttpd_header_dtor(struct khttpd_header *header);
static struct khttpd_header_field *
    khttpd_header_find(struct khttpd_header *header, char *field_name,
	boolean_t include_trailer);
static struct khttpd_header_field *
    khttpd_header_find_next(struct khttpd_header *header,
	struct khttpd_header_field *current, boolean_t include_trailer);
static boolean_t khttpd_header_value_includes(struct khttpd_header *header,
    char *field_name, char *token, boolean_t include_trailer);
static int khttpd_header_addv(struct khttpd_header *header,
    struct iovec *iov, int iovcnt);
static int khttpd_header_add(struct khttpd_header *header, char *field);
static void khttpd_header_start_trailer(struct khttpd_header *header);
static int khttpd_header_list_iterator_init(struct khttpd_header *header,
    char *name, struct khttpd_header_field **fp_out, char **cp_out,
    boolean_t include_trailer);
static int khttpd_header_list_iterator_next(struct khttpd_header *header,
    struct khttpd_header_field **fp_inout, char **cp_inout,
    char **begin_out, char **end_out, boolean_t include_trailer);
static int khttpd_header_get_uint64(struct khttpd_header *header,
    char *name, uint64_t *value_out, boolean_t include_trailer);
static int khttpd_header_get_transfer_encoding(struct khttpd_header *header,
    char *array, int *array_size);

static int  khttpd_request_ctor(void *mem, int size, void *arg, int flags);
static void khttpd_request_dtor(void *mem, int size, void *arg);
static void khttpd_request_dtor_null(struct khttpd_request *dtor);

static int  khttpd_response_ctor(void *mem, int size, void *arg, int flags);
static void khttpd_response_dtor(void *mem, int size, void *arg);
static void khttpd_response_dtor_null(struct khttpd_response *response);

static int  khttpd_socket_ctor(void *mem, int size, void *arg, int flags);
static void khttpd_socket_dtor(void *mem, int size, void *arg);
static void khttpd_socket_clear_all_requests(struct khttpd_socket *socket);
static void khttpd_socket_reset(struct khttpd_socket *socket);
static void khttpd_socket_shutdown(struct khttpd_socket *socket);
static int khttpd_socket_skip(struct khttpd_socket *socket);
static int  khttpd_socket_read(struct khttpd_socket *socket, char terminator,
    struct iovec *iov, int *iovcnt);

static void khttpd_received_body_null(struct khttpd_socket *socket,
    struct khttpd_request *request, char *begin, char *end);
static void khttpd_end_of_message_null(struct khttpd_socket *socket,
    struct khttpd_request *request);

static int khttpd_transmit_end(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_trailer(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_chunk(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_mbuf_data(struct khttpd_socket * socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_static_data(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_body(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);
static int khttpd_transmit_status_line_and_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response);

static void khttpd_dispatch_request(struct khttpd_socket *socket,
    struct khttpd_request *request);
static int khttpd_receive_crlf_following_chunk_data(struct kevent *event);
static int khttpd_receive_chunk(struct kevent *event);
static int khttpd_receive_body(struct kevent *event);
static int khttpd_receive_header_or_trailer(struct kevent *event);
static int khttpd_receive_request_line(struct kevent *event);
static void khttpd_accept_client(struct kevent *event);
static int  khttpd_drain(struct kevent *event);
static void khttpd_handle_socket_event(struct kevent *event);

static void khttpd_set_state(int state);
static int khttpd_start(void);
static void khttpd_stop(void);
static void khttpd_shutdown(void *arg, int howto);
static void khttpd_main(void *arg);
static int khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
	       struct thread *td);

static void khttpd_sysctl_get_or_head(struct khttpd_socket *socket,
    struct khttpd_request *request);
static void khttpd_sysctl_put(struct khttpd_socket *socket,
    struct khttpd_request *request);
static void khttpd_sysctl_options(struct khttpd_socket *socket,
    struct khttpd_request *request);
static void khttpd_sysctl_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request);

static void khttpd_asterisc_received_header(struct khttpd_socket * socket,
    struct khttpd_request *request);

static int khttpd_load(void);
static void khttpd_unload(void);
static int khttpd_loader(struct module *m, int what, void *arg);

/* ----------------------------------------------------- Variable definitions */

/*
 * module variables
 */

MALLOC_DEFINE(M_KHTTPD, "khttpd", "khttpd buffer");

static SPLAY_HEAD(khttpd_route_tree, khttpd_route) khttpd_route_tree =
    SPLAY_INITIALIZER(&khttpd_route_tree);

static TAILQ_HEAD(khttpd_route_list, khttpd_route) khttpd_route_list =
    TAILQ_HEAD_INITIALIZER(khttpd_route_list);

static SLIST_HEAD(khttpd_server_port_list, khttpd_server_port)
    khttpd_server_ports = SLIST_HEAD_INITIALIZER(khttpd_server_port_list);

static struct mtx khttpd_lock;
static struct cdev *khttpd_dev;
static struct proc *khttpd_proc;
static uma_zone_t khttpd_route_zone;
static pid_t khttpd_pid;
static int khttpd_listen_backlog = KHTTPD_LISTEN_BACKLOG;
static int khttpd_state;
static int khttpd_server_status;
static int khttpd_debug;

static char khttpd_crlf[] = { '\r', '\n' };

static struct cdevsw khttpd_cdevsw = {
	.d_version = D_VERSION,
	.d_ioctl   = khttpd_ioctl,
	.d_name	   = "khttpd"
};

static const char *khttpd_state_labels[] = {
	"loading",
	"dormant",
	"starting",
	"active",
	"failed",
	"stopping",
	"unloading",
	"configuring"
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

static const struct {
	short		status;
	const char*	reason;
} khttpd_reason_phrases[] = {
	{ 100, "Continue" },
	{ 101, "Switching Protocols" },
	{ 200, "OK" },
	{ 201, "Created" },
	{ 202, "Accepted" },
	{ 203, "Non-Authoritative Information" },
	{ 204, "No Content" },
	{ 205, "Reset Content" },
	{ 206, "Partial Content" },
	{ 300, "Multiple Choices" },
	{ 301, "Moved Permanently" },
	{ 302, "Found" },
	{ 303, "See Other" },
	{ 304, "Not Modified" },
	{ 305, "Use Proxy" },
	{ 307, "Temporary Redirect" },
	{ 400, "Bad Request" },
	{ 401, "Unauthorized" },
	{ 402, "Payment Required" },
	{ 403, "Forbidden" },
	{ 404, "Not Found" },
	{ 405, "Method Not Allowed" },
	{ 406, "Not Acceptable" },
	{ 407, "Proxy Authentication Required" },
	{ 408, "Request Timeout" },
	{ 409, "Conflict" },
	{ 410, "Gone" },
	{ 411, "Length Required" },
	{ 412, "Precondition Failed" },
	{ 413, "Payload Too Large" },
	{ 414, "URI Too Long" },
	{ 415, "Unsupported Media Type" },
	{ 416, "Range Not Satisfiable" },
	{ 417, "Expectation Failed" },
	{ 426, "Upgrade Required" },
	{ 500, "Internal Server Error" },
	{ 501, "Not Implemented" },
	{ 502, "Bad Gateway" },
	{ 503, "Service Unavailable" },
	{ 504, "Gateway Timeout" },
	{ 505, "HTTP Version Not Supported" },
};

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

static LIST_HEAD(, khttpd_socket) khttpd_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static LIST_HEAD(, khttpd_socket) khttpd_released_sockets =
    LIST_HEAD_INITIALIZER(khttpd_sockets);

static uma_zone_t khttpd_socket_zone;
static uma_zone_t khttpd_request_zone;
static uma_zone_t khttpd_response_zone;
static uma_zone_t khttpd_header_field_zone;
static int khttpd_kqueue;

/* ----------------------------------------------------- Function definitions */

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

SPLAY_PROTOTYPE(khttpd_route_tree, khttpd_route, tree_entry,
    khttpd_route_compare);

SPLAY_GENERATE(khttpd_route_tree, khttpd_route, tree_entry,
    khttpd_route_compare);

#pragma clang diagnostic pop

/*
 * string manipulation functions
 */

static char *
khttpd_find_ch(const char *begin, const char ch)
{
	const char *ptr;

	for (ptr = begin; ; ++ptr)
		if (*ptr == ch)
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
 * mbuf
 */

void
khttpd_mbuf_vprintf(struct mbuf *output, const char *fmt, va_list vl)
{
	struct mbuf *buf;
	int req, buflen;

	TRACE("enter %s", fmt);

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

void
khttpd_mbuf_copy_base64(struct mbuf *output, const char *buf, size_t size)
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
		.fflags	= NOTE_LOWAT,
		.data	= 1,
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

	return (kern_kevent(curthread, kq, 0, 1, &k_ops, NULL));
}

/*
 * route
 */

static int
khttpd_route_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_route *route = (struct khttpd_route *)mem;

	TRACE("enter %p", route);

	route->dtor = khttpd_route_dtor_null;
	bzero(route->data, sizeof(route->data));
	route->ref_count = 1;
	route->path = strdup((char *)arg, M_KHTTPD);

	return (0);
}

static void
khttpd_route_dtor(void *mem, int size, void *arg)
{
	struct khttpd_route *route = (struct khttpd_route *)mem;

	TRACE("enter %p", route);

	route->dtor(route);
	free(route->path, M_KHTTPD);
}

static void
khttpd_route_dtor_null(struct khttpd_route *route)
{
	TRACE("enter %p", route);
}

static int
khttpd_route_compare(struct khttpd_route *x, struct khttpd_route *y)
{
	return strcmp(x->path, y->path);
}

struct khttpd_route *
khttpd_route_find(char *target)
{
	TRACE("enter %s", target);

	struct khttpd_route key = {
		.path = target
	};

	mtx_lock(&khttpd_lock);

	struct khttpd_route *match = 
		SPLAY_FIND(khttpd_route_tree, &khttpd_route_tree, &key);
	if (match == NULL) {
		match = SPLAY_ROOT(&khttpd_route_tree);
		if (match != NULL && 0 < khttpd_route_compare(match, &key))
			match = TAILQ_PREV(match, khttpd_route_list,
			    list_entry);
	}

	if (match != NULL &&
	    strncmp(match->path, key.path, strlen(match->path)) == 0)
		++match->ref_count;
	else
		match = NULL;

	mtx_unlock(&khttpd_lock);

	return (match);
}

void
khttpd_route_acquire(struct khttpd_route* route)
{
	TRACE("enter");

	mtx_lock(&khttpd_lock);
	++route->ref_count;
	mtx_unlock(&khttpd_lock);
}

void
khttpd_route_release(struct khttpd_route* route)
{
	boolean_t need_to_free;

	TRACE("enter");

	mtx_lock(&khttpd_lock);
	need_to_free = --route->ref_count == 0;
	mtx_unlock(&khttpd_lock);

	/*
	 * XXX: uma_zfree can sleep.  We should move this to other place.
	 */
	if (need_to_free)
		uma_zfree(khttpd_route_zone, route);
}

int
khttpd_route_add(char *path, khttpd_received_header_t received_header_fn)
{
	struct khttpd_route *route, *neighbor;

	TRACE("enter");

	route = uma_zalloc_arg(khttpd_route_zone, path, M_WAITOK);
	route->received_header = received_header_fn;

	mtx_lock(&khttpd_lock);

	if (SPLAY_FIND(khttpd_route_tree, &khttpd_route_tree, route) !=
	    NULL) {
		/* there is a route whose path is the same as the given path. */
		mtx_unlock(&khttpd_lock);
		uma_zfree(khttpd_route_zone, route);
		return (EEXIST);
	}

	neighbor = SPLAY_ROOT(&khttpd_route_tree);

	if (neighbor == NULL)
		TAILQ_INSERT_HEAD(&khttpd_route_list, route, list_entry);

	else if (0 < khttpd_route_compare(neighbor, route))
		TAILQ_INSERT_BEFORE(neighbor, route, list_entry);

	else
		TAILQ_INSERT_AFTER(&khttpd_route_list, neighbor, route,
		    list_entry);

	SPLAY_INSERT(khttpd_route_tree, &khttpd_route_tree, route);

	mtx_unlock(&khttpd_lock);

	return (0);
}

void
khttpd_route_remove(struct khttpd_route *route)
{
	boolean_t need_to_free;

	TRACE("enter");

	mtx_lock(&khttpd_lock);

	TAILQ_REMOVE(&khttpd_route_list, route, list_entry);
	SPLAY_REMOVE(khttpd_route_tree, &khttpd_route_tree, route);
	need_to_free = --route->ref_count == 0;

	mtx_unlock(&khttpd_lock);

	if (need_to_free)
		uma_zfree(khttpd_route_zone, route);
}

void
khttpd_route_clear_all(void)
{
	struct khttpd_route *route;

	TRACE("enter");

	mtx_lock(&khttpd_lock);

	while ((route = TAILQ_FIRST(&khttpd_route_list)) != NULL) {
		TAILQ_REMOVE(&khttpd_route_list, route, list_entry);
		SPLAY_REMOVE(khttpd_route_tree, &khttpd_route_tree, route);
		if (--route->ref_count == 0) {
			mtx_unlock(&khttpd_lock);
			uma_zfree(khttpd_route_zone, route);
			mtx_lock(&khttpd_lock);
		}
	}

	mtx_unlock(&khttpd_lock);
}

/*
 * header
 */

static int
khttpd_header_ctor(struct khttpd_header *header)
{
	int i;

	TRACE("enter");

	for (i = 0; i < KHTTPD_HEADER_HASH_SIZE; ++i)
		STAILQ_INIT(&header->index[i]);
	header->end = header->buffer;
	header->trailer_begin = header->buffer + sizeof(header->buffer);

	return (0);
}

static void
khttpd_header_dtor(struct khttpd_header *header)
{
	struct khttpd_header_field *field;
	int i;

	TRACE("enter");

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
khttpd_header_start_trailer(struct khttpd_header *header)
{
	TRACE("enter");
	header->trailer_begin = header->end;
}

static int
khttpd_header_list_iterator_init(struct khttpd_header *header,
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
khttpd_header_list_iterator_next(struct khttpd_header *header,
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

	error = khttpd_header_list_iterator_init(header, name, &fp, &cp, FALSE);
	if (error != 0) {
		TRACE("error init %d", error);
		return (error);
	}

	found = FALSE;
	for (;;) {
		error = khttpd_header_list_iterator_next(header, &fp, &cp,
		    &begin, &end, FALSE);
		if (error == ENOENT)
			break;

		value = 0;
		for (cp = begin; cp < end; ++cp) {
			if (!isdigit(*cp)) {
				if ((khttpd_debug & KHTTPD_DEBUG_TRACE) != 0) {
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

	error = khttpd_header_list_iterator_init(header, "Transfer-Encoding",
	    &fp, &cp, FALSE);
	if (error != 0) {
		TRACE("error init %d", error);
		return (error);
	}

	size = 0;
	max = *array_size;
	for (;;) {
		error = khttpd_header_list_iterator_next(header, &fp, &cp,
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

/*
 * request
 */

static int
khttpd_request_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_request *request = (struct khttpd_request *)mem;

	TRACE("enter %p", request);

	STAILQ_INIT(&request->responses);
	request->dtor = khttpd_request_dtor_null;
	request->received_body = khttpd_received_body_null;
	request->end_of_message = khttpd_end_of_message_null;
	bzero(request->data, sizeof(request->data));
	request->route = NULL;
	request->transfer_codings_count = 0;

	return (khttpd_header_ctor(&request->header));
}

static void
khttpd_request_dtor(void *mem, int size, void *arg)
{
	struct khttpd_request *request = (struct khttpd_request *)mem;
	struct khttpd_response *response;
	struct khttpd_route *route;

	TRACE("enter %p", request);

	while ((response = STAILQ_FIRST(&request->responses)) != NULL) {
		STAILQ_REMOVE_HEAD(&request->responses, link);
		uma_zfree(khttpd_response_zone, response);
	}

	
	if ((route = request->route) != NULL) {
		request->route = NULL;
		khttpd_route_release(route);
	}

	khttpd_header_dtor(&request->header);
}

static void
khttpd_request_dtor_null(struct khttpd_request *request)
{
	TRACE("enter %p", request);
}

/*
 * response
 */

static int
khttpd_response_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_response *response = (struct khttpd_response *)mem;

	TRACE("enter %p", response);

	response->dtor = khttpd_response_dtor_null;
	response->transmit_body = NULL;
	bzero(response->data, sizeof(response->data));
	response->status = -1;
	response->version_major = 1;
	response->version_minor = 1;
	return (khttpd_header_ctor(&response->header));
}

static void
khttpd_response_dtor(void *mem, int size, void *arg)
{
	struct khttpd_response *response = (struct khttpd_response *)mem;

	TRACE("enter %p", response);

	response->dtor(response);
	khttpd_header_dtor(&response->header);
}

static void
khttpd_response_dtor_null(struct khttpd_response *response)
{
	TRACE("enter %p", response);
}

/*
 * socket
 */

static int
khttpd_socket_ctor(void *mem, int size, void *arg, int flags)
{
	struct khttpd_socket *socket = (struct khttpd_socket *)mem;

	TRACE("enter %p", mem);

	socket->event_type.handle_event = khttpd_handle_socket_event;
	STAILQ_INIT(&socket->requests);
	socket->xmit_uio.uio_resid = 0;
	socket->receive = khttpd_receive_request_line;
	socket->transmit = khttpd_transmit_status_line_and_header;
	socket->recv_getp = socket->recv_putp = socket->recv_buf;
	socket->recv_residual = 0;
	socket->fd = -1;
	refcount_init(&socket->ref_count, 1);
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

	TRACE("enter %p %d %d", socket, socket->ref_count, socket->fd);

	if (socket->fd != -1) {
		kern_close(curthread, socket->fd);
		socket->fd = -1;
	}

	khttpd_socket_clear_all_requests(socket);
}

void
khttpd_socket_acquire(struct khttpd_socket *socket)
{
	TRACE("enter %p", socket);

	refcount_acquire(&socket->ref_count);
}

void
khttpd_socket_release(struct khttpd_socket *socket)
{
	TRACE("enter %p", socket);

	if (refcount_release(&socket->ref_count)) {
		mtx_lock(&khttpd_lock);
		LIST_INSERT_HEAD(&khttpd_released_sockets, socket, link);
		mtx_unlock(&khttpd_lock);
	}
}

static void
khttpd_socket_clear_all_requests(struct khttpd_socket *socket)
{
	TRACE("enter %p", socket);

	struct khttpd_request *request;

	while ((request = STAILQ_FIRST(&socket->requests)) != NULL) {
		STAILQ_REMOVE_HEAD(&socket->requests, link);
		uma_zfree(khttpd_request_zone, request);
	}
}

static void
khttpd_socket_reset(struct khttpd_socket *socket)
{
	TRACE("enter %p", socket);

	kern_close(curthread, socket->fd);
	socket->fd = -1;
	socket->eof = TRUE;

	khttpd_socket_clear_all_requests(socket);

	LIST_REMOVE(socket, link);
	khttpd_socket_release(socket);
}

static void
khttpd_socket_shutdown(struct khttpd_socket *socket)
{
	struct shutdown_args args;

	TRACE("enter %p", socket);

	args.s = socket->fd;
	args.how = SHUT_WR;
	sys_shutdown(curthread, &args);

	socket->recv_getp = socket->recv_putp = socket->recv_buf;
	socket->recv_skip = KHTTPD_NO_SKIP;
	socket->receive = khttpd_drain;

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

	TRACE("enter %p %#x", socket, skip);

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
			TRACE("error %d", error);
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

	TRACE("enter %p %#x", socket, terminator);

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
			TRACE("enobufs");
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

		if ((error = kern_readv(td, socket->fd, &auio)) != 0)
			return (error);

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

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0)
		DEBUG("< '%s'", buf);

	return (0);
}

void
khttpd_send_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	int error, transfer_codings_count;
	char transfer_codings[KHTTPD_TRANSFER_CODING_COUNT];

	TRACE("%p %p %p", socket, request, response);

	if (response->status / 100 == 1 ||
	    response->status == 204 ||
	    response->status == 304 ||
	    strcmp(request->request_line, "HEAD") == 0) {
		response->content_length = 0;
		response->chunked = FALSE;
		goto body_fixed;
	}

	transfer_codings_count = sizeof(transfer_codings) /
	    sizeof(transfer_codings[0]);
	error = khttpd_header_get_transfer_encoding(&response->header,
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

		error = khttpd_header_get_uint64(&response->header,
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

	error = khttpd_header_get_uint64(&response->header, "Content-Length",
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
khttpd_send_static_response(struct khttpd_socket *socket,
    struct khttpd_request *request, int status, const char *content,
    boolean_t close)
{
	struct khttpd_response *response;
	size_t len;
	char buffer[32];

	response = uma_zalloc(khttpd_response_zone, M_WAITOK);

	TRACE("enter %p %p %d %d", socket, request, status, close);

	response->status = status;

	if (close) {
		khttpd_header_add(&response->header, "Connection: close");
		socket->receive = khttpd_drain;
	}

	if (content != NULL) {
		response->data[0] = (void *)content;
		len = strlen(content);

		snprintf(buffer, sizeof buffer, "Content-Length: %zd", len);
		khttpd_header_add(&response->header, buffer);

		khttpd_header_add(&response->header,
		    "Content-Type: text/html; charset=US-ASCII");

		response->transmit_body = khttpd_transmit_static_data;
	}

	khttpd_send_response(socket, request, response);
}

void
khttpd_send_bad_request_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %p %p", socket, request);

	static const char content[] = "<!DOCTYPE html>\n"
		"<html lang='en'>\n"
		"  <head>\n"
		"    <meta charset='US-ASCII' />\n"
		"    <title>400 Bad Reqeust</title>\n"
		"  </head>\n"
		"  <body>\n"
		"    <h1>Bad Request</h1>\n"
		"    <p>A request that "
		"	this server could not understand was sent.</p>\n"
		"  </body>\n"
		"</html>\n";

	khttpd_send_static_response(socket, request, 400, content, TRUE);
}

void
khttpd_send_payload_too_large_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %p %p", socket, request);

	static const char content[] = "<!DOCTYPE html>\n"
		"<html lang='en'>\n"
		"  <head>\n"
		"    <meta charset='US-ASCII' />\n"
		"    <title>413 Payload Too Large</title>\n"
		"  </head>\n"
		"  <body>\n"
		"    <h1>Payload Too Large</h1>\n"
		"    <p>The request payload is larger than "
		"	this server could handle.</p>\n"
		"  </body>\n"
		"</html>\n";

	khttpd_send_static_response(socket, request, 413, content, TRUE);
}

void
khttpd_send_not_implemented_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{
	TRACE("enter %p %p %d", socket, request, close);

	static const char content[] = "<!DOCTYPE html>\n"
		"<html lang='en'>\n"
		"  <head>\n"
		"    <meta charset='US-ASCII' />\n"
		"    <title>501 Not Implemented</title>\n"
		"  </head>\n"
		"  <body>\n"
		"    <h1>Not Implemented</h1>\n"
		"    <p>The server does not support "
		"	the requested functionality.</p>\n"
		"  </body>\n"
		"</html>\n";

	khttpd_send_static_response(socket, request, 501, content, close);
}

void
khttpd_send_not_found_response(struct khttpd_socket *socket,
    struct khttpd_request *request, boolean_t close)
{
	TRACE("enter %p %p %d", socket, request, close);

	static const char content[] = "<!DOCTYPE html>\n"
		"<html lang='en'>\n"
		"  <head>\n"
		"    <meta charset='US-ASCII' />\n"
		"    <title>404 Not Found</title>\n"
		"  </head>\n"
		"  <body>\n"
		"    <h1>Not Found</h1>\n"
		"    <p>The server does not have the requested resource.</p>\n"
		"  </body>\n"
		"</html>\n";

	khttpd_send_static_response(socket, request, 404, content, close);
}

void
khttpd_send_internal_error_response(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %p %p", socket, request);

	static const char content[] = "<!DOCTYPE html>\n"
	    "<html lang='en'>\n"
	    "  <head>\n"
	    "	 <meta charset='US-ASCII' />\n"
	    "	 <title>500 Internal Server Error</title>\n"
	    "  </head>\n"
	    "  <body>\n"
	    "	 <h1>Internal Server Error</h1>\n"
	    "	 <p>The server encountered an unexpected condition "
	    "	    that prevent it from fulfilling the reqeust.</p>\n"
	    "  </body>\n"
	    "</html>\n";

	khttpd_send_static_response(socket, request, 500, content, TRUE);
}

void
khttpd_send_options_response(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response,
    const char *allowed_methods)
{
	struct iovec iov[3];
	static const char allow[] = "Allow: ";

	response->status = 200;

	/*
	 * RFC7231 section 4.3.7 mandates the server to generate
	 * Content-Length field with a value of 0.
	 */
	response->data[0] = (void *)"";
	response->transmit_body = khttpd_transmit_static_data;
	khttpd_header_add(&response->header, "Content-Length: 0");

	iov[0].iov_base = (void *)allow;
	iov[0].iov_len = sizeof(allow) - 1;
	iov[1].iov_base = (void *)allowed_methods;
	iov[1].iov_len = strlen(allowed_methods);
	iov[2].iov_base = (void *)khttpd_crlf;
	iov[2].iov_len = sizeof(khttpd_crlf);

	khttpd_header_addv(&response->header, iov,
	    sizeof(iov) / sizeof(iov[0]));

	khttpd_send_response(socket, request, response);
}

static void
khttpd_received_body_null(struct khttpd_socket *socket,
    struct khttpd_request *request, char *begin, char *end)
{
}

static void
khttpd_end_of_message_null(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
}

void
khttpd_ready_to_send(struct khttpd_socket *socket)
{
	TRACE("%s(%p)", __func__, socket);

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

	TRACE("enter %p %p %p", socket, request, response);

	continue_response = 100 <= response->status && response->status < 200;

	close = !continue_response &&
	    khttpd_header_value_includes(&response->header,
		"Connection", "close", FALSE);

	TRACE("continue %d close %d", continue_response, close);

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

	TRACE("enter %p %p %p", socket, request, response);

	socket->xmit_iov[0].iov_base = response->header.trailer_begin;
	len = socket->xmit_iov[1].iov_len = response->header.end -
	    response->header.trailer_begin;

	socket->xmit_iov[1].iov_base = (void *)khttpd_crlf;
	len += socket->xmit_iov[1].iov_len = sizeof(khttpd_crlf);

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = 2;
	socket->xmit_uio.uio_resid = len;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	socket->transmit = khttpd_transmit_end;

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0) {
		end = response->header.end;
		for (cp = response->header.trailer_begin;
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

	TRACE("enter %p %p %p", socket, request, response);

	error = response->transmit_body(socket, request, response);
	TRACE("transmit_body %d", error);
	if (error != 0)
		return (error);

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

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0) {
		line = khttpd_dup_first_line(socket->xmit_line);
		DEBUG("> '%s'", line);
		free(line, M_KHTTPD);
		if (0 < size) 
			DEBUG("> <body>");
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

	TRACE("enter %p %p %p", socket, request, response);

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

	TRACE("enter %p %p %p", socket, request, response);

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

	TRACE("enter %p %p %p", socket, request, response);

	error = response->transmit_body(socket, request, response);
	TRACE("transmit_body %d", error);
	if (error != 0)
		return (error);

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0)
		DEBUG("> <body>");

	return (0);
}

static int
khttpd_transmit_status_line_and_header(struct khttpd_socket *socket,
    struct khttpd_request *request, struct khttpd_response *response)
{
	const char *cp, *ep, *lf, *reason;
	char *line;
	size_t len;
	int begin, end, mid;
	short s, status;

	TRACE("enter %p", socket);

	reason = "Unknown Reason";
	status = response->status;
	begin = 0;
	end = sizeof(khttpd_reason_phrases) / sizeof(khttpd_reason_phrases[0]);
	while (begin < end) {
		mid = (begin + end) >> 1;

		s = khttpd_reason_phrases[mid].status;
		if (s == status) {
			reason = khttpd_reason_phrases[mid].reason;
			break;
		}

		if (s < status)
			begin = mid + 1;
		else
			end = mid;
	}

	len = snprintf(socket->xmit_line, sizeof(socket->xmit_line),
	    "HTTP/%d.%d %d %s\r\n",
	    response->version_major, response->version_minor,
	    status, reason);

	socket->xmit_iov[0].iov_base = socket->xmit_line;
	socket->xmit_iov[0].iov_len = len;

	socket->xmit_iov[1].iov_base = response->header.buffer;
	len += socket->xmit_iov[1].iov_len =
	    MIN(response->header.end, response->header.trailer_begin) -
	    response->header.buffer;

	socket->xmit_iov[2].iov_base = (void *)khttpd_crlf;
	len += socket->xmit_iov[2].iov_len = sizeof(khttpd_crlf);

	socket->xmit_uio.uio_iov = socket->xmit_iov;
	socket->xmit_uio.uio_iovcnt = 3;
	socket->xmit_uio.uio_resid = len;
	socket->xmit_uio.uio_segflg = UIO_SYSSPACE;

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0) {
		line = khttpd_dup_first_line(socket->xmit_line);
		DEBUG("> '%s'", line);
		free(line, M_KHTTPD);

		ep = MIN(response->header.end, response->header.trailer_begin);
		for (cp = response->header.buffer; cp < ep; cp = lf + 1) {
			lf = khttpd_find_ch(cp, '\n');
			line = khttpd_dup_first_line(cp);
			DEBUG("> '%s'", line);
			free(line, M_KHTTPD);
		}

		DEBUG("> ''");
	}

	TRACE("body %d %#jx",
	    response->chunked, (intmax_t)response->content_length);

	if (response->chunked)
		socket->transmit = khttpd_transmit_chunk;
	else if (0 < response->content_length)
		socket->transmit = khttpd_transmit_body;
	else
		socket->transmit = khttpd_transmit_end;

	return (0);
}

static void
khttpd_dispatch_request(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct khttpd_route *route;
	int error;
	boolean_t chunked;
	boolean_t content_length_specified;

	TRACE("%p %p", socket, request);

	error = khttpd_header_get_uint64(&request->header, "Content-Length",
	    &request->content_length, FALSE);
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
		ERROR("failed to get Content-Length field: %d", error);
		return;
	}

	request->transfer_codings_count = sizeof request->transfer_codings /
	    sizeof request->transfer_codings[0];
	error = khttpd_header_get_transfer_encoding(&request->header,
	    request->transfer_codings, &request->transfer_codings_count);
	switch (error) {

	case 0:
		/*
		 * The server doesn't support transfer encodings other than
		 * 'chunked'.
		 */
		if (2 <= request->transfer_codings_count ||
		    (request->transfer_codings_count == 1 &&
		     request->transfer_codings[0] !=
			 KHTTPD_TRANSFER_CODING_CHUNKED)) {
			TRACE("unsupported");
			khttpd_send_not_implemented_response(socket, request, TRUE);
			return;
		}

		chunked = 0 < request->transfer_codings_count &&
		    request->transfer_codings[
			request->transfer_codings_count - 1] ==
		    KHTTPD_TRANSFER_CODING_CHUNKED;

		content_length_specified = FALSE;
		break;

	case ENOENT:
		chunked = FALSE;
		break;

	case EINVAL:
	case ENOBUFS:
		TRACE("invalid %d", error);
		khttpd_send_not_implemented_response(socket, request, TRUE);
		return;

	default:
		khttpd_send_internal_error_response(socket, request);
		ERROR("failed to get Transfer-Encoding: %d", error);
		return;
	}

	socket->recv_chunked = chunked;

	if (chunked) {
		khttpd_header_start_trailer(&request->header);
		socket->receive = khttpd_receive_chunk;
		request->content_length = 0;

	} else if (content_length_specified) {
		socket->receive = khttpd_receive_body;
		socket->recv_residual = request->content_length;

	} else {
		socket->receive = khttpd_receive_request_line;
		request->content_length = 0;

	}

	route = khttpd_route_find(request->target);
	if (route == NULL) {
		TRACE("no route");
		khttpd_send_not_found_response(socket, request,
		    chunked || request->content_length != 0);
		return;
	}

	request->route = route;
	TRACE("received_header %p", route);
	(*route->received_header)(socket, request);
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

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0)
		DEBUG("< <body>");

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

static int
khttpd_receive_header_or_trailer(struct kevent *event)
{
	struct iovec iov[2];
	struct khttpd_request *request;
	struct khttpd_socket  *socket;
	char *buf, *end;
	size_t len;
	int error, i, iovcnt;

	socket = (struct khttpd_socket *)event->udata;
	request = STAILQ_LAST(&socket->requests, khttpd_request, link);

	TRACE("enter %td %d", event->ident, socket->recv_chunked);

	error = khttpd_socket_read(socket, '\n', iov, &iovcnt);
	if (error != 0) {
		TRACE("read %d", error);
		return (error);
	}

	if ((khttpd_debug & KHTTPD_DEBUG_MESSAGE) != 0) {
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

	error = khttpd_header_addv(&request->header, iov, iovcnt);
	switch (error) {

	case 0:
		return (0);

	case ENOMSG:
		if (socket->recv_chunked) {
			request->end_of_message(socket, request);
			socket->receive = khttpd_receive_request_line;
			socket->recv_chunked = FALSE;

		} else {
			khttpd_dispatch_request(socket, request);
		}

		return (0);

	case EBADMSG:
		khttpd_send_bad_request_response(socket, request);
		return (0);

	case EMSGSIZE:
		khttpd_send_not_implemented_response(socket, request, TRUE);
		return (0);

	default:
		panic("unexpected error: %d", error);
	}
}

static int
khttpd_receive_request_line(struct kevent *event)
{
	struct khttpd_request *request;
	struct khttpd_socket *socket;
	char *sep, *target, *target_end, *version;
	int error;

	socket = (struct khttpd_socket *)event->udata;

	TRACE("enter %td", event->ident);

	KASSERT(!socket->recv_chunked, ("recv_chunked must be FALSE"));

	request = uma_zalloc_arg(khttpd_request_zone, event->udata, M_WAITOK);

	error = khttpd_socket_readline(socket, request->request_line);
	if (error != 0) {
		TRACE("readline %d", error);
		goto reject;
	}

	sep = (char *)khttpd_find_ch(request->request_line, ' ');
	if (sep == NULL || sep == request->request_line) {
		TRACE("method separator");
		goto reject;
	}
	*sep = '\0';

	request->target = target = sep + 1;
	sep = (char *)khttpd_find_ch(target, ' ');
	if (sep == NULL || sep == target) {
		TRACE("request-target separator");
		goto reject;
	}
	target_end = khttpd_unquote_uri((char *)target, sep);
	if (target_end == NULL) {
		TRACE("request-target");
		goto reject;
	}
	*target_end = '\0';

	version = sep + 1;

	if (strlen(version) != 8 ||
	    strncmp(version, "HTTP/", 5) != 0 ||
	    !isdigit(version[5]) || version[6] != '.' || !isdigit(version[7])) {
		TRACE("HTTP-version %zd %s", strlen(version), version);
		goto reject;
	}
	request->version_major = version[5] - '0';
	request->version_minor = version[7] - '0';

	socket->receive = khttpd_receive_header_or_trailer;
	STAILQ_INSERT_TAIL(&socket->requests, request, link);

	return (0);

reject:
	uma_zfree(khttpd_request_zone, request);

	if (error != EWOULDBLOCK) {
		khttpd_socket_reset(socket);
		error = 0;
	}

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
	int error;

	TRACE("enter %td", event->ident);

	td = curthread;
	port = (struct khttpd_server_port *)event->udata;

	error = kern_accept4(td, port->fd, &name, &namelen, SOCK_NONBLOCK,
	    NULL);
	if (error != 0) {
		TRACE("accept %d", error);
		return;
	}

	TRACE("ident %d", (int)td->td_retval[0]);

	socket = (struct khttpd_socket *)
	    uma_zalloc(khttpd_socket_zone, M_WAITOK);
	socket->fd = td->td_retval[0];
	bcopy(name, &socket->peer_addr, namelen);

	error = khttpd_kevent_add_read_write(khttpd_kqueue, socket->fd,
	    (struct khttpd_event_type *)socket);
	if (error != 0) {
		TRACE("kevent_add_read_write %d", error);
		goto quit;
	}

	LIST_INSERT_HEAD(&khttpd_sockets, socket, link);

	return;

quit:
	khttpd_socket_release(socket);
}

static int
khttpd_drain(struct kevent *event)
{
	struct iovec aiov;
	struct uio auio;
	struct khttpd_socket *socket;
	struct thread *td;
	int error;

	td = curthread;
	socket = (struct khttpd_socket *)event->udata;

	TRACE("enter %td", event->ident);

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
khttpd_handle_socket_event(struct kevent *event)
{
	struct khttpd_socket *socket;
	struct khttpd_request *request;
	struct khttpd_response *response;
	struct thread *td;
	int error;
	boolean_t enable_new, enable_old;

	td = curthread;
	socket = (struct khttpd_socket *)event->udata;

	TRACE("enter %td", event->ident);

	switch (event->filter) {

	case EVFILT_READ:
		while (!socket->eof && (error = socket->receive(event)) == 0)
			TRACE("receive %d %d", socket->eof, error);

		if (error != 0 && error != EWOULDBLOCK)
			khttpd_socket_reset(socket);

		if (socket->eof && socket->fd != -1)
			khttpd_kevent_delete_read(khttpd_kqueue, socket->fd);

		break;

	case EVFILT_WRITE:
		error = 0;
		for (;;) {
			while (0 < socket->xmit_uio.uio_resid) {
				error = kern_writev(td, socket->fd,
				    &socket->xmit_uio);
				TRACE("writev %d", error);
				if (error != 0)
					goto xmit_end;
			}

			request = STAILQ_FIRST(&socket->requests);
			if (request == NULL)
				break;

			response = STAILQ_FIRST(&request->responses);
			if (response == NULL)
				break;

			error = socket->transmit(socket, request, response);
			TRACE("transmit %d", error);
			if (error == EWOULDBLOCK) {
				error = 0;
				break;
			}
			if (error != 0)
				break;
		}
xmit_end:
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

static void
khttpd_set_state(int state)
{
	int old_state;

	TRACE("enter %d", state);

	mtx_assert(&khttpd_lock, MA_OWNED);

	old_state = khttpd_state;

	if (old_state == state)
		return;

	if (old_state == KHTTPD_ACTIVE && khttpd_proc != NULL) {
		TRACE("signal");
		PROC_LOCK(khttpd_proc);
		kern_psignal(khttpd_proc, SIGUSR1);
		PROC_UNLOCK(khttpd_proc);
	}

	khttpd_state = state;
	wakeup(&khttpd_state);

	STATE_LOG("state-change %s %s",
	    khttpd_state_labels[old_state], khttpd_state_labels[state]);
}

static int
khttpd_server_port_start(struct khttpd_server_port *port)
{
	struct socket_args socket_args;
	struct listen_args listen_args;
	struct thread *td;
	int error;

	KASSERT(port->fd == -1, ("port->fd=%d", port->fd));

	TRACE("enter %p", port);

	td = curthread;

	socket_args.domain = port->addrinfo.ai_family;
	socket_args.type = port->addrinfo.ai_socktype;
	socket_args.protocol = port->addrinfo.ai_protocol;
	error = sys_socket(td, &socket_args);
	if (error != 0) {
		ERROR("socket() failed: %d", error);
		return (error);
	}
	port->fd = td->td_retval[0];

	error = kern_bind(td, port->fd,
	    (struct sockaddr *)&port->addrinfo.ai_addr);
	if (error != 0) {
		ERROR("bind() failed: %d", error);
		goto fail;
	}

	listen_args.s = port->fd;
	listen_args.backlog = khttpd_listen_backlog;
	error = sys_listen(td, &listen_args);
	if (error != 0) {
		ERROR("listen() failed: %d", error);
		goto fail;
	}

	error = khttpd_kevent_add_read(khttpd_kqueue, port->fd,
	    &port->event_type);
	if (error != 0) {
		ERROR("kevent(EVFILT_READ) failed: %d", error);
		goto fail;
	}

	return (0);

fail:
	kern_close(td, port->fd);
	port->fd = -1;

	return (error);
}

static int
khttpd_start(void)
{
	struct khttpd_server_port *port_ptr;
	struct thread *td;
	int error;

	TRACE("enter");

	td = curthread;

	error = sys_kqueue(td, NULL);
	if (error != 0) {
		ERROR("kqueue() failed: %d", error);
		return (error);
	}
	khttpd_kqueue = td->td_retval[0];

	/*
	 * Add a signal event that is triggered when the khttpd_state changes
	 * from KHTTPD_ACTIVE.
	 */
	khttpd_kevent_add_signal(khttpd_kqueue, SIGUSR1,
	    &khttpd_stop_request_type);
	if (error != 0) {
		ERROR("kevent(EVFILT_SIGNAL) failed: %d", error);
		return (error);
	}

	SLIST_FOREACH(port_ptr, &khttpd_server_ports, link) {
		if (port_ptr->fd != -1)
			continue;

		error = khttpd_server_port_start(port_ptr);
		if (error != 0)
			break;
	}

	return (error);
}

static void
khttpd_stop(void)
{
	struct khttpd_server_port *port_ptr;
	struct khttpd_socket *socket;
	struct thread *td;

	TRACE("enter");

	td = curthread;

	while (!LIST_EMPTY(&khttpd_sockets)) {
		socket = LIST_FIRST(&khttpd_sockets);
		LIST_REMOVE(socket, link);
		khttpd_socket_release(socket);
	}

	SLIST_FOREACH(port_ptr, &khttpd_server_ports, link) {
		if (port_ptr->fd != -1) {
			kern_close(td, port_ptr->fd);
			port_ptr->fd = -1;
		}
	}

	if (khttpd_kqueue != -1) {
		kern_close(td, khttpd_kqueue);
		khttpd_kqueue = -1;
	}
}

static void
khttpd_shutdown(void *arg, int howto)
{
	STATE_LOG("shutdown");
	kproc_shutdown(arg, howto);
}

static void
khttpd_main(void *arg)
{
	LIST_HEAD(, khttpd_socket) to_be_released;
	sigset_t sigmask;
	struct sigaction sigact;
	struct kevent event;
	eventhandler_tag pre_sync_tag;
	struct khttpd_socket *socket;
	struct thread *td;
	int error, last_state;

	TRACE("enter %p", arg);

	td = curthread;
	error = 0;

	pre_sync_tag = EVENTHANDLER_REGISTER(shutdown_pre_sync,
	    khttpd_shutdown, khttpd_proc, SHUTDOWN_PRI_DEFAULT);

	khttpd_socket_zone = uma_zcreate("khttpd-socket",
	    sizeof(struct khttpd_socket),
	    khttpd_socket_ctor, khttpd_socket_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, M_WAITOK);

	khttpd_request_zone = uma_zcreate("khttpd-request",
	    sizeof(struct khttpd_request),
	    khttpd_request_ctor, khttpd_request_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, M_WAITOK);

	khttpd_response_zone = uma_zcreate("khttpd-response",
	    sizeof(struct khttpd_response),
	    khttpd_response_ctor, khttpd_response_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, M_WAITOK);

	khttpd_header_field_zone = uma_zcreate("khttpd-header-field",
	    sizeof(struct khttpd_header_field),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, M_WAITOK);

	khttpd_kqueue = -1;

	bzero(&sigact, sizeof sigact);
	sigact.sa_handler = SIG_IGN;
	error = kern_sigaction(td, SIGUSR1, &sigact, NULL, 0);
	if (error != 0)
		goto quit;

	error = kern_sigaction(td, SIGPIPE, &sigact, NULL, 0);
	if (error != 0)
		goto quit;

	SIGEMPTYSET(sigmask);
	SIGADDSET(sigmask, SIGUSR1);
	error = kern_sigprocmask(td, SIG_UNBLOCK, &sigmask, NULL, 0);
	if (error != 0)
		goto quit;

	last_state = -1;

	mtx_lock(&khttpd_lock);

	while (khttpd_state != KHTTPD_UNLOADING) {
		TRACE("state %d", khttpd_state);

		switch (khttpd_state) {

		case KHTTPD_LOADING:
			khttpd_set_state(KHTTPD_DORMANT);
			break;

		case KHTTPD_DORMANT:
		case KHTTPD_FAILED:
			mtx_sleep(&khttpd_state, &khttpd_lock, PCATCH|PDROP,
			    "khttpd-idle", 0);
			kproc_suspend_check(curproc);
			mtx_lock(&khttpd_lock);
			break;

		case KHTTPD_STARTING:
			mtx_unlock(&khttpd_lock);
			error = khttpd_start();
			if (error == 0) {
				mtx_lock(&khttpd_lock);
				khttpd_set_state(KHTTPD_ACTIVE);
			} else {
				khttpd_stop();
				mtx_lock(&khttpd_lock);
				khttpd_server_status = error;
				khttpd_set_state(KHTTPD_FAILED);
			}
			break;

		case KHTTPD_STOPPING:
			mtx_unlock(&khttpd_lock);
			khttpd_stop();
			mtx_lock(&khttpd_lock);
			khttpd_set_state(KHTTPD_DORMANT);
			break;

		case KHTTPD_ACTIVE:
			mtx_unlock(&khttpd_lock);

			error = khttpd_kevent_get(khttpd_kqueue, &event);
			if (error != EINTR) {
				if (error != 0) {
					ERROR("kevent() failed: %d", error);
					mtx_lock(&khttpd_lock);
					khttpd_set_state(KHTTPD_STOPPING);
					break;
				}

				((struct khttpd_event_type *)event.udata)->
					handle_event(&event);
			}

			kproc_suspend_check(curproc);

			mtx_lock(&khttpd_lock);

			if (!LIST_EMPTY(&khttpd_released_sockets)) {
				LIST_INIT(&to_be_released);
				LIST_SWAP(&to_be_released,
				    &khttpd_released_sockets, khttpd_socket,
				    link);
				mtx_unlock(&khttpd_lock);

				while ((socket = LIST_FIRST(&to_be_released))
				    != NULL) {
					LIST_REMOVE(socket, link);
					uma_zfree(khttpd_socket_zone, socket);
				}

				mtx_lock(&khttpd_lock);
			}
			break;

		default:
			panic("invalid khttpd_state %d", khttpd_state);
		}
	}

	mtx_unlock(&khttpd_lock);

quit:
	KASSERT(LIST_EMPTY(&khttpd_sockets), ("khttpd_socket is not empty."));

	/*
	 * Change the state to FAILED, if the initialization failed.
	 */
	mtx_lock(&khttpd_lock);
	if (error != 0 && khttpd_state == KHTTPD_LOADING) {
		khttpd_server_status = error;
		khttpd_set_state(KHTTPD_FAILED);
	}
	mtx_unlock(&khttpd_lock);

	uma_zdestroy(khttpd_header_field_zone);
	uma_zdestroy(khttpd_response_zone);
	uma_zdestroy(khttpd_request_zone);
	uma_zdestroy(khttpd_socket_zone);

	EVENTHANDLER_DEREGISTER(shutdown_pre_sync, pre_sync_tag);

	kproc_exit(0);
}

int
khttpd_enable(void)
{
	int error;
	boolean_t kicked;

	TRACE("enter");

	mtx_lock(&khttpd_lock);

	kicked = FALSE;
	error = 0;
	while (error == 0 && khttpd_state != KHTTPD_ACTIVE) {
		switch (khttpd_state) {

		case KHTTPD_FAILED:
			if (kicked) {
				kicked = FALSE;
				error = khttpd_server_status;
				khttpd_set_state(KHTTPD_DORMANT);
				break;
			}
			/* FALLTHROUGH */

		case KHTTPD_LOADING:
		case KHTTPD_STARTING:
		case KHTTPD_STOPPING:
			mtx_sleep(&khttpd_state, &khttpd_lock, 0,
			    "khttpd-enable", 0);
			break;

		case KHTTPD_DORMANT:
			kicked = TRUE;
			khttpd_set_state(KHTTPD_STARTING);
			break;

		case KHTTPD_UNLOADING:
			error = EBUSY;
			break;

		default:
			panic("invalid khttpd_state: %d", khttpd_state);
		}
	}

	mtx_unlock(&khttpd_lock);

	return (error);
}

void
khttpd_disable(void)
{
	TRACE("enter");

	mtx_lock(&khttpd_lock);

	while (khttpd_state != KHTTPD_DORMANT) {
		switch (khttpd_state) {

		case KHTTPD_LOADING:
		case KHTTPD_STARTING:
		case KHTTPD_STOPPING:
		case KHTTPD_FAILED:
			mtx_sleep(&khttpd_state, &khttpd_lock, 0,
			    "khttpd-disable", 0);
			break;

		case KHTTPD_ACTIVE:
			khttpd_set_state(KHTTPD_STOPPING);
			break;

		default:
			panic("invalid state %d", khttpd_state);
		}
	}

	mtx_unlock(&khttpd_lock);
}

static int
khttpd_add_server_port(struct khttpd_address_info *ai)
{
	struct khttpd_server_port *port;
	int error;

	TRACE("enter %d %d %d",
	    ai->ai_family, ai->ai_socktype, ai->ai_protocol);

	port = malloc(sizeof(*port), M_KHTTPD, M_WAITOK);
	port->event_type.handle_event = khttpd_accept_client;
	bcopy(ai, &port->addrinfo, sizeof(port->addrinfo));
	port->fd = -1;

	error = 0;
	mtx_lock(&khttpd_lock);
	while (khttpd_state != KHTTPD_DORMANT && error == 0) {
		TRACE("state %d", khttpd_state);
		switch (khttpd_state) {

		case KHTTPD_UNLOADING:
		case KHTTPD_ACTIVE:
			error = EBUSY;
			break;

		case KHTTPD_LOADING:
		case KHTTPD_STARTING:
		case KHTTPD_FAILED:
		case KHTTPD_STOPPING:
			mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-add",
			    0);
			break;

		default:
			panic("unknown state %d", khttpd_state);
		}
	}

	if (error != 0) {
		mtx_unlock(&khttpd_lock);
		free(port, M_KHTTPD);
		return (error);
	}

	SLIST_INSERT_HEAD(&khttpd_server_ports, port, link);
	mtx_unlock(&khttpd_lock);

	return (0);
}

static int
khttpd_ioctl(struct cdev *dev, u_long cmd, caddr_t data, int fflag,
    struct thread *td)
{
	int value;

	TRACE("enter %p %#lx %p %#x", dev, cmd, data, fflag);

	switch (cmd) {

	case KHTTPD_IOC_ENABLE:
		return (khttpd_enable());

	case KHTTPD_IOC_DISABLE:
		khttpd_disable();
		return (0);

	case KHTTPD_IOC_DEBUG:
		value = *(int *)data;
		if (value != (value & KHTTPD_DEBUG_ALL))
			return (EINVAL);
		khttpd_debug = value;
		return (0);

	case KHTTPD_IOC_ADD_SERVER_PORT:
		return (khttpd_add_server_port
		    ((struct khttpd_address_info *)data));

	default:
		return (ENOIOCTL);
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
	int error, i, flag_count, item_count, linelen, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	TRACE("enter");

	td = curthread;
	strbuflen = 32;
	strbuf = malloc(strbuflen, M_KHTTPD, M_WAITOK);
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
			khttpd_mbuf_printf(itembuf, "%c%x",
			    i == 0 ? '/' : '.', next_oid[i + 2]);
		m_append(itembuf, 1, "\"");

		/* Get the name of the next entry. */
		next_oid[1] = 1; /* name */
		while ((error = kernel_sysctl(td, next_oid,
			    next_oidlen / sizeof(int) + 2,
			    strbuf, &strbuflen, NULL, 0, NULL, 0)) == ENOMEM) {
			strbuflen <<= 1;
			strbuf = realloc(strbuf, strbuflen, M_KHTTPD, M_WAITOK);
		}

		if (error != 0) {
			ERROR("sysctl failed %d", error);
			goto again;
		}

		/* Print ,"name":"kern.ostype", */
		TRACE("name %s", strbuf);
		khttpd_mbuf_printf(itembuf, ",\n \"name\":\"%s\"", strbuf);

		/* Get the kind and the format of the next entry. */
		next_oid[1] = 4; /* oidfmt */
		while ((error = kernel_sysctl(td, next_oid,
			    next_oidlen / sizeof(int) + 2,
			    strbuf, &strbuflen, NULL, 0, NULL, 0)) == ENOMEM) {
			strbuflen <<= 1;
			strbuf = realloc(strbuf, strbuflen, M_KHTTPD, M_WAITOK);
		}

		if (error != 0) {
			ERROR("sysctl failed %d", error);
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

	linelen = snprintf(strbuf, strbuflen, "Content-Length: %u",
	    m_length(body, NULL));
	if (strbuflen < linelen + 1)
		panic("string buffer too small: required=%d, allocated=%zu",
		    linelen + 1, strbuflen);
	khttpd_header_add(&response->header, strbuf);

	khttpd_header_add(&response->header, "Content-Type: application/json");

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
	size_t valbuflen, vallen;
	u_int kind;
	int error, type;

	CTASSERT(sizeof(((struct sysctl_oid *)0)->oid_kind) == sizeof(kind));

	TRACE("enter");

	td = curthread;
	valbuflen = 32;
	valbuf = malloc(valbuflen, M_KHTTPD, M_WAITOK);
	result = m_get(M_WAITOK, MT_DATA);

	tmpoid[0] = 0;		/* sysctl internal magic */
	tmpoid[1] = 4;		/* oidfmt */
	bcopy(oid, tmpoid + 2, oidlen * sizeof(oid[0]));
	while ((error = kernel_sysctl(td, tmpoid, oidlen + 2,
		    valbuf, &valbuflen, NULL, 0, NULL, 0)) == ENOMEM) {
		valbuflen <<= 1;
		valbuf = realloc(valbuf, valbuflen, M_KHTTPD, M_WAITOK);
	}

	if (error != 0) {
		TRACE("oidfmt %d", error);
		goto quit;
	}

	bcopy(valbuf, &kind, sizeof(kind));
	type = kind & CTLTYPE;

	if (type == 0 || khttpd_sysctl_types_end <= type)
		ERROR("unknown sysctl node type %d", type);

	if (type == CTLTYPE_NODE) {
		TRACE("node");
		error = ENOENT;
		goto quit;
	}

	while ((error = kernel_sysctl(td, oid, oidlen,
		    valbuf, &valbuflen, NULL, 0, &vallen, 0)) == ENOMEM) {
		valbuflen <<= 1;
		valbuf = realloc(valbuf, valbuflen, M_KHTTPD, M_WAITOK);
	}

	if (error != 0) {
		TRACE("get %d", error);
		goto quit;
	}

	switch (type) {

	case CTLTYPE_INT:
		khttpd_mbuf_printf(result, "%d", *(int *)valbuf);
		break;

	case CTLTYPE_STRING:
		khttpd_mbuf_printf(result, "\"%s\"", (char *)valbuf);
		break;

	case CTLTYPE_S64:
		khttpd_mbuf_printf(result, "%jd",
		    (intmax_t)*(int64_t *)valbuf);
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

	case CTLTYPE_OPAQUE:
	default:
		khttpd_mbuf_printf(result, "\"");
		khttpd_mbuf_copy_base64(result, valbuf, vallen);
		khttpd_mbuf_printf(result, "\"");
	}

quit:
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
	int i, value;
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
			if (value << 4 <= value) {
				TRACE("overflow");
				return (-1);
			}
			value <<= 4;
			if (ch <= '9')
				value |= ch - '0';
			else if ('a' <= ch && ch <= 'f')
				value |= ch - 'a';
			else
				value |= ch - 'A';
		}

		if (ch != '.') {
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
    struct khttpd_request *request, const char *name)
{
	int oid[CTL_MAXNAME];
	char buf[32];
	struct mbuf *body;
	struct khttpd_response *response;
	size_t oidlen;
	int error, linelen;

	TRACE("enter %p %p %s", socket, request, name);

	/* the target is "/sys/sysctl/..." */
	oidlen = khttpd_sysctl_parse_oid(name, oid);
	if (oidlen == -1)
		goto not_found;

	body = khttpd_sysctl_entry_to_json(socket, request, oid, oidlen,
	    &error);
	if (body == NULL) {
		if (error == ENOENT)
			goto not_found;
		else
			goto internal_error;
	}

	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
	response->transmit_body = khttpd_transmit_mbuf_data;
	response->data[0] = response->data[1] = body;

	linelen = snprintf(buf, sizeof(buf), "Content-Length: %u",
	    m_length(body, NULL));
	if (sizeof(buf) < linelen + 1)
		panic("result too long: %d", linelen);
	khttpd_header_add(&response->header, buf);

	khttpd_header_add(&response->header, "Content-Type: application/json");

	khttpd_send_response(socket, request, response);
	return;

not_found:
	khttpd_send_not_found_response(socket, request, FALSE);
	return;

internal_error:
	khttpd_send_internal_error_response(socket, request);
	return;
}

static void
khttpd_sysctl_get_or_head(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	const char *name;

	TRACE("enter %p %p", socket, request);

	name = request->target + sizeof(KHTTPD_SYSCTL_PREFIX) - 1;
	if (*name == '\0' || (name[0] == '/' && name[1] == '\0'))
		khttpd_sysctl_get_or_head_index(socket, request);

	else if (*name != '/')
		/*
		 * The last path components of the target and the prefix are
		 * different with each other.
		 */
		khttpd_send_not_found_response(socket, request, FALSE);

	else
		khttpd_sysctl_get_or_head_leaf(socket, request, name + 1);
}

static void
khttpd_sysctl_put(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %p %p", socket, request);

#if 0
	struct khttpd_response *response;
	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
#endif

	khttpd_send_internal_error_response(socket, request);
}

static void
khttpd_sysctl_options(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	int oid[CTL_MAXNAME];
	struct khttpd_response *response;
	struct thread *td;
	const char *name;
	size_t buflen, oidlen;
	u_int kind;
	int error;
	boolean_t writeable;

	TRACE("enter %p %p", socket, request);

	td = curthread;
	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
	writeable = FALSE;

	name = request->target + sizeof(KHTTPD_SYSCTL_PREFIX) - 1;
	if (*name == '\0' || (name[0] == '/' && name[1] == '\0'))
		/*
		 * The target is the same as the route prefix or only "/"
		 * follows the prefix.
		 */
		writeable = FALSE;

	else if (*name != '/')
		/*
		 * The last path components of the target and the prefix are
		 * different with each other.
		 */
		goto not_found;

	else {
		/* the target is "/sys/sysctl/..." */
		oidlen = khttpd_sysctl_parse_oid(name + 1, oid + 2);
		if (oidlen == -1)
			goto not_found;

		oid[0] = 0;	/* sysctl internal magic */
		oid[1] = 4;	/* oidfmt */
		buflen = sizeof(kind);
		error = kernel_sysctl(td, oid, oidlen + 2,
		    &kind, &buflen, NULL, 0, NULL, 0);
		if (error != 0)
			TRACE("oidfmt %d", error);
		if (error == ENOENT || (kind & CTLTYPE) == CTLTYPE_NODE)
			goto not_found;
		if (error != 0)
			goto internal_error;

		writeable = (kind & CTLFLAG_WR) != 0;
	}

	khttpd_send_options_response(socket, request, response,
	    writeable ? "OPTIONS, HEAD, GET, PUT" : "OPTIONS, HEAD, GET");
	return;

not_found:
	khttpd_send_not_found_response(socket, request, FALSE);
	return;

internal_error:
	ERROR("internal error %d", error);
	khttpd_send_internal_error_response(socket, request);
}

static void
khttpd_sysctl_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	TRACE("enter %p %p", socket, request);

	if (strcmp(request->request_line, "GET") == 0 ||
	    strcmp(request->request_line, "HEAD")) {
		khttpd_sysctl_get_or_head(socket, request);
		return;
	}

	if (strcmp(request->request_line, "PUT") == 0) {
		khttpd_sysctl_put(socket, request);
		return;
	}

	if (strcmp(request->request_line, "OPTIONS") == 0) {
		khttpd_sysctl_options(socket, request);
		return;
	}

	khttpd_send_not_implemented_response(socket, request, FALSE);
}

/* ----------------------------------------------------------------- asterisc */

static void
khttpd_asterisc_received_header(struct khttpd_socket *socket,
    struct khttpd_request *request)
{
	struct khttpd_response *response;

	TRACE("enter %p %p", socket, request);

	if (strcmp(request->request_line, "OPTIONS") != 0) {
		khttpd_send_not_implemented_response(socket, request, FALSE);
		return;
	}

	response = uma_zalloc(khttpd_response_zone, M_WAITOK);
	khttpd_send_options_response(socket, request, response,
	    "OPTIONS, HEAD, GET, PUT, POST, DELETE");
}

/* ------------------------------------------------------- module load/unload */

static int
khttpd_load(void)
{
	int error;

	mtx_init(&khttpd_lock, "khttpd", NULL, MTX_DEF);

	khttpd_route_zone = uma_zcreate("khttp-route",
	    sizeof(struct khttpd_route),
	    khttpd_route_ctor, khttpd_route_dtor, NULL, NULL,
	    UMA_ALIGN_PTR, M_WAITOK);

	khttpd_state = KHTTPD_LOADING;

	error = khttpd_route_add("*", khttpd_asterisc_received_header);
	if (error != 0) {
		ERROR("failed to add route '*': %d", error);
		goto error_exit;
	}

	error = khttpd_route_add(KHTTPD_SYSCTL_PREFIX,
	    khttpd_sysctl_received_header);
	if (error != 0) {
		ERROR("failed to add route '" KHTTPD_SYSCTL_PREFIX "': %d",
		    error);
		goto error_exit;
	}

	error = kproc_create(khttpd_main, NULL, &khttpd_proc, 0, 0, "khttpd");
	if (error != 0) {
		ERROR("failed to fork: %d", error);
		goto error_exit;
	}

	khttpd_pid = khttpd_proc->p_pid;

	/*
	 * Wait for the server process to finish initialization.
	 */

	mtx_lock(&khttpd_lock);
	while (khttpd_state == KHTTPD_LOADING)
		mtx_sleep(&khttpd_state, &khttpd_lock, 0, "khttpd-load", 0);
	if (khttpd_state == KHTTPD_FAILED) {
		error = khttpd_server_status;
		goto error_exit;
	}
	mtx_unlock(&khttpd_lock);

	error = make_dev_p(MAKEDEV_CHECKNAME | MAKEDEV_WAITOK, &khttpd_dev,
	    &khttpd_cdevsw, 0, UID_ROOT, GID_WHEEL, 0600, "khttpd");
	if (error != 0) {
		ERROR("failed to create /dev/khttpd: %d", error);
		goto error_exit;
	}

	return (0);

error_exit:
	khttpd_set_state(KHTTPD_UNLOADING);
	khttpd_unload();

	return (error);
}

static void
khttpd_unload(void)
{
	struct khttpd_server_port *port;
	struct proc *proc;

	if (khttpd_dev != NULL) {
		destroy_dev(khttpd_dev);
		khttpd_dev = NULL;
	}

	/*
	 * other than DORMANT -> DORMANT -> UNLOADING
	 *
	 * Note: The state has already been UNLOADING if khttpd_load() failed.
	 */

	mtx_lock(&khttpd_lock);
	if (khttpd_state != KHTTPD_UNLOADING) {
		while (khttpd_state != KHTTPD_DORMANT) {
			if (khttpd_state == KHTTPD_ACTIVE)
				khttpd_set_state(KHTTPD_STOPPING);
			mtx_sleep(&khttpd_state, &khttpd_lock, 0,
			    "khttpd-unload", 0);
		}
		khttpd_set_state(KHTTPD_UNLOADING);
	}
	mtx_unlock(&khttpd_lock);

	/*
	 * Wait the server process to exit to prevent it from accessing
	 * destroyed khttpd_lock.
	 *
	 * Note: If the creation of the process has been failed, khttpd_pid is
	 * 0.  So the loop terminates immediately.
	 */

	while ((proc = pfind(khttpd_pid)) != NULL) {
		PROC_UNLOCK(proc);
		pause("khttpd-exit", hz);
	}

	while ((port = SLIST_FIRST(&khttpd_server_ports)) != NULL) {
		SLIST_REMOVE_HEAD(&khttpd_server_ports, link);
		free(port, M_KHTTPD);
	}

	khttpd_route_clear_all();

	uma_zdestroy(khttpd_route_zone);
	mtx_destroy(&khttpd_lock);
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
