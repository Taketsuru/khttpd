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

#include <sys/param.h>

#ifdef _KERNEL

struct mbuf;
struct khttpd_mbuf_json;
struct khttpd_mbuf_pos;
struct khttpd_stream;

enum {
	KHTTPD_STREAM_FLUSH = 0x0001,
	KHTTPD_STREAM_CLOSE = 0x0002
};

typedef int (*khttpd_stream_receive_fn_t)
    (struct khttpd_stream *, ssize_t *, struct mbuf **);
typedef void (*khttpd_stream_fn_t)(struct khttpd_stream *);
typedef void (*khttpd_stream_cts_fn_t)(struct khttpd_stream *, ssize_t);
typedef bool (*khttpd_stream_send_fn_t)
    (struct khttpd_stream *, struct mbuf *, int);
typedef void (*khttpd_stream_bufstat_fn_t)(struct khttpd_stream *, u_int *,
    int *, long *);
typedef void (*khttpd_stream_log_fn_t)(struct khttpd_stream *,
    struct khttpd_mbuf_json *);

struct khttpd_stream_down_ops {
	khttpd_stream_receive_fn_t	receive;
	khttpd_stream_fn_t		continue_receiving;
	khttpd_stream_fn_t		reset;
	khttpd_stream_send_fn_t		send;
	khttpd_stream_bufstat_fn_t	send_bufstat;
	khttpd_stream_fn_t		notify_of_drain;
	khttpd_stream_fn_t		destroy;
};

struct khttpd_stream_up_ops {
	khttpd_stream_fn_t	data_is_available;
	khttpd_stream_cts_fn_t	clear_to_send;
	khttpd_stream_log_fn_t	error;
};

struct khttpd_stream {
	struct khttpd_stream_up_ops *up_ops;
	struct khttpd_stream_down_ops *down_ops;
	void	*up;
	void	*down;
};

int khttpd_stream_receive_until(struct khttpd_stream *, int, off_t *,
    struct khttpd_mbuf_pos *);

inline int
khttpd_stream_receive(struct khttpd_stream *stream, ssize_t *resid, 
    struct mbuf **m_out)
{

	return (stream->down_ops->receive(stream, resid, m_out));
}

inline void
khttpd_stream_continue_receiving(struct khttpd_stream *stream)
{

	stream->down_ops->continue_receiving(stream);
}

inline void
khttpd_stream_reset(struct khttpd_stream *stream)
{

	stream->down_ops->reset(stream);
}

inline bool
khttpd_stream_send(struct khttpd_stream *stream, struct mbuf *m, int flags)
{

	return (stream->down_ops->send(stream, m, flags));
}

inline void
khttpd_stream_notify_of_drain(struct khttpd_stream *stream)
{

	stream->down_ops->notify_of_drain(stream);
}

inline void
khttpd_stream_destroy(struct khttpd_stream *stream)
{

	if (stream->down != NULL) {
		stream->down_ops->destroy(stream);
		stream->down = NULL;
	}
}

inline void
khttpd_stream_send_bufstat(struct khttpd_stream *stream, u_int *hiwat,
    int *lowat, long *space)
{

	return (stream->down_ops->send_bufstat(stream, hiwat, lowat, space));
}

inline void
khttpd_stream_data_is_available(struct khttpd_stream *stream)
{

	stream->up_ops->data_is_available(stream);
}

inline void
khttpd_stream_clear_to_send(struct khttpd_stream *stream, ssize_t space)
{

	stream->up_ops->clear_to_send(stream, space);
}

inline void
khttpd_stream_error(struct khttpd_stream *stream,
    struct khttpd_mbuf_json *entry)
{

	stream->up_ops->error(stream, entry);
}

#endif	/* _KERNEL */
