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

#include "khttpd_stream.h"

#include <sys/param.h>
#include <sys/mbuf.h>

#include "khttpd_ktr.h"
#include "khttpd_mbuf.h"
#include "khttpd_string.h"

/*
 * PARAMETERS
 *
 * RETURN VALUES
 *
 * If successful, khttpd_stream_read_line() returns 0.  It returns one of the
 * following values on failure.
 *   
 * [EWOULDBLOCK]	More bytes are necessary.
 * 
 * [ENOMSG]		Reaches the end of the stream before it finds a CRLF.
 *
 * [ENOBUFS]		Have read more than *limit bytes.
 *
 * Others		Any other return values from soreceive().
 *
 * USAGE
 *
 *     struct khttpd_mbuf_pos bol, eol;
 *
 *     khttpd_mbuf_pos_init(&bol, <beginning of the line>);
 *     eol = bol;
 *     for (;;) {
 *         error = khttpd_stream_read_until(stream, '\n', limit, &eol);
 *         if (error != EWOULDBLOCK)
 *		break;
 *         ...wait until data become available...
 *     }
 */
int
khttpd_stream_receive_until(struct khttpd_stream *stream, int ch,
    ssize_t *limit, struct khttpd_mbuf_pos *endpos)
{
	char *begin, *cp;
	struct mbuf *ptr, *m;
	int32_t off;
	u_int len;
	int error;

	KHTTPD_ENTRY("%s(%p,%#zd,,)", __func__, stream, *limit);

	if (endpos->unget == ch) {
		endpos->unget = -1;
		return (0);
	}

	ptr = endpos->ptr;
	off = endpos->off;

	for (;;) {
		/* Find the first ch in the mbuf pointed by ptr. */
		begin = mtod(ptr, char *);
		len = ptr->m_len;
		cp = memchr(begin + off, ch, len);
		if (cp != NULL) {
			endpos->ptr = ptr;
			endpos->off = cp - begin + 1;
			return (0);
		}

		if (ptr->m_next != NULL) {
			/* Advance to the next mbuf */
			ptr = ptr->m_next;
			off = 0;

		} else {
			/*
			 * No '\n' found.  Receive further if we reached the
			 * end of the chain.
			 */

			error = *limit == 0 ? ENOMSG :
			    khttpd_stream_receive(stream, limit, &m);

			if (error != 0) {
				endpos->ptr = ptr;
				endpos->off = off;
				return (error);
			}

			ptr = ptr->m_next = m;
			off = 0;
		}
	}
}

extern int
khttpd_stream_receive(struct khttpd_stream *stream, ssize_t *resid, 
    struct mbuf **m_out);

extern void
khttpd_stream_continue_receiving(struct khttpd_stream *stream);

extern void
khttpd_stream_reset(struct khttpd_stream *stream);

extern bool
khttpd_stream_send(struct khttpd_stream *stream, struct mbuf *m, int flags);

extern void
khttpd_stream_notify_of_drain(struct khttpd_stream *stream);

extern void
khttpd_stream_destroy(struct khttpd_stream *stream);

extern void
khttpd_stream_send_bufstat(struct khttpd_stream *stream, u_int *, int *, 
    long *);

extern void
khttpd_stream_data_is_available(struct khttpd_stream *stream);

extern void
khttpd_stream_clear_to_send(struct khttpd_stream *stream, ssize_t);

extern void
khttpd_stream_error(struct khttpd_stream *, struct khttpd_mbuf_json *);
