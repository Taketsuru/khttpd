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
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include "khttpd_field.h"

#include <sys/param.h>
#include <sys/limits.h>
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_stream.h"
#include "khttpd_strtab.h"

static const char *khttpd_fields[] = {
	"Content-Length",
	"Transfer-Encoding",
	"Connection",
	"Expect",
	"Host",
	"Content-Type",
	"Location",
	"Status"
};

CTASSERT(nitems(khttpd_fields) == KHTTPD_FIELD_END);

static struct khttpd_strtab *khttpd_field_strtab;

static int
khttpd_field_init(void)
{

	khttpd_field_strtab = khttpd_strtab_new(khttpd_fields,
	    nitems(khttpd_fields));

	return (khttpd_field_strtab != NULL ? 0 : ENOMEM);
}

static void
khttpd_field_fini(void)
{

	khttpd_strtab_delete(khttpd_field_strtab);
}

KHTTPD_INIT(khttpd_field, khttpd_field_init, khttpd_field_fini,
    KHTTPD_INIT_PHASE_LOCAL);

int
khttpd_field_find(const char *begin, const char *end)
{

	return (khttpd_strtab_find(khttpd_field_strtab, begin, end, FALSE));
}

const char *
khttpd_field_name(int field)
{

	return (field < 0 || KHTTPD_FIELD_END <= field ? NULL :
	    khttpd_fields[field]);
}

int
khttpd_fields_receive(struct khttpd_fields *fields, struct mbuf **mbp,
    struct khttpd_stream *stream)
{
	off_t nread;
	struct mbuf *next, *mb;
	char *data, *cp;
	char *begin, *end, *putp;
	int clen, len;
	int resid;
	int error;

	KHTTPD_ENTRY("%s(%p)", __func__, fields);

	mb = *mbp;
	begin = fields->begin;
	end = fields->end;
	putp = fields->putp;
	resid = fields->resid;
	error = 0;

	while (0 <= resid && putp < end) {
		if (mb == NULL) {
			nread = SSIZE_MAX;
			error = khttpd_stream_receive(stream, &nread, &mb);
			if (error != 0) {
				KHTTPD_NOTE("error %d", error);
				break;
			}
			if (nread == SSIZE_MAX) {
				KHTTPD_NOTE("enomsg");
				error = ENOMSG;
				break;
			}
			KASSERT(mb != NULL, ("mb is NULL"));
		}

		data = mtod(mb, char *);
		len = mb->m_len;
		cp = memchr(data, '\n', len);
		KHTTPD_NOTE("resid %d, putp - begin %d, len %d, cp %p(%d)",
		    resid, putp - begin, len, cp, cp == NULL ? 0 : cp - data);
		if (cp == NULL) {
			resid -= len;
			clen = MIN(end - putp, len);
			bcopy(data, putp, clen);
			putp += clen;
			next = mb->m_next;
			m_free(mb);
			mb = next;
			continue;
		}

		if (cp != data) {
			len = cp[-1] == '\r' ? cp - data - 1 : cp - data;
			clen = MIN(resid, MIN(end - putp, len));
			bcopy(data, putp, clen);
			putp += clen;
		} else if (begin < putp && putp[-1] == '\r') {
			--putp;
		}

		resid -= cp - data + 1;
		m_adj(mb, cp - data + 1);

		/*
		 * This 'if' is necessary to ignore empty lines preceding a
		 * header.
		 */
		if (0 <= resid && begin < putp) {
			if (putp[-1] == '\n') { /* found an empty line */
				break;
			}
			if (putp < end) {
				*putp++ = '\n';
			}
		}
	}

	fields->putp = putp;

	if (error == 0 && resid < 0) {
		KHTTPD_NOTE("enobufs");
		m_freem(mb);
		*mbp = NULL;
		fields->resid = 0;
		return (ENOBUFS);
	}

	fields->resid = resid;
	*mbp = mb;

	return (error);
}

extern void 
khttpd_fields_init(struct khttpd_fields *_fields, char *_begin,
    size_t _bufsize, int _max_input_size);

extern char *
khttpd_fields_begin(struct khttpd_fields *_fields);

extern char *
khttpd_fields_end(struct khttpd_fields *_fields);

extern void
khttpd_fields_reset(struct khttpd_fields *_fields, int _max_input_size);
