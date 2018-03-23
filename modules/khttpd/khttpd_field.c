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
#include <sys/ctype.h>
#include <sys/hash.h>
#include <sys/queue.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

#include "khttpd_init.h"
#include "khttpd_ktr.h"
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

int
khttpd_field_find(const char *begin, const char *end)
{

	return (khttpd_strtab_find(khttpd_field_strtab, begin, end, FALSE));
}

int
khttpd_field_maxlen(void)
{

	return (khttpd_strtab_maxlen(khttpd_field_strtab));
}

const char *
khttpd_field_name(int field)
{

	return (field < 0 || KHTTPD_FIELD_END <= field ? NULL :
	    khttpd_fields[field]);
}

int
khttpd_field_parse(struct khttpd_field_parser *parser, void *arg,
    int (*found_fn)(void *arg, int field, const char *name, const char *value),
    int (*error_fn)(void *arg, int reason, const char *line))
{
	struct mbuf *ptr, *next;
	char *cp0, *cp1, *bolp, *eolp, *enamep, *valuep;
	u_int curlen, len, maxlen, off;
	int ch, error, field;
	bool consume, toolong;

	KHTTPD_ENTRY("%s(%p,%p,%p,%p)",
	    __func__, parser, arg, found_fn, error_fn);
	KASSERT(khttpd_field_strtab != NULL, ("not initialized"));

	ptr = parser->ptr;
	off = parser->off;
	maxlen = parser->maxlen;
	error = 0;
	consume = parser->consume;
	toolong = false;
	while (error == 0) {
		cp0 = mtod(ptr, char *) + off;
		len = ptr->m_len - off;
		if ((cp1 = memchr(cp0, '\n', len)) != NULL) {
			len = cp1 - cp0;
		}

		if (!toolong) {
			curlen = sbuf_len(&parser->line);
			toolong = maxlen < curlen + len;
			sbuf_bcat(&parser->line, cp0, 
			    MIN(len, maxlen - curlen + 1));
		}

		if (cp1 == NULL) {
			if ((next = ptr->m_next) == NULL) {
				if (consume) {
					m_free(ptr);
					ptr = NULL;
					off = 0;
				} else {
					off = ptr->m_len;
				}
				error = EWOULDBLOCK;
				break;
			}

			if (consume) {
				m_free(ptr);
			}
			ptr = next;
			off = 0;
			continue;
		}

		sbuf_finish(&parser->line);

		off += len + 1;
		bolp = sbuf_data(&parser->line);
		eolp = bolp + sbuf_len(&parser->line);

		if (toolong) {
			error = error_fn(arg, KHTTPD_FIELD_ERROR_LONG_LINE,
			    bolp);
			goto next;
		}

		if (bolp < eolp && eolp[-1] == '\r')
			--eolp;

		if (bolp == eolp) {
			error = 0;
			break;
		}

		while ((ch = eolp[-1]) == ' ' || ch == '\t')
			--eolp;
		*eolp = '\0';

		enamep = memchr(bolp, ':', eolp - bolp);
		if (enamep == NULL) {
			error = error_fn(arg, KHTTPD_FIELD_ERROR_NO_SEPARATOR,
			    bolp);
			goto next;
		}

		if (bolp == enamep) {
			error = error_fn(arg, KHTTPD_FIELD_ERROR_NO_NAME, bolp);
			goto next;
		}

		if ((ch = enamep[-1]) == ' ' || ch == '\t') {
			error = error_fn(arg,
			    KHTTPD_FIELD_ERROR_WS_FOLLOWING_NAME, bolp);
			goto next;
		}

		if ((ch = *bolp) == ' ' || ch == '\t') {
			error = error_fn(arg, KHTTPD_FIELD_ERROR_FOLD_LINE,
			    bolp);
			goto next;
		}

		*enamep = '\0';

		valuep = enamep + 1;
		while (valuep < eolp && ((ch = *valuep) == ' ' || ch == '\t')) {
			++valuep;
		}

		field = khttpd_field_find(bolp, enamep);
		error = found_fn(arg, field, bolp, valuep);
 next:
		sbuf_clear(&parser->line);
	}

	parser->ptr = ptr;
	parser->off = off;

	return (error);
}

void
khttpd_field_parse_add_data(struct khttpd_field_parser *parser,
    struct mbuf *data)
{
	struct mbuf *tail;

	KHTTPD_ENTRY("%s(%p,%p)", __func__, parser, data);

	if (parser->tail == NULL) {
		parser->ptr = data;
	} else {
		parser->tail->m_next = data;
	}

	for (tail = data; tail->m_next != NULL; tail = tail->m_next) {
	}
	parser->tail = tail;
}

void
khttpd_field_parse_destroy(struct khttpd_field_parser *parser)
{

	KHTTPD_ENTRY("%s(%p,%p)", __func__, parser);

	if (parser->consume) {
		m_freem(parser->ptr);
	}
	sbuf_delete(&parser->line);
}

void
khttpd_field_parse_init(struct khttpd_field_parser *parser,
    u_int maxlen, bool consume, struct mbuf *data, u_int off)
{

	KHTTPD_ENTRY("%s(%p,%#x,%d,%p)",
	    __func__, parser, maxlen, consume, data);

	sbuf_new(&parser->line, parser->buf, sizeof(parser->buf),
	    SBUF_AUTOEXTEND);

	parser->tail = NULL;
	khttpd_field_parse_add_data(parser, data);
	parser->off = off;
	parser->maxlen = maxlen;
	parser->consume = consume;
}

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
