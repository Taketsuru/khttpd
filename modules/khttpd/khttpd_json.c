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

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/refcount.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/syscallsubr.h>

#include <vm/uma.h>

#include "khttpd.h"
#include "khttpd_private.h"

#ifndef KHTTPD_JSON_EMBEDDED_DATA_SIZE
#define KHTTPD_JSON_EMBEDDED_DATA_SIZE	(128 - 32)
#endif

/* ------------------------------------------------------- type definitions */

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

/* --------------------------------------------------- variable definitions */

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

static const char khttpd_json_null_literal[] = "null";

static uma_zone_t khttpd_json_zone;

/* --------------------------------------------------- function definitions */

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
				stacksize =
				    stacksize < 8 ? 8 : stacksize << 1;
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

int
khttpd_json_type(struct khttpd_json *value)
{

	return value->type;
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

	if (value->size == value->storage_size == 0 ?
	    sizeof(value->data) : value->storage_size)
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
khttpd_json_parse_expect_char(struct khttpd_mbuf_pos *iter, char expected)
{
	char ch;

	ch = khttpd_mbuf_getc(iter);
	if (ch == expected)
		return (TRUE);
	khttpd_mbuf_ungetc(iter, ch);
	return (FALSE);
}

static int
khttpd_json_parse_string(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out)
{
	struct khttpd_json *value;
	int ch, code, error, i, surrogate;

	TRACE("enter");

	khttpd_json_mbuf_skip_ws(iter);
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
khttpd_json_parse_object(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *name, *elem;
	int error;

	TRACE("enter");

	khttpd_json_mbuf_skip_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '{'))
		return (EINVAL);

	error = 0;
	value = khttpd_json_object_new(0);

	khttpd_json_mbuf_skip_ws(iter);
	if (khttpd_json_parse_expect_char(iter, '}')) {
		*value_out = value;
		return (0);
	}

	for (;;) {
		error = khttpd_json_parse_string(iter, &name);
		if (error != 0)
			break;

		khttpd_json_mbuf_skip_ws(iter);
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

		khttpd_json_mbuf_skip_ws(iter);
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
khttpd_json_parse_array(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *elem;
	int error;

	TRACE("enter");

	khttpd_json_mbuf_skip_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '['))
		return (EINVAL);

	error = 0;
	value = khttpd_json_array_new();

	khttpd_json_mbuf_skip_ws(iter);
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

		khttpd_json_mbuf_skip_ws(iter);
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
khttpd_json_parse_expect_seq(struct khttpd_mbuf_pos *iter,
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
khttpd_json_parse_integer(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out)
{
	int ch;
	int64_t value;
	boolean_t negative;

	negative = FALSE;

	khttpd_json_mbuf_skip_ws(iter);
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
khttpd_json_parse(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value;
	int ch, error;

	TRACE("enter");

	if (depth_limit <= 0)
		return (ELOOP);

	value = NULL;
	error = 0;

	khttpd_json_mbuf_skip_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	switch (ch) {

	case '{':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_object(iter, &value, depth_limit);
		break;

	case '[':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_array(iter, &value, depth_limit);
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

struct mbuf *
khttpd_json_mbuf_append_string_wo_quote(struct mbuf *output, const char *begin,
    const char *end)
{
	struct mbuf *tail;
	const char *srcp;
	char *dstp, *dend;
	int32_t code;
	int flc, i, len;
	uint16_t code1, code2;
	unsigned char ch;

	srcp = begin;
	tail = output;
	dstp = mtod(tail, char *) + tail->m_len;
	dend = M_START(tail) + M_SIZE(tail);

	while (srcp < end) {
		ch = (unsigned char)*srcp;
		switch (ch) {

		case '\b':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'b';
			++srcp;
			break;

		case '\f':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'f';
			++srcp;
			break;

		case '\n':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'n';
			++srcp;
			break;

		case '\r':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 'r';
			++srcp;
			break;

		case '\t':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = 't';
			++srcp;
			break;

		case '\"':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = '\"';
			++srcp;
			break;

		case '\\':
			if (dend - dstp < 2)
				goto expand;
			*dstp++ = '\\';
			*dstp++ = '\\';
			++srcp;
			break;

		default:
			if (ch < 0x80) {
				code = ch;
				len = 1;

			} else {
				flc = fls(~ch & 0xff);
				code = ch & (0xff >> (CHAR_BIT + 1 - flc));
				len = CHAR_BIT - flc;

				/*
				 * Write as is if we found a multibyte
				 * sequence starts with 10xxxxxx, a premature
				 * end of string, or a sequence longer than 4
				 * bytes.
				 */
				if (len == 1 || end - srcp < len || 4 < len)
					code = ch;

				for (i = 1; i < len; ++i)
					code = (code << 6) |
					    (srcp[i] & 0x3f);

				/*
				 * Write as is if the code point is not
				 * representable with utf-16, or in the range
				 * reserved for surrogate pairs.
				 */
				if (0x110000 <= code ||
				    (0xd800 <= code && code < 0xe000))
					code = ch;
			}

			if (0x20 <= code && code < 0x80) {
				if (dend - dstp < 1)
					goto expand;
				*dstp++ = code;

			} else if (code < 0x10000) {
				if (dend - dstp < 7)
					goto expand;
				snprintf(dstp, 7, "\\u%04x", code);
				dstp += 6;

			} else {
				if (dend - dstp < 13)
					goto expand;
				code1 = ((code - 0x10000) >> 10) + 0xd800;
				code2 = ((code - 0x10000) & 0x3ff) + 0xdc00;
				snprintf(dstp, 13, "\\u%04x\\u%04x", code1,
				    code2);
				dstp += 12;
			}

			srcp += len;
		}
		continue;

expand:
		tail->m_len = dstp - mtod(tail, char *);
		tail = tail->m_next = m_get(M_WAITOK, MT_DATA);
		dstp = mtod(tail, char *);
		dend = M_START(tail) + M_SIZE(tail);
	}

	tail->m_len = dstp - mtod(tail, char *);

	return (tail);
}

struct mbuf *
khttpd_json_mbuf_append_string_in_mbuf_wo_quote(struct mbuf *output,
    struct mbuf *source)
{
	struct mbuf *tail;
	struct mbuf *srcp;
	const char *begin, *end;
	
	tail = output;
	for (srcp = source; srcp != NULL; srcp = srcp->m_next) {
		begin = mtod(srcp, char *);
		end = begin + srcp->m_len;
		tail = khttpd_json_mbuf_append_string_wo_quote(tail, begin, end);
	}
	return (tail);
}

struct mbuf *
khttpd_json_mbuf_append_string(struct mbuf *output,
    const char *begin, const char *end)
{
	struct mbuf *tail;

	tail = khttpd_mbuf_append_ch(output, '\"');
	tail = khttpd_json_mbuf_append_string_wo_quote(tail, begin, end);
	tail = khttpd_mbuf_append_ch(tail, '\"');
	return (tail);
}

struct mbuf *
khttpd_json_mbuf_append_string_in_mbuf(struct mbuf *output,
    struct mbuf *src)
{
	struct mbuf *tail;

	tail = khttpd_mbuf_append_ch(output, '\"');
	tail = khttpd_json_mbuf_append_string_in_mbuf_wo_quote(tail, src);
	tail = khttpd_mbuf_append_ch(tail, '\"');
	return (tail);
}

struct mbuf *
khttpd_json_mbuf_append_cstring(struct mbuf *output, const char *str)
{

	return str != NULL
	    ? khttpd_json_mbuf_append_string(output, str, str + strlen(str))
	    : khttpd_mbuf_append(output, khttpd_json_null_literal,
		khttpd_json_null_literal + sizeof(khttpd_json_null_literal) -
		1);
}

void
khttpd_json_mbuf_skip_ws(struct khttpd_mbuf_pos *iter)
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
			if (ch != ' ' && ch != '\t' &&
			    ch != '\n' && ch != '\r')
				goto quit;
		}
	}
quit:
	iter->ptr = ptr;
	iter->off = off;
}

int
khttpd_json_init(void)
{

	khttpd_json_zone = uma_zcreate("khttp-json",
	    sizeof(struct khttpd_json),
	    NULL, NULL, NULL, NULL, UMA_ALIGN_PTR, 0);

	return (0);
}

void
khttpd_json_fini(void)
{

	uma_zdestroy(khttpd_json_zone);
}
