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

#include "khttpd_json.h"

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/systm.h>

#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_string.h"

struct khttpd_mbuf_pos {
	struct mbuf    *ptr;
	u_int		off;
	int		unget;
};

struct khttpd_json {
	union {
		int64_t		ivalue;
		char		*storage;
	};
	size_t		size;
	size_t		storage_size;
	char		type;
	void		*data[];
};

#define KHTTPD_JSON_INSTANCE_SIZE 64
#define KHTTPD_JSON_EMBEDDED_DATA_SIZE \
	(KHTTPD_JSON_INSTANCE_SIZE - offsetof(struct khttpd_json, data))

static int khttpd_json_parse_value(struct khttpd_json **,
    struct khttpd_json_problem *, struct khttpd_mbuf_pos *, int);

static void
khttpd_mbuf_pos_init(struct khttpd_mbuf_pos *pos, struct mbuf *ptr,
    int off)
{

	pos->unget = -1;
	pos->ptr = ptr;
	pos->off = off;
}

static int
khttpd_mbuf_getc(struct khttpd_mbuf_pos *pos)
{
	int result;

	if (0 <= pos->unget) {
		result = pos->unget;
		pos->unget = -1;
		return (result);
	}

	while (pos->ptr != NULL && pos->ptr->m_len <= pos->off) {
		pos->off = 0;
		pos->ptr = pos->ptr->m_next;
	}

	if (pos->ptr == NULL) {
		return (-1);
	}

	return (mtod(pos->ptr, unsigned char *)[pos->off++]);
}

static void
khttpd_mbuf_ungetc(struct khttpd_mbuf_pos *pos, int ch)
{

	KASSERT(pos->unget == -1, ("unget=%#02x", pos->unget));
	pos->unget = ch;
}

static void
khttpd_mbuf_get_line_and_column(struct khttpd_mbuf_pos *origin,
    struct khttpd_mbuf_pos *pos, unsigned *line_out, unsigned *column_out)
{
	enum {
		tab_width = 8
	};
	struct mbuf *ptr, *eptr;
	const char *begin, *cp, *end;
	int off, eoff;
	unsigned line, column;

	KASSERT(origin->unget == -1 || 0 < origin->off,
	    ("origin->unget=%#x, origin->off=%d", origin->unget, origin->off));

	eptr = pos->ptr;
	eoff = pos->off;

	if (pos->unget != -1) {
		if (0 < eoff) {
			--eoff;
		} else {
			KASSERT(eptr != origin->ptr,
			    ("origin->ptr=%p, eptr=%p, eoff=0",
				origin->ptr, eptr));

			eptr = NULL;
			eoff = 0;
			
			for (ptr = origin->ptr; ; ptr = ptr->m_next) {
				if (0 < ptr->m_len) {
					eptr = ptr;
					eoff = ptr->m_len - 1;
				}

				if (ptr->m_next == pos->ptr)
					break;
			}

			KASSERT(eptr != NULL, ("chain of empty mbufs"));
		}
	}

	ptr = origin->ptr;
	off = origin->off;

	KASSERT(ptr != eptr || (origin->unget == -1 ? off : off - 1) < eoff,
	    ("ptr=%p, off=%#x, eptr=%p, eoff=%#x", ptr, off, eptr, eoff));

	line = 1;
	column = 1;

	if (origin->unget == '\n')
		++line;
	else if (origin->unget == '\t')
		column = 9;
	else if (origin->unget != -1)
		++column;

	while (ptr != NULL) {
		begin = mtod(ptr, char *) + off;
		end = mtod(ptr, char *) + (ptr == eptr ? eoff : ptr->m_len);
		cp = memchr(begin, '\n', end - begin);
		if (cp != NULL) {
			++line;
			column = 1;
			off = cp + 1 - mtod(ptr, char *);
			continue;
		}

		for (cp = begin; cp < end; ++cp)
			if (*cp == '\t')
				column = roundup2(column - 1 + tab_width,
				    tab_width) + 1;
			else
				++column;

		if (ptr == eptr && eoff <= off)
			break;

		off = 0;
		ptr = ptr->m_next;
	}

	*line_out = line;
	*column_out = column;
}

struct khttpd_json *
khttpd_json_null_new(void)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_NULL;
	result->size = result->storage_size = 0;
	result->ivalue = 0;

	return (result);
}

struct khttpd_json *
khttpd_json_integer_new(int64_t value)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_INTEGER;
	result->size = result->storage_size = 0;
	result->ivalue = value;

	return (result);
}

struct khttpd_json *
khttpd_json_boolean_new(bool value)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_BOOL;
	result->size = result->storage_size = 0;
	result->ivalue = value;

	return (result);
}

struct khttpd_json *
khttpd_json_string_new(void)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_STRING;
	result->size = 0;
	result->storage_size = 0;
	result->storage = (void *)result->data;

	return (result);
}

struct khttpd_json *
khttpd_json_array_new(void)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_ARRAY;
	result->size = 0;
	result->storage_size = 0;
	result->storage = (void *)result->data;

	return (result);
}

struct khttpd_json *
khttpd_json_object_new(void)
{
	struct khttpd_json *result;

	result = khttpd_malloc(KHTTPD_JSON_INSTANCE_SIZE);
	result->type = KHTTPD_JSON_OBJECT;
	result->size = 0;
	result->storage_size = 0;
	result->storage = (void *)result->data;

	return (result);
}

void
khttpd_json_delete(struct khttpd_json *value)
{
	struct khttpd_json *initstack[8];
	struct khttpd_json *ptr, **stack;
	size_t stksiz, depth;

	if (value == NULL)
		return;

	depth = 0;
	stksiz = nitems(initstack);
	stack = initstack;

	ptr = value;
cont:
	for (;;) {
		switch (ptr->type) {
		case KHTTPD_JSON_INTEGER:
		case KHTTPD_JSON_BOOL:
		case KHTTPD_JSON_NULL:
			break;

		case KHTTPD_JSON_ARRAY:
		case KHTTPD_JSON_OBJECT:
			if (ptr->size == 0) {
				if (ptr->storage != (void *)ptr->data)
					khttpd_free(ptr->storage);
				break;
			}

			if (stksiz <= depth) {
				stksiz <<= 1;
				if (stack != initstack)
					stack = khttpd_realloc(stack, stksiz *
					    sizeof(struct khttpd_json *));
				else {
					stack = khttpd_malloc(stksiz *
					    sizeof(struct khttpd_json *));
					bcopy(initstack, stack,
					    sizeof(initstack));
				}
			}

			stack[depth++] = ptr;

			ptr->size -= sizeof(struct khttpd_json *);
			ptr = *(struct khttpd_json **)(ptr->storage +
			    ptr->size);
			goto cont;

		case KHTTPD_JSON_STRING:
			if (ptr->storage != (void *)ptr->data)
				khttpd_free(ptr->storage);
		}

		khttpd_free(ptr);
		if (depth == 0)
			break;

		ptr = stack[--depth];
	}

	if (stack != initstack)
		khttpd_free(stack);
}

static void
khttpd_json_resize(struct khttpd_json *value, size_t newsize)
{
	void *storage;
	size_t ssize;

	KASSERT(value->type == KHTTPD_JSON_ARRAY ||
	    value->type == KHTTPD_JSON_OBJECT ||
	    value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	ssize = value->storage_size;
	if (ssize == 0) {
		ssize = KHTTPD_JSON_EMBEDDED_DATA_SIZE;
		storage = NULL;
	} else
		storage = value->storage;

	if (newsize < ssize)
		return;

	while (ssize < newsize)
		ssize <<= 1;
	value->storage_size = ssize;

	if (storage != NULL)
		value->storage = khttpd_realloc(storage, ssize);
	else {
		value->storage = khttpd_malloc(ssize);
		bcopy(value->data, value->storage, value->size);
	}
}

static void
khttpd_json_copy_deeply(struct khttpd_json *dst, struct khttpd_json *src)
{
	struct khttpd_json **selms, **delms;
	size_t i, nelms;

	KASSERT(src->size % sizeof(struct khttpd_json *) == 0,
	    ("invalid size %zd", src->size));

	if (src->storage_size != 0) {
		khttpd_json_resize(dst, src->size);
	}
	dst->size = src->size;

	selms = (struct khttpd_json **)src->storage;
	delms = (struct khttpd_json **)dst->storage;
	nelms = src->size / sizeof(struct khttpd_json *);
	for (i = 0; i < nelms; ++i) {
		delms[i] = khttpd_json_copy(selms[i]);
	}
}

struct khttpd_json *
khttpd_json_copy(struct khttpd_json *value)
{
	struct khttpd_json *result;

	switch (khttpd_json_type(value)) {

	case KHTTPD_JSON_ARRAY:
		result = khttpd_json_array_new();
		khttpd_json_copy_deeply(result, value);
		break;

	case KHTTPD_JSON_OBJECT:
		result = khttpd_json_object_new();
		khttpd_json_copy_deeply(result, value);
		break;

	case KHTTPD_JSON_INTEGER:
		result = khttpd_json_integer_new
		    (khttpd_json_integer_value(value));
		break;

	case KHTTPD_JSON_BOOL:
		result = khttpd_json_boolean_new
		    (khttpd_json_integer_value(value));
		break;

	case KHTTPD_JSON_STRING:
		result = khttpd_json_string_new();
		if (value->storage_size != 0) {
			khttpd_json_resize(result, value->size);
		}
		result->size = value->size;
		bcopy(value->storage, result->storage, value->size);
		break;

	case KHTTPD_JSON_NULL:
		result = khttpd_json_null_new();
		break;

	default:
		panic("invalid json type %d", khttpd_json_type(value));
	}

	return (result);
}

int
khttpd_json_type(struct khttpd_json *value)
{

	return (value->type);
}

int64_t
khttpd_json_integer_value(struct khttpd_json *value)
{

	KASSERT(value->type == KHTTPD_JSON_INTEGER ||
	    value->type == KHTTPD_JSON_BOOL,
	    ("type %d is neither integer nor bool", value->type));

	return (value->ivalue);
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
	    KHTTPD_JSON_EMBEDDED_DATA_SIZE : value->storage_size)
		khttpd_json_resize(value, value->size + 1);
	value->storage[value->size] = '\0';

	return (value->storage);
}

void
khttpd_json_string_append_char(struct khttpd_json *value, int ch)
{

	KASSERT(value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	if (value->size == value->storage_size == 0 ?
	    KHTTPD_JSON_EMBEDDED_DATA_SIZE : value->storage_size)
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

int
khttpd_json_array_size(struct khttpd_json *value)
{

	KASSERT(value->type == KHTTPD_JSON_ARRAY,
	    ("invalid type %d", value->type));

	return (value->size / sizeof(struct khttpd_json *));
}

struct khttpd_json *
khttpd_json_array_get(struct khttpd_json *value, int index)
{

	KASSERT(value->type == KHTTPD_JSON_ARRAY,
	    ("invalid type %d", value->type));

	return (value->size <= (size_t)index * sizeof(value) ? NULL :
	    ((struct khttpd_json **)value->storage)[index]);
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
}

int
khttpd_json_object_size(struct khttpd_json *value)
{

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	return (value->size / (sizeof(struct khttpd_json *) * 2));
}

struct khttpd_json *
khttpd_json_object_get(struct khttpd_json *value, const char *name)
{
	struct khttpd_json **end, **ptr;
	size_t namelen;

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	namelen = strlen(name);
	end = (struct khttpd_json **)(value->storage + value->size);
	ptr = (struct khttpd_json **)value->storage;
	for (; ptr < end; ptr += 2) {
		KASSERT(ptr[0]->type == KHTTPD_JSON_STRING,
		    ("invalid type %d", ptr[0]->type));
		if (namelen == ptr[0]->size &&
		    strncmp(name, (const char *)ptr[0]->storage, namelen) == 0)
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

void
khttpd_json_object_add(struct khttpd_json *value, struct khttpd_json *name,
    struct khttpd_json *elem)
{
	struct khttpd_json **ptr;
	size_t size, newsize;

	KASSERT(value->type == KHTTPD_JSON_OBJECT,
	    ("invalid type %d", value->type));

	size = value->size;
	newsize = size + sizeof(struct khttpd_json *) * 2;
	khttpd_json_resize(value, newsize);
	ptr = (struct khttpd_json **)(value->storage + size);
	ptr[0] = name;
	ptr[1] = elem;
	value->size = newsize;
}

static bool
khttpd_json_parse_expect_char(struct khttpd_mbuf_pos *iter, char expected)
{
	char ch;

	ch = khttpd_mbuf_getc(iter);
	if (ch == expected)
		return (true);
	khttpd_mbuf_ungetc(iter, ch);
	return (false);
}

static void
khttpd_json_mbuf_skip_ws(struct khttpd_mbuf_pos *iter)
{
	struct mbuf *ptr;
	const char *cp;
	int ch, len, off;

	ch = iter->unget;
	if (ch != -1 && ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
		return;

	iter->unget = -1;

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

static int
khttpd_json_parse_string(struct khttpd_json **value_out,
    struct khttpd_json_problem *output, struct khttpd_mbuf_pos *iter)
{
	struct khttpd_json *value;
	int ch, code, error, i, surrogate;

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
		khttpd_json_delete(value);

	return (error);
}

static int
khttpd_json_parse_object(struct khttpd_json **value_out,
    struct khttpd_json_problem *output, struct khttpd_mbuf_pos *iter,
    int depth_limit)
{
	struct khttpd_json *value, *name, *elem;
	int error;

	error = 0;
	value = khttpd_json_object_new();

	khttpd_json_mbuf_skip_ws(iter);
	if (khttpd_json_parse_expect_char(iter, '}')) {
		*value_out = value;
		return (0);
	}

	name = NULL;

	for (;;) {
		error = khttpd_json_parse_string(&name, output, iter);
		if (error != 0)
			break;

		khttpd_json_mbuf_skip_ws(iter);
		if (!khttpd_json_parse_expect_char(iter, ':')) {
			output->type = "khttpd_json::colon_expected";
			output->title = "a colon is expected";
 			error = EINVAL;
			break;
		}

		error = khttpd_json_parse_value(&elem, output, iter,
		    depth_limit - 1);
		if (error != 0)
			break;

		khttpd_json_object_add(value, name, elem);
		name = NULL;

		khttpd_json_mbuf_skip_ws(iter);
		if (khttpd_json_parse_expect_char(iter, '}'))
			break;

		if (!khttpd_json_parse_expect_char(iter, ',')) {
			error = EINVAL;
			break;
		}
	}

	khttpd_json_delete(name);

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_delete(value);

	return (error);
}

static int
khttpd_json_parse_array(struct khttpd_json **value_out,
    struct khttpd_json_problem *output, struct khttpd_mbuf_pos *iter,
    int depth_limit)
{
	struct khttpd_json *value, *elem;
	int error;

	error = 0;
	value = khttpd_json_array_new();

	khttpd_json_mbuf_skip_ws(iter);
	if (khttpd_json_parse_expect_char(iter, ']')) {
		*value_out = value;
		return (0);
	}

	for (;;) {
		error = khttpd_json_parse_value(&elem, output, iter,
		    depth_limit - 1);
		if (error != 0)
			break;

		khttpd_json_array_add(value, elem);

		khttpd_json_mbuf_skip_ws(iter);
		if (khttpd_json_parse_expect_char(iter, ']'))
			break;
		if (!khttpd_json_parse_expect_char(iter, ',')) {
			output->type = "khttpd_json::comma_expected";
			output->title = "a comma is expected";
			error = EINVAL;
			break;
		}
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_delete(value);

	return (error);
}

static int
khttpd_json_parse_expect_seq(struct khttpd_json_problem *output,
    struct khttpd_mbuf_pos *iter, const char *symbol)
{
	const char *cp;
	int ch;

	for (cp = symbol; (ch = *cp) != '\0'; ++cp)
		if (!khttpd_json_parse_expect_char(iter, ch)) {
			output->type = "khttpd_json::invalid_token";
			output->title = "invalid token";
			return (EINVAL);
		}

	return (0);
}

static int
khttpd_json_parse_integer(struct khttpd_json **value_out,
    struct khttpd_json_problem *output, struct khttpd_mbuf_pos *iter)
{
	int ch;
	uint64_t value;
	bool negative;

	negative = false;

	khttpd_json_mbuf_skip_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	if (ch == '-')
		negative = true;
	else
		khttpd_mbuf_ungetc(iter, ch);

	ch = khttpd_mbuf_getc(iter);
	if (ch == '0') {
		*value_out = 0;
		return (0);
	}
	if (!isdigit(ch)) {
		output->type = "khttpd_json::digit_expected";
		output->title = "a digit is expected";
		return (EINVAL);
	}

	value = ch - '0';
	for (;;) {
		ch = khttpd_mbuf_getc(iter);
		if (!isdigit(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			break;
		}

		/* -2^63 need not be handled */
		if (value * 10 < value) {
			output->type = "khttpd_json::overflow";
			output->title = "overflow";
			return (EOVERFLOW);
		}
		value = value * 10 + (ch - '0');
	}

	*value_out = khttpd_json_integer_new(negative ? 0 - value : value);

	return (0);
}

static int
khttpd_json_parse_value(struct khttpd_json **value_out,
    struct khttpd_json_problem *output, struct khttpd_mbuf_pos *iter,
    int depth_limit)
{
	struct khttpd_json *value;
	int ch, error;

	if (depth_limit <= 0) {
		output->type = "khttpd_json::nesting_too_deep";
		output->title = "nesting too deep";
		return (EINVAL);
	}

	value = NULL;
	error = 0;

	khttpd_json_mbuf_skip_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	switch (ch) {

	case -1:
		error = ENOMSG;
		break;

	case '{':
		error = khttpd_json_parse_object(&value, output, iter,
		    depth_limit);
		break;

	case '[':
		error = khttpd_json_parse_array(&value, output, iter,
		    depth_limit);
		break;

	case '\"':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_string(&value, output, iter);
		break;

	case '-':
		khttpd_mbuf_ungetc(iter, ch);
		error = khttpd_json_parse_integer(&value, output, iter);
		break;

	case 't':
		error = khttpd_json_parse_expect_seq(output, iter, "rue");
		if (error == 0)
			value = khttpd_json_boolean_new(true);
		break;

	case 'f':
		error = khttpd_json_parse_expect_seq(output, iter, "alse");
		if (error == 0)
			value = khttpd_json_boolean_new(false);
		break;

	case 'n':
		error = khttpd_json_parse_expect_seq(output, iter, "ull");
		if (error == 0)
			value = khttpd_json_null_new();
		break;

	default:
		if (isdigit(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			error = khttpd_json_parse_integer(&value, output, iter);
		} else {
			error = EINVAL;
			output->type = "khttpd_json::invalid_token";
			output->title = "invalid token";
		}
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_delete(value);

	return (error);
}

bool
khttpd_json_parse(struct khttpd_json **result,
    struct khttpd_json_problem *output, struct mbuf *input, int depth_limit)
{
	struct khttpd_json *dummy;
	struct khttpd_mbuf_pos origin, iter;
	int error;
	bool ok;

	ok = false;
	bzero(output, sizeof(*output));

	khttpd_mbuf_pos_init(&iter, input, 0);
	error = khttpd_json_parse_value(result, output, &iter, depth_limit);
	switch (error) {

	case 0:
		error = khttpd_json_parse_value(&dummy, output, &iter,
		    depth_limit);
		if (error == ENOMSG)
			ok = true;
		else {
			if (error == 0)
				khttpd_json_delete(dummy);
			output->type = "khttpd_json::trailing_garbage";
			output->title = "trailing garbage";
		}
		break;

	case ENOMSG:
		output->type = "khttpd_json::empty";
		output->title = "empty";
		break;

	default:
		break;
	}

	if (!ok) {
		khttpd_mbuf_pos_init(&origin, input, 0);
		khttpd_mbuf_get_line_and_column(&origin, &iter, &output->line,
		    &output->column);
	}

	return (ok);
}
