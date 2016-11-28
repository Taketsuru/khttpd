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

#include "khttpd_json.h"

#include <sys/types.h>
#include <sys/ctype.h>
#include <sys/queue.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/mbuf.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <vm/uma.h>

#ifdef KHTTPD_TRACE_MALLOC
#include <sys/stack.h>
#endif

#include "khttpd_init.h"
#include "khttpd_ktr.h"
#include "khttpd_malloc.h"
#include "khttpd_mbuf.h"
#include "khttpd_string.h"

#ifndef KHTTPD_TRACE_MALLOC_STACK_DEPTH
#define KHTTPD_TRACE_MALLOC_STACK_DEPTH	8
#endif

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

static int khttpd_json_parse_mbuf(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit);

static uma_zone_t khttpd_json_zone;

void
khttpd_json_delete(struct khttpd_json *value)
{
	struct khttpd_json *initstack[8];
	struct khttpd_json *ptr, **stack;
	size_t stksiz, depth;

	KHTTPD_ENTRY("khttpd_json_delete(%p)", value);

	if (value == NULL)
		return;

	depth = 0;
	stksiz = sizeof(initstack) / sizeof(initstack[0]);
	stack = initstack;

	ptr = value;
cont:
	for (;;) {
		KHTTPD_BRANCH("ptr=%p, type=%d", ptr, ptr->type);

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
				stack = khttpd_realloc(stack == initstack ?
				    NULL : stack,
				    stksiz * sizeof(struct khttpd_json *));
			}

			stack[depth++] = ptr;

			ptr->size -= sizeof(struct khttpd_json *);
			ptr = *(struct khttpd_json **)(ptr->storage +
			    ptr->size);
			goto cont;

		case KHTTPD_JSON_STRING:
			/* 'storage' is NULL if ptr->storage is not used. */
			if (ptr->storage != (void *)ptr->data)
				khttpd_free(ptr->storage);
		}

		uma_zfree(khttpd_json_zone, ptr);
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
	size_t size, ssize;

	KASSERT(value->type == KHTTPD_JSON_ARRAY ||
	    value->type == KHTTPD_JSON_OBJECT ||
	    value->type == KHTTPD_JSON_STRING,
	    ("invalid type %d", value->type));

	size = value->size;
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

	value->storage = khttpd_realloc(storage, ssize);
	if (storage == NULL)
		bcopy(value->data, value->storage, size);
}

int
khttpd_json_type(struct khttpd_json *value)
{

	return (value->type);
}

struct khttpd_json *
khttpd_json_null_new(void)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_NULL;
	result->size = result->storage_size = 0;
	result->ivalue = 0;

	return (result);
}

struct khttpd_json *
khttpd_json_integer_new(int64_t value)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_INTEGER;
	result->size = result->storage_size = 0;
	result->ivalue = value;

	return (result);
}

struct khttpd_json *
khttpd_json_boolean_new(boolean_t value)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_BOOL;
	result->size = result->storage_size = 0;
	result->ivalue = value;

	return (result);
}

int64_t
khttpd_json_integer_value(struct khttpd_json *value)
{

	KASSERT(value->type == KHTTPD_JSON_INTEGER ||
	    value->type == KHTTPD_JSON_BOOL,
	    ("type %d is neither integer nor bool", value->type));

	return (value->ivalue);
}

struct khttpd_json *
khttpd_json_string_new(void)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_STRING;
	result->size = 0;
	result->storage_size = 0;
	result->storage = (void *)result->data;

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

struct khttpd_json *
khttpd_json_array_new(void)
{
	struct khttpd_json *result;

	result = uma_zalloc(khttpd_json_zone, M_WAITOK);
	result->type = KHTTPD_JSON_ARRAY;
	result->size = 0;
	result->storage_size = 0;
	result->storage = (void *)result->data;

	return (result);
}

int
khttpd_json_array_size(struct khttpd_json *value)
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
	result->size = 0;
	len = size_hint * sizeof(struct khttpd_json *) * 2;
	if (len <= KHTTPD_JSON_EMBEDDED_DATA_SIZE) {
		result->storage_size = 0;
		result->storage = (void *)result->data;
	} else {
		result->storage_size = len;
		result->storage = khttpd_malloc(len);
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

	size = value->size;
	newsize = size + sizeof(struct khttpd_json *) * 2;
	khttpd_json_resize(value, newsize);
	ptr = (struct khttpd_json **)(value->storage + size);
	ptr[0] = name;
	ptr[1] = elem;
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

static void
khttpd_json_mbuf_skip_ws(struct khttpd_mbuf_pos *iter)
{
	struct mbuf *ptr;
	const char *cp;
	int ch, len, off;

	KHTTPD_ENTRY("khttpd_json_mbuf_skip_ws({%p,%d,'%c'})", 
	    iter->ptr, iter->off, iter->unget);

	ch = iter->unget;
	if (ch != -1 && ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r') {
		KHTTPD_BRANCH("khttpd_json_mbuf_skip_ws ungetc "
		    "%p,%#lx,'%c'", iter->ptr, iter->off, ch);
		return;
	}
	iter->unget = -1;

	for (ptr = iter->ptr, off = iter->off; ptr != NULL;
	     ptr = ptr->m_next, off = 0) {
		KHTTPD_TR("ptr=%p, len=%d", ptr, ptr->m_len);
		len = ptr->m_len;
		for (cp = mtod(ptr, char *) + off; off < len; ++cp, ++off) {
			ch = *cp;
			if (ch != ' ' && ch != '\t' &&
			    ch != '\n' && ch != '\r') {
				KHTTPD_BRANCH("khttpd_json_mbuf_skip_ws "
				    "%p,%#lx,'%c'", ptr, off, ch);
				goto quit;
			}
		}
	}
quit:
	iter->ptr = ptr;
	iter->off = off;
}

static int
khttpd_json_parse_string(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out)
{
	struct khttpd_json *value;
	int ch, code, error, i, surrogate;

	KHTTPD_ENTRY("khttpd_json_parse_string(%p,%d,%c)",
	    iter->ptr, iter->off, iter->unget);

	khttpd_json_mbuf_skip_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '\"')) {
		TR2("%s %u", __func__, __LINE__);
		return (EINVAL);
	}

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
						TR2("%s %u",
						    __func__, __LINE__);
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
khttpd_json_parse_object(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *name, *elem;
	int error;

	KHTTPD_ENTRY("khttpd_json_parse_object({%p,%d,'%c'})",
	    iter->ptr, iter->off, iter->unget);

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

	name = NULL;

	for (;;) {
		error = khttpd_json_parse_string(iter, &name);
		if (error != 0) {
			TR2("%s %u", __func__, __LINE__);
			break;
		}

		khttpd_json_mbuf_skip_ws(iter);
		if (!khttpd_json_parse_expect_char(iter, ':')) {
			TR2("%s %u", __func__, __LINE__);
			TR3("%p,%d,%c", iter->ptr, iter->off, iter->unget);
			error = EINVAL;
			break;
		}

		error = khttpd_json_parse_mbuf(iter, &elem, depth_limit - 1);
		if (error != 0) {
			TR2("%s %u", __func__, __LINE__);
			TR3("%p,%d,%c", iter->ptr, iter->off, iter->unget);
			break;
		}

		khttpd_json_object_add(value, name, elem);
		name = NULL;

		khttpd_json_mbuf_skip_ws(iter);
		if (khttpd_json_parse_expect_char(iter, '}')) {
			TR2("%s %u", __func__, __LINE__);
			TR3("%p,%d,%c", iter->ptr, iter->off, iter->unget);
			break;
		}
		if (!khttpd_json_parse_expect_char(iter, ',')) {
			TR2("%s %u", __func__, __LINE__);
			TR3("%p,%d,%c", iter->ptr, iter->off, iter->unget);
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
khttpd_json_parse_array(struct khttpd_mbuf_pos *iter, 
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value, *elem;
	int error;

	KHTTPD_ENTRY("khttpd_json_parse_array({%p,%d,'%c'})",
	    iter->ptr, iter->off, iter->unget);

	khttpd_json_mbuf_skip_ws(iter);
	if (!khttpd_json_parse_expect_char(iter, '[')) {
		TR2("%s %u", __func__, __LINE__);
		return (EINVAL);
	}

	error = 0;
	value = khttpd_json_array_new();

	khttpd_json_mbuf_skip_ws(iter);
	if (khttpd_json_parse_expect_char(iter, ']')) {
		*value_out = value;
		return (0);
	}

	for (;;) {
		error = khttpd_json_parse_mbuf(iter, &elem, depth_limit - 1);
		if (error != 0)
			break;

		khttpd_json_array_add(value, elem);

		khttpd_json_mbuf_skip_ws(iter);
		if (khttpd_json_parse_expect_char(iter, ']'))
			break;
		if (!khttpd_json_parse_expect_char(iter, ',')) {
			TR2("%s %u", __func__, __LINE__);
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
khttpd_json_parse_expect_seq(struct khttpd_mbuf_pos *iter,
    const char *symbol)
{
	const char *cp;
	int ch;

	KHTTPD_ENTRY("khttpd_json_parse_expect_seq({%p,%#lx,'%c'},%s)",
	    iter->ptr, iter->off, iter->unget, symbol);

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
	uint64_t value;
	boolean_t negative;

	KHTTPD_ENTRY("khttpd_json_parse_integer({%p,%#lx,'%c'})",
	    iter->ptr, iter->off, iter->unget);

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
	if (!isdigit(ch)) {
		TR2("%s %u", __func__, __LINE__);
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
		if (value * 10 < value)
			return (EOVERFLOW);
		value = value * 10 + (ch - '0');
	}

	*value_out = khttpd_json_integer_new(negative ? 0 - value : value);

	return (0);
}

static int
khttpd_json_parse_mbuf(struct khttpd_mbuf_pos *iter,
    struct khttpd_json **value_out, int depth_limit)
{
	struct khttpd_json *value;
	int ch, error;

	KHTTPD_ENTRY("khttpd_json_parse_mbuf({%p,%#lx,'%c'},, %d)",
	    iter->ptr, iter->off, iter->unget, depth_limit);

	if (depth_limit <= 0)
		return (ELOOP);

	value = NULL;
	error = 0;

	khttpd_json_mbuf_skip_ws(iter);
	ch = khttpd_mbuf_getc(iter);
	switch (ch) {

	case -1:
		error = ENOMSG;
		break;

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
		if (error == 0)
			value = khttpd_json_boolean_new(TRUE);
		break;

	case 'f':
		error = khttpd_json_parse_expect_seq(iter, "alse");
		if (error == 0)
			value = khttpd_json_boolean_new(FALSE);
		break;

	case 'n':
		error = khttpd_json_parse_expect_seq(iter, "ull");
		if (error == 0)
			value = khttpd_json_null_new();
		break;

	default:
		if (isdigit(ch)) {
			khttpd_mbuf_ungetc(iter, ch);
			error = khttpd_json_parse_integer(iter, &value);
		} else
			error = ch == -1 ? ENOMSG : EINVAL;
	}

	if (error == 0)
		*value_out = value;
	else
		khttpd_json_delete(value);

	return (error);
}

boolean_t
khttpd_json_parse_with_diagnosis(struct khttpd_json **result,
    struct khttpd_json_parse_diag *output, struct mbuf *input, int depth_limit)
{
	struct khttpd_json *dummy;
	struct khttpd_mbuf_pos origin, iter;
	int error;
	boolean_t ok;

	KHTTPD_ENTRY("khttpd_json_parse_with_diagnosis(,%p,%p,%d)",
	    output, input, depth_limit);

	ok = FALSE;
	bzero(output, sizeof(*output));

	khttpd_mbuf_pos_init(&iter, input, 0);
	error = khttpd_json_parse_mbuf(&iter, result, depth_limit);
	switch (error) {

	case 0:
		error = khttpd_json_parse_mbuf(&iter, &dummy, depth_limit);
		if (error == ENOMSG)
			ok = TRUE;
		else {
			output->type = "khttpd_json::trailing_garbage";
			output->title = "trailing garbage";
		}
		break;

	case EINVAL:
		output->type = "khttpd_json::syntax error";
		output->title = "syntax error";
		break;

	case EOVERFLOW:
		output->type = "khttpd_json::integer_overflow";
		output->title = "integer overflow";
		break;

	case ELOOP:
		output->type = "khttpd_json::nesting_too_deep";
		output->title = "nesting too deep";
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

#ifdef KHTTPD_TRACE_MALLOC

static int
khttpd_json_ctor(void *mem, int size, void *arg, int flags)
{
	struct stack st;

	KHTTPD_TR("alloc %p %#lx", mem, size);
	stack_save(&st);
	CTRSTACK(KTR_GEN, &st, KHTTPD_TRACE_MALLOC_STACK_DEPTH, 0);

	return (0);
}

static void
khttpd_json_dtor(void *mem, int size, void *arg)
{

	KHTTPD_TR("free %p", mem);
}

#endif

static int
khttpd_json_init(void)
{

	khttpd_json_zone = uma_zcreate("khttp-json", KHTTPD_JSON_INSTANCE_SIZE,
#ifdef KHTTPD_TRACE_MALLOC
	    khttpd_json_ctor, khttpd_json_dtor,
#else
	    NULL, NULL,
#endif
	    NULL, NULL, UMA_ALIGN_PTR, 0);

	return (0);
}

static void
khttpd_json_fini(void)
{

	uma_zdestroy(khttpd_json_zone);
}

KHTTPD_INIT(, khttpd_json_init, khttpd_json_fini, KHTTPD_INIT_PHASE_LOCAL);
