#ifndef ALLOC_H
#define ALLOC_H
/*
 * Squashfs
 *
 * Copyright (c) 2025
 * Phillip Lougher <phillip@squashfs.org.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * alloc.h
 */
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "error.h"

#define TRUE 1
#define FALSE 0

static inline void *_calloc(size_t num, size_t size, const char *func)
{
	void *mem = calloc(num, size);

	if(mem == NULL)
		MEM_ERROR(func);

	return mem;
}

static inline void *_malloc(size_t size, const char *func)
{
	void *mem = malloc(size);

	if(mem == NULL)
		MEM_ERROR(func);

	return mem;
}

static inline void *_realloc(void *ptr, size_t size, const char *func)
{
	void *new = realloc(ptr, size);

	if(new == NULL)
		MEM_ERROR(func);

	return new;
}

static inline char *_strdup(const char *s, const char *func)
{
	char *str = strdup(s);

	if(str == NULL)
		MEM_ERROR(func);

	return str;
}

static inline char *_strndup(const char *s, size_t n, const char *func)
{
	char *str = strndup(s, n);

	if(str == NULL)
		MEM_ERROR(func);

	return str;
}

static inline void _vasprintf(char **restrict strp, const char *restrict fmt, va_list ap, const char *func)
{
	int res = vasprintf(strp, fmt, ap);

	if(res == -1)
		MEM_ERROR(func);
}

static inline void _asprintf(char **restrict strp, const char *func, const char *restrict fmt, ...)
{
	va_list ap;
	int res;

	va_start(ap, fmt);
	res = vasprintf(strp, fmt, ap);
	va_end(ap);

	if(res == -1)
		MEM_ERROR(func);
}

#define CALLOC(num, size) _calloc(num, size, __func__)
#define CALLOC(num, size) _calloc(num, size, __func__)
#define MALLOC(size) _malloc(size, __func__)
#define REALLOC(ptr, size) _realloc(ptr, size, __func__)
#define STRDUP(s) _strdup(s, __func__)
#define STRNDUP(s, n) _strndup(s, n, __func__)
#define VASPRINTF(strp, fmt, ap) _vasprintf(strp, fmt, ap, __func__)
#define ASPRINTF(strp, fmt, args...) _asprintf(strp, __func__, fmt, ## args)
#endif
