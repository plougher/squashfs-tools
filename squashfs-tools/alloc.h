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

#include "error.h"

#define TRUE 1
#define FALSE 0

static inline void *_calloc(size_t num, size_t size, const char *func)
{
	void *mem = calloc(num, size);

	if(mem == NULL)
		MEMERROR(func);

	return mem;
}


static inline void *_malloc(size_t size, const char *func)
{
	void *mem = malloc(size);

	if(mem == NULL)
		MEMERROR(func);

	return mem;
}

static inline char *_strdup(const char *s, const char *func)
{
	char *str = strdup(s);

	if(str == NULL)
		MEMERROR(func);

	return str;
}

#define CALLOC(num, size) _calloc(num, size, __func__)
#define MALLOC(size) _malloc(size, __func__)
#define STRDUP(s) _strdup(s, __func__)
#endif
