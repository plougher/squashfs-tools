#ifndef MATHS_H
#define MATHS_H
/*
 * Squashfs
 *
 * Copyright (c) 2026
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
 * maths.h
 */

#include <limits.h>

#include "error.h"

static inline long long _add_overflow(long long a, long long b, const char *func)
{
	if(LLONG_MAX - a < b)
		MATHS_ERROR("arithmetic overflow", func);

	return a + b;
}

static inline long long _sub_pos(long long a, long long b, const char *func)
{
	if(a < b)
		MATHS_ERROR("arithmetic negative result", func);

	return a - b;
}

#define ADD_OVERFLOW(a, b) _add_overflow(a, b, __func__)
#define SUB_POS(a, b) _sub_pos(a, b, __func__)
#endif
