#ifndef READER_H 
#define READER_H

/*
 * Squashfs
 *
 * Copyright (c) 2022
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
 * reader.h
 */

#define READAHEAD_SIZE			8192
#define READAHEAD_ALLOC			(0x100000 * sizeof(struct readahead *))
#define READAHEAD_INDEX(A)		((A >> 13) & 0xfffff)
#define READAHEAD_OFFSET(A)		(A % READAHEAD_SIZE)

struct readahead {
	long long		start;
	int			size;
	struct readahead	*next;
	char			*src;
	char			data[0] __attribute__((aligned));
};
#endif
