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

/* reader type */
#define COMBINED_READER	1
#define FRAGMENT_READER	2
#define BLOCK_READER	3

/* minimum blocks per reader thread */
#define BLOCKS_MIN	4

struct readahead {
	long long		start;
	int			size;
	struct readahead	*next;
	char			*src;
	char			data[0] __attribute__((aligned));
};

struct read_entry {
	struct dir_ent	*dir_ent;
	unsigned int	file_count;
};

struct reader {
	int		id;
	int		size;
	char		*type;
	char		*pathname;
	struct cache	*buffer;
};

extern struct reader *get_readers(int *);
extern pthread_t *get_reader_threads(int *);
extern int set_read_frag_threads(int);
extern int set_read_block_threads(int);
extern void set_single_threaded();
extern int get_reader_num();
extern void set_sleep_time(int);
extern void check_min_memory(int, int, int);
#endif
