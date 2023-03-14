/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2019, 2022, 2023
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
 * unsquash-34.c
 *
 * Helper functions used by unsquash-3 and unsquash-4.
 */

#include "unsquashfs.h"

static unsigned int **inumber_table = NULL;
static char ***lookup_table = NULL;

long long *alloc_index_table(int indexes)
{
	static long long *alloc_table = NULL;
	static int alloc_size = 0;
	int length = indexes * sizeof(long long);

	if(alloc_size < length || length == 0) {
		long long *table = realloc(alloc_table, length);

		if(table == NULL && length !=0)
			MEM_ERROR();

		alloc_table = table;
		alloc_size = length;
	}

	return alloc_table;
}


/* These functions implement a bit-table to track whether directories have been
 * already visited.  This is to trap corrupted filesystems which have multiple
 * links to the same directory, which is invalid, and which may also create
 * a directory loop, where Unsquashfs will endlessly recurse until either
 * the pathname is too large (extracting), or the stack overflows.
 *
 * Each index entry is 8 Kbytes, and tracks 65536 inode numbers.  The index is
 * allocated on demand because Unsquashfs may not walk the complete filesystem.
 */
static void create_inumber_table()
{
	int indexes = INUMBER_INDEXES(sBlk.s.inodes);

	inumber_table = malloc(indexes * sizeof(unsigned int *));
	if(inumber_table == NULL)
		MEM_ERROR();
	memset(inumber_table, 0, indexes * sizeof(unsigned int *));
}


int inumber_lookup(unsigned int number)
{
	int index = INUMBER_INDEX(number - 1);
	int offset = INUMBER_OFFSET(number - 1);
	int bit = INUMBER_BIT(number - 1);

	if(inumber_table == NULL)
		create_inumber_table();

	/* Lookup number in the bit table */
	if(inumber_table[index] && (inumber_table[index][offset] & bit))
		return TRUE;

	if(inumber_table[index] == NULL) {
		inumber_table[index] = malloc(INUMBER_BYTES);
		if(inumber_table[index] == NULL)
			MEM_ERROR();
		memset(inumber_table[index], 0, INUMBER_BYTES);
	}

	inumber_table[index][offset] |= bit;
	return FALSE;
}


void free_inumber_table()
{
	int i, indexes = INUMBER_INDEXES(sBlk.s.inodes);

	if(inumber_table) {
		for(i = 0; i < indexes; i++)
			if(inumber_table[i])
				free(inumber_table[i]);
		free(inumber_table);
		inumber_table = NULL;
	}
}


/* These functions implement a lookup table to track creation of (non-directory)
 * inodes, and to discover if a hard-link to a previously created file should
 * be made.
 *
 * Each index entry is 32 Kbytes, and tracks 4096 inode numbers.  The index is
 * allocated on demand because Unsquashfs may not walk the complete filesystem.
 */
static void create_lookup_table()
{
	int indexes = LOOKUP_INDEXES(sBlk.s.inodes);

	lookup_table = malloc(indexes * sizeof(char *));
	if(lookup_table == NULL)
		MEM_ERROR();
	memset(lookup_table, 0, indexes * sizeof(char *));
}


char *lookup(unsigned int number)
{
	int index = LOOKUP_INDEX(number - 1);
	int offset = LOOKUP_OFFSET(number - 1);

	if(lookup_table == NULL)
		create_lookup_table();

	/* Lookup number in table */
	if(lookup_table[index] == NULL)
		return NULL;

	return lookup_table[index][offset];
}


void insert_lookup(unsigned int number, char *pathname)
{
	int index = LOOKUP_INDEX(number - 1);
	int offset = LOOKUP_OFFSET(number - 1);

	if(lookup_table == NULL)
		create_lookup_table();

	if(lookup_table[index] == NULL) {
		lookup_table[index] = malloc(LOOKUP_BYTES);
		if(lookup_table[index] == NULL)
			MEM_ERROR();
		memset(lookup_table[index], 0, LOOKUP_BYTES);
	}

	lookup_table[index][offset] = pathname;
}


void free_lookup_table(int free_pathname)
{
	int i, indexes = LOOKUP_INDEXES(sBlk.s.inodes);

	if(lookup_table) {
		for(i = 0; i < indexes; i++)
			if(lookup_table[i]) {
				if(free_pathname) {
					int j;

					for(j = 0; j < LOOKUP_OFFSETS; j++)
						if(lookup_table[i][j])
							free(lookup_table[i][j]);
				}
				free(lookup_table[i]);
			}
		free(lookup_table);
		lookup_table = NULL;
	}
}
