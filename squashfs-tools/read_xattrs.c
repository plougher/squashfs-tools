/*
 * Read a squashfs filesystem.  This is a highly compressed read only filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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
 * read_xattrs.c
 */

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#ifndef linux
#define __BYTE_ORDER BYTE_ORDER
#define __BIG_ENDIAN BIG_ENDIAN
#define __LITTLE_ENDIAN LITTLE_ENDIAN
#else
#include <endian.h>
#endif

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "read_fs.h"
#include "global.h"
#include "compressor.h"
#include "xattr.h"

#include <stdlib.h>

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...)		do { \
						printf("mksquashfs: "s, ## args); \
					} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...)		do { \
						fprintf(stderr, s, ## args); \
					} while(0)

extern void read_destination(int, long long, int, char *);
extern int read_block(int, long long, long long *, void *,
        squashfs_super_block *);

struct hash_entry {
	long long		start;
	unsigned int		offset;
	struct hash_entry	*next;
} *hash_table[65536];


static int save_xattr_block(long long start, int offset)
{
	struct hash_entry *hash_entry = malloc(sizeof(*hash_entry));
	int hash = start & 0xffff;

	TRACE("save_xattr_block: start %lld, offset %d\n", start, offset);

	if(hash_entry == NULL) {
		ERROR("Failed to allocate hash entry\n");
		return -1;
	}

	hash_entry->start = start;
	hash_entry->offset = offset;
	hash_entry->next = hash_table[hash];
	hash_table[hash] = hash_entry;

	return 1;
}


static int get_xattr_block(long long start)
{
	int hash = start & 0xffff;
	struct hash_entry *hash_entry = hash_table[hash];

	for(; hash_entry; hash_entry = hash_entry->next)
		if(hash_entry->start == start)
			break;

	TRACE("get_xattr_block: start %lld, offset %d\n", start,
		hash_entry ? hash_entry->offset : -1);

	return hash_entry ? hash_entry->offset : -1;
}


static int read_xattr_entry(struct xattr_list *xattr,
	struct squashfs_xattr_entry *entry, void *name)
{
	int i, len, type = entry->type & XATTR_PREFIX_MASK;

	for(i = 0; prefix_table[i].type != -1; i++)
		if(prefix_table[i].type == type)
			break;

	if(prefix_table[i].type == -1)
		return 0;

	len = strlen(prefix_table[i].prefix);
	xattr->full_name = malloc(len + entry->size + 1);
	memcpy(xattr->full_name, prefix_table[i].prefix, len);
	memcpy(xattr->full_name + len, name, entry->size);
	xattr->full_name[len + entry->size] = '\0';
	xattr->name = xattr->full_name + len;
	xattr->size = entry->size;
	xattr->type = type;

	return 1;
}


int get_xattrs(int fd, squashfs_super_block *sBlk)
{
	int bytes, i, id, ids, indexes, index_bytes;
	long long *index, start, end;
	struct squashfs_xattr_table id_table;
	struct squashfs_xattr_id *xattr_ids;
	void *xattrs = NULL;

	TRACE("get_xattrs\n");

	if(sBlk->xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return 1;

	/*
	 * Read xattr id table, containing start of xattr metadata and the
	 * number of xattrs in the file system
	 */
	read_destination(fd, sBlk->xattr_id_table_start, sizeof(id_table),
		(char *) &id_table);
	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);

	/*
	 * Allocate and read the index to the xattr id table metadata
	 * blocks
	 */
	ids = id_table.xattr_ids;
	index_bytes = SQUASHFS_XATTR_BLOCK_BYTES(ids);
	indexes = SQUASHFS_XATTR_BLOCKS(ids);
	index = malloc(index_bytes);
	if(index == NULL) {
		ERROR("Failed to allocate index array\n");
		return 0;
	}

	read_destination(fd, sBlk->xattr_id_table_start + sizeof(id_table),
		index_bytes, (char *) index);
	SQUASHFS_INSWAP_LONG_LONGS(index, indexes);

	/*
	 * Allocate enough space for the uncompressed xattr id table, and
	 * read and decompress it
	 */
	bytes = SQUASHFS_XATTR_BYTES(ids);
	xattr_ids = malloc(bytes);
	if(xattr_ids == NULL) {
		ERROR("Failed to allocate xattr id table\n");
		goto failed1;
	}

	for(i = 0; i < indexes; i++) {
		int length = read_block(fd, index[i], NULL,
			((unsigned char *) xattr_ids) +
			(i * SQUASHFS_METADATA_SIZE), sBlk);
		TRACE("Read xattr id table block %d, from 0x%llx, length "
			"%d\n", i, index[i], length);
		if(length == 0) {
			ERROR("Failed to read xattr id table block %d, "
				"from 0x%llx, length %d\n", i, index[i],
				length);
			goto failed2;
		}
	}

	/*
	 * Read and decompress the xattr metadata
	 *
	 * Note the first xattr id table metadata block is immediately after
	 * the last xattr metadata block, so we can use index[0] to work out
	 * the end of the xattr metadata
	 */
	start = id_table.xattr_table_start;
	end = index[0];
	for(i = 0; start < end; i++) {
		int length;
		void *x = realloc(xattrs, (i + 1) * SQUASHFS_METADATA_SIZE);
		if(x == NULL) {
			ERROR("Failed to realloc xattr data\n");
			goto failed3;
		}
		xattrs = x;

		/* store mapping from location of compressed block in fs ->
		 * location of uncompressed block in memory */
		save_xattr_block(start, i * SQUASHFS_METADATA_SIZE);

		length = read_block(fd, start, &start,
			((unsigned char *) xattrs) +
			(i * SQUASHFS_METADATA_SIZE), sBlk);
		TRACE("Read xattr block %d, length %d\n", i, length);
		if(length == 0) {
			ERROR("Failed to read xattr block %d\n", i);
			goto failed3;
		}
	}

	/*
	 * for each xattr id read and construct its list of xattr
	 * name:value pairs, and add them to the *current* file system
	 * being built
	 */
	for(i = 0; i < ids; i++) {
	        struct xattr_list *xattr_list = NULL;
		unsigned int count, offset;
		void *xptr;
		int j;

		/* swap if necessary the xattr id entry */
		SQUASHFS_INSWAP_XATTR_ID(&xattr_ids[i]);

		count = xattr_ids[i].count;
		start = SQUASHFS_XATTR_BLK(xattr_ids[i].xattr) +
			id_table.xattr_table_start;
		offset = SQUASHFS_XATTR_OFFSET(xattr_ids[i].xattr);
		xptr = xattrs + get_xattr_block(start) + offset;

		TRACE("get_xattrs: xattr_id %d, count %d, start %lld, offset "
			"%d\n", i, count, start, offset);

		for(j = 0; j < count; j++) {
			struct squashfs_xattr_entry entry;
			struct squashfs_xattr_val val;

			xattr_list = realloc(xattr_list, (j + 1) *
						sizeof(struct xattr_list));
			if(xattr_list == NULL) {
				ERROR("Out of memory in get_xattrs\n");
				goto failed3;
			}
			
			SQUASHFS_SWAP_XATTR_ENTRY(&entry, xptr);
			xptr += sizeof(entry);
			read_xattr_entry(&xattr_list[j], &entry, xptr);
			xptr += entry.size;
			
			TRACE("get_xattrs: xattr %d, type %d, size %d, name "
				"%s\n", j, entry.type, entry.size,
				xattr_list[j].full_name); 

			if(entry.type & SQUASHFS_XATTR_VALUE_OOL) {
				long long xattr;
				void *ool_xptr;

				xptr += sizeof(val);
				SQUASHFS_SWAP_LONG_LONGS(&xattr, xptr, 1);
				xptr += sizeof(xattr);	
				start = SQUASHFS_XATTR_BLK(xattr) +
					id_table.xattr_table_start;
				offset = SQUASHFS_XATTR_OFFSET(xattr);
				ool_xptr = xattrs + get_xattr_block(start) +
					offset;
				SQUASHFS_SWAP_XATTR_VAL(&val, ool_xptr);
				xattr_list[j].value = ool_xptr + sizeof(val);
			} else {
				SQUASHFS_SWAP_XATTR_VAL(&val, xptr);
				xattr_list[j].value = xptr + sizeof(val);
				xptr += sizeof(val) + val.vsize;
			}

			TRACE("get_xattrs: xattr %d, vsize %d\n", j, val.vsize);

			xattr_list[j].vsize = val.vsize;
		}

		id = generate_xattrs(count, xattr_list);

		/*
		 * Sanity check, the new xattr id should be the same as the
		 * xattr id in the original file system
		 */
		if(id != i) {
			ERROR("BUG, different xattr_id in get_xattrs\n");
			goto failed3;
		}
	}

	free(index);
	free(xattr_ids);

	return 1;

failed3:
	free(xattrs);
failed2:
	free(xattr_ids);
failed1:
	free(index);
	return 0;
}
