/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
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
 * fragment.c
 */


#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

int get_fragment_location(struct super_block *s, unsigned int fragment,
				long long *fragment_start_block)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	int block = SQUASHFS_FRAGMENT_INDEX(fragment);
	int offset = SQUASHFS_FRAGMENT_INDEX_OFFSET(fragment);
	long long start_block = le64_to_cpu(msblk->fragment_index[block]);
	struct squashfs_fragment_entry fragment_entry;
	int size = 0;

	if (!squashfs_get_cached_block(s, &fragment_entry, start_block, offset,
				 sizeof(fragment_entry), &start_block, &offset))
		goto out;

	*fragment_start_block = le64_to_cpu(fragment_entry.start_block);
	size = le32_to_cpu(fragment_entry.size);

out:
	return size;
}


void release_cached_fragment(struct squashfs_sb_info *msblk,
				struct squashfs_cache_entry *fragment)
{
	squashfs_cache_put(msblk->fragment_cache, fragment);
}


struct squashfs_cache_entry *get_cached_fragment(struct super_block *s,
				long long start_block, int length)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;

	return squashfs_cache_get(s, msblk->fragment_cache, start_block,
		length);
}


__le64 *read_fragment_index_table(struct super_block *s,
	long long fragment_table_start, unsigned int fragments)
{
	unsigned int length = SQUASHFS_FRAGMENT_INDEX_BYTES(fragments);
	__le64 *fragment_index;

	/* Allocate fragment index table */
	fragment_index = kmalloc(length, GFP_KERNEL);
	if (fragment_index == NULL) {
		ERROR("Failed to allocate fragment index table\n");
		return NULL;
	}

	if (!squashfs_read_data(s, (char *) fragment_index,
			fragment_table_start,
			length | SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, length)) {
		ERROR("unable to read fragment index table\n");
		kfree(fragment_index);
		return NULL;
	}

	return fragment_index;
}
