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
 * id.c
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

int get_id(struct super_block *s, unsigned int index, unsigned int *id)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	long long start_block =
			le64_to_cpu(msblk->id_table[SQUASHFS_ID_BLOCK(index)]);
	int offset = SQUASHFS_ID_BLOCK_OFFSET(index);
	__le32 disk_id;

	if (!squashfs_get_cached_block(s, &disk_id, start_block, offset,
				 sizeof(__le32), &start_block, &offset))
		return 0;

	*id = le32_to_cpu(disk_id);
	return 1;
}


int read_id_index_table(struct super_block *s)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;
	unsigned int length = SQUASHFS_ID_BLOCK_BYTES(sblk->no_ids);

	TRACE("In read_id_index_table, length %d\n", length);

	/* Allocate id index table */
	msblk->id_table = kmalloc(length, GFP_KERNEL);
	if (msblk->id_table == NULL) {
		ERROR("Failed to allocate id index table\n");
		return 0;
	}
   
	if (!squashfs_read_data(s, (char *) msblk->id_table,
			sblk->id_table_start, length |
			SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, length)) {
		ERROR("unable to read id index table\n");
		return 0;
	}

	return 1;
}
