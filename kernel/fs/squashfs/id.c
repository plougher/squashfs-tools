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

	if (!squashfs_read_metadata(s, &disk_id, start_block, offset,
				 sizeof(__le32), &start_block, &offset))
		return 0;

	*id = le32_to_cpu(disk_id);
	return 1;
}


__le64 *read_id_index_table(struct super_block *s, long long id_table_start,
	unsigned short no_ids)
{
	unsigned int length = SQUASHFS_ID_BLOCK_BYTES(no_ids);
	__le64 *id_table;

	TRACE("In read_id_index_table, length %d\n", length);

	/* Allocate id index table */
	id_table = kmalloc(length, GFP_KERNEL);
	if (id_table == NULL) {
		ERROR("Failed to allocate id index table\n");
		return NULL;
	}

	if (!squashfs_read_data(s, id_table, id_table_start, length |
			SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, length)) {
		ERROR("unable to read id index table\n");
		kfree(id_table);
		return NULL;
	}

	return id_table;
}
