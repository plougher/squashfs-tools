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
 * namei.c
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static int get_dir_index_using_name(struct super_block *s,
			long long *next_block, unsigned int *next_offset,
			long long index_start, unsigned int index_offset,
			int i_count, const char *name, int len)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	int i, size, length = 0;
	struct squashfs_dir_index *index;
	char *str;

	TRACE("Entered get_dir_index_using_name, i_count %d\n", i_count);

	str = kmalloc(sizeof(struct squashfs_dir_index) +
		(SQUASHFS_NAME_LEN + 1) * 2, GFP_KERNEL);
	if (str == NULL) {
		ERROR("Failed to allocate squashfs_dir_index\n");
		goto failure;
	}

	index = (struct squashfs_dir_index *) (str + SQUASHFS_NAME_LEN + 1);
	strncpy(str, name, len);
	str[len] = '\0';

	for (i = 0; i < i_count; i++) {
		squashfs_get_cached_block(s, index, index_start, index_offset,
					sizeof(struct squashfs_dir_index),
					&index_start, &index_offset);

		size = le32_to_cpu(index->size) + 1;

		squashfs_get_cached_block(s, index->name, index_start,
					index_offset, size, &index_start,
					&index_offset);

		index->name[size] = '\0';

		if (strcmp(index->name, str) > 0)
			break;

		length = le32_to_cpu(index->index);
		*next_block = le32_to_cpu(index->start_block) +
					msblk->directory_table_start;
	}

	*next_offset = (length + *next_offset) % SQUASHFS_METADATA_SIZE;
	kfree(str);

failure:
	return length + 3;
}


static struct dentry *squashfs_lookup(struct inode *i, struct dentry *dentry,
				struct nameidata *nd)
{
	const unsigned char *name = dentry->d_name.name;
	int len = dentry->d_name.len;
	struct inode *inode = NULL;
	struct squashfs_sb_info *msblk = i->i_sb->s_fs_info;
	long long next_block = SQUASHFS_I(i)->start_block +
				msblk->directory_table_start;
	int next_offset = SQUASHFS_I(i)->offset, length = 0, dir_count, size;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire;
	unsigned int start_block, offset, ino_number;
	long long ino;

	TRACE("Entered squashfs_lookup [%llx:%x]\n", next_block, next_offset);

	dire = kmalloc(sizeof(struct squashfs_dir_entry) +
		SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		goto exit_lookup;
	}

	if (len > SQUASHFS_NAME_LEN)
		goto exit_lookup;

	length = get_dir_index_using_name(i->i_sb, &next_block, &next_offset,
				SQUASHFS_I(i)->u.s2.directory_index_start,
				SQUASHFS_I(i)->u.s2.directory_index_offset,
				SQUASHFS_I(i)->u.s2.directory_index_count, name,
				len);

	while (length < i_size_read(i)) {
		/* read directory header */
		if (!squashfs_get_cached_block(i->i_sb, &dirh, next_block,
				next_offset, sizeof(dirh), &next_block,
				&next_offset))
			goto failed_read;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;
		while (dir_count--) {
			if (!squashfs_get_cached_block(i->i_sb, dire,
					next_block, next_offset, sizeof(*dire),
					&next_block, &next_offset))
				goto failed_read;

			size = le16_to_cpu(dire->size) + 1;

			if (!squashfs_get_cached_block(i->i_sb, dire->name,
					next_block, next_offset, size,
					&next_block, &next_offset))
				goto failed_read;

			length += sizeof(*dire) + size;

			if (name[0] < dire->name[0])
				goto exit_lookup;

			if (len == size && !strncmp(name, dire->name, len)) {
				start_block = le32_to_cpu(dirh.start_block);
				offset = le32_to_cpu(dire->offset);
				ino_number = le32_to_cpu(dirh.inode_number) +
					(short) le16_to_cpu(dire->inode_number);
				ino = SQUASHFS_MKINODE(start_block, offset);

				TRACE("calling squashfs_iget for directory "
					"entry %s, inode  %x:%x, %d\n", name,
					start_block, offset, ino_number);

				inode = squashfs_iget(i->i_sb, ino, ino_number);

				goto exit_lookup;
			}
		}
	}

exit_lookup:
	kfree(dire);
	if (inode)
		return d_splice_alias(inode, dentry);
	d_add(dentry, inode);
	return ERR_PTR(0);

failed_read:
	ERROR("Unable to read directory block [%llx:%x]\n", next_block,
		next_offset);
	goto exit_lookup;
}


const struct inode_operations squashfs_dir_inode_ops = {
	.lookup = squashfs_lookup
};
