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
 * dir.c
 */


#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static const unsigned char squashfs_filetype_table[] = {
	DT_UNKNOWN, DT_DIR, DT_REG, DT_LNK, DT_BLK, DT_CHR, DT_FIFO, DT_SOCK
};

static int get_dir_index_using_offset(struct super_block *s,
				long long *next_block, unsigned int *next_offset,
				long long index_start, unsigned int index_offset, int i_count,
				long long f_pos)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;
	int i, index, length = 0;
	struct squashfs_dir_index dir_index;

	TRACE("Entered get_dir_index_using_offset, i_count %d, f_pos %lld\n",
					i_count, f_pos);

	f_pos -= 3;
	if (f_pos == 0)
		goto finish;

	for (i = 0; i < i_count; i++) {
			squashfs_get_cached_block(s, &dir_index, index_start, index_offset,
					sizeof(dir_index), &index_start, &index_offset);

		index = le32_to_cpu(dir_index.index);
		if (index > f_pos)
			break;

		squashfs_get_cached_block(s, NULL, index_start, index_offset,
					le32_to_cpu(dir_index.size) + 1, &index_start,
					&index_offset);

		length = index;
		*next_block = le32_to_cpu(dir_index.start_block) +
				sblk->directory_table_start;
	}

	*next_offset = (length + *next_offset) % SQUASHFS_METADATA_SIZE;

finish:
	return length + 3;
}


static int squashfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	struct inode *i = file->f_dentry->d_inode;
	struct squashfs_sb_info *msblk = i->i_sb->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;
	long long next_block = SQUASHFS_I(i)->start_block +
				sblk->directory_table_start;
	int next_offset = SQUASHFS_I(i)->offset, length = 0, dir_count, size, type;
	unsigned int inode_number;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire;

	TRACE("Entered squashfs_readdir [%llx:%x]\n", next_block, next_offset);

	dire = kmalloc(sizeof(struct squashfs_dir_entry) + SQUASHFS_NAME_LEN + 1,
			GFP_KERNEL);
	if (dire == NULL) {
		ERROR("Failed to allocate squashfs_dir_entry\n");
		goto finish;
	}

	while(file->f_pos < 3) {
		char *name;
		int size, i_ino;

		if(file->f_pos == 0) {
			name = ".";
			size = 1;
			i_ino = i->i_ino;
		} else {
			name = "..";
			size = 2;
			i_ino = SQUASHFS_I(i)->u.s2.parent_inode;
		}
		TRACE("Calling filldir(%p, %s, %d, %lld, %d, %d)\n",
				dirent, name, size, file->f_pos, i_ino,
				squashfs_filetype_table[1]);

		if (filldir(dirent, name, size, file->f_pos, i_ino,
				squashfs_filetype_table[1]) < 0) {
				TRACE("Filldir returned less than 0\n");
			goto finish;
		}
		file->f_pos += size;
	}

	length = get_dir_index_using_offset(i->i_sb, &next_block, &next_offset,
				SQUASHFS_I(i)->u.s2.directory_index_start,
				SQUASHFS_I(i)->u.s2.directory_index_offset,
				SQUASHFS_I(i)->u.s2.directory_index_count, file->f_pos);

	while (length < i_size_read(i)) {
		/* read directory header */
		if (!squashfs_get_cached_block(i->i_sb, &dirh, next_block,
				next_offset, sizeof(dirh), &next_block, &next_offset))
			goto failed_read;

		length += sizeof(dirh);

		dir_count = le32_to_cpu(dirh.count) + 1;
		while (dir_count--) {
			if (!squashfs_get_cached_block(i->i_sb, dire, next_block,
					next_offset, sizeof(*dire), &next_block, &next_offset))
				goto failed_read;

			size = le16_to_cpu(dire->size) + 1;

			if (!squashfs_get_cached_block(i->i_sb, dire->name, next_block,
						next_offset, size, &next_block, &next_offset))
				goto failed_read;

			length += sizeof(*dire) + size;

			if (file->f_pos >= length)
				continue;

			dire->name[size] = '\0';
			inode_number = le32_to_cpu(dirh.inode_number) +
					((short) le16_to_cpu(dire->inode_number));
			type = le16_to_cpu(dire->type);

			TRACE("Calling filldir(%p, %s, %d, %lld, %x:%x, %d, %d)\n",
					dirent, dire->name, size, file->f_pos,
					le32_to_cpu(dirh.start_block), le16_to_cpu(dire->offset),
					inode_number, squashfs_filetype_table[type]);

			if (filldir(dirent, dire->name, size, file->f_pos, inode_number,
					squashfs_filetype_table[type]) < 0) {
				TRACE("Filldir returned less than 0\n");
				goto finish;
			}
			file->f_pos = length;
		}
	}

finish:
	kfree(dire);
	return 0;

failed_read:
	ERROR("Unable to read directory block [%llx:%x]\n", next_block,
		next_offset);
	kfree(dire);
	return 0;
}


const struct file_operations squashfs_dir_ops = {
	.read = generic_read_dir,
	.readdir = squashfs_readdir
};
