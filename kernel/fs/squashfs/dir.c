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
	int i, length = 0;
	struct squashfs_dir_index index;

	TRACE("Entered get_dir_index_using_offset, i_count %d, f_pos %d\n",
					i_count, (unsigned int) f_pos);

	f_pos -= 3;
	if (f_pos == 0)
		goto finish;

	for (i = 0; i < i_count; i++) {
		if (msblk->swap) {
			struct squashfs_dir_index sindex;
			squashfs_get_cached_block(s, &sindex, index_start, index_offset,
					sizeof(sindex), &index_start, &index_offset);
			SQUASHFS_SWAP_DIR_INDEX(&index, &sindex);
		} else
			squashfs_get_cached_block(s, &index, index_start, index_offset,
					sizeof(index), &index_start, &index_offset);

		if (index.index > f_pos)
			break;

		squashfs_get_cached_block(s, NULL, index_start, index_offset,
					index.size + 1, &index_start, &index_offset);

		length = index.index;
		*next_block = index.start_block + sblk->directory_table_start;
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
	int next_offset = SQUASHFS_I(i)->offset, length = 0, dir_count;
	struct squashfs_dir_header dirh;
	struct squashfs_dir_entry *dire;

	TRACE("Entered squashfs_readdir [%llx:%x]\n", next_block, next_offset);

	dire = kmalloc(sizeof(struct squashfs_dir_entry) +
		SQUASHFS_NAME_LEN + 1, GFP_KERNEL);
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
		TRACE("Calling filldir(%x, %s, %d, %d, %d, %d)\n",
				(unsigned int) dirent, name, size, (int)
				file->f_pos, i_ino, squashfs_filetype_table[1]);

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
		if (msblk->swap) {
			struct squashfs_dir_header sdirh;
			
			if (!squashfs_get_cached_block(i->i_sb, &sdirh, next_block,
					 next_offset, sizeof(sdirh), &next_block, &next_offset))
				goto failed_read;

			length += sizeof(sdirh);
			SQUASHFS_SWAP_DIR_HEADER(&dirh, &sdirh);
		} else {
			if (!squashfs_get_cached_block(i->i_sb, &dirh, next_block,
					next_offset, sizeof(dirh), &next_block, &next_offset))
				goto failed_read;

			length += sizeof(dirh);
		}

		dir_count = dirh.count + 1;
		while (dir_count--) {
			if (msblk->swap) {
				struct squashfs_dir_entry sdire;
				if (!squashfs_get_cached_block(i->i_sb, &sdire, next_block,
						next_offset, sizeof(sdire), &next_block, &next_offset))
					goto failed_read;
				
				length += sizeof(sdire);
				SQUASHFS_SWAP_DIR_ENTRY(dire, &sdire);
			} else {
				if (!squashfs_get_cached_block(i->i_sb, dire, next_block,
						next_offset, sizeof(*dire), &next_block, &next_offset))
					goto failed_read;

				length += sizeof(*dire);
			}

			if (!squashfs_get_cached_block(i->i_sb, dire->name, next_block,
						next_offset, dire->size + 1, &next_block, &next_offset))
				goto failed_read;

			length += dire->size + 1;

			if (file->f_pos >= length)
				continue;

			dire->name[dire->size + 1] = '\0';

			TRACE("Calling filldir(%x, %s, %d, %d, %x:%x, %d, %d)\n",
					(unsigned int) dirent, dire->name, dire->size + 1,
					(int) file->f_pos, dirh.start_block, dire->offset,
					dirh.inode_number + dire->inode_number,
					squashfs_filetype_table[dire->type]);

			if (filldir(dirent, dire->name, dire->size + 1, file->f_pos,
					dirh.inode_number + dire->inode_number,
					squashfs_filetype_table[dire->type]) < 0) {
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
