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
 * inode.c
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static int squashfs_new_inode(struct super_block *s, struct inode *i,
				struct squashfs_base_inode_header *inodeb)
{
	if (get_id(s, le16_to_cpu(inodeb->uid), &i->i_uid) == 0)
		goto out;
	if (get_id(s, le16_to_cpu(inodeb->guid), &i->i_gid) == 0)
		goto out;

	i->i_ino = le32_to_cpu(inodeb->inode_number);
	i->i_mtime.tv_sec = le32_to_cpu(inodeb->mtime);
	i->i_atime.tv_sec = i->i_mtime.tv_sec;
	i->i_ctime.tv_sec = i->i_mtime.tv_sec;
	i->i_mode = le16_to_cpu(inodeb->mode);
	i->i_size = 0;

	return 1;

out:
	return 0;
}


struct inode *squashfs_iget(struct super_block *s,
				squashfs_inode_t inode,
				unsigned int inode_number)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct inode *i = iget_locked(s, inode_number);

	TRACE("Entered squashfs_iget\n");

	if (i && (i->i_state & I_NEW)) {
		(msblk->read_inode)(i, inode);
		unlock_new_inode(i);
	}

	return i;
}


int squashfs_read_inode(struct inode *i, squashfs_inode_t inode)
{
	struct super_block *s = i->i_sb;
	struct squashfs_sb_info *msblk = s->s_fs_info;
	long long block = SQUASHFS_INODE_BLK(inode) + msblk->inode_table_start;
	unsigned int offset = SQUASHFS_INODE_OFFSET(inode);
	long long next_block;
	unsigned int next_offset;
	int type;
	union squashfs_inode_header id;
	struct squashfs_base_inode_header *inodeb = &id.base;

	TRACE("Entered squashfs_read_inode\n");

	if (!squashfs_get_cached_block(s, inodeb, block, offset,
				sizeof(*inodeb), &next_block, &next_offset))
		goto failed_read;

	if (squashfs_new_inode(s, i, inodeb) == 0)
			goto failed_read;

	type = le16_to_cpu(inodeb->inode_type);
	switch (type) {
	case SQUASHFS_FILE_TYPE: {
		unsigned int frag_offset, frag_size, frag;
		long long frag_blk;
		struct squashfs_reg_inode_header *inodep = &id.reg;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		frag = le32_to_cpu(inodep->fragment);
		if (frag != SQUASHFS_INVALID_FRAG) {
			frag_offset = le32_to_cpu(inodep->offset);
			frag_size = get_fragment_location(s, frag, &frag_blk);
			if (frag_size == 0)
				goto failed_read;
		} else {
			frag_blk = SQUASHFS_INVALID_BLK;
			frag_size = 0;
			frag_offset = 0;
		}

		i->i_nlink = 1;
		i->i_size = le32_to_cpu(inodep->file_size);
		i->i_fop = &generic_ro_fops;
		i->i_mode |= S_IFREG;
		i->i_blocks = ((i->i_size - 1) >> 9) + 1;
		SQUASHFS_I(i)->u.s1.fragment_block = frag_blk;
		SQUASHFS_I(i)->u.s1.fragment_size = frag_size;
		SQUASHFS_I(i)->u.s1.fragment_offset = frag_offset;
		SQUASHFS_I(i)->start_block = le32_to_cpu(inodep->start_block);
		SQUASHFS_I(i)->u.s1.block_list_start = next_block;
		SQUASHFS_I(i)->offset = next_offset;
		i->i_data.a_ops = &squashfs_aops;

		TRACE("File inode %x:%x, start_block %llx, block_list_start "
				"%llx, offset %x\n", SQUASHFS_INODE_BLK(inode),
				offset, SQUASHFS_I(i)->start_block, next_block,
				next_offset);
		break;
	}
	case SQUASHFS_LREG_TYPE: {
		unsigned int frag_offset, frag_size, frag;
		long long frag_blk;
		struct squashfs_lreg_inode_header *inodep = &id.lreg;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		frag = le32_to_cpu(inodep->fragment);
		if (frag != SQUASHFS_INVALID_FRAG) {
			frag_offset = le32_to_cpu(inodep->offset);
			frag_size = get_fragment_location(s, frag, &frag_blk);
			if (frag_size == 0)
				goto failed_read;
		} else {
			frag_blk = SQUASHFS_INVALID_BLK;
			frag_size = 0;
			frag_offset = 0;
		}

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_size = le64_to_cpu(inodep->file_size);
		i->i_fop = &generic_ro_fops;
		i->i_mode |= S_IFREG;
		i->i_blocks = ((i->i_size - le64_to_cpu(inodep->sparse) - 1)
				>> 9) + 1;

		SQUASHFS_I(i)->u.s1.fragment__block = frag_blk;
		SQUASHFS_I(i)->u.s1.fragment_size = frag_size;
		SQUASHFS_I(i)->u.s1.fragment_offset = frag_offset;
		SQUASHFS_I(i)->start_block = le64_to_cpu(inodep->start_block);
		SQUASHFS_I(i)->u.s1.block_list_start = next_block;
		SQUASHFS_I(i)->offset = next_offset;
		i->i_data.a_ops = &squashfs_aops;

		TRACE("File inode %x:%x, start_block %llx, block_list_start "
				"%llx, offset %x\n", SQUASHFS_INODE_BLK(inode),
				offset, SQUASHFS_I(i)->start_block, next_block,
				next_offset);
		break;
	}
	case SQUASHFS_DIR_TYPE: {
		struct squashfs_dir_inode_header *inodep = &id.dir;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_size = le16_to_cpu(inodep->file_size);
		i->i_op = &squashfs_dir_inode_ops;
		i->i_fop = &squashfs_dir_ops;
		i->i_mode |= S_IFDIR;
		SQUASHFS_I(i)->start_block = le32_to_cpu(inodep->start_block);
		SQUASHFS_I(i)->offset = le16_to_cpu(inodep->offset);
		SQUASHFS_I(i)->u.s2.dir_index_count = 0;
		SQUASHFS_I(i)->u.s2.parent_inode =
				le32_to_cpu(inodep->parent_inode);

		TRACE("Directory inode %x:%x, start_block %llx, offset %x\n",
				SQUASHFS_INODE_BLK(inode), offset,
				SQUASHFS_I(i)->start_block,
				le16_to_cpu(inodep->offset));
		break;
	}
	case SQUASHFS_LDIR_TYPE: {
		struct squashfs_ldir_inode_header *inodep = &id.ldir;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_size = le32_to_cpu(inodep->file_size);
		i->i_op = &squashfs_dir_inode_ops;
		i->i_fop = &squashfs_dir_ops;
		i->i_mode |= S_IFDIR;
		SQUASHFS_I(i)->start_block = le32_to_cpu(inodep->start_block);
		SQUASHFS_I(i)->offset = le16_to_cpu(inodep->offset);
		SQUASHFS_I(i)->u.s2.dir_index_start = next_block;
		SQUASHFS_I(i)->u.s2.dir_index_offset = next_offset;
		SQUASHFS_I(i)->u.s2.dir_index_count =
					le16_to_cpu(inodep->i_count);
		SQUASHFS_I(i)->u.s2.parent_inode =
					le32_to_cpu(inodep->parent_inode);

		TRACE("Long directory inode %x:%x, start_block %llx, offset "
				"%x\n", SQUASHFS_INODE_BLK(inode), offset,
				SQUASHFS_I(i)->start_block,
				le16_to_cpu(inodep->offset));
		break;
	}
	case SQUASHFS_SYMLINK_TYPE: {
		struct squashfs_symlink_inode_header *inodep = &id.symlink;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_size = le32_to_cpu(inodep->symlink_size);
		i->i_op = &page_symlink_inode_operations;
		i->i_data.a_ops = &squashfs_symlink_aops;
		i->i_mode |= S_IFLNK;
		SQUASHFS_I(i)->start_block = next_block;
		SQUASHFS_I(i)->offset = next_offset;

		TRACE("Symbolic link inode %x:%x, start_block %llx, offset "
				"%x\n", SQUASHFS_INODE_BLK(inode), offset,
				next_block, next_offset);
		break;
	}
	case SQUASHFS_BLKDEV_TYPE:
	case SQUASHFS_CHRDEV_TYPE: {
		struct squashfs_dev_inode_header *inodep = &id.dev;
		unsigned int rdev;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_mode |= (type == SQUASHFS_CHRDEV_TYPE) ? S_IFCHR : S_IFBLK;
		rdev = le32_to_cpu(inodep->rdev);
		init_special_inode(i, le16_to_cpu(i->i_mode),
					old_decode_dev(rdev));

		TRACE("Device inode %x:%x, rdev %x\n",
				SQUASHFS_INODE_BLK(inode), offset, rdev);
		break;
	}
	case SQUASHFS_FIFO_TYPE:
	case SQUASHFS_SOCKET_TYPE: {
		struct squashfs_ipc_inode_header *inodep = &id.ipc;

		if (!squashfs_get_cached_block(s, inodep, block, offset,
				sizeof(*inodep), &next_block, &next_offset))
			goto failed_read;

		i->i_nlink = le32_to_cpu(inodep->nlink);
		i->i_mode |= (type == SQUASHFS_FIFO_TYPE) ? S_IFIFO : S_IFSOCK;
		init_special_inode(i, le16_to_cpu(i->i_mode), 0);
		break;
	}
	default:
		ERROR("Unknown inode type %d in squashfs_iget!\n", type);
		goto failed_read1;
	}

	return 1;

failed_read:
	ERROR("Unable to read inode [%llx:%x]\n", block, offset);

failed_read1:
	make_bad_inode(i);
	return 0;
}
