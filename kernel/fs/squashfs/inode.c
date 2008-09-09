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
	if(get_id(s, inodeb->uid, &i->i_uid) == 0)
		goto out;
	if(get_id(s, inodeb->guid, &i->i_gid) == 0)
		goto out;

	i->i_ino = inodeb->inode_number;
	i->i_mtime.tv_sec = inodeb->mtime;
	i->i_atime.tv_sec = inodeb->mtime;
	i->i_ctime.tv_sec = inodeb->mtime;
	i->i_mode = inodeb->mode;
	i->i_size = 0;

	return 1;

out:
	return 0;
}


struct inode *squashfs_iget(struct super_block *s,
				squashfs_inode_t inode, unsigned int inode_number)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct inode *i = iget_locked(s, inode_number);

	TRACE("Entered squashfs_iget\n");

	if(i && (i->i_state & I_NEW)) {
		(msblk->read_inode)(i, inode);
		unlock_new_inode(i);
	}

	return i;
}


int squashfs_read_inode(struct inode *i, squashfs_inode_t inode)
{
	struct super_block *s = i->i_sb;
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;
	long long block = SQUASHFS_INODE_BLK(inode) + sblk->inode_table_start;
	unsigned int offset = SQUASHFS_INODE_OFFSET(inode);
	long long next_block;
	unsigned int next_offset;
	union squashfs_inode_header id, sid;
	struct squashfs_base_inode_header *inodeb = &id.base, *sinodeb = &sid.base;

	TRACE("Entered squashfs_read_inode\n");

	if (msblk->swap) {
		if (!squashfs_get_cached_block(s, sinodeb, block, offset,
					sizeof(*sinodeb), &next_block, &next_offset))
			goto failed_read;
		SQUASHFS_SWAP_BASE_INODE_HEADER(inodeb, sinodeb, sizeof(*sinodeb));
	} else
		if (!squashfs_get_cached_block(s, inodeb, block, offset,
					sizeof(*inodeb), &next_block, &next_offset))
			goto failed_read;

	if(squashfs_new_inode(s, i, inodeb) == 0)
			goto failed_read;

	switch(inodeb->inode_type) {
		case SQUASHFS_FILE_TYPE: {
			unsigned int frag_size;
			long long frag_blk;
			struct squashfs_reg_inode_header *inodep = &id.reg;
			struct squashfs_reg_inode_header *sinodep = &sid.reg;
				
			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_REG_INODE_HEADER(inodep, sinodep);
			} else
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			if (inodep->fragment != SQUASHFS_INVALID_FRAG) {
					frag_size = get_fragment_location(s, inodep->fragment,
								&frag_blk);
					if (frag_size == 0)	
						goto failed_read;
			} else {
				frag_blk = SQUASHFS_INVALID_BLK;
				frag_size = 0;
			}
				
			i->i_nlink = 1;
			i->i_size = inodep->file_size;
			i->i_fop = &generic_ro_fops;
			i->i_mode |= S_IFREG;
			i->i_blocks = ((i->i_size - 1) >> 9) + 1;
			SQUASHFS_I(i)->u.s1.fragment_start_block = frag_blk;
			SQUASHFS_I(i)->u.s1.fragment_size = frag_size;
			SQUASHFS_I(i)->u.s1.fragment_offset = inodep->offset;
			SQUASHFS_I(i)->start_block = inodep->start_block;
			SQUASHFS_I(i)->u.s1.block_list_start = next_block;
			SQUASHFS_I(i)->offset = next_offset;
			i->i_data.a_ops = &squashfs_aops;

			TRACE("File inode %x:%x, start_block %llx, "
					"block_list_start %llx, offset %x\n",
					SQUASHFS_INODE_BLK(inode), offset,
					inodep->start_block, next_block,
					next_offset);
			break;
		}
		case SQUASHFS_LREG_TYPE: {
			unsigned int frag_size;
			long long frag_blk;
			struct squashfs_lreg_inode_header *inodep = &id.lreg;
			struct squashfs_lreg_inode_header *sinodep = &sid.lreg;
				
			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_LREG_INODE_HEADER(inodep, sinodep);
			} else
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			if (inodep->fragment != SQUASHFS_INVALID_FRAG) {
				frag_size = get_fragment_location(s, inodep->fragment,
						&frag_blk);
				if (frag_size == 0)
					goto failed_read;
			} else {
				frag_blk = SQUASHFS_INVALID_BLK;
				frag_size = 0;
			}
				
			i->i_nlink = inodep->nlink;
			i->i_size = inodep->file_size;
			i->i_fop = &generic_ro_fops;
			i->i_mode |= S_IFREG;
			i->i_blocks = ((inodep->file_size - inodep->sparse - 1) >> 9) + 1;
				
			SQUASHFS_I(i)->u.s1.fragment_start_block = frag_blk;
			SQUASHFS_I(i)->u.s1.fragment_size = frag_size;
			SQUASHFS_I(i)->u.s1.fragment_offset = inodep->offset;
			SQUASHFS_I(i)->start_block = inodep->start_block;
			SQUASHFS_I(i)->u.s1.block_list_start = next_block;
			SQUASHFS_I(i)->offset = next_offset;
			i->i_data.a_ops = &squashfs_aops;

			TRACE("File inode %x:%x, start_block %llx, "
					"block_list_start %llx, offset %x\n",
					SQUASHFS_INODE_BLK(inode), offset,
					inodep->start_block, next_block,
					next_offset);
			break;
		}
		case SQUASHFS_DIR_TYPE: {
			struct squashfs_dir_inode_header *inodep = &id.dir;
			struct squashfs_dir_inode_header *sinodep = &sid.dir;

			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_DIR_INODE_HEADER(inodep, sinodep);
			} else
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			i->i_nlink = inodep->nlink;
			i->i_size = inodep->file_size;
			i->i_op = &squashfs_dir_inode_ops;
			i->i_fop = &squashfs_dir_ops;
			i->i_mode |= S_IFDIR;
			SQUASHFS_I(i)->start_block = inodep->start_block;
			SQUASHFS_I(i)->offset = inodep->offset;
			SQUASHFS_I(i)->u.s2.directory_index_count = 0;
			SQUASHFS_I(i)->u.s2.parent_inode = inodep->parent_inode;

			TRACE("Directory inode %x:%x, start_block %x, offset "
					"%x\n", SQUASHFS_INODE_BLK(inode),
					offset, inodep->start_block,
					inodep->offset);
			break;
		}
		case SQUASHFS_LDIR_TYPE: {
			struct squashfs_ldir_inode_header *inodep = &id.ldir;
			struct squashfs_ldir_inode_header *sinodep = &sid.ldir;

			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_LDIR_INODE_HEADER(inodep, sinodep);
			} else
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			i->i_nlink = inodep->nlink;
			i->i_size = inodep->file_size;
			i->i_op = &squashfs_dir_inode_ops;
			i->i_fop = &squashfs_dir_ops;
			i->i_mode |= S_IFDIR;
			SQUASHFS_I(i)->start_block = inodep->start_block;
			SQUASHFS_I(i)->offset = inodep->offset;
			SQUASHFS_I(i)->u.s2.directory_index_start = next_block;
			SQUASHFS_I(i)->u.s2.directory_index_offset = next_offset;
			SQUASHFS_I(i)->u.s2.directory_index_count = inodep->i_count;
			SQUASHFS_I(i)->u.s2.parent_inode = inodep->parent_inode;

			TRACE("Long directory inode %x:%x, start_block %x, offset %x\n",
					SQUASHFS_INODE_BLK(inode), offset,
					inodep->start_block, inodep->offset);
			break;
		}
		case SQUASHFS_SYMLINK_TYPE: {
			struct squashfs_symlink_inode_header *inodep = &id.symlink;
			struct squashfs_symlink_inode_header *sinodep = &sid.symlink;
	
			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_SYMLINK_INODE_HEADER(inodep, sinodep);
			} else
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			i->i_nlink = inodep->nlink;
			i->i_size = inodep->symlink_size;
			i->i_op = &page_symlink_inode_operations;
			i->i_data.a_ops = &squashfs_symlink_aops;
			i->i_mode |= S_IFLNK;
			SQUASHFS_I(i)->start_block = next_block;
			SQUASHFS_I(i)->offset = next_offset;

			TRACE("Symbolic link inode %x:%x, start_block %llx, offset %x\n",
					SQUASHFS_INODE_BLK(inode), offset,
					next_block, next_offset);
			break;
		 }
		 case SQUASHFS_BLKDEV_TYPE:
		 case SQUASHFS_CHRDEV_TYPE: {
			struct squashfs_dev_inode_header *inodep = &id.dev;
			struct squashfs_dev_inode_header *sinodep = &sid.dev;

			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_DEV_INODE_HEADER(inodep, sinodep);
			} else	
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			i->i_nlink = inodep->nlink;
			i->i_mode |= (inodeb->inode_type == SQUASHFS_CHRDEV_TYPE) ?
					S_IFCHR : S_IFBLK;
			init_special_inode(i, i->i_mode, old_decode_dev(inodep->rdev));

			TRACE("Device inode %x:%x, rdev %x\n",
					SQUASHFS_INODE_BLK(inode), offset, inodep->rdev);
			break;
		 }
		 case SQUASHFS_FIFO_TYPE:
		 case SQUASHFS_SOCKET_TYPE: {
			struct squashfs_ipc_inode_header *inodep = &id.ipc;
			struct squashfs_ipc_inode_header *sinodep = &sid.ipc;

			if (msblk->swap) {
				if (!squashfs_get_cached_block(s, sinodep, block, offset,
						sizeof(*sinodep), &next_block, &next_offset))
					goto failed_read;
				SQUASHFS_SWAP_IPC_INODE_HEADER(inodep, sinodep);
			} else	
				if (!squashfs_get_cached_block(s, inodep, block, offset,
						sizeof(*inodep), &next_block, &next_offset))
					goto failed_read;

			i->i_nlink = inodep->nlink;
			i->i_mode |= (inodeb->inode_type == SQUASHFS_FIFO_TYPE)
							? S_IFIFO : S_IFSOCK;
			init_special_inode(i, i->i_mode, 0);
			break;
		 }
		 default:
			ERROR("Unknown inode type %d in squashfs_iget!\n",
					inodeb->inode_type);
			goto failed_read1;
	}
	
	return 1;

failed_read:
	ERROR("Unable to read inode [%llx:%x]\n", block, offset);

failed_read1:
	make_bad_inode(i);
	return 0;
}
