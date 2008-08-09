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
 * export.c
 */

#include <linux/squashfs_fs.h>
#include <linux/module.h>
#include <linux/zlib.h>
#include <linux/fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>
#include <linux/buffer_head.h>
#include <linux/vfs.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/smp_lock.h>
#include <linux/exportfs.h>

#include "squashfs.h"
static squashfs_inode_t squashfs_inode_lookup(struct super_block *s, int ino)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	long long start = msblk->inode_lookup_table[SQUASHFS_LOOKUP_BLOCK(ino - 1)];
	int offset = SQUASHFS_LOOKUP_BLOCK_OFFSET(ino - 1);
	squashfs_inode_t inode;

	TRACE("Entered squashfs_inode_lookup, inode_number = %d\n", ino);

	if (msblk->swap) {
		squashfs_inode_t sinode;

		if (!squashfs_get_cached_block(s, &sinode, start, offset,
					sizeof(sinode), &start, &offset))
			goto out;
		SQUASHFS_SWAP_INODE_T((&inode), &sinode);
	} else if (!squashfs_get_cached_block(s, &inode, start, offset,
					sizeof(inode), &start, &offset))
			goto out;

	TRACE("squashfs_inode_lookup, inode = 0x%llx\n", inode);

	return inode;

out:
	return SQUASHFS_INVALID_BLK;
}


static struct dentry *squashfs_export_iget(struct super_block *s,
	unsigned int inode_number)
{
	squashfs_inode_t inode;
	struct inode *i;
	struct dentry *dentry;

	TRACE("Entered squashfs_export_iget\n");

	inode = squashfs_inode_lookup(s, inode_number);
	if(inode == SQUASHFS_INVALID_BLK) {
		dentry = ERR_PTR(-ENOENT);
		goto failure;
	}

	i = squashfs_iget(s, inode, inode_number);
	if(i == NULL) {
		dentry = ERR_PTR(-EACCES);
		goto failure;
	}

	dentry = d_alloc_anon(i);
	if (dentry == NULL) {
		iput(i);
		dentry = ERR_PTR(-ENOMEM);
	}

failure:
	return dentry;
}


static struct dentry *squashfs_fh_to_dentry(struct super_block *s,
		struct fid *fid, int fh_len, int fh_type)
{
	if((fh_type != FILEID_INO32_GEN && fh_type != FILEID_INO32_GEN_PARENT) ||
			fh_len < 2)
		return NULL;

	return squashfs_export_iget(s, fid->i32.ino);
}


static struct dentry *squashfs_fh_to_parent(struct super_block *s,
		struct fid *fid, int fh_len, int fh_type)
{
	if(fh_type != FILEID_INO32_GEN_PARENT || fh_len < 4)
		return NULL;

	return squashfs_export_iget(s, fid->i32.parent_ino);
}


static struct dentry *squashfs_get_parent(struct dentry *child)
{
	struct inode *i = child->d_inode;

	TRACE("Entered squashfs_get_parent\n");

	return squashfs_export_iget(i->i_sb, SQUASHFS_I(i)->u.s2.parent_inode);
}


int read_inode_lookup_table(struct super_block *s)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;
	unsigned int length = SQUASHFS_LOOKUP_BLOCK_BYTES(sblk->inodes);

	TRACE("In read_inode_lookup_table, length %d\n", length);

	/* Allocate inode lookup table */
	msblk->inode_lookup_table = kmalloc(length, GFP_KERNEL);
	if (msblk->inode_lookup_table == NULL) {
		ERROR("Failed to allocate inode lookup table\n");
		return 0;
	}
   
	if (!squashfs_read_data(s, (char *) msblk->inode_lookup_table,
			sblk->lookup_table_start, length |
			SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, length)) {
		ERROR("unable to read inode lookup table\n");
		return 0;
	}

	if (msblk->swap) {
		int i;
		long long block;

		for (i = 0; i < SQUASHFS_LOOKUP_BLOCKS(sblk->inodes); i++) {
			SQUASHFS_SWAP_LOOKUP_BLOCKS((&block),
						&msblk->inode_lookup_table[i], 1);
			msblk->inode_lookup_table[i] = block;
		}
	}

	return 1;
}


const struct export_operations squashfs_export_ops = {
	.fh_to_dentry = squashfs_fh_to_dentry,
	.fh_to_parent = squashfs_fh_to_parent,
	.get_parent = squashfs_get_parent
};
