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

/*
 * This file implements code to make Squashfs filesystems exportable (NFS etc.)
 *
 * The export code uses an inode lookup table to map inode numbers passed in
 * filehandles to an inode location on disk.  This table is stored compressed
 * into metadata blocks.  A second index table is used to locate these.  This
 * second index table for speed of access (and because it is small) is read at
 * mount time and cached in memory.
 *
 * The inode lookup table is used only by the export code, inode disk
 * locations are directly encoded in directories, enabling direct access
 * without an intermediate lookup for all operations except the export ops.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/dcache.h>
#include <linux/exportfs.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static long long squashfs_inode_lookup(struct super_block *s, int ino)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	int blk = SQUASHFS_LOOKUP_BLOCK(ino - 1);
	int offset = SQUASHFS_LOOKUP_BLOCK_OFFSET(ino - 1);
	long long start = le64_to_cpu(msblk->inode_lookup_table[blk]);
	__le64 inode;

	TRACE("Entered squashfs_inode_lookup, inode_number = %d\n", ino);

	if (!squashfs_read_metadata(s, &inode, start, offset,
					sizeof(inode), &start, &offset))
		return SQUASHFS_INVALID_BLK;

	TRACE("squashfs_inode_lookup, inode = 0x%llx\n", le64_to_cpu(inode));
	return le64_to_cpu(inode);
}


static struct dentry *squashfs_export_iget(struct super_block *s,
	unsigned int inode_number)
{
	long long inode;
	struct dentry *dentry = ERR_PTR(-ENOENT);

	TRACE("Entered squashfs_export_iget\n");

	inode = squashfs_inode_lookup(s, inode_number);
	if (inode != SQUASHFS_INVALID_BLK)
		dentry = d_obtain_alias(squashfs_iget(s, inode, inode_number));

	return dentry;
}


static struct dentry *squashfs_fh_to_dentry(struct super_block *s,
		struct fid *fid, int fh_len, int fh_type)
{
	if ((fh_type != FILEID_INO32_GEN && fh_type != FILEID_INO32_GEN_PARENT)
			|| fh_len < 2)
		return NULL;

	return squashfs_export_iget(s, fid->i32.ino);
}


static struct dentry *squashfs_fh_to_parent(struct super_block *s,
		struct fid *fid, int fh_len, int fh_type)
{
	if (fh_type != FILEID_INO32_GEN_PARENT || fh_len < 4)
		return NULL;

	return squashfs_export_iget(s, fid->i32.parent_ino);
}


static struct dentry *squashfs_get_parent(struct dentry *child)
{
	struct inode *i = child->d_inode;

	return squashfs_export_iget(i->i_sb, SQUASHFS_I(i)->parent_inode);
}


__le64 *read_inode_lookup_table(struct super_block *s,
		long long lookup_table_start, unsigned int inodes)
{
	unsigned int length = SQUASHFS_LOOKUP_BLOCK_BYTES(inodes);
	__le64 *inode_lookup_table;

	TRACE("In read_inode_lookup_table, length %d\n", length);

	/* Allocate inode lookup table */
	inode_lookup_table = kmalloc(length, GFP_KERNEL);
	if (inode_lookup_table == NULL) {
		ERROR("Failed to allocate inode lookup table\n");
		return NULL;
	}
 
	if (!squashfs_read_data(s, inode_lookup_table, lookup_table_start,
			length | SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, length)) {
		ERROR("unable to read inode lookup table\n");
		kfree(inode_lookup_table);
		return NULL;
	}

	return inode_lookup_table;
}


const struct export_operations squashfs_export_ops = {
	.fh_to_dentry = squashfs_fh_to_dentry,
	.fh_to_parent = squashfs_fh_to_parent,
	.get_parent = squashfs_get_parent
};
