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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * super.c
 */

/*
 * This file implements code to read the superblock, read and initialise
 * in-memory structures at mount time, and all the VFS glue code to register
 * the filesystem.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mutex.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static struct file_system_type squashfs_fs_type;
static struct super_operations squashfs_super_ops;

static int supported_squashfs_filesystem(short major, short minor, int silent)
{
	if (major < SQUASHFS_MAJOR) {
		SERROR("Major/Minor mismatch, older Squashfs %d.%d filesystems "
				"are unsupported\n", major, minor);
		return 0;
	} else if (major > SQUASHFS_MAJOR || minor > SQUASHFS_MINOR) {
		SERROR("Major/Minor mismatch, trying to mount newer %d.%d "
				"filesystem\n", major, minor);
		SERROR("Please update your kernel\n");
		return 0;
	}

	return 1;
}


static int squashfs_fill_super(struct super_block *s, void *data, int silent)
{
	struct squashfs_sb_info *msblk;
	struct squashfs_super_block *sblk = NULL;
	char b[BDEVNAME_SIZE];
	struct inode *root;
	long long root_inode;
	unsigned short flags;
	unsigned int fragments;
	long long lookup_table_start;
	int res;

	TRACE("Entered squashfs_fill_superblock\n");

	s->s_fs_info = kzalloc(sizeof(*msblk), GFP_KERNEL);
	if (s->s_fs_info == NULL) {
		ERROR("Failed to allocate squashfs_sb_info\n");
		goto failure2;
	}
	msblk = s->s_fs_info;

	msblk->stream.workspace = vmalloc(zlib_inflate_workspacesize());
	if (msblk->stream.workspace == NULL) {
		ERROR("Failed to allocate zlib workspace\n");
		goto failure;
	}

	sblk = kzalloc(sizeof(*sblk), GFP_KERNEL);
	if (sblk == NULL) {
		ERROR("Failed to allocate squashfs_super_block\n");
		goto failure;
	}

	msblk->devblksize = sb_min_blocksize(s, BLOCK_SIZE);
	msblk->devblksize_log2 = ffz(~msblk->devblksize);

	mutex_init(&msblk->read_data_mutex);
	mutex_init(&msblk->read_page_mutex);
	mutex_init(&msblk->meta_index_mutex);

	/*
	 * msblk->bytes_used is checked in squashfs_read_data to ensure reads
	 * are not beyond filesystem end.  But as we're using squashfs_read_data
	 * here to read the superblock (including the value of
	 * bytes_used) we need to set it to an initial sensible dummy value
	 */
	msblk->bytes_used = sizeof(*sblk);
	res = squashfs_read_data(s, sblk, SQUASHFS_START, sizeof(*sblk) |
			SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, sizeof(*sblk));

	if (res == 0) {
		SERROR("unable to read squashfs_super_block\n");
		goto failed_mount;
	}

	/* Check it is a SQUASHFS superblock */
	s->s_magic = le32_to_cpu(sblk->s_magic);
	if (s->s_magic != SQUASHFS_MAGIC) {
		SERROR("Can't find a SQUASHFS superblock on %s\n",
						bdevname(s->s_bdev, b));
		goto failed_mount;
	}

	/* Check the MAJOR & MINOR versions */
	if (!supported_squashfs_filesystem(le16_to_cpu(sblk->s_major),
			le16_to_cpu(sblk->s_minor), silent))
		goto failed_mount;

	/* Check the filesystem does not extend beyond the end of the
	   block device */
	msblk->bytes_used = le64_to_cpu(sblk->bytes_used);
	if (msblk->bytes_used < 0 || msblk->bytes_used >
			i_size_read(s->s_bdev->bd_inode))
		goto failed_mount;

	/* Check block size for sanity */
	msblk->block_size = le32_to_cpu(sblk->block_size);
	if (msblk->block_size > SQUASHFS_FILE_SIZE)
		goto failed_mount;

	msblk->block_log = le16_to_cpu(sblk->block_log);
	if (msblk->block_log > SQUASHFS_FILE_LOG)
		goto failed_mount;

	/* Check the root inode for sanity */
	root_inode = le64_to_cpu(sblk->root_inode);
	if (SQUASHFS_INODE_OFFSET(root_inode) > SQUASHFS_METADATA_SIZE)
		goto failed_mount;

	msblk->inode_table_start = le64_to_cpu(sblk->inode_table_start);
	msblk->directory_table_start = le64_to_cpu(sblk->directory_table_start);
	msblk->inodes = le32_to_cpu(sblk->inodes);
	flags = le16_to_cpu(sblk->flags);

	TRACE("Found valid superblock on %s\n", bdevname(s->s_bdev, b));
	TRACE("Inodes are %scompressed\n", SQUASHFS_UNCOMPRESSED_INODES(flags)
				? "un" : "");
	TRACE("Data is %scompressed\n", SQUASHFS_UNCOMPRESSED_DATA(flags)
				? "un" : "");
	TRACE("Filesystem size %lld bytes\n", msblk->bytes_used);
	TRACE("Block size %d\n", msblk->block_size);
	TRACE("Number of inodes %d\n", msblk->inodes);
	TRACE("Number of fragments %d\n", le32_to_cpu(sblk->fragments));
	TRACE("Number of ids %d\n", le16_to_cpu(sblk->no_ids));
	TRACE("sblk->inode_table_start %llx\n", msblk->inode_table_start);
	TRACE("sblk->directory_table_start %llx\n",
				msblk->directory_table_start);
	TRACE("sblk->fragment_table_start %llx\n",
				le64_to_cpu(sblk->fragment_table_start));
	TRACE("sblk->id_table_start %llx\n", le64_to_cpu(sblk->id_table_start));

	s->s_maxbytes = MAX_LFS_FILESIZE;
	s->s_flags |= MS_RDONLY;
	s->s_op = &squashfs_super_ops;

	msblk->block_cache = squashfs_cache_init("metadata",
			SQUASHFS_CACHED_BLKS, SQUASHFS_METADATA_SIZE, 0);
	if (msblk->block_cache == NULL)
		goto failed_mount;

	/* Allocate read_page block */
	msblk->read_page = vmalloc(msblk->block_size);
	if (msblk->read_page == NULL) {
		ERROR("Failed to allocate read_page block\n");
		goto failed_mount;
	}

	/* Allocate and read id index table */
	msblk->id_table = read_id_index_table(s,
		le64_to_cpu(sblk->id_table_start), le16_to_cpu(sblk->no_ids));
	if (msblk->id_table == NULL)
		goto failed_mount;

	fragments = le32_to_cpu(sblk->fragments);
	if (fragments == 0)
		goto allocate_lookup_table;

	msblk->fragment_cache = squashfs_cache_init("fragment",
		SQUASHFS_CACHED_FRAGMENTS, msblk->block_size, 1);
	if (msblk->fragment_cache == NULL)
		goto failed_mount;

	/* Allocate and read fragment index table */
	msblk->fragment_index = read_fragment_index_table(s,
		le64_to_cpu(sblk->fragment_table_start), fragments);
	if (msblk->fragment_index == NULL)
		goto failed_mount;

allocate_lookup_table:
	lookup_table_start = le64_to_cpu(sblk->lookup_table_start);
	if (lookup_table_start == SQUASHFS_INVALID_BLK)
		goto allocate_root;

	/* Allocate and read inode lookup table */
	msblk->inode_lookup_table = read_inode_lookup_table(s,
		lookup_table_start, msblk->inodes);
	if (msblk->inode_lookup_table == NULL)
		goto failed_mount;

	s->s_export_op = &squashfs_export_ops;

allocate_root:
	root = new_inode(s);
	if (squashfs_read_inode(root, root_inode) == 0)
		goto failed_mount;
	insert_inode_hash(root);

	s->s_root = d_alloc_root(root);
	if (s->s_root == NULL) {
		ERROR("Root inode create failed\n");
		iput(root);
		goto failed_mount;
	}

	TRACE("Leaving squashfs_fill_super\n");
	kfree(sblk);
	return 0;

failed_mount:
	squashfs_cache_delete(msblk->block_cache);
	squashfs_cache_delete(msblk->fragment_cache);
	kfree(msblk->inode_lookup_table);
	kfree(msblk->fragment_index);
	kfree(msblk->id_table);
	vfree(msblk->read_page);
	vfree(msblk->stream.workspace);
	kfree(s->s_fs_info);
	s->s_fs_info = NULL;
	kfree(sblk);
	return -EINVAL;

failure:
	vfree(msblk->stream.workspace);
	kfree(s->s_fs_info);
	s->s_fs_info = NULL;
failure2:
	return -ENOMEM;
}


static int squashfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct squashfs_sb_info *msblk = dentry->d_sb->s_fs_info;

	TRACE("Entered squashfs_statfs\n");

	buf->f_type = SQUASHFS_MAGIC;
	buf->f_bsize = msblk->block_size;
	buf->f_blocks = ((msblk->bytes_used - 1) >> msblk->block_log) + 1;
	buf->f_bfree = buf->f_bavail = 0;
	buf->f_files = msblk->inodes;
	buf->f_ffree = 0;
	buf->f_namelen = SQUASHFS_NAME_LEN;

	return 0;
}


static int squashfs_remount(struct super_block *s, int *flags, char *data)
{
	*flags |= MS_RDONLY;
	return 0;
}


static void squashfs_put_super(struct super_block *s)
{
	if (s->s_fs_info) {
		struct squashfs_sb_info *sbi = s->s_fs_info;
		squashfs_cache_delete(sbi->block_cache);
		squashfs_cache_delete(sbi->fragment_cache);
		vfree(sbi->read_page);
		kfree(sbi->id_table);
		kfree(sbi->fragment_index);
		kfree(sbi->meta_index);
		vfree(sbi->stream.workspace);
		kfree(s->s_fs_info);
		s->s_fs_info = NULL;
	}
}


static int squashfs_get_sb(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *data,
				struct vfsmount *mnt)
{
	return get_sb_bdev(fs_type, flags, dev_name, data, squashfs_fill_super,
				mnt);
}


static struct kmem_cache *squashfs_inode_cachep;


static void init_once(void *foo)
{
	struct squashfs_inode_info *ei = foo;

	inode_init_once(&ei->vfs_inode);
}


static int __init init_inodecache(void)
{
	squashfs_inode_cachep = kmem_cache_create("squashfs_inode_cache",
	 	sizeof(struct squashfs_inode_info), 0,
		SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT, init_once);

	return squashfs_inode_cachep ? 0 : -ENOMEM;
}


static void destroy_inodecache(void)
{
	kmem_cache_destroy(squashfs_inode_cachep);
}


static int __init init_squashfs_fs(void)
{
	int err = init_inodecache();

	if (err)
		goto out;

	err = register_filesystem(&squashfs_fs_type);
	if (err) {
		destroy_inodecache();
		goto out;
	}

	printk(KERN_INFO "squashfs: version 4.0-CVS (2008/10/14) "
		"Phillip Lougher\n");

out:
	return err;
}


static void __exit exit_squashfs_fs(void)
{
	unregister_filesystem(&squashfs_fs_type);
	destroy_inodecache();
}


static struct inode *squashfs_alloc_inode(struct super_block *sb)
{
	struct squashfs_inode_info *ei =
		kmem_cache_alloc(squashfs_inode_cachep, GFP_KERNEL);

	return ei ? &ei->vfs_inode : NULL;
}


static void squashfs_destroy_inode(struct inode *inode)
{
	kmem_cache_free(squashfs_inode_cachep, SQUASHFS_I(inode));
}


static struct file_system_type squashfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "squashfs",
	.get_sb = squashfs_get_sb,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV
};

static struct super_operations squashfs_super_ops = {
	.alloc_inode = squashfs_alloc_inode,
	.destroy_inode = squashfs_destroy_inode,
	.statfs = squashfs_statfs,
	.put_super = squashfs_put_super,
	.remount_fs = squashfs_remount
};

module_init(init_squashfs_fs);
module_exit(exit_squashfs_fs);
MODULE_DESCRIPTION("squashfs 4.0-CVS, a compressed read-only filesystem");
MODULE_AUTHOR("Phillip Lougher <phillip@lougher.demon.co.uk>");
MODULE_LICENSE("GPL");
