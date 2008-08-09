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
 * super.c
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

static struct file_system_type squashfs_fs_type;
static struct super_operations squashfs_super_ops;

static int supported_squashfs_filesystem(struct squashfs_sb_info *msblk, int silent)
{
	struct squashfs_super_block *sblk = &msblk->sblk;

	msblk->read_inode = squashfs_read_inode;
	msblk->read_blocklist = read_blocklist;
	msblk->read_fragment_index_table = read_fragment_index_table;

	if (sblk->s_major == 1) {
		if (!squashfs_1_0_supported(msblk)) {
			SERROR("Major/Minor mismatch, Squashfs 1.0 filesystems "
				"are unsupported\n");
			SERROR("Please recompile with Squashfs 1.0 support enabled\n");
			return 0;
		}
	} else if (sblk->s_major == 2) {
		if (!squashfs_2_0_supported(msblk)) {
			SERROR("Major/Minor mismatch, Squashfs 2.0 filesystems "
				"are unsupported\n");
			SERROR("Please recompile with Squashfs 2.0 support enabled\n");
			return 0;
		}
	} else if(sblk->s_major != SQUASHFS_MAJOR || sblk->s_minor >
			SQUASHFS_MINOR) {
		SERROR("Major/Minor mismatch, trying to mount newer %d.%d "
				"filesystem\n", sblk->s_major, sblk->s_minor);
		SERROR("Please update your kernel\n");
		return 0;
	}

	return 1;
}


static int squashfs_fill_super(struct super_block *s, void *data, int silent)
{
	struct squashfs_sb_info *msblk;
	struct squashfs_super_block *sblk;
	char b[BDEVNAME_SIZE];
	struct inode *root;

	TRACE("Entered squashfs_fill_superblock\n");

	s->s_fs_info = kzalloc(sizeof(struct squashfs_sb_info), GFP_KERNEL);
	if (s->s_fs_info == NULL) {
		ERROR("Failed to allocate superblock\n");
		goto failure;
	}
	msblk = s->s_fs_info;

	msblk->stream.workspace = vmalloc(zlib_inflate_workspacesize());
	if (msblk->stream.workspace == NULL) {
		ERROR("Failed to allocate zlib workspace\n");
		goto failure;
	}
	sblk = &msblk->sblk;
	
	msblk->devblksize = sb_min_blocksize(s, BLOCK_SIZE);
	msblk->devblksize_log2 = ffz(~msblk->devblksize);

	mutex_init(&msblk->read_data_mutex);
	mutex_init(&msblk->read_page_mutex);
	mutex_init(&msblk->meta_index_mutex);
	
	/* sblk->bytes_used is checked in squashfs_read_data to ensure reads are not
 	 * beyond filesystem end.  As we're using squashfs_read_data to read sblk here,
 	 * first set sblk->bytes_used to a useful value */
	sblk->bytes_used = sizeof(struct squashfs_super_block);
	if (!squashfs_read_data(s, (char *) sblk, SQUASHFS_START,
					sizeof(struct squashfs_super_block) |
					SQUASHFS_COMPRESSED_BIT_BLOCK, NULL, sizeof(struct squashfs_super_block))) {
		SERROR("unable to read superblock\n");
		goto failed_mount;
	}

	/* Check it is a SQUASHFS superblock */
	if ((s->s_magic = sblk->s_magic) != SQUASHFS_MAGIC) {
		if (sblk->s_magic == SQUASHFS_MAGIC_SWAP) {
			struct squashfs_super_block ssblk;

			WARNING("Mounting a different endian SQUASHFS filesystem on %s\n",
				bdevname(s->s_bdev, b));

			//SQUASHFS_SWAP_SUPER_BLOCK(&ssblk, sblk);
			memcpy(sblk, &ssblk, sizeof(struct squashfs_super_block));
			msblk->swap = 1;
		} else  {
			SERROR("Can't find a SQUASHFS superblock on %s\n",
							bdevname(s->s_bdev, b));
			goto failed_mount;
		}
	}

	/* Check the MAJOR & MINOR versions */
	if(!supported_squashfs_filesystem(msblk, silent))
		goto failed_mount;

	/* Check the filesystem does not extend beyond the end of the
	   block device */
	if(sblk->bytes_used < 0 || sblk->bytes_used > i_size_read(s->s_bdev->bd_inode))
		goto failed_mount;

	/* Check the root inode for sanity */
	if (SQUASHFS_INODE_OFFSET(sblk->root_inode) > SQUASHFS_METADATA_SIZE)
		goto failed_mount;

	TRACE("Found valid superblock on %s\n", bdevname(s->s_bdev, b));
	TRACE("Inodes are %scompressed\n", SQUASHFS_UNCOMPRESSED_INODES(sblk->flags)
					? "un" : "");
	TRACE("Data is %scompressed\n", SQUASHFS_UNCOMPRESSED_DATA(sblk->flags)
					? "un" : "");
	TRACE("Check data is %spresent in the filesystem\n",
					SQUASHFS_CHECK_DATA(sblk->flags) ?  "" : "not ");
	TRACE("Filesystem size %lld bytes\n", sblk->bytes_used);
	TRACE("Block size %d\n", sblk->block_size);
	TRACE("Number of inodes %d\n", sblk->inodes);
	if (sblk->s_major > 1)
		TRACE("Number of fragments %d\n", sblk->fragments);
	TRACE("Number of ids %d\n", sblk->no_ids);
	TRACE("sblk->inode_table_start %llx\n", sblk->inode_table_start);
	TRACE("sblk->directory_table_start %llx\n", sblk->directory_table_start);
	if (sblk->s_major > 1)
		TRACE("sblk->fragment_table_start %llx\n", sblk->fragment_table_start);
	TRACE("sblk->id_table_start %llx\n", sblk->id_table_start);

	s->s_maxbytes = MAX_LFS_FILESIZE;
	s->s_flags |= MS_RDONLY;
	s->s_op = &squashfs_super_ops;

	msblk->block_cache = squashfs_cache_init("metadata", SQUASHFS_CACHED_BLKS,
		SQUASHFS_METADATA_SIZE, 0);
	if (msblk->block_cache == NULL)
		goto failed_mount;

	/* Allocate read_page block */
	msblk->read_page = vmalloc(sblk->block_size);
	if (msblk->read_page == NULL) {
		ERROR("Failed to allocate read_page block\n");
		goto failed_mount;
	}

	/* Allocate and read id index table */
	if (read_id_index_table(s) == 0)
		goto failed_mount;

	if (sblk->s_major == 1 && squashfs_1_0_supported(msblk))
		goto allocate_root;

	msblk->fragment_cache = squashfs_cache_init("fragment",
		SQUASHFS_CACHED_FRAGMENTS, sblk->block_size, 1);
	if (msblk->fragment_cache == NULL)
		goto failed_mount;

	/* Allocate and read fragment index table */
	if (msblk->read_fragment_index_table(s) == 0)
		goto failed_mount;

	if(sblk->s_major < 3 || sblk->lookup_table_start == SQUASHFS_INVALID_BLK)
		goto allocate_root;

	/* Allocate and read inode lookup table */
	if (read_inode_lookup_table(s) == 0)
		goto failed_mount;

	s->s_export_op = &squashfs_export_ops;

allocate_root:
	root = new_inode(s);
	if ((msblk->read_inode)(root, sblk->root_inode) == 0)
		goto failed_mount;
	insert_inode_hash(root);

	s->s_root = d_alloc_root(root);
	if (s->s_root == NULL) {
		ERROR("Root inode create failed\n");
		iput(root);
		goto failed_mount;
	}

	TRACE("Leaving squashfs_fill_super\n");
	return 0;

failed_mount:
	kfree(msblk->inode_lookup_table);
	kfree(msblk->fragment_index);
	squashfs_cache_delete(msblk->fragment_cache);
	kfree(msblk->id_table);
	vfree(msblk->read_page);
	squashfs_cache_delete(msblk->block_cache);
	kfree(msblk->fragment_index_2);
	vfree(msblk->stream.workspace);
	kfree(s->s_fs_info);
	s->s_fs_info = NULL;
	return -EINVAL;

failure:
	return -ENOMEM;
}


static int squashfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct squashfs_sb_info *msblk = dentry->d_sb->s_fs_info;
	struct squashfs_super_block *sblk = &msblk->sblk;

	TRACE("Entered squashfs_statfs\n");

	buf->f_type = SQUASHFS_MAGIC;
	buf->f_bsize = sblk->block_size;
	buf->f_blocks = ((sblk->bytes_used - 1) >> sblk->block_log) + 1;
	buf->f_bfree = buf->f_bavail = 0;
	buf->f_files = sblk->inodes;
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
		kfree(sbi->fragment_index_2);
		kfree(sbi->meta_index);
		vfree(sbi->stream.workspace);
		kfree(s->s_fs_info);
		s->s_fs_info = NULL;
	}
}


static int squashfs_get_sb(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *data, struct vfsmount *mnt)
{
	return get_sb_bdev(fs_type, flags, dev_name, data, squashfs_fill_super,
				mnt);
}


static struct kmem_cache * squashfs_inode_cachep;


static void init_once(struct kmem_cache *cachep, void *foo)
{
	struct squashfs_inode_info *ei = foo;

	inode_init_once(&ei->vfs_inode);
}


static int __init init_inodecache(void)
{
	squashfs_inode_cachep = kmem_cache_create("squashfs_inode_cache",
	    sizeof(struct squashfs_inode_info), 0,
		SLAB_HWCACHE_ALIGN|SLAB_RECLAIM_ACCOUNT, init_once);
	if (squashfs_inode_cachep == NULL)
		return -ENOMEM;
	return 0;
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

	printk(KERN_INFO "squashfs: version 4.0-CVS (2008/07/27) "
		"Phillip Lougher\n");

	err = register_filesystem(&squashfs_fs_type);
	if (err)
		destroy_inodecache();

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
	struct squashfs_inode_info *ei;
	ei = kmem_cache_alloc(squashfs_inode_cachep, GFP_KERNEL);
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
