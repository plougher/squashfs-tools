#ifndef SQUASHFS_FS_SB
#define SQUASHFS_FS_SB
/*
 * Squashfs
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
 * squashfs_fs_sb.h
 */

#include <linux/squashfs_fs.h>

struct squashfs_cache_entry {
	long long	block;
	int		length;
	int		locked;
	long long	next_index;
	char		pending;
	char		error;
	int		waiting;
	wait_queue_head_t	wait_queue;
	char		*data;
};

struct squashfs_cache {
	char *name;
	int entries;
	int block_size;
	int next_blk;
	int waiting;
	int unused;
	int use_vmalloc;
	spinlock_t lock;
	wait_queue_head_t wait_queue;
	struct squashfs_cache_entry entry[0];
};

struct squashfs_sb_info {
	int			devblksize;
	int			devblksize_log2;
	int			swap;
	struct squashfs_cache	*block_cache;
	struct squashfs_cache	*fragment_cache;
	int			next_meta_index;
	__le64			*id_table;
	__le64			*fragment_index;
	unsigned int		*fragment_index_2;
	char			*read_page;
	struct mutex		read_data_mutex;
	struct mutex		read_page_mutex;
	struct mutex		meta_index_mutex;
	struct meta_index	*meta_index;
	z_stream		stream;
	__le64			*inode_lookup_table;
	long long		inode_table_start;
	long long		directory_table_start;
	unsigned int		block_size;
	unsigned short		block_log;
	long long		bytes_used;
	unsigned int		inodes;
	int			(*read_inode)(struct inode *i,  squashfs_inode_t \
				inode);
	long long		(*read_blocklist)(struct inode *inode, int \
				index, int readahead_blks, void *block_list, \
				unsigned short **block_p, unsigned int *bsize);
	__le64			*(*read_fragment_index_table)(struct super_block *s, long long, unsigned int);
};
#endif
