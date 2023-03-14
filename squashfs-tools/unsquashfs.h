#ifndef UNSQUASHFS_H
#define UNSQUASHFS_H
/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2013, 2014, 2019, 2021, 2022, 2023
 * Phillip Lougher <phillip@squashfs.org.uk>
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
 * unsquashfs.h
 */

#define TRUE 1
#define FALSE 0
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <utime.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <regex.h>
#include <signal.h>
#include <pthread.h>
#include <math.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "endian_compat.h"
#include "squashfs_fs.h"
#include "unsquashfs_error.h"

#define TABLE_HASH(start)	(start & 0xffff)

/*
 * Unified superblock containing fields for all superblocks
 */
struct super_block {
	struct squashfs_super_block s;
	/* fields only used by squashfs 3 and earlier layouts */
	unsigned int		no_uids;
	unsigned int		no_guids;
	long long		uid_start;
	long long		guid_start;
	/* fields only used by squashfs 4 */
	unsigned int		xattr_ids;
};


struct hash_table_entry {
	long long	start;
	int		length;
	void 		*buffer;
	long long 	next_index;
	struct hash_table_entry *next;
};

struct inode {
	int		blocks;
	long long	block_start;
	unsigned int	block_offset;
	long long	data;
	unsigned int	fragment;
	int		frag_bytes;
	gid_t		gid;
	unsigned int	inode_number;
	int		mode;
	int		offset;
	long long	start;
	char		*symlink;
	time_t		time;
	int		type;
	uid_t		uid;
	char		sparse;
	unsigned int	xattr;
};

typedef struct squashfs_operations {
	struct dir *(*opendir)(unsigned int block_start,
		unsigned int offset, struct inode **i);
	void (*read_fragment)(unsigned int fragment, long long *start_block,
		int *size);
	void (*read_block_list)(unsigned int *block_list, long long start,
		unsigned int offset, int blocks);
	struct inode *(*read_inode)(unsigned int start_block,
		unsigned int offset);
	int (*read_filesystem_tables)();
	void (*stat)(char *);
} squashfs_operations;

struct test {
	int	mask;
	int	value;
	int	position;
	char	mode;
};


/* Cache status struct.  Caches are used to keep
  track of memory buffers passed between different threads */
struct cache {
	int			max_buffers;
	int			count;
	int			used;
	int			buffer_size;
	int			wait_free;
	int			wait_pending;
	pthread_mutex_t		mutex;
	pthread_cond_t		wait_for_free;
	pthread_cond_t		wait_for_pending;
	struct cache_entry	*free_list;
	struct cache_entry	*hash_table[65536];
};

/* struct describing a cache entry passed between threads */
struct cache_entry {
	struct cache		*cache;
	long long		block;
	int			size;
	int			used;
	int			error;
	int			pending;
	struct cache_entry	*hash_next;
	struct cache_entry	*hash_prev;
	struct cache_entry	*free_next;
	struct cache_entry	*free_prev;
	char			*data;
};

/* struct describing queues used to pass data between threads */
struct queue {
	int		size;
	int		readp;
	int		writep;
	pthread_mutex_t	mutex;
	pthread_cond_t	empty;
	pthread_cond_t	full;
	void		**data;
};

/* default size of fragment buffer in Mbytes */
#define FRAGMENT_BUFFER_DEFAULT 256
/* default size of data buffer in Mbytes */
#define DATA_BUFFER_DEFAULT 256

#define DIR_ENT_SIZE	16

struct dir_ent	{
	char		*name;
	unsigned int	start_block;
	unsigned int	offset;
	unsigned int	type;
	struct dir_ent	*next;
};

struct dir {
	int		dir_count;
	unsigned int	mode;
	uid_t		uid;
	gid_t		guid;
	unsigned int	mtime;
	unsigned int	xattr;
	struct dir_ent	*dirs;
	struct dir_ent	*cur_entry;
};

struct file_entry {
	int		offset;
	int		size;
	struct cache_entry *buffer;
};


struct squashfs_file {
	int		fd;
	int		blocks;
	long long	file_size;
	int		mode;
	uid_t		uid;
	gid_t		gid;
	time_t		time;
	char		*pathname;
	char		sparse;
	unsigned int	xattr;
};

struct path_entry {
	char		*name;
	int		type;
	regex_t		*preg;
	struct pathname	*paths;
};

struct pathname {
	int			names;
	struct path_entry	*name;
};

struct pathnames {
	int		count;
	struct pathname	*path[0];
};

#define PATHS_ALLOC_SIZE 10
#define PATH_TYPE_LINK 1
#define PATH_TYPE_EXTRACT 2
#define PATH_TYPE_EXCLUDE 4

struct directory_level {
	unsigned int	start_block;
	unsigned int	offset;
	char		*name;
};

struct symlink {
	char		*pathname;
	struct symlink	*next;
};

struct directory_stack {
	int			size;
	unsigned int		type;
	unsigned int		start_block;
	unsigned int		offset;
	char			*name;
	struct directory_level 	*stack;
	struct symlink		*symlink;
};

#define MAX_FOLLOW_SYMLINKS 256

/* These macros implement a bit-table to track whether directories have been
 * already visited.  This is to trap corrupted filesystems which have multiple
 * links to the same directory, which is invalid, and which may also create
 * a directory loop, where Unsquashfs will endlessly recurse until either
 * the pathname is too large (extracting), or the stack overflows.
 *
 * Each index entry is 8 Kbytes, and tracks 65536 inode numbers.  The index is
 * allocated on demand because Unsquashfs may not walk the complete filesystem.
 */
#define INUMBER_INDEXES(INODES)		((((INODES) - 1) >> 16) + 1)
#define INUMBER_INDEX(NUMBER)		((NUMBER) >> 16)
#define INUMBER_OFFSET(NUMBER)		(((NUMBER) & 0xffff) >> 5)
#define INUMBER_BIT(NUMBER)		(1 << ((NUMBER) & 0x1f))
#define INUMBER_BYTES			8192

/* These macros implement a lookup table to track creation of (non-directory)
 * inodes, and to discover if a hard-link to a previously created file should
 * be made.
 *
 * Each index entry is 32 Kbytes, and tracks 4096 inode numbers.  The index is
 * allocated on demand because Unsquashfs may not walk the complete filesystem.
 */
#define LOOKUP_INDEXES(INODES)		((((INODES) - 1) >> 12) + 1)
#define LOOKUP_INDEX(NUMBER)		((NUMBER) >> 12)
#define LOOKUP_OFFSET(NUMBER)		((NUMBER) & 0xfff)
#define LOOKUP_BYTES			32768
#define LOOKUP_OFFSETS			4096

/* Maximum transfer size for Linux read() call on both 32-bit and 64-bit systems.
 * See READ(2) */
#define MAXIMUM_READ_SIZE 0x7ffff000

/* globals */
extern struct super_block sBlk;
extern int swap;
extern struct hash_table_entry *directory_table_hash[65536];
extern pthread_mutex_t screen_mutex;
extern int progress_enabled;
extern int inode_number;
extern int lookup_type[];
extern int fd;
extern int no_xattrs;
extern struct queue *to_reader, *to_inflate, *to_writer;
extern struct cache *fragment_cache, *data_cache;
extern struct compressor *comp;
extern int use_localtime;
extern unsigned int timeval;
extern int time_opt;

/* unsquashfs.c */
extern int read_inode_data(void *, long long *, unsigned int *, int);
extern int read_directory_data(void *, long long *, unsigned int *, int);
extern int read_fs_bytes(int fd, long long, long long, void *);
extern int read_block(int, long long, long long *, int, void *);
extern void enable_progress_bar();
extern void disable_progress_bar();
extern void dump_queue(struct queue *);
extern void dump_cache(struct cache *);
extern int write_bytes(int, char *, int);

/* unsquash-1.c */
int read_super_1(squashfs_operations **, void *);

/* unsquash-2.c */
int read_super_2(squashfs_operations **, void *);

/* unsquash-3.c */
int read_super_3(char *, squashfs_operations **, void *);

/* unsquash-4.c */
int read_super_4(squashfs_operations **);

/* unsquash-123.c */
extern int read_ids(int, long long, long long, unsigned int **);

/* unsquash-34.c */
extern long long *alloc_index_table(int);
extern int inumber_lookup(unsigned int);
extern void free_inumber_table();
extern char *lookup(unsigned int);
extern void insert_lookup(unsigned int, char *);
extern void free_lookup_table(int);

/* unsquash-1234.c */
extern int check_name(char *, int);
extern void squashfs_closedir(struct dir *);
extern int check_directory(struct dir *);

/* unsquash-12.c */
extern void sort_directory(struct dir_ent **, int);

/* date.c */
extern int exec_date(char *, unsigned int *);
#endif
