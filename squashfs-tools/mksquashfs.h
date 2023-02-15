#ifndef MKSQUASHFS_H
#define MKSQUASHFS_H
/*
 * Squashfs
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011
 * 2012, 2013, 2014, 2019, 2021, 2022, 2023
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
 * mksquashfs.h
 *
 */

struct dir_info {
	char			*pathname;
	char			*subpath;
	unsigned int		count;
	unsigned int		directory_count;
	unsigned int		depth;
	unsigned int		excluded;
	char			dir_is_ldir;
	struct dir_ent		*dir_ent;
	struct dir_ent		*list;
	DIR			*linuxdir;
};

struct dir_ent {
	char			*name;
	char			*source_name;
	char			*nonstandard_pathname;
	struct inode_info	*inode;
	struct dir_info		*dir;
	struct dir_info		*our_dir;
	struct dir_ent		*next;
};

struct inode_info {
	struct stat		buf;
	struct inode_info	*next;
	struct pseudo_dev	*pseudo;
	struct tar_file		*tar_file;
	struct pseudo_xattr	*xattr;
	squashfs_inode		inode;
	unsigned int		inode_number;
	unsigned int		nlink;
	char			dummy_root_dir;
	char			type;
	char			read;
	char			root_entry;
	char			no_fragments;
	char			always_use_fragments;
	char			noD;
	char			noF;
	char			tarfile;
	char			symlink[0];
};


/* in memory file info */
struct file_info {
	long long		file_size;
	long long		bytes;
	long long		start;
	long long		sparse;
	unsigned int		*block_list;
	struct file_info	*frag_next;
	struct file_info	*block_next;
	struct fragment		*fragment;
	struct dup_info		*dup;
	unsigned int		blocks;
	unsigned short		checksum;
	unsigned short		fragment_checksum;
	char			have_frag_checksum;
	char			have_checksum;
};


struct dup_info {
	struct file_info	*file;
	struct file_info	*frag;
	struct dup_info		*next;
};


/* fragment block data structures */
struct fragment {
	unsigned int		index;
	int			offset;
	int			size;
};

/* in memory uid tables */
#define ID_ENTRIES 256
#define ID_HASH(id) (id & (ID_ENTRIES - 1))
#define ISA_UID 1
#define ISA_GID 2

struct id {
	unsigned int id;
	int	index;
	char	flags;
	struct id *next;
};

/* fragment to file mapping used when appending */
struct append_file {
	struct file_info *file;
	struct append_file *next;
};

/*
 * Amount of physical memory to use by default, and the default queue
 * ratios
 */
#define SQUASHFS_TAKE 4
#define SQUASHFS_READQ_MEM 4
#define SQUASHFS_BWRITEQ_MEM 4
#define SQUASHFS_FWRITEQ_MEM 4

/*
 * Lowest amount of physical memory considered viable for Mksquashfs
 * to run in Mbytes
 */
#define SQUASHFS_LOWMEM 64

/* offset of data in compressed metadata blocks (allowing room for
 * compressed size */
#define BLOCK_OFFSET 2

#ifdef REPRODUCIBLE_DEFAULT
#define NOREP_STR
#define REP_STR " (default)"
#define REP_DEF 1
#else
#define NOREP_STR " (default)"
#define REP_STR
#define REP_DEF 0
#endif

/* in memory directory data */
#define I_COUNT_SIZE		128
#define DIR_ENTRIES		32
#define INODE_HASH_SIZE		65536
#define INODE_HASH_MASK		(INODE_HASH_SIZE - 1)
#define INODE_HASH(dev, ino)	(ino & INODE_HASH_MASK)

struct cached_dir_index {
	struct squashfs_dir_index	index;
	char				*name;
};

struct directory {
	unsigned int		start_block;
	unsigned int		size;
	unsigned char		*buff;
	unsigned char		*p;
	unsigned int		entry_count;
	unsigned char		*entry_count_p;
	unsigned int		i_count;
	unsigned int		i_size;
	struct cached_dir_index	*index;
	unsigned char		*index_count_p;
	unsigned int		inode_number;
};

/* exclude file handling */
/* list of exclude dirs/files */
struct exclude_info {
	dev_t			st_dev;
	ino_t			st_ino;
};

#define EXCLUDE_SIZE 8192

struct pathname {
	int names;
	struct path_entry *name;
};

struct pathnames {
	int count;
	struct pathname *path[0];
};
#define PATHS_ALLOC_SIZE 10

#define FRAG_SIZE 32768

struct old_root_entry_info {
	char			*name;
	struct inode_info	inode;
};

#define ALLOC_SIZE 128

/* Maximum transfer size for Linux read() call on both 32-bit and 64-bit systems.
 * See READ(2) */
#define MAXIMUM_READ_SIZE 0x7ffff000

extern int sleep_time;
extern struct cache *reader_buffer, *fragment_buffer, *reserve_cache;
extern struct cache *bwriter_buffer, *fwriter_buffer;
extern struct queue *to_reader, *to_deflate, *to_writer, *from_writer,
	*to_frag, *locked_fragment, *to_process_frag;
extern struct append_file **file_mapping;
extern struct seq_queue *to_main, *to_order;
extern pthread_mutex_t fragment_mutex, dup_mutex;
extern struct squashfs_fragment_entry *fragment_table;
extern struct compressor *comp;
extern int block_size;
extern int block_log;
extern int sorted;
extern int noF;
extern int noD;
extern int old_exclude;
extern int no_fragments;
extern int always_use_fragments;
extern struct file_info **dupl_frag;
extern int duplicate_checking;
extern int no_hardlinks;
extern struct dir_info *root_dir;
extern struct pathnames *paths;
extern int tarfile;
extern int root_mode_opt;
extern mode_t root_mode;
extern int root_time_opt;
extern unsigned int root_time;
extern int root_uid_opt;
extern unsigned int root_uid;
extern int root_gid_opt;
extern unsigned int root_gid;
extern struct inode_info *inode_info[INODE_HASH_SIZE];
extern int quiet;
extern int sequence_count;
extern int pseudo_override;
extern int global_uid_opt;
extern unsigned int global_uid;
extern int global_gid_opt;
extern unsigned int global_gid;
extern int sleep_time;

extern int read_fs_bytes(int, long long, long long, void *);
extern void add_file(long long, long long, long long, unsigned int *, int,
	unsigned int, int, int);
extern struct id *create_id(unsigned int);
extern unsigned int get_uid(unsigned int);
extern unsigned int get_guid(unsigned int);
extern long long read_bytes(int, void *, long long);
extern unsigned short get_checksum_mem(char *, int);
extern int reproducible;
extern void *reader(void *arg);
extern squashfs_inode create_inode(struct dir_info *dir_info,
	struct dir_ent *dir_ent, int type, long long byte_size,
	long long start_block, unsigned int offset, unsigned int *block_list,
	struct fragment *fragment, struct directory *dir_in, long long sparse);
extern void free_fragment(struct fragment *fragment);
extern struct file_info *write_file(struct dir_ent *dir_ent, int *dup);
extern int excluded(char *name, struct pathnames *paths, struct pathnames **new);
extern struct dir_ent *lookup_name(struct dir_info *dir, char *name);
extern struct dir_ent *create_dir_entry(char *name, char *source_name,
	char *nonstandard_pathname, struct dir_info *dir);
extern void add_dir_entry(struct dir_ent *dir_ent, struct dir_info *sub_dir,
	struct inode_info *inode_info);
extern void free_dir_entry(struct dir_ent *dir_ent);
extern void free_dir(struct dir_info *dir);
extern struct dir_info *create_dir(char *pathname, char *subpath, unsigned int depth);
extern char *subpathname(struct dir_ent *dir_ent);
extern struct dir_info *scan1_opendir(char *pathname, char *subpath, unsigned int depth);
extern squashfs_inode do_directory_scans(struct dir_ent *dir_ent, int progress);
extern struct inode_info *lookup_inode(struct stat *buf);
extern int exec_date(char *, unsigned int *);
#endif
