/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014, 2017, 2019, 2020, 2021, 2022, 2023, 2024, 2025
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
 * mksquashfs.c
 */

#define FALSE 0
#define TRUE 1
#define MAX_LINE 16384

#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <pthread.h>
#include <regex.h>
#include <sys/wait.h>
#include <limits.h>
#include <ctype.h>

#ifdef __linux__
#include <sys/sysmacros.h>
#endif

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "mksquashfs.h"
#include "sort.h"
#include "pseudo.h"
#include "compressor.h"
#include "xattr.h"
#include "action.h"
#include "mksquashfs_error.h"
#include "progressbar.h"
#include "info.h"
#include "caches-queues-lists.h"
#include "read_fs.h"
#include "restore.h"
#include "process_fragments.h"
#include "fnmatch_compat.h"
#include "tar.h"
#include "merge_sort.h"
#include "nprocessors_compat.h"
#include "memory_compat.h"
#include "memory.h"
#include "mksquashfs_help.h"
#include "print_pager.h"
#include "symbolic_mode.h"
#include "thread.h"
#include "reader.h"
#include "limit.h"
#include "alloc.h"
#include "virt_disk_pos.h"

/* Compression options */
int noF = FALSE;
int noI = FALSE;
int noId = FALSE;
int noD = FALSE;
int noX = FALSE;

/* block size used to build filesystem */
int block_size = SQUASHFS_FILE_SIZE;
int block_log;

/* Fragment options, are fragments in filesystem and are they used for tailends? */
int no_fragments = FALSE;
int always_use_fragments = FALSE;

/* Are duplicates detected in fileystem ? */
int duplicate_checking = TRUE;

/* Are filesystems exportable via NFS? */
int exportable = TRUE;

/* Are sparse files detected and stored? */
int sparse_files = TRUE;

/* Options which override root inode settings */
int root_mode_opt = FALSE;
struct mode_data *root_mode;
int root_uid_opt = FALSE;
unsigned int root_uid;
int root_gid_opt = FALSE;
unsigned int root_gid;

/* Options which override inode settings for all files and directories */
int global_file_mode_opt = FALSE;
struct mode_data *global_file_mode;
int global_dir_mode_opt = FALSE;
struct mode_data *global_dir_mode;
int global_uid_opt = FALSE;
unsigned int global_uid;
int global_gid_opt = FALSE;
unsigned int global_gid;

/* Offset all uid/gid */
unsigned int uid_gid_offset = 0;

/* Do pseudo uids and guids override -all-root, -force-uid and -force-gid? */
int pseudo_override = FALSE;

/* Time value over-ride options */
unsigned int mkfs_time;
int mkfs_time_opt = FALSE;
unsigned int root_time;
int root_time_opt = FALSE;
unsigned int inode_time;
int inode_time_opt = FALSE;
int clamping = TRUE;
unsigned int inode_time_latest = 0;
int mkfs_inode_opt = FALSE;
int root_inode_opt = FALSE;

/* Is max depth option in effect, and max depth to descend into directories */
int max_depth_opt = FALSE;
unsigned int max_depth;

/* how should Mksquashfs treat the source files? */
int tarstyle = FALSE;
int keep_as_directory = FALSE;

/* should Mksquashfs read files from stdin, like cpio? */
int cpiostyle = FALSE;
char filename_terminator = '\n';

/* Should Mksquashfs detect hardlinked files? */
int no_hardlinks = FALSE;

/* Should Mksquashfs cross filesystem boundaries? */
int one_file_system = FALSE;
int one_file_system_x = FALSE;
dev_t *source_dev;
dev_t cur_dev;

/* Is Mksquashfs processing a tarfile? */
int tarfile = FALSE;

/* Is Mksquashfs reading a pseudo file from stdin? */
int pseudo_stdin = FALSE;

/* has a default Pseudo file directory been defined for cases where
 * a directory in the pathname is missing? */
struct pseudo_dev *pseudo_dir = NULL;

/* Is Mksquashfs storing Xattrs, or excluding/including xattrs using regexs? */
int no_xattrs = XATTR_DEF;
unsigned int xattr_bytes = 0, total_xattr_bytes = 0;
regex_t *xattr_exclude_preg = NULL;
regex_t *xattr_include_preg = NULL;

/* Does Mksquashfs print a summary and other information when running? */
int quiet = FALSE;

/* Does Mksquashfs display information as files and directories are archived? */
int display_info = FALSE;
FILE *info_file = NULL;

/* Is Mksquashfs using the older non-wildcard exclude code? */
int old_exclude = TRUE;

/* Is Mksquashfs using regexs in exclude file matching (default wildcards)? */
int use_regex = FALSE;

/* Will Mksquashfs pad the filesystem to a multiple of 4 Kbytes? */
int nopad = FALSE;

/* Should Mksquashfs treat normally ignored errors as fatal? */
int exit_on_error = FALSE;

/* Should Mksquashfs ignore the -mem and -mem-options because the
 * amount of system memory cannot be obtained? */
int mem_options_disabled = FALSE;

/* Is filesystem stored at an offset from the start of the block device/file? */
long long start_offset = 0;

/* File count statistics used to print summary and fill in superblock */
unsigned int file_count = 0, sym_count = 0, dev_count = 0, dir_count = 0,
fifo_count = 0, sock_count = 0, id_count = 0;
long long hardlnk_count = 0;

/* superblock attributes */
struct squashfs_super_block sBlk;

/* count of the uncompressed size of the filesystem */
long long total_bytes = 0;

/* in memory directory table - possibly compressed */
char *directory_table = NULL;
long long directory_bytes = 0, directory_size = 0, total_directory_bytes = 0;

/* cached directory table */
char *directory_data_cache = NULL;
unsigned int directory_cache_bytes = 0, directory_cache_size = 0;

/* in memory inode table - possibly compressed */
char *inode_table = NULL;
long long inode_bytes = 0, inode_size = 0, total_inode_bytes = 0;

/* cached inode table */
char *data_cache = NULL;
unsigned int cache_bytes = 0, cache_size = 0, inode_count = 0;

/* inode lookup table */
squashfs_inode *inode_lookup_table = NULL;
struct inode_info *inode_info[INODE_HASH_SIZE];

/* hash tables used to do fast duplicate searches in duplicate check */
struct file_info **dupl_frag;
struct file_info **dupl_block;
unsigned int dup_files = 0;

int exclude = 0;
struct exclude_info *exclude_paths = NULL;

struct path_entry {
	char *name;
	regex_t *preg;
	struct pathname *paths;
};

struct pathnames *paths = NULL;
struct pathname *path = NULL;
struct pathname *stickypath = NULL;

unsigned int fragments = 0;

struct squashfs_fragment_entry *fragment_table = NULL;

int fragments_locked = FALSE;

/* current inode number for directories and non directories */
unsigned int inode_no = 1;
unsigned int root_inode_number = 0;
unsigned int inode_start_no = 1;

/* list of source dirs/files */
int source = 0;
char **source_path;
int option_offset;

/* flag whether destination file is a block device */
int block_device = FALSE;

/* flag indicating whether files are sorted using sort list(s) */
int sorted = FALSE;

/* save destination file name for deleting on error */
char *destination_file = NULL;

struct id *id_hash_table[ID_ENTRIES];
struct id *id_table[SQUASHFS_IDS], *sid_table[SQUASHFS_IDS];
unsigned int uid_count = 0, guid_count = 0;
unsigned int sid_count = 0, suid_count = 0, sguid_count = 0;

/* caches used to store buffers being worked on, and queues
 * used to send buffers between threads */
struct cache *fragment_buffer, *reserve_cache;
struct cache *fwriter_buffer;
struct queue_cache *bwriter_buffer;
struct queue *to_reader, *to_writer, *from_writer, *to_frag, *from_order;
struct queue_cache *to_deflate;
struct read_queue *to_process_frag;
struct seq_queue *to_main;

/* pthread threads and mutexes */
pthread_t reader_thread1, writer_thread, main_thread;
pthread_t *deflator_thread, *frag_deflator_thread, *frag_thread;
pthread_t *restore_thread = NULL;
pthread_mutex_t	fragment_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	lseek_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	dup_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t	pos_mutex = PTHREAD_MUTEX_INITIALIZER;

/* reproducible image queues and threads */
struct seq_queue *to_order;
pthread_t order_thread;

/* user options that control parallelisation */
int processors = -1;

/* Compressor options (-X) and initialised compressor (-comp XXX) */
int comp_opts = FALSE;
int X_opt_parsed = FALSE;
struct compressor *comp = NULL;
int compressor_opt_parsed = FALSE;
void *stream = NULL;

/* root of the in-core directory structure */
struct dir_info *root_dir;

/* log file */
FILE *log_fd;
int logging=FALSE;

/* file descriptor of the output filesystem */
int fd;

/* Current file position in output filesystem */
off_t fd_pos = 0;

/* Variables used for appending */
int appending = TRUE;

/* restore orignal filesystem state if appending to existing filesystem is
 * cancelled */
char *sdata_cache, *sdirectory_data_cache, *sdirectory_compressed;
long long sbytes, stotal_bytes;
long long sinode_bytes, stotal_inode_bytes;
long long sdirectory_bytes, stotal_directory_bytes;
unsigned int scache_bytes, sdirectory_cache_bytes,
	sdirectory_compressed_bytes, sinode_count = 0,
	sfile_count, ssym_count, sdev_count, sdir_count,
	sfifo_count, ssock_count, sdup_files;
unsigned int sfragments;

/* list of root directory entries read from original filesystem */
int old_root_entries = 0;
struct old_root_entry_info *old_root_entry;

/* fragment to file mapping used when appending */
struct append_file **file_mapping;

/* recovery file for abnormal exit on appending */
char *recovery_file = NULL;
char *recovery_pathname = NULL;
int recover = TRUE;

/* variable to force single threaded reader mode */
int force_single_threaded = FALSE;

/* list of options that have an argument */
char *option_table[] = { "comp", "b", "mkfs-time", "fstime", "inode-time",
	"root-mode", "force-uid", "force-gid", "action", "log-action",
	"true-action", "false-action", "action-file", "log-action-file",
	"true-action-file", "false-action-file", "p", "pf", "sort",
	"root-becomes", "recover", "recovery-path", "throttle", "limit",
	"processors", "mem", "offset", "o", "log", "a", "va", "ta", "fa", "af",
	"vaf", "taf", "faf", "read-queue", "write-queue", "fragment-queue",
	"root-time", "root-uid", "root-gid", "xattrs-exclude", "xattrs-include",
	"xattrs-add", "default-mode", "default-uid", "default-gid",
	"mem-percent", "-pd", "-pseudo-dir", "help-option", "ho", "help-section",
	"hs", "info-file", "force-file-mode", "force-dir-mode",
	"small-readers", "block-readers", "uid-gid-offset", "all-time",
	"overcommit", NULL
};

char *sqfstar_option_table[] = { "comp", "b", "mkfs-time", "fstime",
	"inode-time", "root-mode", "force-uid", "force-gid", "throttle",
	"limit", "processors", "mem", "offset", "o", "root-time", "root-uid",
	"root-gid", "xattrs-exclude", "xattrs-include", "xattrs-add", "p", "pf",
	"default-mode", "default-uid", "default-gid", "mem-percent", "pd",
	"pseudo-dir", "help-option", "ho", "help-section", "hs", "info-file",
	"force-file-mode", "force-dir-mode", "uid-gid-offset", "all-time",
	"overcommit", NULL
};

static char *read_from_disk(long long start, unsigned int avail_bytes, int buff);
static void add_old_root_entry(char *name, squashfs_inode inode,
	unsigned int inode_number, int type);
static struct file_info *duplicate(int *dup, int *block_dup,
	long long file_size, long long bytes, unsigned int *block_list,
	struct file_buffer **buffer_list, long long start,
	struct dir_ent *dir_ent, struct file_buffer *file_buffer, int blocks,
	long long sparse, int bl_hash);
static struct dir_info *dir_scan1(char *, char *, struct pathnames *,
	struct dir_ent *(_readdir)(struct dir_info *), unsigned int);
static void dir_scan2(struct dir_info *dir, struct pseudo *pseudo);
static void dir_scan3(struct dir_info *dir);
static void dir_scan4(struct dir_info *dir, int symlink);
static void dir_scan5(struct dir_info *dir);
static void dir_scan6(struct dir_info *dir);
static void dir_scan7(struct dir_info *dir);
static void dir_scan8(squashfs_inode *inode, struct dir_info *dir_info);
static struct dir_ent *scan1_readdir(struct dir_info *dir);
static struct dir_ent *scan1_single_readdir(struct dir_info *dir);
static struct dir_ent *scan1_encomp_readdir(struct dir_info *dir);
static struct file_info *add_non_dup(long long file_size, long long bytes,
	unsigned int blocks, long long sparse, unsigned int *block_list,
	long long start, struct fragment *fragment, unsigned short checksum,
	unsigned short fragment_checksum, int checksum_flag,
	int checksum_frag_flag, int blocks_dup, int frag_dup, int bl_hash);
long long generic_write_table(long long, void *, int, void *, int);
void restorefs();
struct dir_info *scan1_opendir(char *pathname, char *subpath,
							unsigned int depth);
static void write_filesystem_tables(struct squashfs_super_block *sBlk);
unsigned short get_checksum_mem(char *buff, int bytes);
static void print_summary();
void write_destination(int fd, long long byte, long long bytes, void *buff);
static int old_excluded(char *filename, struct stat *buf);


void prep_exit()
{
	if(restore_thread) {
		if(pthread_self() == *restore_thread) {
			/*
			 * Recursive failure when trying to restore filesystem!
			 * Nothing to do except to exit, otherwise we'll just
			 * appear to hang.  The user should be able to restore
			 * from the recovery file (which is why it was added, in
			 * case of catastrophic failure in Mksquashfs)
			 */
			exit(1);
		} else {
			/* signal the restore thread to restore */
			pthread_kill(*restore_thread, SIGUSR1);
			pthread_exit(NULL);
		}
	} else if(!appending) {
		if(destination_file && !block_device)
			unlink(destination_file);
	} else if(recovery_file)
		unlink(recovery_file);
}


void pre_exit_squashfs()
{
	prep_exit();
}


int add_overflow(int a, int b)
{
	return (INT_MAX - a) < b;
}


int shift_overflow(int a, int shift)
{
	return (INT_MAX >> shift) < a;
}

 
int multiply_overflow(int a, int multiplier)
{
	return (INT_MAX / multiplier) < a;
}


int multiply_overflowll(long long a, int multiplier)
{
	return (LLONG_MAX / multiplier) < a;
}


#define MKINODE(A)	((squashfs_inode)(((squashfs_inode) inode_bytes << 16) \
			+ (((char *)A) - data_cache)))


static long long get_sequence()
{
	static long long sequence = 0;

	return sequence ++;
}


static inline void send_orderer_reset(long long vpos)
{
	struct file_buffer *buffer = MALLOC(sizeof(struct file_buffer));

	buffer->cache = NULL;
	buffer->sequence = get_sequence();
	buffer->buffer_type = RESET_CMD;
	buffer->block = vpos;

	order_queue_put(to_order, buffer);
}


static inline void  sync_writer_thread()
{
	struct file_buffer *buffer = MALLOC(sizeof(struct file_buffer));

	buffer->cache = NULL;
	buffer->sequence = get_sequence();
	buffer->buffer_type = WSYNC_CMD;

	order_queue_put(to_order, buffer);
	if(queue_get(from_writer) != 0)
		BAD_ERROR("Got unexpecteed response in sync_writer_thread\n");
}


static inline void  sync_orderer_thread()
{
	struct file_buffer *buffer = MALLOC(sizeof(struct file_buffer));

	buffer->cache = NULL;
	buffer->sequence = get_sequence();
	buffer->buffer_type = OSYNC_CMD;

	order_queue_put(to_order, buffer);
	if(queue_get(from_order) != 0)
		BAD_ERROR("Got unexpecteed response in sync_orderer_thread\n");
}


static inline void send_orderer_create_map(long long vpos)
{
	struct file_buffer *buffer = MALLOC(sizeof(struct file_buffer));

	buffer->cache = NULL;
	buffer->sequence = get_sequence();
	buffer->buffer_type = MAP_CMD;
	buffer->block = vpos;

	order_queue_put(to_order, buffer);
}



static inline void put_write_buffer_hash(struct file_buffer *buffer)
{
	buffer->block = get_and_inc_vpos(buffer->size);
	buffer->sequence = get_sequence();
	queue_cache_hash(buffer, buffer->block);
	order_queue_put(to_order, buffer);
}


static inline void put_write_buffer(struct file_buffer *buffer)
{
	buffer->block = get_and_inc_vpos(buffer->size);
	buffer->sequence = get_sequence();
	order_queue_put(to_order, buffer);
}


void restorefs()
{
	int i, res;

	ERROR("Exiting - restoring original filesystem!\n\n");

	set_dpos(sbytes);
	memcpy(data_cache, sdata_cache, cache_bytes = scache_bytes);
	memcpy(directory_data_cache, sdirectory_data_cache,
		sdirectory_cache_bytes);
	directory_cache_bytes = sdirectory_cache_bytes;
	inode_bytes = sinode_bytes;
	directory_bytes = sdirectory_bytes;
 	memcpy(directory_table + directory_bytes, sdirectory_compressed,
		sdirectory_compressed_bytes);
 	directory_bytes += sdirectory_compressed_bytes;
	total_bytes = stotal_bytes;
	total_inode_bytes = stotal_inode_bytes;
	total_directory_bytes = stotal_directory_bytes;
	inode_count = sinode_count;
	file_count = sfile_count;
	sym_count = ssym_count;
	dev_count = sdev_count;
	dir_count = sdir_count;
	fifo_count = sfifo_count;
	sock_count = ssock_count;
	dup_files = sdup_files;
	fragments = sfragments;
	id_count = sid_count;
	restore_xattrs();
	write_filesystem_tables(&sBlk);

	if(!block_device) {
		int res = ftruncate(fd, get_dpos());
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}

	if(!nopad && (i = get_dpos() & (4096 - 1))) {
		char temp[4096] = {0};
		write_destination(fd, get_dpos(), 4096 - i, temp);
	}

	res = close(fd);

	if(res == -1)
		BAD_ERROR("Failed to close output filesystem, close returned %s\n",
				strerror(errno));

	if(recovery_file)
		unlink(recovery_file);

	if(!quiet)
		print_summary();

	exit(1);
}


static void sighandler(int arg)
{
	EXIT_MKSQUASHFS();
}


static int mangle2(void *strm, char *d, char *s, int size,
	int block_size, int uncompressed, int data_block)
{
	int error, c_byte = 0;

	if(!uncompressed) {
		c_byte = compressor_compress(comp, strm, d, s, size, block_size,
			 &error);
		if(c_byte == -1)
			BAD_ERROR("mangle2:: %s compress failed with error "
				"code %d\n", comp->name, error);
	}

	if(c_byte == 0 || c_byte >= size) {
		memcpy(d, s, size);
		return size | (data_block ? SQUASHFS_COMPRESSED_BIT_BLOCK :
			SQUASHFS_COMPRESSED_BIT);
	}

	return c_byte;
}


int mangle(char *d, char *s, int size, int block_size,
	int uncompressed, int data_block)
{
	return mangle2(stream, d, s, size, block_size, uncompressed,
		data_block);
}


static void *get_inode(int req_size)
{
	int data_space;
	unsigned short c_byte;

	while(cache_bytes >= SQUASHFS_METADATA_SIZE) {
		if((inode_size - inode_bytes) <
				((SQUASHFS_METADATA_SIZE << 1)) + 2) {
			inode_table = REALLOC(inode_table, inode_size +
				(SQUASHFS_METADATA_SIZE << 1) + 2);
			inode_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}

		c_byte = mangle(inode_table + inode_bytes + BLOCK_OFFSET,
			data_cache, SQUASHFS_METADATA_SIZE,
			SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Inode block @ 0x%x, size %d\n", inode_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, inode_table + inode_bytes, 1);
		inode_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		total_inode_bytes += SQUASHFS_METADATA_SIZE + BLOCK_OFFSET;
		memmove(data_cache, data_cache + SQUASHFS_METADATA_SIZE,
			cache_bytes - SQUASHFS_METADATA_SIZE);
		cache_bytes -= SQUASHFS_METADATA_SIZE;
	}

	data_space = (cache_size - cache_bytes);
	if(data_space < req_size) {
			int realloc_size = cache_size == 0 ?
				((req_size + SQUASHFS_METADATA_SIZE) &
				~(SQUASHFS_METADATA_SIZE - 1)) : req_size -
				data_space;

			data_cache = REALLOC(data_cache, cache_size +
				realloc_size);
			cache_size += realloc_size;
	}

	cache_bytes += req_size;

	return data_cache + cache_bytes - req_size;
}


long long read_bytes(int fd, void *buff, long long bytes)
{
	long long res, count;

	for(count = 0; count < bytes; count += res) {
		int len = (bytes - count) > MAXIMUM_READ_SIZE ?
					MAXIMUM_READ_SIZE : bytes - count;

		res = read(fd, buff + count, len);
		if(res < 1) {
			if(res == 0)
				goto bytes_read;
			else if(errno != EINTR) {
				ERROR("Read failed because %s\n",
						strerror(errno));
				return -1;
			} else
				res = 0;
		}
	}

bytes_read:
	return count;
}


int read_fs_bytes(int fd, long long byte, long long bytes, void *buff)
{
	off_t off = byte + start_offset;
	int res = 1;

	TRACE("read_fs_bytes: reading from position 0x%llx, bytes %lld\n",
		byte, bytes);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &lseek_mutex);
	pthread_mutex_lock(&lseek_mutex);

	if(fd_pos != off) {
		if(lseek(fd, off, SEEK_SET) == -1) {
			ERROR("read_fs_bytes: Lseek on destination failed "
				"because %s, offset=0x%llx\n", strerror(errno),
				(long long) off);
			fd_pos = LLONG_MAX;
			res = FALSE;
			goto unlock;
		}
	}

	if(read_bytes(fd, buff, bytes) < bytes) {
		ERROR("Read on destination failed\n");
		fd_pos = LLONG_MAX;
		res = FALSE;
		goto unlock;
	}

	fd_pos = off + bytes;

unlock:
	pthread_cleanup_pop(1);

	return res;
}


static int write_bytes(int fd, void *buff, long long bytes)
{
	long long res, count;

	for(count = 0; count < bytes; count += res) {
		int len = (bytes - count) > MAXIMUM_READ_SIZE ?
					MAXIMUM_READ_SIZE : bytes - count;

		res = write(fd, buff + count, len);
		if(res == -1) {
			if(errno != EINTR) {
				ERROR("Write failed because %s\n",
						strerror(errno));
				return -1;
			}
			res = 0;
		}
	}

	return 0;
}


void write_destination(int fd, long long byte, long long bytes, void *buff)
{
	off_t off = start_offset + byte;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &lseek_mutex);
	pthread_mutex_lock(&lseek_mutex);

	if(fd_pos != off) {
		if(lseek(fd, off, SEEK_SET) == -1) {
			ERROR("write_destination: Lseek on destination failed "
				"because %s, offset=0x%llx\n", strerror(errno),
				(long long) off);
			BAD_ERROR("Probably out of space on output %s\n",
				block_device ? "block device" : "filesystem");
		}
	}

	if(write_bytes(fd, buff, bytes) == -1) {
		ERROR("Failed to write to output %s\n",
			block_device ? "block device" : "filesystem");
		BAD_ERROR("Probably out of space on output %s\n",
			block_device ? "block device" : "filesystem");
	}

	fd_pos = off + bytes;
	pthread_cleanup_pop(1);
}


static long long write_inodes()
{
	unsigned short c_byte;
	int avail_bytes;
	char *datap = data_cache;
	long long start_bytes;

	while(cache_bytes) {
		if(inode_size - inode_bytes <
				((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			inode_table = REALLOC(inode_table, inode_size +
				((SQUASHFS_METADATA_SIZE << 1) + 2));
			inode_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}
		avail_bytes = cache_bytes > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : cache_bytes;
		c_byte = mangle(inode_table + inode_bytes + BLOCK_OFFSET, datap,
			avail_bytes, SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Inode block @ 0x%x, size %d\n", inode_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, inode_table + inode_bytes, 1); 
		inode_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		total_inode_bytes += avail_bytes + BLOCK_OFFSET;
		datap += avail_bytes;
		cache_bytes -= avail_bytes;
	}

	start_bytes = get_and_inc_dpos(inode_bytes);
	write_destination(fd, start_bytes, inode_bytes,  inode_table);

	return start_bytes;
}


static long long write_directories()
{
	unsigned short c_byte;
	int avail_bytes;
	char *directoryp = directory_data_cache;
	long long start_bytes;

	while(directory_cache_bytes) {
		if(directory_size - directory_bytes <
				((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			directory_table = REALLOC(directory_table,
				directory_size + ((SQUASHFS_METADATA_SIZE << 1)
				+ 2));
			directory_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}
		avail_bytes = directory_cache_bytes > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : directory_cache_bytes;
		c_byte = mangle(directory_table + directory_bytes +
			BLOCK_OFFSET, directoryp, avail_bytes,
			SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Directory block @ 0x%x, size %d\n", directory_bytes,
			c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte,
			directory_table + directory_bytes, 1);
		directory_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		total_directory_bytes += avail_bytes + BLOCK_OFFSET;
		directoryp += avail_bytes;
		directory_cache_bytes -= avail_bytes;
	}

	start_bytes = get_and_inc_dpos(directory_bytes);
	write_destination(fd, start_bytes, directory_bytes, directory_table);

	return start_bytes;
}


static int check_id_table_offset()
{
	int i;

	INFO("Updating id table with -uid-gid-offset value %u", uid_gid_offset);

	for(i = 0; i < id_count; i++) {
		long long id = id_table[i]->id + uid_gid_offset;

		if(id > (((long long) 1 << 32) - 1))
			return FALSE;

		id_table[i]->id = id;
	}

	return TRUE;
}


static long long write_id_table()
{
	unsigned int id_bytes = SQUASHFS_ID_BYTES(id_count);
	unsigned int p[id_count];
	int i;

	TRACE("write_id_table: ids %d, id_bytes %d\n", id_count, id_bytes);
	for(i = 0; i < id_count; i++) {
		TRACE("write_id_table: id index %d, id %d", i, id_table[i]->id);
		SQUASHFS_SWAP_INTS(&id_table[i]->id, p + i, 1);
	}

	return generic_write_table(id_bytes, p, 0, NULL, noI || noId);
}


static struct id *get_id(unsigned int id)
{
	int hash = ID_HASH(id);
	struct id *entry = id_hash_table[hash];

	for(; entry; entry = entry->next)
		if(entry->id == id)
			break;

	return entry;
}


struct id *create_id(unsigned int id)
{
	int hash = ID_HASH(id);
	struct id *entry = MALLOC(sizeof(struct id));
	entry->id = id;
	entry->index = id_count ++;
	entry->flags = 0;
	entry->next = id_hash_table[hash];
	id_hash_table[hash] = entry;
	id_table[entry->index] = entry;
	return entry;
}


unsigned int get_uid(unsigned int uid)
{
	struct id *entry = get_id(uid);

	if(entry == NULL) {
		if(id_count == SQUASHFS_IDS)
			BAD_ERROR("Out of uids!\n");
		entry = create_id(uid);
	}

	if((entry->flags & ISA_UID) == 0) {
		entry->flags |= ISA_UID;
		uid_count ++;
	}

	return entry->index;
}


unsigned int get_guid(unsigned int guid)
{
	struct id *entry = get_id(guid);

	if(entry == NULL) {
		if(id_count == SQUASHFS_IDS)
			BAD_ERROR("Out of gids!\n");
		entry = create_id(guid);
	}

	if((entry->flags & ISA_GID) == 0) {
		entry->flags |= ISA_GID;
		guid_count ++;
	}

	return entry->index;
}


char *pathname(struct dir_ent *dir_ent)
{
	static char *pathname = NULL;
	static int size = ALLOC_SIZE;

	if (dir_ent->nonstandard_pathname)
		return dir_ent->nonstandard_pathname;

	if(pathname == NULL)
		pathname = MALLOC(ALLOC_SIZE);

	for(;;) {
		int res = snprintf(pathname, size, "%s/%s",
			dir_ent->our_dir->pathname,
			dir_ent->source_name ? : dir_ent->name);

		if(res < 0)
			BAD_ERROR("snprintf failed in pathname\n");
		else if(res >= size) {
			/*
			 * pathname is too small to contain the result, so
			 * increase it and try again
			 */
			size = (res + ALLOC_SIZE) & ~(ALLOC_SIZE - 1);
			pathname = REALLOC(pathname, size);
		} else
			break;
	}

	return pathname;
}



char *subpathname(struct dir_ent *dir_ent)
{
	static char *subpath = NULL;
	static int size = ALLOC_SIZE;
	int res;

	if(subpath == NULL)
		subpath = MALLOC(ALLOC_SIZE);

	for(;;) {
		if(dir_ent->our_dir->subpath[0] != '\0')
			res = snprintf(subpath, size, "%s/%s",
				dir_ent->our_dir->subpath, dir_ent->name);
		else
			res = snprintf(subpath, size, "/%s", dir_ent->name);

		if(res < 0)
			BAD_ERROR("snprintf failed in subpathname\n");
		else if(res >= size) {
			/*
			 * subpath is too small to contain the result, so
			 * increase it and try again
			 */
			size = (res + ALLOC_SIZE) & ~(ALLOC_SIZE - 1);
			subpath = REALLOC(subpath, size);
		} else
			break;
	}

	return subpath;
}


static inline unsigned int get_inode_no(struct inode_info *inode)
{
	return inode->inode_number;
}


static inline unsigned int get_parent_no(struct dir_info *dir)
{
	return dir->depth ? get_inode_no(dir->dir_ent->inode) : inode_no;
}

	
static inline unsigned int get_time(time_t orig)
{
	unsigned int time = orig;

	if(inode_time_opt) {
		if(clamping)
			time = time > inode_time ? inode_time : time;
		else
			time = inode_time;
	}

	return time;
}


squashfs_inode create_inode(struct dir_info *dir_info,
	struct dir_ent *dir_ent, int type, long long byte_size,
	long long start_block, unsigned int offset, unsigned int *block_list,
	struct fragment *fragment, struct directory *dir_in, long long sparse)
{
	struct stat *buf = &dir_ent->inode->buf;
	union squashfs_inode_header inode_header;
	struct squashfs_base_inode_header *base = &inode_header.base;
	void *inode;
	char *filename = pathname(dir_ent);
	int nlink = dir_ent->inode->nlink;
	int xattr = read_xattrs(dir_ent, type);
	unsigned int uid, gid;
	mode_t mode;

	switch(type) {
	case SQUASHFS_FILE_TYPE:
		if(dir_ent->inode->nlink > 1 ||
				byte_size >= (1LL << 32) ||
				start_block >= (1LL << 32) ||
				sparse || IS_XATTR(xattr))
			type = SQUASHFS_LREG_TYPE;
		break;
	case SQUASHFS_DIR_TYPE:
		if(dir_info->dir_is_ldir || IS_XATTR(xattr))
			type = SQUASHFS_LDIR_TYPE;
		break;
	case SQUASHFS_SYMLINK_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LSYMLINK_TYPE;
		break;
	case SQUASHFS_BLKDEV_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LBLKDEV_TYPE;
		break;
	case SQUASHFS_CHRDEV_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LCHRDEV_TYPE;
		break;
	case SQUASHFS_FIFO_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LFIFO_TYPE;
		break;
	case SQUASHFS_SOCKET_TYPE:
		if(IS_XATTR(xattr))
			type = SQUASHFS_LSOCKET_TYPE;
		break;
	}

	if(type != SQUASHFS_DIR_TYPE  && type != SQUASHFS_LDIR_TYPE) {
		if(!pseudo_override && global_file_mode_opt)
			mode = mode_execute(global_file_mode, buf->st_mode);
		else
			mode = buf->st_mode;
	} else {
		if(!pseudo_override && global_dir_mode_opt)
			mode = mode_execute(global_dir_mode, buf->st_mode);
		else
			mode = buf->st_mode;
	}

	if(!pseudo_override && global_uid_opt)
		uid = global_uid;
	else
		uid = buf->st_uid;

	if(!pseudo_override && global_gid_opt)
		gid = global_gid;
	else
		gid = buf->st_gid;

	base->mode = SQUASHFS_MODE(mode);
	base->inode_type = type;
	base->uid = get_uid(uid);
	base->guid = get_guid(gid);
	base->mtime = get_time(buf->st_mtime);
	base->inode_number = get_inode_no(dir_ent->inode);

	if(type == SQUASHFS_FILE_TYPE) {
		int i;
		struct squashfs_reg_inode_header *reg = &inode_header.reg;
		size_t off = offsetof(struct squashfs_reg_inode_header, block_list);

		inode = get_inode(sizeof(*reg) + offset * sizeof(unsigned int));
		reg->file_size = byte_size;
		reg->start_block = start_block;
		reg->fragment = fragment->index;
		reg->offset = fragment->offset;
		SQUASHFS_SWAP_REG_INODE_HEADER(reg, inode);
		SQUASHFS_SWAP_INTS(block_list, inode + off, offset);
		TRACE("File inode, file_size %lld, start_block 0x%llx, blocks "
			"%d, fragment %d, offset %d, size %d\n", byte_size,
			start_block, offset, fragment->index, fragment->offset,
			fragment->size);
		for(i = 0; i < offset; i++)
			TRACE("Block %d, size %d\n", i, block_list[i]);
	}
	else if(type == SQUASHFS_LREG_TYPE) {
		int i;
		struct squashfs_lreg_inode_header *reg = &inode_header.lreg;
		size_t off = offsetof(struct squashfs_lreg_inode_header, block_list);

		inode = get_inode(sizeof(*reg) + offset * sizeof(unsigned int));
		reg->nlink = nlink;
		reg->file_size = byte_size;
		reg->start_block = start_block;
		reg->fragment = fragment->index;
		reg->offset = fragment->offset;
		if(sparse && sparse >= byte_size)
			sparse = byte_size - 1;
		reg->sparse = sparse;
		reg->xattr = xattr;
		SQUASHFS_SWAP_LREG_INODE_HEADER(reg, inode);
		SQUASHFS_SWAP_INTS(block_list, inode + off, offset);
		TRACE("Long file inode, file_size %lld, start_block 0x%llx, "
			"blocks %d, fragment %d, offset %d, size %d, nlink %d"
			"\n", byte_size, start_block, offset, fragment->index,
			fragment->offset, fragment->size, nlink);
		for(i = 0; i < offset; i++)
			TRACE("Block %d, size %d\n", i, block_list[i]);
	}
	else if(type == SQUASHFS_LDIR_TYPE) {
		int i;
		unsigned char *p;
		struct squashfs_ldir_inode_header *dir = &inode_header.ldir;
		struct cached_dir_index *index = dir_in->index;
		unsigned int i_count = dir_in->i_count;
		unsigned int i_size = dir_in->i_size;

		if(byte_size >= 1LL << 32)
			BAD_ERROR("directory greater than 2^32-1 bytes!\n");

		inode = get_inode(sizeof(*dir) + i_size);
		dir->inode_type = SQUASHFS_LDIR_TYPE;
		dir->nlink = dir_ent->dir->directory_count + 2;
		dir->file_size = byte_size;
		dir->offset = offset;
		dir->start_block = start_block;
		dir->i_count = i_count;
		dir->parent_inode = get_parent_no(dir_ent->our_dir);
		dir->xattr = xattr;

		SQUASHFS_SWAP_LDIR_INODE_HEADER(dir, inode);
		p = inode + offsetof(struct squashfs_ldir_inode_header, index);
		for(i = 0; i < i_count; i++) {
			SQUASHFS_SWAP_DIR_INDEX(&index[i].index, p);
			p += offsetof(struct squashfs_dir_index, name);
			memcpy(p, index[i].name, index[i].index.size + 1);
			p += index[i].index.size + 1;
		}
		TRACE("Long directory inode, file_size %lld, start_block "
			"0x%llx, offset 0x%x, nlink %d\n", byte_size,
			start_block, offset, dir_ent->dir->directory_count + 2);
	}
	else if(type == SQUASHFS_DIR_TYPE) {
		struct squashfs_dir_inode_header *dir = &inode_header.dir;

		inode = get_inode(sizeof(*dir));
		dir->nlink = dir_ent->dir->directory_count + 2;
		dir->file_size = byte_size;
		dir->offset = offset;
		dir->start_block = start_block;
		dir->parent_inode = get_parent_no(dir_ent->our_dir);
		SQUASHFS_SWAP_DIR_INODE_HEADER(dir, inode);
		TRACE("Directory inode, file_size %lld, start_block 0x%llx, "
			"offset 0x%x, nlink %d\n", byte_size, start_block,
			offset, dir_ent->dir->directory_count + 2);
	}
	else if(type == SQUASHFS_CHRDEV_TYPE || type == SQUASHFS_BLKDEV_TYPE) {
		struct squashfs_dev_inode_header *dev = &inode_header.dev;
		unsigned int major = major(buf->st_rdev);
		unsigned int minor = minor(buf->st_rdev);

		if(major > 0xfff) {
			ERROR("Major %d out of range in device node %s, "
				"truncating to %d\n", major, filename,
				major & 0xfff);
			major &= 0xfff;
		}
		if(minor > 0xfffff) {
			ERROR("Minor %d out of range in device node %s, "
				"truncating to %d\n", minor, filename,
				minor & 0xfffff);
			minor &= 0xfffff;
		}
		inode = get_inode(sizeof(*dev));
		dev->nlink = nlink;
		dev->rdev = (major << 8) | (minor & 0xff) |
				((minor & ~0xff) << 12);
		SQUASHFS_SWAP_DEV_INODE_HEADER(dev, inode);
		TRACE("Device inode, rdev 0x%x, nlink %d\n", dev->rdev, nlink);
	}
	else if(type == SQUASHFS_LCHRDEV_TYPE || type == SQUASHFS_LBLKDEV_TYPE) {
		struct squashfs_ldev_inode_header *dev = &inode_header.ldev;
		unsigned int major = major(buf->st_rdev);
		unsigned int minor = minor(buf->st_rdev);

		if(major > 0xfff) {
			ERROR("Major %d out of range in device node %s, "
				"truncating to %d\n", major, filename,
				major & 0xfff);
			major &= 0xfff;
		}
		if(minor > 0xfffff) {
			ERROR("Minor %d out of range in device node %s, "
				"truncating to %d\n", minor, filename,
				minor & 0xfffff);
			minor &= 0xfffff;
		}
		inode = get_inode(sizeof(*dev));
		dev->nlink = nlink;
		dev->rdev = (major << 8) | (minor & 0xff) |
				((minor & ~0xff) << 12);
		dev->xattr = xattr;
		SQUASHFS_SWAP_LDEV_INODE_HEADER(dev, inode);
		TRACE("Device inode, rdev 0x%x, nlink %d\n", dev->rdev, nlink);
	}
	else if(type == SQUASHFS_SYMLINK_TYPE) {
		struct squashfs_symlink_inode_header *symlink = &inode_header.symlink;
		int byte = strlen(dir_ent->inode->symlink);
		size_t off = offsetof(struct squashfs_symlink_inode_header, symlink);

		inode = get_inode(sizeof(*symlink) + byte);
		symlink->nlink = nlink;
		symlink->symlink_size = byte;
		SQUASHFS_SWAP_SYMLINK_INODE_HEADER(symlink, inode);
		strncpy(inode + off, dir_ent->inode->symlink, byte);
		TRACE("Symbolic link inode, symlink_size %d, nlink %d\n", byte,
			nlink);
	}
	else if(type == SQUASHFS_LSYMLINK_TYPE) {
		struct squashfs_symlink_inode_header *symlink = &inode_header.symlink;
		int byte = strlen(dir_ent->inode->symlink);
		size_t off = offsetof(struct squashfs_symlink_inode_header, symlink);

		inode = get_inode(sizeof(*symlink) + byte +
						sizeof(unsigned int));
		symlink->nlink = nlink;
		symlink->symlink_size = byte;
		SQUASHFS_SWAP_SYMLINK_INODE_HEADER(symlink, inode);
		strncpy(inode + off, dir_ent->inode->symlink, byte);
		SQUASHFS_SWAP_INTS(&xattr, inode + off + byte, 1);
		TRACE("Symbolic link inode, symlink_size %d, nlink %d\n", byte,
			nlink);
	}
	else if(type == SQUASHFS_FIFO_TYPE || type == SQUASHFS_SOCKET_TYPE) {
		struct squashfs_ipc_inode_header *ipc = &inode_header.ipc;

		inode = get_inode(sizeof(*ipc));
		ipc->nlink = nlink;
		SQUASHFS_SWAP_IPC_INODE_HEADER(ipc, inode);
		TRACE("ipc inode, type %s, nlink %d\n", type ==
			SQUASHFS_FIFO_TYPE ? "fifo" : "socket", nlink);
	}
	else if(type == SQUASHFS_LFIFO_TYPE || type == SQUASHFS_LSOCKET_TYPE) {
		struct squashfs_lipc_inode_header *ipc = &inode_header.lipc;

		inode = get_inode(sizeof(*ipc));
		ipc->nlink = nlink;
		ipc->xattr = xattr;
		SQUASHFS_SWAP_LIPC_INODE_HEADER(ipc, inode);
		TRACE("ipc inode, type %s, nlink %d\n", type ==
			SQUASHFS_FIFO_TYPE ? "fifo" : "socket", nlink);
	} else
		BAD_ERROR("Unrecognised inode %d in create_inode\n", type);

	inode_count ++;

	TRACE("Created inode 0x%llx, type %d, uid %d, guid %d\n",
				MKINODE(inode), type, base->uid, base->guid);

	return MKINODE(inode);
}


static void add_dir(squashfs_inode inode, unsigned int inode_number, char *name,
	int type, struct directory *dir)
{
	struct squashfs_dir_entry idir;
	unsigned int start_block = inode >> 16;
	unsigned int offset = inode & 0xffff;
	unsigned int size = strlen(name);
	size_t name_off = offsetof(struct squashfs_dir_entry, name);

	if(size > SQUASHFS_NAME_LEN) {
		size = SQUASHFS_NAME_LEN;
		ERROR("Filename is greater than %d characters, truncating! ..."
			"\n", SQUASHFS_NAME_LEN);
	}

	if(dir->offset + sizeof(struct squashfs_dir_entry) + size +
			sizeof(struct squashfs_dir_header) >= dir->size)
		dir->buff= REALLOC(dir->buff, dir->size += SQUASHFS_METADATA_SIZE);

	if(dir->entry_count == 256 || start_block != dir->start_block ||
			(dir->have_dir_header &&
			((dir->offset + sizeof(struct squashfs_dir_entry) + size -
			dir->index_count_offset) > SQUASHFS_METADATA_SIZE)) ||
			((long long) inode_number - dir->inode_number) > 32767
			|| ((long long) inode_number - dir->inode_number)
			< -32768) {
		if(dir->have_dir_header) {
			struct squashfs_dir_header dir_header;

			if((dir->offset + sizeof(struct squashfs_dir_entry) + size -
					dir->index_count_offset) >
					SQUASHFS_METADATA_SIZE) {
				if(dir->i_count % I_COUNT_SIZE == 0)
					dir->index = REALLOC(dir->index,
						(dir->i_count + I_COUNT_SIZE) *
						sizeof(struct cached_dir_index));
				dir->index[dir->i_count].index.index = dir->offset;
				dir->index[dir->i_count].index.size = size - 1;
				dir->index[dir->i_count++].name = name;
				dir->i_size += sizeof(struct squashfs_dir_index)
					+ size;
				dir->index_count_offset = dir->offset;
			}

			dir_header.count = dir->entry_count - 1;
			dir_header.start_block = dir->start_block;
			dir_header.inode_number = dir->inode_number;
			SQUASHFS_SWAP_DIR_HEADER(&dir_header,
				(dir->buff + dir->entry_count_offset));

		}


		dir->entry_count_offset = dir->offset;
		dir->have_dir_header = TRUE;
		dir->start_block = start_block;
		dir->entry_count = 0;
		dir->inode_number = inode_number;
		dir->offset += sizeof(struct squashfs_dir_header);
	}

	idir.offset = offset;
	idir.type = type;
	idir.size = size - 1;
	idir.inode_number = ((long long) inode_number - dir->inode_number);
	SQUASHFS_SWAP_DIR_ENTRY(&idir, (dir->buff + dir->offset));
	strncpy((char *) dir->buff + dir->offset + name_off, name, size);
	dir->offset += sizeof(struct squashfs_dir_entry) + size;
	dir->entry_count ++;
}


static squashfs_inode write_dir(struct dir_info *dir_info,
	struct directory *dir)
{
	long long dir_size = dir->offset;
	int data_space = directory_cache_size - directory_cache_bytes;
	unsigned int directory_block, directory_offset, i_count, index;
	unsigned short c_byte;
	void *cache;

	if(data_space < dir_size) {
		int realloc_size = directory_cache_size == 0 ?
			((dir_size + SQUASHFS_METADATA_SIZE) &
			~(SQUASHFS_METADATA_SIZE - 1)) : dir_size - data_space;

		directory_data_cache = REALLOC(directory_data_cache,
			directory_cache_size + realloc_size);
		directory_cache_size += realloc_size;
	}

	if(dir_size) {
		struct squashfs_dir_header dir_header;

		dir_header.count = dir->entry_count - 1;
		dir_header.start_block = dir->start_block;
		dir_header.inode_number = dir->inode_number;
		SQUASHFS_SWAP_DIR_HEADER(&dir_header, (dir->buff + dir->entry_count_offset));
		memcpy(directory_data_cache + directory_cache_bytes, dir->buff,
			dir_size);
	}
	directory_offset = directory_cache_bytes;
	directory_block = directory_bytes;
	directory_cache_bytes += dir_size;
	i_count = 0;
	index = SQUASHFS_METADATA_SIZE - directory_offset;
	cache = directory_data_cache;

	while(1) {
		while(i_count < dir->i_count &&
				dir->index[i_count].index.index < index)
			dir->index[i_count++].index.start_block =
				directory_bytes;
		index += SQUASHFS_METADATA_SIZE;

		if(directory_cache_bytes < SQUASHFS_METADATA_SIZE)
			break;

		if((directory_size - directory_bytes) <
					((SQUASHFS_METADATA_SIZE << 1) + 2)) {
			directory_table = REALLOC(directory_table,
				directory_size + (SQUASHFS_METADATA_SIZE << 1)
				+ 2);
			directory_size += SQUASHFS_METADATA_SIZE << 1;
		}

		c_byte = mangle(directory_table + directory_bytes +
				BLOCK_OFFSET, cache, SQUASHFS_METADATA_SIZE,
				SQUASHFS_METADATA_SIZE, noI, 0);
		TRACE("Directory block @ 0x%x, size %d\n", directory_bytes,
			c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte,
			directory_table + directory_bytes, 1);
		directory_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		total_directory_bytes += SQUASHFS_METADATA_SIZE + BLOCK_OFFSET;
		directory_cache_bytes -= SQUASHFS_METADATA_SIZE;
		cache += SQUASHFS_METADATA_SIZE;
	}

	if(directory_cache_bytes)
		memmove(directory_data_cache, cache, directory_cache_bytes);

	dir_count ++;

#ifndef SQUASHFS_TRACE
	return create_inode(dir_info, dir_info->dir_ent, SQUASHFS_DIR_TYPE,
		dir_size + 3, directory_block, directory_offset, NULL, NULL,
		dir, 0);
#else
	{
		unsigned char *dirp;
		int count;
		squashfs_inode inode;

		inode = create_inode(dir_info, dir_info->dir_ent, SQUASHFS_DIR_TYPE,
			dir_size + 3, directory_block, directory_offset, NULL, NULL,
			dir, 0);

		TRACE("Directory contents of inode 0x%llx\n", inode);
		dirp = dir->buff;
		while(dirp < (dir->buff + dir->offset)) {
			char buffer[SQUASHFS_NAME_LEN + 1];
			struct squashfs_dir_entry idir, *idirp;
			struct squashfs_dir_header dirh;
			SQUASHFS_SWAP_DIR_HEADER((struct squashfs_dir_header *) dirp,
				&dirh);
			count = dirh.count + 1;
			dirp += sizeof(struct squashfs_dir_header);

			TRACE("\tStart block 0x%x, count %d\n",
				dirh.start_block, count);

			while(count--) {
				idirp = (struct squashfs_dir_entry *) dirp;
				SQUASHFS_SWAP_DIR_ENTRY(idirp, &idir);
				strncpy(buffer, idirp->name, idir.size + 1);
				buffer[idir.size + 1] = '\0';
				TRACE("\t\tname %s, inode offset 0x%x, type "
					"%d\n", buffer, idir.offset, idir.type);
				dirp += sizeof(struct squashfs_dir_entry) + idir.size +
					1;
			}
		}

		return inode;
	}
#endif
}


static struct file_buffer *get_fragment(struct fragment *fragment)
{
	struct squashfs_fragment_entry *disk_fragment;
	struct file_buffer *buffer, *compressed_buffer;
	long long start_block;
	int res, size, index = fragment->index, compressed;
	char locked;

	/*
	 * Lookup fragment block in cache.
	 * If the fragment block doesn't exist, then get the compressed version
	 * from the writer cache or off disk, and decompress it.
	 *
	 * This routine has two things which complicate the code:
	 *
	 *	1. Multiple threads can simultaneously lookup/create the
	 *	   same buffer.  This means a buffer needs to be "locked"
	 *	   when it is being filled in, to prevent other threads from
	 *	   using it when it is not ready.  This is because we now do
	 *	   fragment duplicate checking in parallel.
	 *	2. We have two caches which need to be checked for the
	 *	   presence of fragment blocks: the normal fragment cache
	 *	   and a "reserve" cache.  The reserve cache is used to
	 *	   prevent an unnecessary pipeline stall when the fragment cache
	 *	   is full of fragments waiting to be compressed.
	 */

	if(fragment->index == SQUASHFS_INVALID_FRAG)
		return NULL;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &dup_mutex);
	pthread_mutex_lock(&dup_mutex);

again:
	buffer = cache_lookup_nowait(fragment_buffer, index, &locked);
	if(buffer) {
		pthread_mutex_unlock(&dup_mutex);
		if(locked)
			/* got a buffer being filled in.  Wait for it */
			cache_wait_unlock(buffer);
		goto finished;
	}

	/* not in fragment cache, is it in the reserve cache? */
	buffer = cache_lookup_nowait(reserve_cache, index, &locked);
	if(buffer) {
		pthread_mutex_unlock(&dup_mutex);
		if(locked)
			/* got a buffer being filled in.  Wait for it */
			cache_wait_unlock(buffer);
		goto finished;
	}

	/* in neither cache, try to get it from the fragment cache */
	buffer = cache_get_nowait(fragment_buffer, index);
	if(!buffer) {
		/*
		 * no room, get it from the reserve cache, this is
		 * dimensioned so it will always have space (no more than
		 * processors + 1 can have an outstanding reserve buffer)
		 */
		buffer = cache_get_nowait(reserve_cache, index);
		if(!buffer) {
			/* failsafe */
			ERROR("no space in reserve cache\n");
			goto again;
		}
	}

	pthread_mutex_unlock(&dup_mutex);

	compressed_buffer = cache_lookup(fwriter_buffer, index);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &fragment_mutex);
	pthread_mutex_lock(&fragment_mutex);
	disk_fragment = &fragment_table[index];
	size = SQUASHFS_COMPRESSED_SIZE_BLOCK(disk_fragment->size);
	compressed = SQUASHFS_COMPRESSED_BLOCK(disk_fragment->size);
	start_block = disk_fragment->start_block;
	pthread_cleanup_pop(1);

	if(compressed) {
		int error;
		char *data;

		if(compressed_buffer)
			data = compressed_buffer->data;
		else {
			data = read_from_disk(start_block, size, 0);
			if(data == NULL) {
				ERROR("Failed to read fragment from output"
					" filesystem\n");
				BAD_ERROR("Output filesystem corrupted?\n");
			}
		}

		res = compressor_uncompress(comp, buffer->data, data, size,
			block_size, &error);
		if(res == -1)
			BAD_ERROR("%s uncompress failed with error code %d\n",
				comp->name, error);
	} else if(compressed_buffer)
		memcpy(buffer->data, compressed_buffer->data, size);
	else {
		res = read_fs_bytes(fd, start_block, size, buffer->data);
		if(res == 0) {
			ERROR("Failed to read fragment from output "
				"filesystem\n");
			BAD_ERROR("Output filesystem corrupted?\n");
		}
	}

	cache_unlock(buffer);
	gen_cache_block_put(compressed_buffer);

finished:
	pthread_cleanup_pop(0);

	return buffer;
}


static unsigned short get_fragment_checksum(struct file_info *file)
{
	struct file_buffer *frag_buffer;
	struct append_file *append;
	int res, index = file->fragment->index;
	unsigned short checksum;

	if(index == SQUASHFS_INVALID_FRAG)
		return 0;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &dup_mutex);
	pthread_mutex_lock(&dup_mutex);
	res = file->have_frag_checksum;
	checksum = file->fragment_checksum;
	pthread_cleanup_pop(1);

	if(res)
		return checksum;

	frag_buffer = get_fragment(file->fragment);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &dup_mutex);

	for(append = file_mapping[index]; append; append = append->next) {
		int offset = append->file->fragment->offset;
		int size = append->file->fragment->size;
		unsigned short cksum =
			get_checksum_mem(frag_buffer->data + offset, size);

		if(file == append->file)
			checksum = cksum;

		pthread_mutex_lock(&dup_mutex);
		append->file->fragment_checksum = cksum;
		append->file->have_frag_checksum = TRUE;
		pthread_mutex_unlock(&dup_mutex);
	}

	gen_cache_block_put(frag_buffer);
	pthread_cleanup_pop(0);

	return checksum;
}


static void log_fragment(unsigned int fragment, long long start)
{
	if(logging)
		fprintf(log_fd, "Fragment %u, %lld\n", fragment, start);
}


static void write_fragment(struct file_buffer *fragment)
{
	if(fragment == NULL)
		return;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &fragment_mutex);
	pthread_mutex_lock(&fragment_mutex);
	fragment_table[fragment->block].unused = 0;
	fragment->sequence = get_sequence();
	queue_put(to_frag, fragment);
	pthread_cleanup_pop(1);
}


static struct file_buffer *allocate_fragment()
{
	struct file_buffer *fragment = cache_get(fragment_buffer, fragments);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &fragment_mutex);
	pthread_mutex_lock(&fragment_mutex);

	if(fragments % FRAG_SIZE == 0)
		fragment_table = REALLOC(fragment_table, (fragments +
			FRAG_SIZE) * sizeof(struct squashfs_fragment_entry));

	fragment->size = 0;
	fragment->block = fragments ++;

	pthread_cleanup_pop(1);

	return fragment;
}


static struct fragment empty_fragment = {SQUASHFS_INVALID_FRAG, 0, 0};


void free_fragment(struct fragment *fragment)
{
	if(fragment != &empty_fragment)
		free(fragment);
}


static struct fragment *get_and_fill_fragment(struct file_buffer *file_buffer,
	struct dir_ent *dir_ent, int tail)
{
	struct fragment *ffrg;
	struct file_buffer **fragment;

	if(file_buffer == NULL || file_buffer->size == 0)
		return &empty_fragment;

	fragment = eval_frag_actions(root_dir, dir_ent, tail);

	if((*fragment) && (*fragment)->size + file_buffer->size > block_size) {
		write_fragment(*fragment);
		*fragment = NULL;
	}

	ffrg = MALLOC(sizeof(struct fragment));

	if(*fragment == NULL)
		*fragment = allocate_fragment();

	ffrg->index = (*fragment)->block;
	ffrg->offset = (*fragment)->size;
	ffrg->size = file_buffer->size;
	memcpy((*fragment)->data + (*fragment)->size, file_buffer->data,
		file_buffer->size);
	(*fragment)->size += file_buffer->size;

	return ffrg;
}


long long generic_write_table(long long length, void *buffer, int length2,
	void *buffer2, int uncompressed)
{
	int meta_blocks = (length + SQUASHFS_METADATA_SIZE - 1) /
		SQUASHFS_METADATA_SIZE;
	int compressed_size, i, list_size = meta_blocks * sizeof(long long);
	long long *list = MALLOC(list_size), start_bytes, bytes;
	unsigned short c_byte;
	char cbuffer[(SQUASHFS_METADATA_SIZE << 2) + 2];
	
#ifdef SQUASHFS_TRACE
	long long obytes = get_dpos();
	long long olength = length;
#endif

	for(i = 0; i < meta_blocks; i++) {
		int avail_bytes = length > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : length;
		c_byte = mangle(cbuffer + BLOCK_OFFSET, buffer + i *
			SQUASHFS_METADATA_SIZE , avail_bytes,
			SQUASHFS_METADATA_SIZE, uncompressed, 0);
		SQUASHFS_SWAP_SHORTS(&c_byte, cbuffer, 1);
		compressed_size = SQUASHFS_COMPRESSED_SIZE(c_byte) +
			BLOCK_OFFSET;
		bytes = get_and_inc_dpos(compressed_size);
		write_destination(fd, bytes, compressed_size, cbuffer);
		list[i] = bytes;
		total_bytes += avail_bytes;
		length -= avail_bytes;
		TRACE("block %d @ 0x%llx, compressed size %d\n", i, bytes,
			compressed_size);
	}

	start_bytes = get_and_inc_dpos(length2);
	if(length2) {
		write_destination(fd, start_bytes, length2, buffer2);
		total_bytes += length2;
	}
		
	SQUASHFS_INSWAP_LONG_LONGS(list, meta_blocks);
	bytes = get_and_inc_dpos(list_size);
	write_destination(fd, bytes, list_size, list);
	total_bytes += list_size;

	TRACE("generic_write_table: total uncompressed %lld compressed %lld\n",
		olength, get_dpos() - obytes);

	free(list);

	return start_bytes;
}


static long long write_fragment_table()
{
	long long frag_bytes = SQUASHFS_FRAGMENT_BYTES(fragments);
	unsigned int i;

	TRACE("write_fragment_table: fragments %u, frag_bytes %d\n", fragments,
		frag_bytes);
	for(i = 0; i < fragments; i++) {
		TRACE("write_fragment_table: fragment %u, start_block 0x%llx, "
			"size %d\n", i, fragment_table[i].start_block,
			fragment_table[i].size);
		SQUASHFS_INSWAP_FRAGMENT_ENTRY(&fragment_table[i]);
	}

	return generic_write_table(frag_bytes, fragment_table, 0, NULL, noF);
}


static char *read_from_disk(long long start, unsigned int avail_bytes, int buff)
{
	int res;
	static char *buffer1 = NULL, *buffer2 = NULL;
	char **buffer = buff == 0 ? &buffer1 : &buffer2;

	if(*buffer == NULL)
		*buffer = MALLOC(block_size);

	res = read_fs_bytes(fd, start, avail_bytes, *buffer);
	if(res == 0)
		return NULL;

	return *buffer;
}


/*
 * Compute 16 bit BSD checksum over the data
 */
unsigned short get_checksum(char *buff, int bytes, unsigned short chksum)
{
	unsigned char *b = (unsigned char *) buff;

	while(bytes --) {
		chksum = (chksum & 1) ? (chksum >> 1) | 0x8000 : chksum >> 1;
		chksum += *b++;
	}

	return chksum;
}


static unsigned short get_checksum_disk(long long start, long long l,
	unsigned int *blocks)
{
	long long dpos = -1;
	unsigned short chksum = 0;
	unsigned int bytes;
	struct file_buffer *write_buffer;
	int i;

	for(i = 0; l; i++)  {
		bytes = SQUASHFS_COMPRESSED_SIZE_BLOCK(blocks[i]);
		if(bytes == 0) /* sparse block */
			continue;
		write_buffer = queue_cache_lookup(bwriter_buffer, start);
		if(write_buffer) {
			chksum = get_checksum(write_buffer->data, bytes,
				chksum);
			gen_cache_block_put(write_buffer);
		} else {
			void *data;

			if(dpos == -1)
				dpos = get_virt_disk(start);

			data = read_from_disk(dpos, bytes, 0);
			if(data == NULL) {	
				ERROR("Failed to checksum data from output"
					" filesystem\n");
				BAD_ERROR("Output filesystem corrupted?\n");
			}

			chksum = get_checksum(data, bytes, chksum);
		}

		l -= bytes;
		start += bytes;
		if(dpos != -1)
			dpos += bytes;
	}

	return chksum;
}


static unsigned short get_checksum_buffers(long long start, long long l,
	unsigned int *blocks, struct file_buffer **buffers)
{
	unsigned short chksum = 0;
	unsigned int bytes;
	int i;

	for(i = 0; l; i++)  {
		bytes = SQUASHFS_COMPRESSED_SIZE_BLOCK(blocks[i]);
		if(bytes == 0) /* sparse block */
			continue;
		if(buffers[i])
			chksum = get_checksum(buffers[i]->data, bytes, chksum);
		else {
			void *data = read_from_disk(start, bytes, 0);
			if(data == NULL) {
				ERROR("Failed to checksum data from output"
					" filesystem\n");
				BAD_ERROR("Output filesystem corrupted?\n");
			}

			chksum = get_checksum(data, bytes, chksum);
		}

		l -= bytes;
		start += bytes;
	}

	return chksum;
}


unsigned short get_checksum_mem(char *buff, int bytes)
{
	return get_checksum(buff, bytes, 0);
}


static int block_hash(int size, int blocks)
{
	return ((size << 10) & 0xffc00) | (blocks & 0x3ff);
}


void add_file(long long start, long long file_size, long long file_bytes,
	unsigned int *block_listp, int blocks, unsigned int fragment,
	int offset, int bytes)
{
	struct fragment *frg;
	unsigned int *block_list = block_listp;
	struct file_info *dupl_ptr;
	struct append_file *append_file;
	struct file_info *file;
	int blocks_dup = FALSE, frag_dup = FALSE;
	int bl_hash = 0;

	if(!duplicate_checking || file_size == 0)
		return;

	if(blocks) {
		bl_hash = block_hash(block_list[0], blocks);
		dupl_ptr = dupl_block[bl_hash];

		for(; dupl_ptr; dupl_ptr = dupl_ptr->block_next) {
			if(start == dupl_ptr->start)
				break;
		}

		if(dupl_ptr) {
			/*
			 * Our blocks have already been added. If we don't
			 * have a fragment, then we've finished checking
			 */
			if(fragment == SQUASHFS_INVALID_FRAG)
				return;

			/*
			 * This entry probably created both the blocks and
			 * the tail-end fragment, and so check for that
			 */
			if((fragment == dupl_ptr->fragment->index) &&
					(offset == dupl_ptr->fragment->offset)
					&& (bytes == dupl_ptr->fragment->size))
				return;

			/*
			 * Remember our blocks are duplicate, and continue
			 * looking for the tail-end fragment
			 */
			blocks_dup = TRUE;
		}
	}

	if(fragment != SQUASHFS_INVALID_FRAG) {
		dupl_ptr = dupl_frag[bytes];

		for(; dupl_ptr; dupl_ptr = dupl_ptr->frag_next)
			if((fragment == dupl_ptr->fragment->index) &&
					(offset == dupl_ptr->fragment->offset)
					&& (bytes == dupl_ptr->fragment->size))
				break;

		if(dupl_ptr) {
			/*
			 * Our tail-end fragment entry has already been added.
			 * If there's no blocks or they're dup, then we're done
			 * here
			 */
			if(blocks == 0 || blocks_dup)
				return;

			/* Remember our tail-end fragment entry is duplicate */
			frag_dup = TRUE;
		}
	}

	frg = MALLOC(sizeof(struct fragment));
	frg->index = fragment;
	frg->offset = offset;
	frg->size = bytes;

	file = add_non_dup(file_size, file_bytes, blocks, 0, block_list, start,
			frg, 0, 0, FALSE, FALSE, blocks_dup, frag_dup, bl_hash);

	if(fragment == SQUASHFS_INVALID_FRAG)
		return;

	append_file = MALLOC(sizeof(struct append_file));
	append_file->file = file;
	append_file->next = file_mapping[fragment];
	file_mapping[fragment] = append_file;
}


static int pre_duplicate(long long file_size, struct inode_info *inode,
				struct file_buffer *buffer, int *bl_hash)
{
	struct file_info *dupl_ptr;
	long long fragment_size;
	int blocks;

	if(inode->no_fragments || (!inode->always_use_fragments && file_size >=
								block_size)) {
		blocks = (file_size + block_size - 1) >> block_log;
		fragment_size = 0;
	} else {
		blocks = file_size >> block_log;
		fragment_size = file_size & (block_size - 1);
	}

	/* Look for a possible duplicate set of blocks */
	if(blocks) {
		*bl_hash = block_hash(buffer->size, blocks);
		for(dupl_ptr = dupl_block[*bl_hash]; dupl_ptr;dupl_ptr = dupl_ptr->block_next)
			if(dupl_ptr->blocks == blocks && dupl_ptr->block_list[0] == buffer->c_byte)
				return TRUE;
	}

	/* Look for a possible duplicate fragment */
	if(fragment_size) {
		for(dupl_ptr = dupl_frag[fragment_size]; dupl_ptr; dupl_ptr = dupl_ptr->frag_next)
			if(dupl_ptr->fragment->size == fragment_size)
				return TRUE;
	}

	return FALSE;
}


static struct file_info *create_non_dup(long long file_size, long long bytes,
	unsigned int blocks, long long sparse, unsigned int *block_list,
	long long start,struct fragment *fragment,unsigned short checksum,
	unsigned short fragment_checksum, int checksum_flag,
	int checksum_frag_flag)
{
	struct file_info *dupl_ptr = MALLOC(sizeof(struct file_info));

	dupl_ptr->file_size = file_size;
	dupl_ptr->bytes = bytes;
	dupl_ptr->blocks = blocks;
	dupl_ptr->sparse = sparse;
	dupl_ptr->block_list = block_list;
	dupl_ptr->start = start;
	dupl_ptr->fragment = fragment;
	dupl_ptr->checksum = checksum;
	dupl_ptr->fragment_checksum = fragment_checksum;
	dupl_ptr->have_frag_checksum = checksum_frag_flag;
	dupl_ptr->have_checksum = checksum_flag;
	dupl_ptr->block_next = NULL;
	dupl_ptr->frag_next = NULL;
	dupl_ptr->dup = NULL;

	return dupl_ptr;
}


static struct file_info *add_non_dup(long long file_size, long long bytes,
	unsigned int blocks, long long sparse, unsigned int *block_list,
	long long start,struct fragment *fragment,unsigned short checksum,
	unsigned short fragment_checksum, int checksum_flag,
	int checksum_frag_flag, int blocks_dup, int frag_dup, int bl_hash)
{
	struct file_info *dupl_ptr = MALLOC(sizeof(struct file_info));
	int fragment_size = fragment->size;

	dupl_ptr->file_size = file_size;
	dupl_ptr->bytes = bytes;
	dupl_ptr->blocks = blocks;
	dupl_ptr->sparse = sparse;
	dupl_ptr->block_list = block_list;
	dupl_ptr->start = start;
	dupl_ptr->fragment = fragment;
	dupl_ptr->checksum = checksum;
	dupl_ptr->fragment_checksum = fragment_checksum;
	dupl_ptr->have_frag_checksum = checksum_frag_flag;
	dupl_ptr->have_checksum = checksum_flag;
	dupl_ptr->block_next = NULL;
	dupl_ptr->frag_next = NULL;
	dupl_ptr->dup = NULL;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &dup_mutex);
        pthread_mutex_lock(&dup_mutex);

	if(blocks && !blocks_dup) {
		dupl_ptr->block_next = dupl_block[bl_hash];
		dupl_block[bl_hash] = dupl_ptr;
	}

	if(fragment_size && !frag_dup) {
		dupl_ptr->frag_next = dupl_frag[fragment_size];
		dupl_frag[fragment_size] = dupl_ptr;
	}

	dup_files ++;

	pthread_cleanup_pop(1);

	return dupl_ptr;
}


static struct file_info *frag_duplicate(struct file_buffer *file_buffer, int *duplicate)
{
	struct file_info *dupl_ptr;
	struct file_buffer *buffer;
	struct file_info *dupl_start = file_buffer->dupl_start;
	long long file_size = file_buffer->file_size;
	unsigned short checksum = file_buffer->checksum;
	int res;

	if(file_buffer->duplicate)
		dupl_ptr = dupl_start;
	else {
		for(dupl_ptr = dupl_frag[file_size];
				dupl_ptr && dupl_ptr != dupl_start;
				dupl_ptr = dupl_ptr->frag_next) {
			if(file_size == dupl_ptr->fragment->size) {
				if(get_fragment_checksum(dupl_ptr) == checksum) {
					buffer = get_fragment(dupl_ptr->fragment);
					res = memcmp(file_buffer->data,
						buffer->data +
						dupl_ptr->fragment->offset,
						file_size);
					gen_cache_block_put(buffer);
					if(res == 0)
						break;
				}
			}
		}

		if(!dupl_ptr || dupl_ptr == dupl_start) {
			*duplicate = FALSE;
			return NULL;
		}
	}

	if(dupl_ptr->file_size == file_size) {
		/* File only has a fragment, and so this is an exact match */
		TRACE("Found duplicate file, fragment %u, size %d, offset %d, "
			"checksum 0x%x\n", dupl_ptr->fragment->index, file_size,
			dupl_ptr->fragment->offset, checksum);
		*duplicate = TRUE;
		return dupl_ptr;
	} else {
		struct dup_info *dup;

		/*
		 * File also has a block list.  Create a new file without
		 * a block_list, and link it to this file.  First check whether
		 * it is already there.
		 */
		if(dupl_ptr->dup) {
			*duplicate = TRUE;
			return dupl_ptr->dup->file;
		}

		dup = MALLOC(sizeof(struct dup_info));
		dup->file = create_non_dup(file_size, 0, 0, 0, NULL, 0,
				dupl_ptr->fragment, 0, checksum, TRUE, TRUE);
		dup->next = NULL;
		dupl_ptr->dup = dup;
		*duplicate = FALSE;
		return dup->file;
	}
}


static void reset_and_truncate(void)
{
	int res = reset_vpos();

	if(res)
		send_orderer_reset(get_marked_vpos());
}


static struct file_info *duplicate(int *dupf, int *block_dup,
	long long file_size, long long bytes, unsigned int *block_list,
	struct file_buffer **buffer_list, long long start,
	struct dir_ent *dir_ent, struct file_buffer *file_buffer, int blocks,
	long long sparse, int bl_hash)
{
	struct file_info *dupl_ptr, *file;
	struct file_info *block_dupl = NULL, *frag_dupl = NULL;
	struct dup_info *dup;
	int frag_bytes = file_buffer ? file_buffer->size : 0;
	unsigned short fragment_checksum = file_buffer ?
		file_buffer->checksum : 0;
	unsigned short checksum = 0;
	char checksum_flag = FALSE;
	struct fragment *fragment;
	long long dupl_start, cached_target = -1;

	/* Look for a possible duplicate set of blocks */
	for(dupl_ptr = dupl_block[bl_hash]; dupl_ptr;
					dupl_ptr = dupl_ptr->block_next) {
		if(bytes == dupl_ptr->bytes && blocks == dupl_ptr->blocks) {
			long long target_start = start, dup_start = dupl_ptr->start;
			long long dtarget_start = -1, ddup_start = -1;
			int block;

			/*
			 * Block list has same uncompressed size and same
			 * compressed size.  Now check if each block compressed
			 * to the same size
			 */
			if(memcmp(block_list, dupl_ptr->block_list, blocks *
					sizeof(unsigned int)) != 0)
				continue;

			/* Now get the checksums and compare */
			if(checksum_flag == FALSE) {
				checksum = get_checksum_buffers(start, bytes, block_list, buffer_list);
				checksum_flag = TRUE;
			}

			if(!dupl_ptr->have_checksum) {
				dupl_ptr->checksum =
					get_checksum_disk(dupl_ptr->start,
						dupl_ptr->bytes, dupl_ptr->block_list);
				dupl_ptr->have_checksum = TRUE;
			}

			if(checksum != dupl_ptr->checksum)
				continue;

			/*
			 * Checksums match, so now we need to do a byte by byte
			 * comparison
			 */
			for(block = 0; block < blocks; block ++) {
				int size = SQUASHFS_COMPRESSED_SIZE_BLOCK(block_list[block]);
				struct file_buffer *dup_buffer = NULL;
				char *target_data, *dup_data;
				int res;

				/* Sparse blocks obviously match */
				if(size == 0)
					continue;

				/*
				 * Get the block for our file.  This will be in
				 * the cache unless the cache wasn't large
				 * enough to hold the entire file, in which case
				 * the block will have been written to disk.
				 */
				if(buffer_list[block])
					target_data = buffer_list[block]->data;
				else {
					if(dtarget_start == -1) {
						if(cached_target == -1)
							cached_target = get_virt_disk(target_start);
						dtarget_start = cached_target;
					}
					target_data = read_from_disk(dtarget_start, size, 0);
					if(target_data == NULL) {
						ERROR("Failed to read data from"
							" output filesystem\n");
						BAD_ERROR("Output filesystem"
							" corrupted?\n");
					}
				}

				/*
				 * Get the block for the other file.  This may
				 * still be in the cache (if it was written
				 * recently), otherwise it will have to be read
				 * back from disk
				 */
				dup_buffer = queue_cache_lookup(bwriter_buffer, dup_start);
				if(dup_buffer)
					dup_data = dup_buffer->data;
				else {
					if(ddup_start == -1)
						ddup_start  = get_virt_disk(dup_start);
					dup_data = read_from_disk(ddup_start, size, 1);
					if(dup_data == NULL) {
						ERROR("Failed to read data from"
							" output filesystem\n");
						BAD_ERROR("Output filesystem"
							" corrupted?\n");
					}
				}

				res = memcmp(target_data, dup_data, size);
				gen_cache_block_put(dup_buffer);
				if(res != 0)
					break;
				target_start += size;
				dup_start += size;
				if(dtarget_start)
					dtarget_start += size;
				if(ddup_start != -1)
					ddup_start += size;
			}

			if(block != blocks)
				continue;

			/*
			 * Yes, the block list matches.  We can use this, rather
			 * than writing an identical block list.
			 * If both it and us doesn't have a tail-end fragment
			 * then we're finished.  Return the duplicate.
			 *
			 * We have to deal with the special case where the
			 * last block is a sparse block.  This means the
			 * file will have matched, but, it may be a different
			 * file length (because a tail-end sparse block may be
			 * anything from 1 byte to block_size - 1 in size, but
			 * stored as zero).  We can still use the block list in
			 * this case, but, we must return a new entry with the
			 * correct file size
			 */
			if(!frag_bytes && !dupl_ptr->fragment->size) {
				*dupf = *block_dup = TRUE;
				reset_and_truncate();
				if(file_size == dupl_ptr->file_size)
					return dupl_ptr;
				else
					return create_non_dup(file_size, bytes,
						blocks, sparse,
						dupl_ptr->block_list,
						dupl_ptr->start,
						dupl_ptr->fragment, checksum, 0,
						checksum_flag, FALSE);
			}

			/*
			 * We've got a tail-end fragment, and this file most
			 * likely has a matching tail-end fragment (i.e. it is
			 * a completely duplicate file).  So save time and have
			 * a look now.
			 */
			if(frag_bytes == dupl_ptr->fragment->size &&
					fragment_checksum ==
					get_fragment_checksum(dupl_ptr)) {
				/*
				 * Checksums match, so now we need to do a byte
				 * by byte comparison
				 * */
				struct file_buffer *frag_buffer = get_fragment(dupl_ptr->fragment);
				int res = memcmp(file_buffer->data,
					frag_buffer->data +
					dupl_ptr->fragment->offset, frag_bytes);

				gen_cache_block_put(frag_buffer);

				if(res == 0) {
					/*
					 * Yes, the fragment matches.  We're now
					 * finished.  Return the duplicate
					 */
					*dupf = *block_dup = TRUE;
					reset_and_truncate();
					return dupl_ptr;
				}
			}

			/*
			 * No, the fragment didn't match.  Remember the file
			 * with the matching blocks, and look for a matching
			 * fragment in the fragment list
			 */
			block_dupl = dupl_ptr;
			break;
		}
	}

	/* Look for a possible duplicate fragment */
	if(frag_bytes) {
		for(dupl_ptr = dupl_frag[frag_bytes]; dupl_ptr;
					dupl_ptr = dupl_ptr->frag_next) {
			if(frag_bytes == dupl_ptr->fragment->size &&
					fragment_checksum ==
					get_fragment_checksum(dupl_ptr)) {
				/*
				 * Checksums match, so now we need to do a byte
				 * by byte comparison
				 */
				struct file_buffer *frag_buffer = get_fragment(dupl_ptr->fragment);
				int res = memcmp(file_buffer->data,
					frag_buffer->data +
					dupl_ptr->fragment->offset, frag_bytes);

				gen_cache_block_put(frag_buffer);

				if(res == 0) {
					/*
					 * Yes, the fragment matches.  This file
					 * may have a matching block list and
					 * fragment, in which case we're
					 * finished.
					 */
					if(block_dupl && block_dupl->start == dupl_ptr->start) {
						*dupf = *block_dup = TRUE;
						reset_and_truncate();
						return dupl_ptr;
					}

					/*
					 * Block list doesn't match.  We can
					 * construct a hybrid from these two
					 * partially matching files
					 */
					frag_dupl = dupl_ptr;
					break;
				}
			}
		}
	}

	/*
	 * If we've got here, then we've either matched on nothing, or got a
	 * partial match.  Matched on nothing is straightforward
	 */
	if(!block_dupl && !frag_dupl) {
		*dupf = *block_dup = FALSE;
		fragment = get_and_fill_fragment(file_buffer, dir_ent, TRUE);

		return add_non_dup(file_size, bytes, blocks, sparse, block_list,
				start, fragment, checksum, fragment_checksum,
				checksum_flag, file_buffer != NULL, FALSE,
				FALSE, bl_hash);
	}

	/*
	 * At this point, we may have
	 * 1. A partially matching single file.  For example the file may
	 *    contain the block list we want, but, it has the wrong tail-end,
	 *    or vice-versa,
	 * 2. A partially matching single file for another reason.  For example
	 *    it has the block list we want, and a tail-end, whereas we don't
	 *    have a tail-end.  Note the vice-versa situation doesn't appear
	 *    here (it is handled in frag_duplicate).
	 * 3. We have two partially matching files.  One has the block list we
	 *    want, and the other has the tail-end we want.
	 *
	 * Strictly speaking, a file which is constructed from one or two
	 * partial matches isn't a duplicate (of any single file), and it will
	 * be confusing to list it as such (using the -info option).  But a
	 * second and thereafter appearance of this combination *is* a
	 * duplicate of another file.  Some of this second and thereafter
	 * appearance is already handled above
	 */

	if(block_dupl && (!frag_bytes || frag_dupl)) {
		/*
		 * This file won't be added to any hash list, because it is a
		 * complete duplicate, and it doesn't need extra data to be
		 * stored, e.g. part 2 & 3 above.  So keep track of it by adding
		 * it to a linked list.  Obviously check if it's already there
		 * first.
		 */
		for(dup = block_dupl->dup; dup; dup = dup->next)
			if((!frag_bytes && dup->frag == NULL) ||
					(frag_bytes && dup->frag == frag_dupl))
				break;

		if(dup) {
			/* Found a matching file.  Return the duplicate */
			*dupf = *block_dup = TRUE;
			reset_and_truncate();
			return dup->file;
		}
	}

	if(block_dupl && !frag_dupl) {
		/*
		 * We have a matching block list but no matching fragment.
		 * We have to reset the bytes counter to the start of the
		 * block list before getting and filling the fragment because
		 * if the current fragment is too full, this will force a
		 * write out of the fragment.
		 */
		reset_and_truncate();
	}

	if(frag_dupl)
		fragment = frag_dupl->fragment;
	else
		fragment = get_and_fill_fragment(file_buffer, dir_ent, TRUE);

	if(block_dupl) {
		dupl_start = block_dupl->start;
		block_list = block_dupl->block_list;
	} else
		dupl_start = start;

	*dupf = FALSE;
	*block_dup = block_dupl != NULL;

	file = create_non_dup(file_size, bytes, blocks, sparse, block_list,
		dupl_start, fragment, checksum, fragment_checksum, checksum_flag,
		file_buffer != NULL);

	if(!block_dupl || (frag_bytes && !frag_dupl)) {
		/*
		 * Partial duplicate, had to store some extra data for this
		 * file, either a block list, or a fragment
		 */
		pthread_cleanup_push((void *) pthread_mutex_unlock, &dup_mutex);
		pthread_mutex_lock(&dup_mutex);

		if(!block_dupl) {
			file->block_next = dupl_block[bl_hash];
			dupl_block[bl_hash] = file;
		}

		if(frag_bytes && !frag_dupl) {
			file->frag_next = dupl_frag[frag_bytes];
			dupl_frag[frag_bytes] = file;
		}

		dup_files ++;

		pthread_cleanup_pop(1);
	} else {
		dup = MALLOC(sizeof(struct dup_info));
		dup->frag = frag_dupl;
		dup->file = file;
		dup->next = block_dupl->dup;
		block_dupl->dup = dup;
		reset_and_truncate();
	}

	return file;
}


static void *writer(void *arg)
{
	while(1) {
		struct file_buffer *file_buffer = queue_get(to_writer);
		off_t off;

		if(file_buffer == NULL) {
			queue_put(from_writer, NULL);
			continue;
		}

		off = start_offset + file_buffer->block;

		pthread_cleanup_push((void *) pthread_mutex_unlock, &lseek_mutex);
		pthread_mutex_lock(&lseek_mutex);

		if(fd_pos != off) {
			if(lseek(fd, off, SEEK_SET) == -1) {
				ERROR("writer: Lseek on destination failed "
					"because %s, offset=0x%llx\n",
					strerror(errno), (long long) off);
				BAD_ERROR("Probably out of space on output "
					"%s\n", block_device ? "block device" :
					"filesystem");
			}

		}

		if(write_bytes(fd, file_buffer->data, file_buffer->size) == -1) {
			ERROR("Failed to write to output %s\n",
				block_device ? "block device" : "filesystem");
			BAD_ERROR("Probably out of space on output %s\n",
				block_device ? "block device" : "filesystem");
		}

		fd_pos = off + file_buffer->size;
		pthread_cleanup_pop(1);

		gen_cache_block_put(file_buffer);
	}
}


static int all_zero(struct file_buffer *file_buffer)
{
	int i;
	long entries = file_buffer->size / sizeof(long);
	long *p = (long *) file_buffer->data;

	for(i = 0; i < entries && p[i] == 0; i++);

	if(i == entries) {
		for(i = file_buffer->size & ~(sizeof(long) - 1);
			i < file_buffer->size && file_buffer->data[i] == 0;
			i++);

		return i == file_buffer->size;
	}

	return 0;
}


static void *deflator(void *arg)
{
	void *stream = NULL;
	int res, tid = get_thread_id(THREAD_BLOCK);

	res = compressor_init(comp, &stream, block_size, 1);
	if(res)
		BAD_ERROR("deflator:: compressor_init failed\n");

	while(1) {
		struct file_buffer *write_buffer;
		struct file_buffer *file_buffer = queue_cache_get_tid(tid, to_deflate, &write_buffer);

		if(sparse_files && all_zero(file_buffer)) { 
			file_buffer->c_byte = 0;
			gen_cache_block_put(write_buffer);
			main_queue_put(to_main, file_buffer);
		} else {
			write_buffer->c_byte = mangle2(stream,
				write_buffer->data, file_buffer->data,
				file_buffer->size, block_size,
				file_buffer->noD, 1);
			write_buffer->file_size = file_buffer->file_size;
			write_buffer->file_count = file_buffer->file_count;
			write_buffer->block = file_buffer->block;
			write_buffer->version = file_buffer->version;
			write_buffer->next_state = file_buffer->next_state;
			write_buffer->size = SQUASHFS_COMPRESSED_SIZE_BLOCK
				(write_buffer->c_byte);
			write_buffer->fragment = FALSE;
			write_buffer->error = FALSE;
			gen_cache_block_put(file_buffer);
			main_queue_put(to_main, write_buffer);
		}
	}
}


static void *frag_deflator(void *arg)
{
	void *stream = NULL;
	int res, tid = get_thread_id(THREAD_FRAGMENT);

	res = compressor_init(comp, &stream, block_size, 1);
	if(res)
		BAD_ERROR("frag_deflator:: compressor_init failed\n");

	while(1) {
		int c_byte;
		struct file_buffer *file_buffer = queue_get_tid(tid, to_frag);
		struct file_buffer *write_buffer =
			cache_get(fwriter_buffer, file_buffer->block);

		c_byte = mangle2(stream, write_buffer->data, file_buffer->data,
			file_buffer->size, block_size, noF, 1);
		write_buffer->block = file_buffer->block;
		write_buffer->sequence = file_buffer->sequence;
		write_buffer->c_byte = c_byte;
		write_buffer->size = SQUASHFS_COMPRESSED_SIZE_BLOCK(c_byte);
		write_buffer->fragment = FALSE;
		order_queue_put(to_order, write_buffer);
		TRACE("Writing fragment %lld, uncompressed size %d, "
			"compressed size %d\n", file_buffer->block,
			file_buffer->size, SQUASHFS_COMPRESSED_SIZE_BLOCK(c_byte));
		gen_cache_block_put(file_buffer);
	}
}


static void *orderer(void *arg)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &fragment_mutex);

	while(1) {
		struct file_buffer *write_buffer = order_queue_get(to_order);
		long long block = write_buffer->block;

		if(write_buffer->buffer_type == GEN_CACHE) {
			pthread_mutex_lock(&fragment_mutex);
			write_buffer->block = get_and_inc_dpos(SQUASHFS_COMPRESSED_SIZE_BLOCK(write_buffer->size));
			fragment_table[block].start_block = write_buffer->block;
			fragment_table[block].size = write_buffer->c_byte;
			pthread_mutex_unlock(&fragment_mutex);
			log_fragment(block, write_buffer->block);
			queue_put(to_writer, write_buffer);
		} else if(write_buffer->buffer_type == QUEUE_CACHE) {
			write_buffer->block = get_and_inc_dpos(SQUASHFS_COMPRESSED_SIZE_BLOCK(write_buffer->size));
			add_virt_disk(block, write_buffer->block);
			queue_put(to_writer, write_buffer);
		} else if(write_buffer->buffer_type == WSYNC_CMD) {
			free(write_buffer);
			queue_put(to_writer, NULL);
		} else if(write_buffer->buffer_type == OSYNC_CMD) {
			free(write_buffer);
			queue_put(from_order, NULL);
		} else if(write_buffer->buffer_type == RESET_CMD) {
			set_dpos(get_virt_disk(write_buffer->block));
			free(write_buffer);
		} else if(write_buffer->buffer_type == MAP_CMD) {
			add_virt_disk(block, get_dpos());
			free(write_buffer);
		} else

			BAD_ERROR("Bug in orderer\n");
	}

	pthread_cleanup_pop(0);
	return NULL;
}


static struct file_buffer *get_file_buffer()
{
	struct file_buffer *file_buffer = main_queue_get(to_main);

	return file_buffer;
}


static struct file_info *write_file_empty(struct dir_ent *dir_ent,
	struct file_buffer *file_buffer, int *duplicate_file)
{
	file_count ++;
	*duplicate_file = FALSE;
	gen_cache_block_put(file_buffer);
	return create_non_dup(0, 0, 0, 0, NULL, 0, &empty_fragment, 0, 0,
								FALSE, FALSE);
}


static struct file_info *write_file_frag(struct dir_ent *dir_ent,
	struct file_buffer *file_buffer, int *duplicate_file)
{
	int size = file_buffer->file_size;
	struct fragment *fragment;
	unsigned short checksum = file_buffer->checksum;
	struct file_info *file;

	file = frag_duplicate(file_buffer, duplicate_file);
	if(!file) {
		fragment = get_and_fill_fragment(file_buffer, dir_ent, FALSE);

		if(duplicate_checking)
			file = add_non_dup(size, 0, 0, 0, NULL, 0, fragment, 0,
				checksum, TRUE, TRUE, FALSE, FALSE, 0);
		else
			file = create_non_dup(size, 0, 0, 0, NULL, 0, fragment,
				0, checksum, TRUE, TRUE);
	}

	gen_cache_block_put(file_buffer);

	total_bytes += size;
	file_count ++;

	inc_progress_bar();

	return file;
}


static void log_file(struct dir_ent *dir_ent, long long start)
{
	if(logging && start)
		fprintf(log_fd, "%s, %lld\n", pathname(dir_ent), start);
}


static struct file_info *write_file_process(int *status, struct dir_ent *dir_ent,
	struct file_buffer *read_buffer, int *duplicate_file)
{
	long long read_size, file_bytes;
	struct fragment *fragment;
	unsigned int *block_list = NULL;
	int block = 0;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;
	struct file_info *file;

	*duplicate_file = FALSE;

	file_bytes = 0;
	mark_vpos();
	while (1) {
		read_size = read_buffer->file_size;
		if(read_buffer->fragment) {
			fragment_buffer = read_buffer;
		} else {
			block_list = REALLOC(block_list, (block + 1) *
				sizeof(unsigned int));
			block_list[block ++] = read_buffer->c_byte;
			if(read_buffer->c_byte) {
				file_bytes += read_buffer->size;
				put_write_buffer_hash(read_buffer);
			} else {
				sparse += read_buffer->size;
				gen_cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(read_size != -1)
			break;

		read_buffer = get_file_buffer();
		if(read_buffer->error)
			goto read_err;
	}

	fragment = get_and_fill_fragment(fragment_buffer, dir_ent, block != 0);

	if(duplicate_checking) {
		int bl_hash = block ? block_hash(block_list[0], block) : 0;

		file = add_non_dup(read_size, file_bytes, block, sparse,
			block_list, get_marked_vpos(), fragment, 0,
			fragment_buffer ?  fragment_buffer->checksum : 0, FALSE,
			TRUE, FALSE, FALSE, bl_hash);
	} else
		file = create_non_dup(read_size, file_bytes, block, sparse,
			block_list, get_marked_vpos(), fragment, 0,
			fragment_buffer ?  fragment_buffer->checksum : 0, FALSE,
			TRUE);

	if(!is_vpos_marked())
		send_orderer_create_map(get_marked_vpos());

	gen_cache_block_put(fragment_buffer);
	file_count ++;
	total_bytes += read_size;

	log_file(dir_ent, file->start);

	*status = 0;
	unmark_vpos();
	return file;

read_err:
	dec_progress_bar(block);
	*status = read_buffer->error;
	reset_and_truncate();
	free(block_list);
	gen_cache_block_put(read_buffer);
	unmark_vpos();
	return NULL;
}


static struct file_info *write_file_blocks_dup(int *status, struct dir_ent *dir_ent,
	struct file_buffer *read_buffer, int *duplicate_file, int bl_hash)
{
	int block, thresh;
	long long read_size = read_buffer->file_size;
	long long file_bytes;
	int blocks = (read_size + block_size - 1) >> block_log;
	unsigned int *block_list;
	struct file_buffer **buffer_list;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;
	struct file_info *file;
	int block_dup;
	int cache_size = cache_maxsize(read_buffer);

	block_list = MALLOC(blocks * sizeof(unsigned int));
	buffer_list = MALLOC(blocks * sizeof(struct file_buffer *));

	file_bytes = 0;
	mark_vpos();
	thresh = blocks > cache_size ? blocks - cache_size : 0;

	for(block = 0; block < blocks;) {
		if(read_buffer->fragment) {
			block_list[block] = 0;
			buffer_list[block] = NULL;
			fragment_buffer = read_buffer;
			blocks = read_size >> block_log;
		} else {
			block_list[block] = read_buffer->c_byte;

			if(read_buffer->c_byte) {
				file_bytes += read_buffer->size;
				if(block < thresh) {
					buffer_list[block] = NULL;
					put_write_buffer(read_buffer);
				} else
					buffer_list[block] = read_buffer;
			} else {
				buffer_list[block] = NULL;
				sparse += read_buffer->size;
				gen_cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(++block < blocks) {
			read_buffer = get_file_buffer();
			if(read_buffer->error)
				goto read_err;
		}
	}

	/*
	 * sparse count is needed to ensure squashfs correctly reports a
 	 * a smaller block count on stat calls to sparse files.  This is
 	 * to ensure intelligent applications like cp correctly handle the
 	 * file as a sparse file.  If the file in the original filesystem isn't
 	 * stored as a sparse file then still store it sparsely in squashfs, but
 	 * report it as non-sparse on stat calls to preserve semantics
 	 */
	if(sparse && (dir_ent->inode->buf.st_blocks << 9) >= read_size)
		sparse = 0;

	file = duplicate(duplicate_file, &block_dup, read_size, file_bytes,
		block_list, buffer_list, get_marked_vpos(), dir_ent,
		fragment_buffer, blocks, sparse, bl_hash);

	if(block_dup == FALSE) {
		for(block = thresh; block < blocks; block ++)
			if(buffer_list[block])
				put_write_buffer_hash(buffer_list[block]);

		if(!is_vpos_marked())
			send_orderer_create_map(get_marked_vpos());
	} else {
		for(block = thresh; block < blocks; block ++)
			gen_cache_block_put(buffer_list[block]);
	}

	gen_cache_block_put(fragment_buffer);
	free(buffer_list);
	file_count ++;
	total_bytes += read_size;

	if(block_dup == TRUE)
		free(block_list);
	else
		log_file(dir_ent, file->start);

	*status = 0;
	unmark_vpos();
	return file;

read_err:
	dec_progress_bar(block);
	*status = read_buffer->error;
	reset_and_truncate();
	for(blocks = thresh; blocks < block; blocks ++)
		gen_cache_block_put(buffer_list[blocks]);
	free(buffer_list);
	free(block_list);
	gen_cache_block_put(read_buffer);
	unmark_vpos();
	return NULL;
}


static struct file_info *write_file_blocks(int *status, struct dir_ent *dir_ent,
	struct file_buffer *read_buffer, int *dup)
{
	long long read_size = read_buffer->file_size;
	long long file_bytes;
	struct fragment *fragment;
	unsigned int *block_list;
	int block;
	int blocks = (read_size + block_size - 1) >> block_log;
	long long sparse = 0;
	struct file_buffer *fragment_buffer = NULL;
	struct file_info *file;
	int bl_hash = 0;

	if(pre_duplicate(read_size, dir_ent->inode, read_buffer, &bl_hash))
		return write_file_blocks_dup(status, dir_ent, read_buffer, dup, bl_hash);

	*dup = FALSE;

	block_list = MALLOC(blocks * sizeof(unsigned int));

	file_bytes = 0;
	mark_vpos();
	for(block = 0; block < blocks;) {
		if(read_buffer->fragment) {
			block_list[block] = 0;
			fragment_buffer = read_buffer;
			blocks = read_size >> block_log;
		} else {
			block_list[block] = read_buffer->c_byte;
			if(read_buffer->c_byte) {
				file_bytes += read_buffer->size;
				put_write_buffer_hash(read_buffer);
			} else {
				sparse += read_buffer->size;
				gen_cache_block_put(read_buffer);
			}
		}
		inc_progress_bar();

		if(++block < blocks) {
			read_buffer = get_file_buffer();
			if(read_buffer->error)
				goto read_err;
		}
	}

	/*
	 * sparse count is needed to ensure squashfs correctly reports a
 	 * a smaller block count on stat calls to sparse files.  This is
 	 * to ensure intelligent applications like cp correctly handle the
 	 * file as a sparse file.  If the file in the original filesystem isn't
 	 * stored as a sparse file then still store it sparsely in squashfs, but
 	 * report it as non-sparse on stat calls to preserve semantics
 	 */
	if(sparse && (dir_ent->inode->buf.st_blocks << 9) >= read_size)
		sparse = 0;

	fragment = get_and_fill_fragment(fragment_buffer, dir_ent, TRUE);

	if(duplicate_checking)
		file = add_non_dup(read_size, file_bytes, blocks, sparse,
			block_list, get_marked_vpos(), fragment, 0, fragment_buffer ?
			fragment_buffer->checksum : 0, FALSE, TRUE, FALSE,
			FALSE, bl_hash);
	else
		file = create_non_dup(read_size, file_bytes, blocks, sparse,
			block_list, get_marked_vpos(), fragment, 0, fragment_buffer ?
			fragment_buffer->checksum : 0, FALSE, TRUE);

	if(!is_vpos_marked())
		send_orderer_create_map(get_marked_vpos());

	gen_cache_block_put(fragment_buffer);
	file_count ++;
	total_bytes += read_size;

	log_file(dir_ent, file->start);

	*status = 0;
	unmark_vpos();
	return file;

read_err:
	dec_progress_bar(block);
	*status = read_buffer->error;
	reset_and_truncate();
	free(block_list);
	gen_cache_block_put(read_buffer);
	unmark_vpos();
	return NULL;
}


struct file_info *write_file(struct dir_ent *dir, int *dup)
{
	int status;
	struct file_buffer *read_buffer;
	struct file_info *file;

again:
	read_buffer = get_file_buffer();
	status = read_buffer->error;

	if(status)
		gen_cache_block_put(read_buffer);
	else if(read_buffer->file_size == -1)
		file = write_file_process(&status, dir, read_buffer, dup);
	else if(read_buffer->file_size == 0)
		file = write_file_empty(dir, read_buffer, dup);
	else if(read_buffer->fragment && read_buffer->c_byte)
		file = write_file_frag(dir, read_buffer, dup);
	else
		file = write_file_blocks(&status, dir, read_buffer, dup);

	if(status == 2) {
		ERROR("File %s changed size while reading filesystem, "
			"attempting to re-read\n", pathname(dir));
		goto again;
	} else if(status == 1) {
		ERROR_START("Failed to read file %s", pathname(dir));
		ERROR_EXIT(", creating empty file\n");
		file = write_file_empty(dir, NULL, dup);
	} else if(status)
		BAD_ERROR("Unexpected status value in write_file()\n");

	return file;
}


#define BUFF_SIZE 512
char *name;
static char *basename_r();

static char *getbase(char *pathname)
{
	static char *b_buffer = NULL;
	static int b_size = BUFF_SIZE;
	char *result;

	if(b_buffer == NULL)
		b_buffer = MALLOC(b_size);

	while(1) {
		if(*pathname != '/') {
			result = getcwd(b_buffer, b_size);
			if(result == NULL && errno != ERANGE)
				BAD_ERROR("Getcwd failed in getbase\n");

			/* enough room for pathname + "/" + '\0' terminator? */
			if(result && strlen(pathname) + 2 <=
						b_size - strlen(b_buffer)) {
				strcat(strcat(b_buffer, "/"), pathname);
				break;
			}
		} else if(strlen(pathname) < b_size) {
			strcpy(b_buffer, pathname);
			break;
		}

		/* Buffer not large enough, realloc and try again */
		b_buffer = REALLOC(b_buffer, b_size += BUFF_SIZE);
	}

	name = b_buffer;
	if(((result = basename_r()) == NULL) || (strcmp(result, "..") == 0))
		return NULL;
	else
		return result;
}


static char *basename_r()
{
	char *s;
	char *p;
	int n = 1;

	for(;;) {
		s = name;
		if(*name == '\0')
			return NULL;
		if(*name != '/') {
			while(*name != '\0' && *name != '/') name++;
			n = name - s;
		}
		while(*name == '/') name++;
		if(strncmp(s, ".", n) == 0)
			continue;
		if((*name == '\0') || (strncmp(s, "..", n) == 0) ||
				((p = basename_r()) == NULL)) {
			s[n] = '\0';
			return s;
		}
		if(strcmp(p, "..") == 0)
			continue;
		return p;
	}
}


static inline void dec_nlink_inode(struct dir_ent *dir_ent)
{
	if(dir_ent->inode == NULL || dir_ent->inode->root_entry)
		return;

	if(dir_ent->inode->nlink == 1) {
		/* Delete this inode, as the last or only reference
		 * to it is going away */
		struct stat *buf = &dir_ent->inode->buf;
		int ino_hash = INODE_HASH(buf->st_dev, buf->st_ino);
		struct inode_info *inode = inode_info[ino_hash];
		struct inode_info *prev = NULL;

		while(inode && inode != dir_ent->inode) {
			prev = inode;
			inode = inode->next;
		}

		if(inode) {
			if(prev)
				prev->next = inode->next;
			else
				inode_info[ino_hash] = inode->next;
		}

		/* Decrement the progress bar */
		if((buf->st_mode & S_IFMT) == S_IFREG)
			progress_bar_size(-((buf->st_size + block_size - 1)
								 >> block_log));

		free(dir_ent->inode);
		dir_ent->inode = NULL;
	} else
		dir_ent->inode->nlink --;
}


static struct inode_info *lookup_inode3(struct stat *buf, struct pseudo_dev *pseudo,
	char *symlink, int bytes)
{
	static char warned = FALSE;
	int ino_hash = INODE_HASH(buf->st_dev, buf->st_ino);
	struct inode_info *inode;

	if(buf->st_mtime < 0) {
		/* Squashfs cannot store timestamps before the epoch
		 * (1970-01-01), and so round up to zero.  But warn
		 * the first time this happens
		 */
		if(!warned) {
			ERROR("WARNING: File has timestamp before the epoch of "
				"1970-01-01, this cannot be\nstored in "
				"Squashfs.  Rounding to 1970-01-01.\nFurther "
				"messages are supressed.\n");
			warned = TRUE;
		}

		buf->st_mtime = 0;
	}

	/*
	 * Look-up inode in hash table, if it already exists we have a
	 * hardlink, so increment the nlink count and return it.
	 * Don't do the look-up for directories because Unix/Linux doesn't
	 * allow hard-links to directories.
	 */
	if ((buf->st_mode & S_IFMT) != S_IFDIR && !no_hardlinks) {
		for(inode = inode_info[ino_hash]; inode; inode = inode->next) {
			if(memcmp(buf, &inode->buf, sizeof(struct stat)) == 0) {
				inode->nlink ++;
				return inode;
			}
		}
	}

	if((buf->st_mode & S_IFMT) == S_IFREG)
		progress_bar_size((buf->st_size + block_size - 1)
							 >> block_log);

	inode = MALLOC(sizeof(struct inode_info) + bytes);

	if(bytes)
		memcpy(&inode->symlink, symlink, bytes);
	memcpy(&inode->buf, buf, sizeof(struct stat));
	inode->scanned = FALSE;
	inode->read = FALSE;
	inode->root_entry = FALSE;
	inode->pseudo = pseudo;
	inode->inode = SQUASHFS_INVALID_BLK;
	inode->nlink = 1;
	inode->inode_number = 0;
	inode->dummy_root_dir = FALSE;
	inode->xattr = NULL;
	inode->tarfile = FALSE;

	/*
	 * Copy filesystem wide defaults into inode, these filesystem
	 * wide defaults may be altered on an individual inode basis by
	 * user specified actions
	 *
	*/
	inode->no_fragments = no_fragments;
	inode->always_use_fragments = always_use_fragments;
	inode->noD = noD;
	inode->noF = noF;

	inode->next = inode_info[ino_hash];
	inode_info[ino_hash] = inode;

	return inode;
}


static struct inode_info *lookup_inode2(struct stat *buf, struct pseudo_dev *pseudo)
{
	return lookup_inode3(buf, pseudo, NULL, 0);
}


struct inode_info *lookup_inode(struct stat *buf)
{
	return lookup_inode2(buf, NULL);
}


static inline void alloc_inode_no(struct inode_info *inode, unsigned int use_this)
{
	if (inode->inode_number == 0) {
		inode->inode_number = use_this ? : inode_no ++;
	}
}


struct dir_info *create_dir(char *pathname, char *subpath, unsigned int depth)
{
	struct dir_info *dir = MALLOC(sizeof(struct dir_info));

	dir->pathname = STRDUP(pathname);
	dir->subpath = STRDUP(subpath);
	dir->count = 0;
	dir->directory_count = 0;
	dir->dir_is_ldir = TRUE;
	dir->list = NULL;
	dir->depth = depth;
	dir->excluded = 0;

	return dir;
}


struct dir_ent *lookup_name(struct dir_info *dir, char *name)
{
	struct dir_ent *dir_ent = dir->list;

	for(; dir_ent && strcmp(dir_ent->name, name) != 0;
					dir_ent = dir_ent->next);

	return dir_ent;
}


struct dir_ent *create_dir_entry(char *name, char *source_name,
	char *nonstandard_pathname, struct dir_info *dir)
{
	struct dir_ent *dir_ent = MALLOC(sizeof(struct dir_ent));

	dir_ent->name = name;
	dir_ent->source_name = source_name;
	dir_ent->nonstandard_pathname = nonstandard_pathname;
	dir_ent->our_dir = dir;
	dir_ent->inode = NULL;
	dir_ent->next = NULL;

	return dir_ent;
}


void add_dir_entry(struct dir_ent *dir_ent, struct dir_info *sub_dir,
	struct inode_info *inode_info)
{
	struct dir_info *dir = dir_ent->our_dir;

	if(sub_dir)
		sub_dir->dir_ent = dir_ent;
	dir_ent->inode = inode_info;
	dir_ent->dir = sub_dir;

	dir_ent->next = dir->list;
	dir->list = dir_ent;
	dir->count++;
}


static inline void add_dir_entry2(char *name, char *source_name,
	char *nonstandard_pathname, struct dir_info *sub_dir,
	struct inode_info *inode_info, struct dir_info *dir)
{
	struct dir_ent *dir_ent = create_dir_entry(name, source_name,
		nonstandard_pathname, dir);


	add_dir_entry(dir_ent, sub_dir, inode_info);
}


void free_dir_entry(struct dir_ent *dir_ent)
{
	if(dir_ent->name)
		free(dir_ent->name);

	if(dir_ent->source_name)
		free(dir_ent->source_name);

	if(dir_ent->nonstandard_pathname)
		free(dir_ent->nonstandard_pathname);

	/* if this entry has been associated with an inode, then we need
	 * to update the inode nlink count */
	dec_nlink_inode(dir_ent);

	free(dir_ent);
}


static inline void add_excluded(struct dir_info *dir)
{
	dir->excluded ++;
}


squashfs_inode do_directory_scans(struct dir_ent *dir_ent, int progress)
{
	squashfs_inode inode;
	struct pseudo *pseudo = get_pseudo();

	/*
	 * Process most actions and any pseudo files
	 */

	/* if there's a root pseudo definition skip it, it will have already
	 * been handled if no sources specified on command line.
	 * If sources have been specified, then just ignore it, as sources
	 * on the command line take precedence.
	 */
	if(pseudo != NULL && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0) {
		if(pseudo->head->xattr)
			root_dir->dir_ent->inode->xattr = pseudo->head->xattr;

		pseudo = pseudo->head->pseudo;
	}

	if(actions() || pseudo)
		dir_scan2(root_dir, pseudo);

	/*
	 * Process move actions
	 */
	if(move_actions()) {
		dir_scan3(root_dir);
		do_move_actions();
	}

	/*
	 * Process prune actions
	 */
	if(prune_actions()) {
		dir_scan4(root_dir, TRUE);
		dir_scan4(root_dir, FALSE);
	}

	/*
	 * Process empty actions
	 */
	if(empty_actions())
		dir_scan5(root_dir);

 	/*
	 * Sort directories and compute the inode numbers
	 */
	dir_scan6(root_dir);

	if(mkfs_inode_opt || root_inode_opt)
		inode_time_latest = get_time(inode_time_latest);

	if(root_inode_opt)
		dir_ent->inode->buf.st_mtime = inode_time_latest;

	alloc_inode_no(dir_ent->inode, root_inode_number);

	/* Increase the progress bar by 5%, and map the inode count to
	 * that 5%.  This means the progress bar will continue to show
	 * progress after all the file data blocks have been processed
	 */
	progress_bar_metadata(inode_no - inode_start_no);

	eval_actions(root_dir, dir_ent);

	if(sorted)
		generate_file_priorities(root_dir, 0,
			&root_dir->dir_ent->inode->buf);

	if(appending) {
		sigset_t sigmask;

		restore_thread = init_restore_thread();
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGINT);
		sigaddset(&sigmask, SIGTERM);
		sigaddset(&sigmask, SIGUSR1);
		if(pthread_sigmask(SIG_BLOCK, &sigmask, NULL) != 0)
			BAD_ERROR("Failed to set signal mask\n");
		write_destination(fd, SQUASHFS_START, 4, "\0\0\0\0");
	}

	queue_put(to_reader, root_dir);

	if(sorted)
		sort_files_and_write(root_dir);
	else if(!tarfile)
		dir_scan7(root_dir);

	sync_orderer_thread();

	dir_scan8(&inode, root_dir);
	inc_meta_progress_bar();
	dir_ent->inode->inode = inode;
	dir_ent->inode->type = SQUASHFS_DIR_TYPE;

	return inode;
}


static squashfs_inode scan_single(char *pathname, int progress)
{
	struct stat buf;
	struct dir_ent *dir_ent;

	if(appending)
		root_dir = dir_scan1(pathname, "", paths, scan1_single_readdir, 1);
	else
		root_dir = dir_scan1(pathname, "", paths, scan1_readdir, 1);

	if(root_dir == NULL)
		BAD_ERROR("Failed to scan source directory\n");

	/* Create root directory dir_ent and associated inode, and connect
	 * it to the root directory dir_info structure */
	dir_ent = create_dir_entry("", NULL, pathname, scan1_opendir("", "", 0));

	if(lstat(pathname, &buf) == -1)
		/* source directory has disappeared? */
		BAD_ERROR("Cannot stat source directory %s because %s\n",
						pathname, strerror(errno));
	if(global_dir_mode_opt) {
		if(pseudo_override)
			buf.st_mode = mode_execute(global_dir_mode, buf.st_mode);
	} else if(root_mode_opt)
		buf.st_mode = mode_execute(root_mode, buf.st_mode);

	if(root_uid_opt)
		buf.st_uid = root_uid;

	if(root_gid_opt)
		buf.st_gid = root_gid;

	if(root_time_opt)
		buf.st_mtime = root_time;

	if(pseudo_override && global_uid_opt)
		buf.st_uid = global_uid;

	if(pseudo_override && global_gid_opt)
		buf.st_gid = global_gid;

	dir_ent->inode = lookup_inode(&buf);
	dir_ent->dir = root_dir;
	root_dir->dir_ent = dir_ent;

	return do_directory_scans(dir_ent, progress);
}


static squashfs_inode scan_encomp(int progress)
{
	struct stat buf;
	struct dir_ent *dir_ent;

	root_dir = dir_scan1("", "", paths, scan1_encomp_readdir, 1);
	if(root_dir == NULL)
		BAD_ERROR("Failed to scan source\n");

	/* Create root directory dir_ent and associated inode, and connect
	 * it to the root directory dir_info structure */
	dir_ent = create_dir_entry("", NULL, "", scan1_opendir("", "", 0));

	/*
	 * dummy top level directory, multiple sources specified on
	 * command line
	 */
	memset(&buf, 0, sizeof(buf));
	buf.st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFDIR;
	if(global_dir_mode_opt) {
		if(pseudo_override)
			buf.st_mode = mode_execute(global_dir_mode, buf.st_mode);
	} else if(root_mode_opt)
		buf.st_mode = mode_execute(root_mode, buf.st_mode);
	if(root_uid_opt)
		buf.st_uid = root_uid;
	else
		buf.st_uid = getuid();
	if(root_gid_opt)
		buf.st_gid = root_gid;
	else
		buf.st_gid = getgid();
	if(root_time_opt)
		buf.st_mtime = root_time;
	else
		buf.st_mtime = time(NULL);
	if(pseudo_override && global_uid_opt)
		buf.st_uid = global_uid;

	if(pseudo_override && global_gid_opt)
		buf.st_gid = global_gid;

	buf.st_dev = 0;
	buf.st_ino = 0;
	dir_ent->inode = lookup_inode(&buf);
	dir_ent->inode->dummy_root_dir = TRUE;
	dir_ent->dir = root_dir;
	root_dir->dir_ent = dir_ent;

	return do_directory_scans(dir_ent, progress);
}


static squashfs_inode dir_scan(int directory, int progress)
{
	int single = !keep_as_directory && source == 1;

	if(single && directory)
		return scan_single(source_path[0], progress);
	else
		return scan_encomp(progress);
}


/*
 * dir_scan1 routines...
 * These scan the source directories into memory for processing.
 * Exclude actions are processed here (in contrast to the other actions)
 * because they affect what is scanned.
 */
struct dir_info *scan1_opendir(char *pathname, char *subpath, unsigned int depth)
{
	struct dir_info *dir = MALLOC(sizeof(struct dir_info));

	if(pathname[0] != '\0') {
		dir->linuxdir = opendir(pathname);
		if(dir->linuxdir == NULL) {
			free(dir);
			return NULL;
		}
	}

	dir->pathname = STRDUP(pathname);
	dir->subpath = STRDUP(subpath);
	dir->count = 0;
	dir->directory_count = 0;
	dir->dir_is_ldir = TRUE;
	dir->list = NULL;
	dir->depth = depth;
	dir->excluded = 0;

	return dir;
}


static struct dir_ent *scan1_encomp_readdir(struct dir_info *dir)
{
	static int index = 0;

	if(dir->count < old_root_entries) {
		int i;

		for(i = 0; i < old_root_entries; i++) {
			if(old_root_entry[i].inode.type == SQUASHFS_DIR_TYPE)
				dir->directory_count ++;
			add_dir_entry2(old_root_entry[i].name, NULL, NULL, NULL,
				&old_root_entry[i].inode, dir);
		}
	}

	while(index < source) {
		char *basename = NULL;
		char *dir_name = getbase(source_path[index]);
		int pass = 1;

		if(dir_name == NULL) {
			ERROR_START("Bad source directory %s",
				source_path[index]);
			ERROR_EXIT(" - skipping ...\n");
			index ++;
			continue;
		}
		dir_name = STRDUP(dir_name);
		for(;;) {
			struct dir_ent *dir_ent = dir->list;

			for(; dir_ent && strcmp(dir_ent->name, dir_name) != 0;
				dir_ent = dir_ent->next);
			if(dir_ent == NULL)
				break;
			ERROR("Source directory entry %s already used! - trying"
				" ", dir_name);
			if(pass == 1)
				basename = dir_name;
			else
				free(dir_name);
			ASPRINTF(&dir_name, "%s_%d", basename, pass++);
			ERROR("%s\n", dir_name);
		}

		if(one_file_system && source > 1)
			cur_dev = source_dev[index];

		return create_dir_entry(dir_name, basename,
			STRDUP(source_path[index ++]), dir);
	}
	return NULL;
}


static struct dir_ent *scan1_single_readdir(struct dir_info *dir)
{
	struct dirent *d_name;
	int i;

	if(dir->count < old_root_entries) {
		for(i = 0; i < old_root_entries; i++) {
			if(old_root_entry[i].inode.type == SQUASHFS_DIR_TYPE)
				dir->directory_count ++;
			add_dir_entry2(old_root_entry[i].name, NULL, NULL, NULL,
				&old_root_entry[i].inode, dir);
		}
	}

	if((d_name = readdir(dir->linuxdir)) != NULL) {
		char *basename = NULL;
		char *dir_name = STRDUP(d_name->d_name);
		int pass = 1;

		for(;;) {
			struct dir_ent *dir_ent = dir->list;

			for(; dir_ent && strcmp(dir_ent->name, dir_name) != 0;
				dir_ent = dir_ent->next);
			if(dir_ent == NULL)
				break;
			ERROR("Source directory entry %s already used! - trying"
				" ", dir_name);
			if (pass == 1)
				basename = dir_name;
			else
				free(dir_name);
			ASPRINTF(&dir_name, "%s_%d", d_name->d_name, pass++);
			ERROR("%s\n", dir_name);
		}
		return create_dir_entry(dir_name, basename, NULL, dir);
	}

	return NULL;
}


static struct dir_ent *scan1_readdir(struct dir_info *dir)
{
	struct dirent *d_name = readdir(dir->linuxdir);

	return d_name ?
		create_dir_entry(STRDUP(d_name->d_name), NULL, NULL, dir) :
		NULL;
}


static void scan1_freedir(struct dir_info *dir)
{
	if(dir->pathname[0] != '\0')
		closedir(dir->linuxdir);
}


static struct dir_info *dir_scan1(char *filename, char *subpath,
	struct pathnames *paths,
	struct dir_ent *(_readdir)(struct dir_info *), unsigned int depth)
{
	struct dir_info *dir = scan1_opendir(filename, subpath, depth);
	struct dir_ent *dir_ent;

	if(dir == NULL) {
		ERROR_START("Could not open %s", filename);
		ERROR_EXIT(", skipping...\n");
		return NULL;
	}

	if(max_depth_opt && depth > max_depth) {
		add_excluded(dir);
		scan1_freedir(dir);
		return dir;
	}

	while((dir_ent = _readdir(dir))) {
		struct dir_info *sub_dir;
		struct stat buf;
		struct pathnames *new = NULL;
		char *filename = pathname(dir_ent);
		char *subpath = NULL;
		char *dir_name = dir_ent->name;
		int create_empty_directory = FALSE;

		if(strcmp(dir_name, ".") == 0 || strcmp(dir_name, "..") == 0) {
			free_dir_entry(dir_ent);
			continue;
		}

		if(lstat(filename, &buf) == -1) {
			ERROR_START("Cannot stat dir/file %s because %s",
				filename, strerror(errno));
			ERROR_EXIT(", ignoring\n");
			free_dir_entry(dir_ent);
			continue;
		}

		if(one_file_system) {
			if(buf.st_dev != cur_dev) {
				if(!S_ISDIR(buf.st_mode) || one_file_system_x) {
					ERROR("%s is on a different filesystem, ignored\n", filename);
					free_dir_entry(dir_ent);
					continue;
				}

				create_empty_directory = TRUE;
			}
		}

		if((buf.st_mode & S_IFMT) != S_IFREG &&
					(buf.st_mode & S_IFMT) != S_IFDIR &&
					(buf.st_mode & S_IFMT) != S_IFLNK &&
					(buf.st_mode & S_IFMT) != S_IFCHR &&
					(buf.st_mode & S_IFMT) != S_IFBLK &&
					(buf.st_mode & S_IFMT) != S_IFIFO &&
					(buf.st_mode & S_IFMT) != S_IFSOCK) {
			ERROR_START("File %s has unrecognised filetype %d",
				filename, buf.st_mode & S_IFMT);
			ERROR_EXIT(", ignoring\n");
			free_dir_entry(dir_ent);
			continue;
		}

		if(old_exclude && old_excluded(filename, &buf)) {
			add_excluded(dir);
			free_dir_entry(dir_ent);
			continue;
		}

		if(!old_exclude && excluded(dir_name, paths, &new)) {
			add_excluded(dir);
			free_dir_entry(dir_ent);
			continue;
		}

		if(exclude_actions()) {
			subpath = subpathname(dir_ent);
			
			if(eval_exclude_actions(dir_name, filename, subpath,
							&buf, depth, dir_ent)) {
				add_excluded(dir);
				free_dir_entry(dir_ent);
				continue;
			}
		}

		switch(buf.st_mode & S_IFMT) {
		case S_IFDIR:
			if(subpath == NULL)
				subpath = subpathname(dir_ent);

			if(create_empty_directory) {
				ERROR("%s is on a different filesystem, creating empty directory\n", filename);
				sub_dir = create_dir(filename, subpath, depth + 1);
			} else
				sub_dir = dir_scan1(filename, subpath, new,
						scan1_readdir, depth + 1);
			if(sub_dir) {
				dir->directory_count ++;
				add_dir_entry(dir_ent, sub_dir,
							lookup_inode(&buf));
			} else
				free_dir_entry(dir_ent);
			break;
		case S_IFLNK: {
			int byte;
			static char buff[65536]; /* overflow safe */

			byte = readlink(filename, buff, 65536);
			if(byte == -1) {
				ERROR_START("Failed to read symlink %s",
								filename);
				ERROR_EXIT(", ignoring\n");
			} else if(byte == 65536) {
				ERROR_START("Symlink %s is greater than 65535 "
							"bytes!", filename);
				ERROR_EXIT(", ignoring\n");
			} else {
				/* readlink doesn't 0 terminate the returned
				 * path */
				buff[byte] = '\0';
				add_dir_entry(dir_ent, NULL, lookup_inode3(&buf,
							 NULL, buff, byte + 1));
			}
			break;
		}
		default:
			add_dir_entry(dir_ent, NULL, lookup_inode(&buf));
		}

		free(new);
	}

	scan1_freedir(dir);

	return dir;
}


/*
 * dir_scan2 routines...
 * This processes most actions and any pseudo files
 */
static struct dir_ent *scan2_readdir(struct dir_info *dir, struct dir_ent *dir_ent)
{
	if (dir_ent == NULL)
		dir_ent = dir->list;
	else
		dir_ent = dir_ent->next;

	for(; dir_ent && dir_ent->inode->root_entry; dir_ent = dir_ent->next);

	return dir_ent;	
}


static void dir_scan2(struct dir_info *dir, struct pseudo *pseudo)
{
	struct dir_ent *dirent = NULL;
	struct pseudo_entry *pseudo_ent;
	struct stat buf;
	int empty = dir->count == 0;
	
	while((dirent = scan2_readdir(dir, dirent)) != NULL) {
		struct inode_info *inode_info = dirent->inode;
		struct stat *buf = &inode_info->buf;
		char *name = dirent->name;

		eval_actions(root_dir, dirent);

		if(pseudo_override && global_uid_opt)
			buf->st_uid = global_uid;

		if(pseudo_override && global_gid_opt)
			buf->st_gid = global_gid;
			
		if((buf->st_mode & S_IFMT) == S_IFDIR) {
			if(pseudo_override && global_dir_mode_opt)
				buf->st_mode = mode_execute(global_dir_mode, buf->st_mode);
			dir_scan2(dirent->dir, pseudo_subdir(name, pseudo));
		} else if(pseudo_override && global_file_mode_opt)
			buf->st_mode = mode_execute(global_file_mode, buf->st_mode);
	}

	/*
	 * Process pseudo modify and add (file, directory etc) definitions
	 */
	while((pseudo_ent = pseudo_readdir(pseudo)) != NULL) {
		struct dir_ent *dir_ent = NULL;

		if(appending && dir->depth == 1) {
			dir_ent = lookup_name(dir, pseudo_ent->name);

			if(dir_ent && dir_ent->inode->root_entry) {
				BAD_ERROR("Pseudo files: File \"%s\" "
					"already exists in root directory of "
					"the\nfilesystem being appended to. "
					"Pseudo definitions can\'t modify it "
					"or (if directory) add files to it\n",
					pseudo_ent->name);
			}
		}

		if((!appending || dir->depth != 1) && !empty)
			dir_ent = lookup_name(dir, pseudo_ent->name);

		if(pseudo_ent->dev == NULL) {
			if(dir_ent == NULL && pseudo_dir) {
				struct dir_ent *dir_ent = create_dir_entry(pseudo_ent->name, NULL,
						pseudo_ent->pathname, dir);
				char *subpath = subpathname(dir_ent);
				struct dir_info *sub_dir = scan1_opendir("", subpath, dir->depth + 1);

				memset(&buf, 0, sizeof(buf));
				buf.st_mode = pseudo_dir->buf->mode;
				buf.st_uid = pseudo_dir->buf->uid;
				buf.st_gid = pseudo_dir->buf->gid;
				buf.st_mtime = pseudo_dir->buf->mtime;
				buf.st_ino = pseudo_dir->buf->ino;

				dir_scan2(sub_dir, pseudo_ent->pseudo);
				dir->directory_count ++;
				add_dir_entry(dir_ent, sub_dir, lookup_inode2(&buf, pseudo_dir));
				continue;
			} else if(dir_ent == NULL && pseudo_ent->pseudo)
				BAD_ERROR("Pathname \"%s\" does not exist in "
					"filesystem.  Some pseudo definitions "
					"will not be created.\n",
					pseudo_ent->pathname);
			else if(dir_ent && !S_ISDIR(dir_ent->inode->buf.st_mode) &&
								pseudo_ent->pseudo)
				BAD_ERROR("Pathname \"%s\" is not a directory.  Some "
					"pseudo definitions will not be created.\n",
					pseudo_ent->pathname);
			else
				continue;
		}

		if(pseudo_ent->dev->type == 'm' || pseudo_ent->dev->type == 'M') {
			struct stat *buf;
			if(dir_ent == NULL) {
				ERROR_START("Pseudo modify file \"%s\" does "
					"not exist in source filesystem.",
					pseudo_ent->pathname);
				ERROR_EXIT("  Ignoring.\n");
				continue;
			}
			buf = &dir_ent->inode->buf;
			buf->st_mode = (buf->st_mode & S_IFMT) |
				pseudo_ent->dev->buf->mode;
			buf->st_uid = pseudo_ent->dev->buf->uid;
			buf->st_gid = pseudo_ent->dev->buf->gid;
			if(pseudo_ent->dev->type == 'M')
				buf->st_mtime = pseudo_ent->dev->buf->mtime;
			continue;
		}

		if(dir_ent) {
			ERROR_START("Pseudo file \"%s\" exists in source "
				"filesystem \"%s\".", pseudo_ent->pathname,
				pathname(dir_ent));
			ERROR_EXIT("\nIgnoring, exclude it (-e/-ef) to override.\n");
			continue;
		}

		if(pseudo_ent->dev->type != 'l') {
			memset(&buf, 0, sizeof(buf));
			buf.st_mode = pseudo_ent->dev->buf->mode;
			buf.st_uid = pseudo_ent->dev->buf->uid;
			buf.st_gid = pseudo_ent->dev->buf->gid;
			buf.st_rdev = makedev(pseudo_ent->dev->buf->major,
				pseudo_ent->dev->buf->minor);
			buf.st_mtime = pseudo_ent->dev->buf->mtime;
			buf.st_ino = pseudo_ent->dev->buf->ino;

			if(pseudo_ent->dev->type == 'r') {
				buf.st_size = pseudo_ent->dev->data->length;
				if(pseudo_ent->dev->data->sparse == FALSE)
					buf.st_blocks = (buf.st_size + 511) >> 9;
			}
		}

		if(pseudo_ent->dev->type == 'd') {
			struct dir_ent *dir_ent =
				create_dir_entry(pseudo_ent->name, NULL,
						pseudo_ent->pathname, dir);
			char *subpath = subpathname(dir_ent);
			struct dir_info *sub_dir = scan1_opendir("", subpath,
						dir->depth + 1);
			dir_scan2(sub_dir, pseudo_ent->pseudo);
			dir->directory_count ++;
			add_dir_entry(dir_ent, sub_dir,
				lookup_inode2(&buf, pseudo_ent->dev));
		} else if(pseudo_ent->dev->type == 's') {
			add_dir_entry2(pseudo_ent->name, NULL,
				pseudo_ent->pathname, NULL,
				lookup_inode3(&buf, pseudo_ent->dev,
				pseudo_ent->dev->symlink,
				strlen(pseudo_ent->dev->symlink) + 1), dir);
		} else if(pseudo_ent->dev->type == 'l') {
			if(S_ISLNK(pseudo_ent->dev->linkbuf->st_mode)) {
				int byte;
				static char buff[65536]; /* overflow safe */

				byte = readlink(pseudo_ent->dev->linkname, buff, 65536);
				if(byte == -1) {
					ERROR_START("Failed to read symlink %s", pseudo_ent->dev->linkname);
					ERROR_EXIT(", ignoring\n");
				} else if(byte == 65536) {
					ERROR_START("Symlink %s is greater than 65535 bytes!", pseudo_ent->dev->linkname);
					ERROR_EXIT(", ignoring\n");
				} else {
					/* readlink doesn't 0 terminate the returned path */
					buff[byte] = '\0';
					add_dir_entry2(pseudo_ent->name, NULL, pseudo_ent->dev->linkname, NULL,
							lookup_inode3(pseudo_ent->dev->linkbuf, NULL, buff, byte + 1), dir);
				}
			} else
				add_dir_entry2(pseudo_ent->name, NULL,
					pseudo_ent->dev->linkname, NULL,
					lookup_inode(pseudo_ent->dev->linkbuf), dir);
		} else {
			add_dir_entry2(pseudo_ent->name, NULL,
				pseudo_ent->pathname, NULL,
				lookup_inode2(&buf, pseudo_ent->dev), dir);
		}
	}

	/*
	 * Process pseudo xattr definitions
	 */
	if(pseudo)
		pseudo->current = NULL;

	while((pseudo_ent = pseudo_readdir(pseudo)) != NULL) {
		struct dir_ent *dir_ent = NULL;

		if(pseudo_ent->xattr == NULL)
			continue;

		dir_ent = lookup_name(dir, pseudo_ent->name);
		if(dir_ent == NULL)
			BAD_ERROR("File \"%s\" does not exist, can not add Pseudo xattr to it.\n",
				pseudo_ent->pathname);

		dir_ent->inode->xattr = pseudo_ent->xattr;
	}
}


/*
 * dir_scan3 routines...
 * This processes the move action
 */
static void dir_scan3(struct dir_info *dir)
{
	struct dir_ent *dir_ent = NULL;

	while((dir_ent = scan2_readdir(dir, dir_ent)) != NULL) {

		eval_move_actions(root_dir, dir_ent);

		if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			dir_scan3(dir_ent->dir);
	}
}


/*
 * dir_scan4 routines...
 * This processes the prune action.  This action is designed to do fine
 * grained tuning of the in-core directory structure after the exclude,
 * move and pseudo actions have been performed.  This allows complex
 * tests to be performed which are impossible at exclude time (i.e.
 * tests which rely on the in-core directory structure)
 */
void free_dir(struct dir_info *dir)
{
	struct dir_ent *dir_ent = dir->list;

	while(dir_ent) {
		struct dir_ent *tmp = dir_ent;

		if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			if(dir_ent->dir)
				free_dir(dir_ent->dir);

		dir_ent = dir_ent->next;
		free_dir_entry(tmp);
	}

	free(dir->pathname);
	free(dir->subpath);
	free(dir);
}
	

static void dir_scan4(struct dir_info *dir, int symlink)
{
	struct dir_ent *dir_ent = dir->list, *prev = NULL;

	while(dir_ent) {
		if(dir_ent->inode->root_entry) {
			prev = dir_ent;
			dir_ent = dir_ent->next;
			continue;
		}

		if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			dir_scan4(dir_ent->dir, symlink);

		if(symlink != ((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFLNK)) {
			prev = dir_ent;
			dir_ent = dir_ent->next;
			continue;
		}

		if(eval_prune_actions(root_dir, dir_ent)) {
			struct dir_ent *tmp = dir_ent;

			if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR) {
				free_dir(dir_ent->dir);
				dir->directory_count --;
			}

			dir->count --;

			/* remove dir_ent from list */
			dir_ent = dir_ent->next;
			if(prev)
				prev->next = dir_ent;
			else
				dir->list = dir_ent;
			
			/* free it */
			free_dir_entry(tmp);

			add_excluded(dir);
			continue;
		}

		prev = dir_ent;
		dir_ent = dir_ent->next;
	}
}


/*
 * dir_scan5 routines...
 * This processes the empty action.  This action has to be processed after
 * all other actions because the previous exclude and move actions and the
 * pseudo actions affect whether a directory is empty
 */
static void dir_scan5(struct dir_info *dir)
{
	struct dir_ent *dir_ent = dir->list, *prev = NULL;

	while(dir_ent) {
		if(dir_ent->inode->root_entry) {
			prev = dir_ent;
			dir_ent = dir_ent->next;
			continue;
		}

		if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR) {
			dir_scan5(dir_ent->dir);

			if(eval_empty_actions(root_dir, dir_ent)) {
				struct dir_ent *tmp = dir_ent;

				/*
				 * delete sub-directory, this is by definition
				 * empty
				 */
				free(dir_ent->dir->pathname);
				free(dir_ent->dir->subpath);
				free(dir_ent->dir);

				/* remove dir_ent from list */
				dir_ent = dir_ent->next;
				if(prev)
					prev->next = dir_ent;
				else
					dir->list = dir_ent;
			
				/* free it */
				free_dir_entry(tmp);

				/* update counts */
				dir->directory_count --;
				dir->count --;
				add_excluded(dir);
				continue;
			}
		}

		prev = dir_ent;
		dir_ent = dir_ent->next;
	}
}


/*
 * dir_scan6 routines...
 * This sorts every directory and computes the inode numbers
 */

/*
 * Instantiate bottom up linked list merge sort.
 *
 * Qsort and other O(n log n) algorithms work well with arrays but not
 * linked lists.  Merge sort another O(n log n) sort algorithm on the other hand
 * is not ideal for arrays (as it needs an additonal n storage locations
 * as sorting is not done in place), but it is ideal for linked lists because
 * it doesn't require any extra storage,
 */ 
SORT(sort_directory, dir_ent, name, next);

static void dir_scan6(struct dir_info *dir)
{
	struct dir_ent *dir_ent;
	unsigned int byte_count = 0;

	sort_directory(&(dir->list), dir->count);

	for(dir_ent = dir->list; dir_ent; dir_ent = dir_ent->next) {
		byte_count += strlen(dir_ent->name) +
			sizeof(struct squashfs_dir_entry);

		if(dir_ent->inode->root_entry)
			continue;

		if((mkfs_inode_opt || root_inode_opt) && inode_time_latest < dir_ent->inode->buf.st_mtime)
			inode_time_latest = dir_ent->inode->buf.st_mtime;

		alloc_inode_no(dir_ent->inode, 0);

		if((dir_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			dir_scan6(dir_ent->dir);
	}

	if((dir->count < 257 && byte_count < SQUASHFS_METADATA_SIZE))
		dir->dir_is_ldir = FALSE;
}


/*
 * dir_scan7 routines...
 * This writes out the file data to the destination
 */
static void dir_scan7(struct dir_info *dir)
{
	struct dir_ent *dir_ent;
	int duplicate_file;

	for(dir_ent = dir->list; dir_ent; dir_ent = dir_ent->next) {
		struct inode_info *inode = dir_ent->inode;

		if(inode->root_entry)
			continue;
		else if(S_ISREG(inode->buf.st_mode) && inode->read == FALSE) {
			inode->file = write_file(dir_ent, &duplicate_file);
			inode->read = TRUE;
			INFO("file %s, uncompressed size %lld " "bytes %s\n",
				subpathname(dir_ent), (long long)
				inode->buf.st_size, duplicate_file ?
				"DUPLICATE" : "");
		} else if(S_ISREG(inode->buf.st_mode) && inode->read)
			INFO("file %s, uncompressed size %lld bytes LINK\n",
				subpathname(dir_ent), (long long) inode->buf.st_size);
		else if(S_ISDIR(inode->buf.st_mode))
			dir_scan7(dir_ent->dir);
	}
}


/*
 * dir_scan8 routines...
 * This generates the filesystem metadata and writes it out to the destination
 */
static void scan8_init_dir(struct directory *dir)
{
	dir->buff = MALLOC(SQUASHFS_METADATA_SIZE);
	dir->size = SQUASHFS_METADATA_SIZE;
	dir->offset = 0;
	dir->index_count_offset = 0;
	dir->entry_count = 256;
	dir->entry_count_offset = 0;
	dir->have_dir_header = FALSE;
	dir->index = NULL;
	dir->i_count = dir->i_size = 0;
}


static struct dir_ent *scan8_readdir(struct directory *dir, struct dir_info *dir_info,
	struct dir_ent *dir_ent)
{
	if (dir_ent == NULL)
		dir_ent = dir_info->list;
	else
		dir_ent = dir_ent->next;

	for(; dir_ent && dir_ent->inode->root_entry; dir_ent = dir_ent->next)
		add_dir(dir_ent->inode->inode, dir_ent->inode->inode_number,
			dir_ent->name, dir_ent->inode->type, dir);

	return dir_ent;	
}


static void scan8_freedir(struct directory *dir)
{
	if(dir->index)
		free(dir->index);
	free(dir->buff);
}


static void dir_scan8(squashfs_inode *inode, struct dir_info *dir_info)
{
	int squashfs_type;
	struct directory dir;
	struct dir_ent *dir_ent = NULL;
	struct file_info *file;
	
	scan8_init_dir(&dir);
	
	while((dir_ent = scan8_readdir(&dir, dir_info, dir_ent)) != NULL) {
		struct stat *buf = &dir_ent->inode->buf;

		update_info(dir_ent);

		if(dir_ent->inode->inode == SQUASHFS_INVALID_BLK) {
			switch(buf->st_mode & S_IFMT) {
				case S_IFREG:
					if(dir_ent->inode->tarfile)
						file = dir_ent->inode->tar_file->file;
					else
						file = dir_ent->inode->file;
					squashfs_type = SQUASHFS_FILE_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, file->file_size,
						get_virt_disk(file->start),
						file->blocks, file->block_list,
						file->fragment, NULL,
						file->sparse);
					if((duplicate_checking == FALSE &&
							!(tarfile && no_hardlinks)) ||
							file->file_size == 0) {
						free_fragment(file->fragment);
						free(file->block_list);
						free(file);
					}
					break;

				case S_IFDIR:
					squashfs_type = SQUASHFS_DIR_TYPE;
					dir_scan8(inode, dir_ent->dir);
					break;

				case S_IFLNK:
					squashfs_type = SQUASHFS_SYMLINK_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("symbolic link %s inode 0x%llx\n",
						subpathname(dir_ent), *inode);
					sym_count ++;
					break;

				case S_IFCHR:
					squashfs_type = SQUASHFS_CHRDEV_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("character device %s inode 0x%llx"
						"\n", subpathname(dir_ent),
						*inode);
					dev_count ++;
					break;

				case S_IFBLK:
					squashfs_type = SQUASHFS_BLKDEV_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("block device %s inode 0x%llx\n",
						subpathname(dir_ent), *inode);
					dev_count ++;
					break;

				case S_IFIFO:
					squashfs_type = SQUASHFS_FIFO_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("fifo %s inode 0x%llx\n",
						subpathname(dir_ent), *inode);
					fifo_count ++;
					break;

				case S_IFSOCK:
					squashfs_type = SQUASHFS_SOCKET_TYPE;
					*inode = create_inode(NULL, dir_ent,
						squashfs_type, 0, 0, 0, NULL,
						NULL, NULL, 0);
					INFO("unix domain socket %s inode "
						"0x%llx\n",
						subpathname(dir_ent), *inode);
					sock_count ++;
					break;

				default:
					BAD_ERROR("%s unrecognised file type, "
						"mode is %x\n",
						subpathname(dir_ent),
						buf->st_mode);
			}
			dir_ent->inode->inode = *inode;
			dir_ent->inode->type = squashfs_type;
			inc_meta_progress_bar();
		 } else {
			*inode = dir_ent->inode->inode;
			squashfs_type = dir_ent->inode->type;
			switch(squashfs_type) {
				case SQUASHFS_SYMLINK_TYPE:
					INFO("symbolic link %s inode 0x%llx "
						"LINK\n", subpathname(dir_ent),
						 *inode);
					break;
				case SQUASHFS_CHRDEV_TYPE:
					INFO("character device %s inode 0x%llx "
						"LINK\n", subpathname(dir_ent),
						*inode);
					break;
				case SQUASHFS_BLKDEV_TYPE:
					INFO("block device %s inode 0x%llx "
						"LINK\n", subpathname(dir_ent),
						*inode);
					break;
				case SQUASHFS_FIFO_TYPE:
					INFO("fifo %s inode 0x%llx LINK\n",
						subpathname(dir_ent), *inode);
					break;
				case SQUASHFS_SOCKET_TYPE:
					INFO("unix domain socket %s inode "
						"0x%llx LINK\n",
						subpathname(dir_ent), *inode);
					break;
			}
			hardlnk_count ++;
		}
		
		add_dir(*inode, get_inode_no(dir_ent->inode), dir_ent->name,
			squashfs_type, &dir);
	}

	*inode = write_dir(dir_info, &dir);
	INFO("directory %s inode 0x%llx\n", subpathname(dir_info->dir_ent),
		*inode);

	scan8_freedir(&dir);
}


static void handle_root_entries(struct dir_info *dir)
{
	int i;

	if(dir->count == 0) {
		for(i = 0; i < old_root_entries; i++) {
			if(old_root_entry[i].inode.type == SQUASHFS_DIR_TYPE)
				dir->directory_count ++;
			add_dir_entry2(STRDUP(old_root_entry[i].name), NULL,
				NULL, NULL, &old_root_entry[i].inode, dir);
		}
	}
}


static char *walk_source(char *source, char **pathname, char **name)
{
	char *path = source, *start;

	while(*source == '/')
		source ++;

	start = source;
	while(*source != '/' && *source != '\0')
		source ++;

	*name = STRNDUP(start, source - start);

	if(*pathname == NULL)
		*pathname = STRNDUP(path, source - path);
	else {
		char *orig = *pathname;
		int size = strlen(orig) + (source - path) + 2;

		*pathname = MALLOC(size);
		strcpy(*pathname, orig);
		strcat(*pathname, "/");
		strncat(*pathname, path, source - path);
	}

	while(*source == '/')
		source ++;

	return source;
}


static struct dir_info *add_source(struct dir_info *sdir, char *source,
		char *subpath, char *file, char **prefix,
		struct pathnames *paths, unsigned int depth)
{
	struct dir_info *sub;
	struct dir_ent *entry;
	struct pathnames *new = NULL;
	struct dir_info *dir = sdir;
	struct stat buf;
	char *name, *newsubpath = NULL;
	int res;

	if(max_depth_opt && depth > max_depth)
		return NULL;

	if(dir == NULL)
		dir = create_dir("", subpath, depth);

	if(depth == 1)
		*prefix = source[0] == '/' ? STRDUP("/") : STRDUP(".");

	if(appending && file == NULL)
		handle_root_entries(dir);

	source = walk_source(source, &file, &name);

	while(depth == 1 && (name[0] == '\0' || strcmp(name, "..") == 0
						|| strcmp(name, ".") == 0)){
		char *old = file;

		if(name[0] == '\0' || source[0] == '\0') {
			/* Ran out of pathname skipping leading ".." and "."
			 * If cpiostyle, just ignore it, find always produces
			 * these if run as "find ." or "find .." etc.
			 *
			 * If tarstyle after skipping what we *must* skip
			 * in the pathname (we can't store directories named
			 * ".." or "." or simply "/") there's nothing left after
			 * stripping (i.e. someone just typed "..", "." on
			 * the command line).  This isn't what -tarstyle is
			 * intended for, and Mksquashfs without -tarstyle
			 * can handle this scenario */
			if(cpiostyle)
				goto failed_early;
			else
				BAD_ERROR("Empty source after stripping '/', "
					"'..' and '.'.  Run Mksquashfs without "
					"-tarstyle to handle this!\n");
		}

		source = walk_source(source, &file, &name);
		if(name[0] == '\0' || strcmp(name, "..") == 0 || strcmp(name, ".") == 0)
			free(old);
		else
			*prefix = old;
	}

	if((strcmp(name, ".") == 0) || strcmp(name, "..") == 0)
		BAD_ERROR("Source path can't have '.' or '..' embedded in it with -tarstyle/-cpiostyle[0]\n");

	res = lstat(file, &buf);
	if (res == -1)
		BAD_ERROR("Can't stat %s because %s\n", file, strerror(errno));

	entry = lookup_name(dir, name);

	if(entry) {
		/*
		 * name already there.  This must be the same file, otherwise
		 * we have a clash, as we can't have two different files with
		 * the same pathname.
		 *
		 * An original root entry from the file being appended to
		 * is never the same file.
		 */
		if(entry->inode->root_entry)
			BAD_ERROR("Source %s conflicts with name in filesystem "
						"being appended to\n", name);

		res = memcmp(&buf, &(entry->inode->buf), sizeof(buf));
		if(res)
			BAD_ERROR("Can't have two different sources with same "
								"pathname\n");

		/*
		 * Matching file.
		 *
		 * For tarstyle source handling (leaf directores are
		 * recursively descended)
		 *
		 * - If we're at the leaf of the source, then we either match
		 *   or encompass this pre-existing include.  So delete any
		 *   sub-directories of this pre-existing include.
		 *
		 * - If we're not at the leaf of the source, but we're at
		 *   the leaf of the pre-existing include, then the
		 *   pre-existing include encompasses this source.  So nothing
		 *   more to do.
		 *
		 * - Otherwise this is not the leaf of the source, or the leaf
		 *   of the pre-existing include, so recurse continuing walking
		 *   the source.
		 *
		 * For cpiostyle source handling (leaf directories are not
		 * recursively descended)
		 *
		 * - If we're at the leaf of the source, then we have a
		 *   pre-existing include.  So nothing to do.
		 *
		 * - If we're not at the leaf of the source, but we're at
		 *   the leaf of the pre-existing include, then recurse
		 *   walking the source.
		 *
		 * - Otherwise this is not the leaf of the source, or the leaf
		 *   of the pre-existing include, so recurse continuing walking
		 *   the source.
		 */
		if(source[0] == '\0') {
			if(tarstyle && entry->dir) {
				free_dir(entry->dir);
				entry->dir = NULL;
			}
		} else if(S_ISDIR(buf.st_mode)) {
			if(cpiostyle || entry->dir) {
				excluded(entry->name, paths, &new);
				subpath = subpathname(entry);
				sub = add_source(entry->dir, source, subpath,
						file, prefix, new, depth + 1);
				if(sub == NULL)
					goto failed_match;
				entry->dir = sub;
				sub->dir_ent = entry;
			}
		} else
			BAD_ERROR("Source component %s is not a directory\n", name);

		free(name);
		free(file);
	} else {
		/*
		 * No matching name found.
		 *
		 * - If we're at the leaf of the source, then add it.
		 *
		 * - If we're not at the leaf of the source, we will add it,
		 *   and recurse walking the source
		 */
		if(old_exclude && old_excluded(file, &buf))
			goto failed_early;

		if(old_exclude == FALSE && excluded(name, paths, &new))
			goto failed_early;

		entry = create_dir_entry(name, NULL, file, dir);

		if(exclude_actions()) {
			newsubpath = subpathname(entry);
			if(eval_exclude_actions(name, file, newsubpath, &buf,
							depth, entry)) {
				goto failed_entry;
			}
		}

		if(source[0] == '\0' && S_ISLNK(buf.st_mode)) {
			int byte;
			static char buff[65536]; /* overflow safe */
			struct inode_info *i;

			byte = readlink(file, buff, 65536);
			if(byte == -1)
				BAD_ERROR("Failed to read source symlink %s", file);
			else if(byte == 65536)
				BAD_ERROR("Symlink %s is greater than 65536 "
						"bytes!", file);

			/* readlink doesn't 0 terminate the returned path */
			buff[byte] = '\0';
			i = lookup_inode3(&buf, NULL, buff, byte + 1);
			add_dir_entry(entry, NULL, i);
		} else if(source[0] == '\0') {
			add_dir_entry(entry, NULL, lookup_inode(&buf));
			if(S_ISDIR(buf.st_mode))
				dir->directory_count ++;
		} else if(S_ISDIR(buf.st_mode)) {
			if(newsubpath == NULL)
				newsubpath = subpathname(entry);
			sub = add_source(NULL, source, newsubpath, file, prefix,
								new, depth + 1);
			if(sub == NULL)
				goto failed_entry;
			add_dir_entry(entry, sub, lookup_inode(&buf));
			dir->directory_count ++;
		} else
			BAD_ERROR("Source component %s is not a directory\n", name);
	}

	free(new);
	return dir;

failed_early:
	free(new);
	free(name);
	free(file);
	if(sdir == NULL)
		free_dir(dir);
	return NULL;

failed_entry:
	free(new);
	free_dir_entry(entry);
	if(sdir == NULL)
		free_dir(dir);
	return NULL;

failed_match:
	free(new);
	free(name);
	free(file);
	return NULL;
}


static struct dir_info *populate_tree(struct dir_info *dir, struct pathnames *paths)
{
	struct dir_ent *entry;
	struct dir_info *new;

	for(entry = dir->list; entry; entry = entry->next) {
		if(entry->inode->root_entry)
			continue;

		if(S_ISDIR(entry->inode->buf.st_mode)) {
			struct pathnames *newp = NULL;

			excluded(entry->name, paths, &newp);

			if(entry->dir == NULL && cpiostyle) {
				entry->dir = create_dir(pathname(entry),
					subpathname(entry), dir->depth + 1);
				entry->dir->dir_ent = entry;
			} else if(entry->dir == NULL) {
				cur_dev = entry->inode->buf.st_dev;
				new = dir_scan1(pathname(entry),
					subpathname(entry), newp, scan1_readdir,
					dir->depth + 1);
				if(new == NULL)
					return NULL;

				entry->dir = new;
				new->dir_ent = entry;
			} else {
				new = populate_tree(entry->dir, newp);
				if(new == NULL)
					return NULL;
			}

			free(newp);
		}
	}

	return dir;
}


static char *get_filename_from_stdin(char terminator)
{
	static int path_max = -1;
	static int bytes = 0;
	static int size = 0;
	static char *buffer = NULL;
	static char *filename = NULL;
	static char *src = NULL;
	char *dest = filename;
	int used = 0;

	/* Get the maximum pathname size supported on this system */
	if(path_max == -1)
		path_max = get_pathmax();

	if(buffer == NULL)
		buffer = MALLOC(4096);

	while(1) {
		if(bytes == 0) {
			bytes = read_bytes(STDIN_FILENO, buffer, 4096);

			if(bytes == -1)
				BAD_ERROR("Failed to read Tar file from STDIN\n");

			if(bytes == 0) {
				if(used)
					ERROR("Got EOF when reading filename from STDIN, ignoring\n");
				free(filename);
				free(buffer);
				return NULL;
			}
			src = buffer;
		}

		if(size - used <= 1) {
			int offset = dest - filename;
			filename = REALLOC(filename, size += 100);
			dest = filename + offset;
		}

		if(*src == terminator) {
			src++;
			bytes--;
			break;
		}

		if(used >= (path_max - 1))
			BAD_ERROR("Cpiostyle input filename exceeds maximum "
				"path limit of %d bytes!\n", path_max);

		*dest++ = *src++;
		bytes --;
		used ++;
	}

	*dest = '\0';
	return filename;
}


static char *get_next_filename()
{
	static int cur = 0;
	char *filename;

	if(cpiostyle) {
		while(1) {
			filename = get_filename_from_stdin(filename_terminator);
			if(filename == NULL || strlen(filename) != 0)
				break;
		}
		return filename;
	} else if(cur < source)
		return source_path[cur ++];
	else
		return NULL;
}


static squashfs_inode process_source(int progress)
{
	int res, first = TRUE, same = FALSE;
	char *filename, *prefix, *pathname;
	struct stat buf, buf2;
	struct dir_ent *entry;
	struct dir_info *new;

	while((filename = get_next_filename())) {
		new = add_source(root_dir, filename, "", NULL, &prefix, paths, 1);

		if(new) {
			/* does argv[i] start from the same directory? */
			if(first) {
				res = lstat(prefix, &buf);
				if (res == -1)
					BAD_ERROR("Can't stat %s because %s\n",
						prefix, strerror(errno));
				first = FALSE;
				same = TRUE;
				pathname = STRDUP(prefix);
			} else if(same) {
				res = lstat(prefix, &buf2);
				if (res == -1)
					BAD_ERROR("Can't stat %s because %s\n",
						prefix, strerror(errno));

				if(buf.st_dev != buf2.st_dev ||
						buf.st_ino != buf2.st_ino)
					same = FALSE;
			}
			free(prefix);
			root_dir = new;
		}
	}

	if(root_dir == NULL) {
		/* Empty directory tree after processing the sources, and
		 * so everything was excluded.
		 * We need to create an empty directory to reflect this, and
		 * if appending, fill it with the original root directory
		 * contents */
		root_dir = scan1_opendir("", "", 0);

		if(appending)
			handle_root_entries(root_dir);
	}

	new = scan1_opendir("", "", 0);

	if(!same) {
		/*
		 * Top level directory conflict.  Create dummy
		 * top level directory
		 */
		memset(&buf, 0, sizeof(buf));
		buf.st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFDIR;
		if(global_dir_mode_opt) {
			if(pseudo_override)
				buf.st_mode = mode_execute(global_dir_mode, buf.st_mode);
		} else if(root_mode_opt)
			buf.st_mode = mode_execute(root_mode, buf.st_mode);
		if(root_uid_opt)
			buf.st_uid = root_uid;
		else
			buf.st_uid = getuid();
		if(root_gid_opt)
			buf.st_gid = root_gid;
		else
			buf.st_gid = getgid();
		if(root_time_opt)
			buf.st_mtime = root_time;
		else
			buf.st_mtime = time(NULL);
		if(pseudo_override && global_uid_opt)
			buf.st_uid = global_uid;
		if(pseudo_override && global_gid_opt)
			buf.st_gid = global_gid;

		entry = create_dir_entry("", NULL, "", new);
		entry->inode = lookup_inode(&buf);
		entry->inode->dummy_root_dir = TRUE;
	} else {
		if(global_dir_mode_opt) {
			if(pseudo_override)
				buf.st_mode = mode_execute(global_dir_mode, buf.st_mode);
		} else if(root_mode_opt)
			buf.st_mode = mode_execute(root_mode, buf.st_mode);
		if(root_uid_opt)
			buf.st_uid = root_uid;
		if(root_gid_opt)
			buf.st_gid = root_gid;
		if(root_time_opt)
			buf.st_mtime = root_time;
		if(pseudo_override && global_uid_opt)
			buf.st_uid = global_uid;
		if(pseudo_override && global_gid_opt)
			buf.st_gid = global_gid;

		entry = create_dir_entry("", NULL, pathname, new);
		entry->inode = lookup_inode(&buf);
	}


	entry->dir = root_dir;
	root_dir->dir_ent = entry;

	root_dir = populate_tree(root_dir, paths);
	if(root_dir == NULL)
		BAD_ERROR("Failed to read directory hierarchy\n");

	return do_directory_scans(entry, progress);
}


/*
 * Source directory specified as - which means no source directories
 *
 * Here the pseudo definitions will be providing the source directory
 */
static squashfs_inode no_sources(int progress)
{
	struct stat buf;
	struct dir_ent *dir_ent;
	struct pseudo_dev *pseudo_dev;
	struct pseudo *pseudo = get_pseudo();

	if(pseudo == NULL || pseudo->names != 1 || strcmp(pseudo->head->name, "/") != 0) {
		if(!pseudo_dir) {
			ERROR_START("Source is \"-\", but no pseudo definition for \"/\"\n");
			ERROR_EXIT("Did you forget to specify -cpiostyle or -tar?\n");
			EXIT_MKSQUASHFS();
		} else
			pseudo_dev = pseudo_dir;
	} else
		pseudo_dev = pseudo->head->dev;

	/* create root directory */
	root_dir = scan1_opendir("", "", 1);

	if(appending)
		handle_root_entries(root_dir);

	/* Create root directory dir_ent and associated inode, and connect
	 * it to the root directory dir_info structure */
	dir_ent = create_dir_entry("", NULL, "", scan1_opendir("", "", 0));

	memset(&buf, 0, sizeof(buf));

	buf.st_mode = pseudo_dev->buf->mode;
	if(root_mode_opt && !global_dir_mode_opt)
		buf.st_mode = mode_execute(root_mode, buf.st_mode);
	if(root_uid_opt)
		buf.st_uid = root_uid;
	else
		buf.st_uid = pseudo_dev->buf->uid;

	if(root_gid_opt)
		buf.st_gid = root_gid;
	else
		buf.st_gid = pseudo_dev->buf->gid;

	if(root_time_opt)
		buf.st_mtime = root_time;
	else
		buf.st_mtime = pseudo_dev->buf->mtime;

	buf.st_ino = pseudo_dev->buf->ino;

	dir_ent->inode = lookup_inode2(&buf, pseudo_dev);
	dir_ent->dir = root_dir;
	root_dir->dir_ent = dir_ent;

	return do_directory_scans(dir_ent, progress);
}


static unsigned int slog(unsigned int block)
{
	int i;

	for(i = 12; i <= 20; i++)
		if(block == (1 << i))
			return i;
	return 0;
}


static int old_excluded(char *filename, struct stat *buf)
{
	int i;

	for(i = 0; i < exclude; i++)
		if((exclude_paths[i].st_dev == buf->st_dev) &&
				(exclude_paths[i].st_ino == buf->st_ino))
			return TRUE;
	return FALSE;
}


#define ADD_ENTRY(buf) \
	if(exclude % EXCLUDE_SIZE == 0) \
		exclude_paths = REALLOC(exclude_paths, (exclude + EXCLUDE_SIZE) \
			* sizeof(struct exclude_info)); \
	exclude_paths[exclude].st_dev = buf.st_dev; \
	exclude_paths[exclude++].st_ino = buf.st_ino;
static int old_add_exclude(char *path)
{
	int i;
	char *filename;
	struct stat buf;

	if(path[0] == '/' || strncmp(path, "./", 2) == 0 ||
			strncmp(path, "../", 3) == 0) {
		if(lstat(path, &buf) == -1) {
			ERROR_START("Cannot stat exclude dir/file %s because "
				"%s", path, strerror(errno));
			ERROR_EXIT(", ignoring\n");
			return TRUE;
		}
		ADD_ENTRY(buf);
		return TRUE;
	}

	for(i = 0; i < source; i++) {
		ASPRINTF(&filename, "%s/%s", source_path[i], path);
		if(lstat(filename, &buf) == -1) {
			if(!(errno == ENOENT || errno == ENOTDIR)) {
				ERROR_START("Cannot stat exclude dir/file %s "
					"because %s", filename, strerror(errno));
				ERROR_EXIT(", ignoring\n");
			}
			free(filename);
			continue;
		}
		free(filename);
		ADD_ENTRY(buf);
	}
	return TRUE;
}


static void add_old_root_entry(char *name, squashfs_inode inode,
	unsigned int inode_number, int type)
{
	old_root_entry = REALLOC(old_root_entry,
		sizeof(struct old_root_entry_info) * (old_root_entries + 1));

	old_root_entry[old_root_entries].name = STRDUP(name);
	old_root_entry[old_root_entries].inode.inode = inode;
	old_root_entry[old_root_entries].inode.inode_number = inode_number;
	old_root_entry[old_root_entries].inode.type = type;
	old_root_entry[old_root_entries++].inode.root_entry = TRUE;
}


static void initialise_threads(int readq, int fragq, int bwriteq, int fwriteq,
	int freelst, char *destination_file, char *command, int overcommit)
{
	int i, res;
	sigset_t sigmask, old_mask;
	int total_mem = readq;
	int fragment_size;
	int fwriter_size;
	int bwriter_size;

	if(processors == -1)
		processors = get_nprocessors();

	set_overcommit(overcommit);

	/*
	 * Never allow the total size of the queues to be larger than
	 * physical memory
	 *
	 * When adding together the possibly user supplied values, make
	 * sure they've not been deliberately contrived to overflow an int
	 */
	if(add_overflow(total_mem, fragq))
		BAD_ERROR("Queue sizes rediculously too large\n");
	total_mem += fragq;
	if(add_overflow(total_mem, bwriteq))
		BAD_ERROR("Queue sizes rediculously too large\n");
	total_mem += bwriteq;
	if(add_overflow(total_mem, fwriteq))
		BAD_ERROR("Queue sizes rediculously too large\n");
	total_mem += fwriteq;

	if(!mem_options_disabled) {
		res = check_usable_phys_mem(total_mem, command);
		if(res != TRUE)
			EXIT_MKSQUASHFS();
	}

	/*
	 * convert from queue size in Mbytes to queue size in
	 * blocks.
	 *
	 * This isn't going to overflow an int unless there exists
	 * systems with more than 8 Petabytes of RAM!
	 */
	fragment_size = fragq << (20 - block_log);
	bwriter_size = bwriteq << (20 - block_log);
	fwriter_size = fwriteq << (20 - block_log);

	check_min_memory(readq, bwriteq, block_log);

	/*
	 * setup signal handlers for the main thread, these cleanup
	 * deleting the destination file, if appending the
	 * handlers for SIGTERM and SIGINT will be replaced with handlers
	 * allowing the user to press ^C twice to restore the existing
	 * filesystem.
	 *
	 * SIGUSR1 is an internal signal, which is used by the sub-threads
	 * to tell the main thread to terminate, deleting the destination file,
	 * or if necessary restoring the filesystem on appending
	 */
	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);
	signal(SIGUSR1, sighandler);

	/* block SIGQUIT and SIGHUP, these are handled by the info thread */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGQUIT);
	sigaddset(&sigmask, SIGHUP);
	if(pthread_sigmask(SIG_BLOCK, &sigmask, NULL) != 0)
		BAD_ERROR("Failed to set signal mask in initialise_threads\n");

	/*
	 * temporarily block these signals, so the created sub-threads
	 * will ignore them, ensuring the main thread handles them
	 */
	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGINT);
	sigaddset(&sigmask, SIGTERM);
	sigaddset(&sigmask, SIGUSR1);
	if(pthread_sigmask(SIG_BLOCK, &sigmask, &old_mask) != 0)
		BAD_ERROR("Failed to set signal mask in initialise_threads\n");

	if(multiply_overflow(processors, 3) ||
			multiply_overflow(processors * 3, sizeof(pthread_t)))
		BAD_ERROR("Processors too large\n");

	deflator_thread = MALLOC(processors * 3 * sizeof(pthread_t));
	frag_deflator_thread = &deflator_thread[processors];
	frag_thread = &frag_deflator_thread[processors];

	to_reader = queue_init(1, NULL);
	bwriter_buffer = to_deflate = queue_cache_init(&thread_mutex, block_size, freelst);
	to_process_frag = read_queue_init();
	to_writer = queue_init(bwriter_size + fwriter_size, NULL);
	from_writer = queue_init(1, NULL);
	from_order = queue_init(1, NULL);
	to_frag = queue_init(fragment_size, &thread_mutex);
	to_main = seq_queue_init();
	to_order = seq_queue_init();
	fwriter_buffer = cache_init(block_size, fwriter_size, 1, freelst);
	fragment_buffer = cache_init(block_size, fragment_size, 1, 0);
	reserve_cache = cache_init(block_size, processors + 1, 1, 0);
	pthread_create(&reader_thread1, NULL, initial_reader, NULL);
	pthread_create(&writer_thread, NULL, writer, NULL);
	init_progress_bar();
	init_info();

	for(i = 0; i < processors; i++) {
		if(pthread_create(&deflator_thread[i], NULL, deflator, NULL))
			BAD_ERROR("Failed to create thread\n");
		if(pthread_create(&frag_deflator_thread[i], NULL, frag_deflator, NULL) != 0)
			BAD_ERROR("Failed to create thread\n");
		if(pthread_create(&frag_thread[i], NULL, frag_thrd,
				(void *) destination_file) != 0)
			BAD_ERROR("Failed to create thread\n");
	}

	main_thread = pthread_self();

	pthread_create(&order_thread, NULL, orderer, NULL);

	if(!quiet)
		printf("Parallel mksquashfs: Using %d processor%s\n", processors,
			processors == 1 ? "" : "s");

	/* Restore the signal mask for the main thread */
	if(pthread_sigmask(SIG_SETMASK, &old_mask, NULL) != 0)
		BAD_ERROR("Failed to set signal mask in initialise_threads\n");
}


static long long write_inode_lookup_table()
{
	int i, lookup_bytes = SQUASHFS_LOOKUP_BYTES(inode_count);
	unsigned int inode_number;

	if(inode_count == sinode_count)
		goto skip_inode_hash_table;

	inode_lookup_table = REALLOC(inode_lookup_table, lookup_bytes);

	for(i = 0; i < INODE_HASH_SIZE; i ++) {
		struct inode_info *inode;

		for(inode = inode_info[i]; inode; inode = inode->next) {

			inode_number = get_inode_no(inode);

			/* The empty action will produce orphaned inode
			 * entries in the inode_info[] table.  These
			 * entries because they are orphaned will not be
			 * allocated an inode number in dir_scan5(), so
			 * skip any entries with the default dummy inode
			 * number of 0 */
			if(inode_number == 0)
				continue;

			SQUASHFS_SWAP_LONG_LONGS(&inode->inode,
				&inode_lookup_table[inode_number - 1], 1);

		}
	}

skip_inode_hash_table:
	return generic_write_table(lookup_bytes, inode_lookup_table, 0, NULL,
		noI);
}


static char *get_component(char *target, char **targname)
{
	char *start;

	while(*target == '/')
		target ++;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = STRNDUP(start, target - start);

	while(*target == '/')
		target ++;

	return target;
}


static void free_path(struct pathname *paths)
{
	int i;

	for(i = 0; i < paths->names; i++) {
		if(paths->name[i].paths)
			free_path(paths->name[i].paths);
		free(paths->name[i].name);
		if(paths->name[i].preg) {
			regfree(paths->name[i].preg);
			free(paths->name[i].preg);
		}
	}

	free(paths);
}


static struct pathname *add_path(struct pathname *paths, char *target, char *alltarget)
{
	char *targname;
	int i, error;

	target = get_component(target, &targname);

	if(paths == NULL) {
		paths = MALLOC(sizeof(struct pathname));
		paths->names = 0;
		paths->name = NULL;
	}

	for(i = 0; i < paths->names; i++)
		if(strcmp(paths->name[i].name, targname) == 0)
			break;

	if(i == paths->names) {
		/* allocate new name entry */
		paths->names ++;
		paths->name = REALLOC(paths->name, (i + 1) *
			sizeof(struct path_entry));
		paths->name[i].name = targname;
		paths->name[i].paths = NULL;
		if(use_regex) {
			paths->name[i].preg = MALLOC(sizeof(regex_t));
			error = regcomp(paths->name[i].preg, targname,
				REG_EXTENDED|REG_NOSUB);
			if(error) {
				char str[1024]; /* overflow safe */

				regerror(error, paths->name[i].preg, str, 1024);
				BAD_ERROR("invalid regex %s in export %s, "
					"because %s\n", targname, alltarget,
					str);
			}
		} else
			paths->name[i].preg = NULL;

		if(target[0] == '\0')
			/* at leaf pathname component */
			paths->name[i].paths = NULL;
		else
			/* recurse adding child components */
			paths->name[i].paths = add_path(NULL, target,
				alltarget);
	} else {
		/* existing matching entry */
		free(targname);

		if(paths->name[i].paths == NULL) {
			/* No sub-directory which means this is the leaf
			 * component of a pre-existing exclude which subsumes
			 * the exclude currently being added, in which case stop
			 * adding components */
		} else if(target[0] == '\0') {
			/* at leaf pathname component and child components exist
			 * from more specific excludes, delete as they're
			 * subsumed by this exclude */
			free_path(paths->name[i].paths);
			paths->name[i].paths = NULL;
		} else
			/* recurse adding child components */
			add_path(paths->name[i].paths, target, alltarget);
	}

	return paths;
}


static void add_exclude(char *target)
{

	if(target[0] == '/' || strncmp(target, "./", 2) == 0 ||
			strncmp(target, "../", 3) == 0)
		BAD_ERROR("/, ./ and ../ prefixed excludes not supported with "
			"-wildcards or -regex options\n");	
	else if(strncmp(target, "... ", 4) == 0)
		stickypath = add_path(stickypath, target + 4, target + 4);
	else	
		path = add_path(path, target, target);
}


static struct pathnames *add_subdir(struct pathnames *paths, struct pathname *path)
{
	int count = paths == NULL ? 0 : paths->count;

	if(count % PATHS_ALLOC_SIZE == 0)
		paths = REALLOC(paths, sizeof(struct pathnames) +
			(count + PATHS_ALLOC_SIZE) * sizeof(struct pathname *));

	paths->path[count] = path;
	paths->count = count  + 1;
	return paths;
}


static int excluded_match(char *name, struct pathname *path, struct pathnames **new)
{
	int i;

	for(i = 0; i < path->names; i++) {
		int match = use_regex ?
			regexec(path->name[i].preg, name, (size_t) 0,
					NULL, 0) == 0 :
			fnmatch(path->name[i].name, name,
				FNM_PATHNAME|FNM_PERIOD|FNM_EXTMATCH) == 0;

		if(match) {
			 if(path->name[i].paths == NULL) {
				/* match on a leaf component, any subdirectories
			 	* in the filesystem should be excluded */
				free(*new);
				*new = NULL;
				return TRUE;
			 } else
				/* match on a non-leaf component, add any
				 * subdirectories to the new set of
				 * subdirectories to scan for this name */
				*new = add_subdir(*new, path->name[i].paths);
		}
	}

	return FALSE;
}


int excluded(char *name, struct pathnames *paths, struct pathnames **new)
{
	int n;
		
	if(stickypath && excluded_match(name, stickypath, new))
		return TRUE;

	for(n = 0; paths && n < paths->count; n++) {
		int res = excluded_match(name, paths->path[n], new);
		if(res)
			return TRUE;
	}

	/*
	 * Either:
	 * -  no matching names found, return empty new search set, or
	 * -  one or more matches with sub-directories found (no leaf matches),
	 *    in which case return new search set.
	 *
	 * In either case return FALSE as we don't want to exclude this entry
	 */
	return FALSE;
}


static void process_exclude_file(char *argv)
{
	FILE *fd;
	char buffer[MAX_LINE + 1]; /* overflow safe */
	char *filename;

	fd = fopen(argv, "r");
	if(fd == NULL)
		BAD_ERROR("Failed to open exclude file \"%s\" because %s\n",
			argv, strerror(errno));

	while(fgets(filename = buffer, MAX_LINE + 1, fd) != NULL) {
		int len = strlen(filename);

		if(len == MAX_LINE && filename[len - 1] != '\n')
			/* line too large */
			BAD_ERROR("Line too long when reading "
				"exclude file \"%s\", larger than %d "
				"bytes\n", argv, MAX_LINE);

		/*
		 * Remove '\n' terminator if it exists (the last line
		 * in the file may not be '\n' terminated)
		 */
		if(len && filename[len - 1] == '\n')
			filename[len - 1] = '\0';

		/* Skip any leading whitespace */
		while(isspace(*filename))
			filename ++;

		/* if comment line, skip */
		if(*filename == '#')
			continue;

		/*
		 * check for initial backslash, to accommodate
		 * filenames with leading space or leading # character
		 */
		if(*filename == '\\')
			filename ++;

		/* if line is now empty after skipping characters, skip it */
		if(*filename == '\0')
			continue;

		if(old_exclude)
			old_add_exclude(filename);
		else
			add_exclude(filename);
	}

	if(ferror(fd))
		BAD_ERROR("Reading exclude file \"%s\" failed because %s\n",
			argv, strerror(errno));

	fclose(fd);
}


#define RECOVER_ID "Squashfs recovery file v1.0\n"
#define RECOVER_ID_SIZE 28

static void write_recovery_data(struct squashfs_super_block *sBlk)
{
	int recoverfd;
	long long res, bytes = sBlk->bytes_used - sBlk->inode_table_start;
	pid_t pid = getpid();
	char *metadata;
	char header[] = RECOVER_ID;

	if(recover == FALSE) {
		if(!quiet) {
			printf("No recovery data option specified.\n");
			printf("Skipping saving recovery file.\n\n");
		}

		return;
	}

	if(recovery_pathname == NULL) {
		recovery_pathname = getenv("HOME");
		if(recovery_pathname == NULL)
			BAD_ERROR("Could not read $HOME, use -recovery-path or -no-recovery options\n");
	}

	ASPRINTF(&recovery_file, "%s/squashfs_recovery_%s_%d", recovery_pathname,
		getbase(destination_file), pid);
	metadata = MALLOC(bytes);
	res = read_fs_bytes(fd, sBlk->inode_table_start, bytes, metadata);
	if(res == 0) {
		ERROR("Failed to read append filesystem metadata\n");
		BAD_ERROR("Filesystem corrupted?\n");
	}

	recoverfd = open(recovery_file, O_CREAT | O_TRUNC | O_RDWR, S_IRWXU);
	if(recoverfd == -1)
		BAD_ERROR("Failed to create recovery file, because %s.  "
			"Aborting\n", strerror(errno));
		
	if(write_bytes(recoverfd, header, RECOVER_ID_SIZE) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	if(write_bytes(recoverfd, sBlk, sizeof(struct squashfs_super_block)) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	if(write_bytes(recoverfd, metadata, bytes) == -1)
		BAD_ERROR("Failed to write recovery file, because %s\n",
			strerror(errno));

	res = close(recoverfd);

	if(res == -1)
		BAD_ERROR("Failed to close recovery file, close returned %s\n",
				strerror(errno));

	free(metadata);
	
	printf("Recovery file \"%s\" written\n", recovery_file);
	printf("If Mksquashfs aborts abnormally (i.e. power failure), run\n");
	printf("mksquashfs - %s -recover %s\n", destination_file,
		recovery_file);
	printf("to restore filesystem\n\n");
}


static void read_recovery_data(char *recovery_file, char *destination_file)
{
	int fd, recoverfd;
	struct squashfs_super_block orig_sBlk, sBlk;
	char *metadata;
	long long res, bytes;
	struct stat buf;
	char header[] = RECOVER_ID;
	char header2[RECOVER_ID_SIZE];

	recoverfd = open(recovery_file, O_RDONLY);
	if(recoverfd == -1)
		BAD_ERROR("Failed to open recovery file because %s\n",
			strerror(errno));

	if(stat(destination_file, &buf) == -1)
		BAD_ERROR("Failed to stat destination file, because %s\n",
			strerror(errno));

	fd = open(destination_file, O_RDWR);
	if(fd == -1)
		BAD_ERROR("Failed to open destination file because %s\n",
			strerror(errno));

	res = read_bytes(recoverfd, header2, RECOVER_ID_SIZE);
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < RECOVER_ID_SIZE)
		BAD_ERROR("Recovery file appears to be truncated\n");
	if(strncmp(header, header2, RECOVER_ID_SIZE) !=0 )
		BAD_ERROR("Not a recovery file\n");

	res = read_bytes(recoverfd, &sBlk, sizeof(struct squashfs_super_block));
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < sizeof(struct squashfs_super_block))
		BAD_ERROR("Recovery file appears to be truncated\n");

	res = read_fs_bytes(fd, 0, sizeof(struct squashfs_super_block), &orig_sBlk);
	if(res == 0) {
		ERROR("Failed to read superblock from output filesystem\n");
		BAD_ERROR("Output filesystem is empty!\n");
	}

	if(memcmp(((char *) &sBlk) + 4, ((char *) &orig_sBlk) + 4,
			sizeof(struct squashfs_super_block) - 4) != 0)
		BAD_ERROR("Recovery file and destination file do not seem to "
			"match\n");

	bytes = sBlk.bytes_used - sBlk.inode_table_start;

	metadata = MALLOC(bytes);
	res = read_bytes(recoverfd, metadata, bytes);
	if(res == -1)
		BAD_ERROR("Failed to read recovery file, because %s\n",
			strerror(errno));
	if(res < bytes)
		BAD_ERROR("Recovery file appears to be truncated\n");

	write_destination(fd, 0, sizeof(struct squashfs_super_block), &sBlk);

	write_destination(fd, sBlk.inode_table_start, bytes, metadata);

	res = close(recoverfd);

	if(res == -1)
		BAD_ERROR("Failed to close recovery file, close returned %s\n",
				strerror(errno));

	res = close(fd);

	if(res == -1)
		BAD_ERROR("Failed to close output filesystem, close returned %s\n",
				strerror(errno));

	printf("Successfully wrote recovery file \"%s\".  Exiting\n",
		recovery_file);
	
	exit(0);
}


static void write_filesystem_tables(struct squashfs_super_block *sBlk)
{
	sBlk->fragments = fragments;
	sBlk->no_ids = id_count;
	sBlk->inode_table_start = write_inodes();
	sBlk->directory_table_start = write_directories();
	sBlk->fragment_table_start = write_fragment_table();
	sBlk->lookup_table_start = exportable ? write_inode_lookup_table() :
		SQUASHFS_INVALID_BLK;
	sBlk->id_table_start = write_id_table();
	sBlk->xattr_id_table_start = write_xattrs();

	TRACE("sBlk->inode_table_start 0x%llx\n", sBlk->inode_table_start);
	TRACE("sBlk->directory_table_start 0x%llx\n",
		sBlk->directory_table_start);
	TRACE("sBlk->fragment_table_start 0x%llx\n", sBlk->fragment_table_start);
	if(exportable)
		TRACE("sBlk->lookup_table_start 0x%llx\n",
			sBlk->lookup_table_start);

	sBlk->bytes_used = get_dpos();

	sBlk->compression = comp->id;

	SQUASHFS_INSWAP_SUPER_BLOCK(sBlk); 
	write_destination(fd, SQUASHFS_START, sizeof(*sBlk), sBlk);

	total_bytes += total_inode_bytes + total_directory_bytes +
		sizeof(struct squashfs_super_block) + total_xattr_bytes;
}


static int parse_numberll(char *start, long long *res, int size)
{
	char *end;
	long long number;

	errno = 0; /* To distinguish success/failure after call */

	number = strtoll(start, &end, 10);

	/*
	 * check for strtoll underflow or overflow in conversion, and other
	 * errors.
	 */
	if((errno == ERANGE && (number == LLONG_MIN || number == LLONG_MAX)) ||
			(errno != 0 && number == 0))
		return 0;

	/* reject negative numbers as invalid */
	if(number < 0)
		return 0;

	if(size == 1) {
		/*
		 * Allow a multiplier of  k, K, m, M, g, G optionally
		 * followed by B, b, or bytes.
		 *
		 * Check for multiplier and trailing junk.
		 * But first check that a number exists before the
		 * multiplier
		 */
		if(end == start)
			return 0;

		switch(end[0]) {
		case 'g':
		case 'G':
			if(multiply_overflowll(number, 1073741824))
				return 0;
			number *= 1073741824;

			if(end[1] != '\0')
				/* trailing junk after multiplier, but
				 * allow it to be B, b or bytes */
				if(strcmp(end + 1, "bytes") && strcmp(end + 1, "B") && strcmp(end + 1, "b"))
					return 0;

			break;
		case 'm':
		case 'M':
			if(multiply_overflowll(number, 1048576))
				return 0;
			number *= 1048576;

			if(end[1] != '\0')
				/* trailing junk after multiplier, but
				 * allow it to be B, b or bytes */
				if(strcmp(end + 1, "bytes") && strcmp(end + 1, "B") && strcmp(end + 1, "b"))
					return 0;

			break;
		case 'k':
		case 'K':
			if(multiply_overflowll(number, 1024))
				return 0;
			number *= 1024;

			if(end[1] != '\0')
				/* trailing junk after multiplier, but
				 * allow it to be B, b or bytes */
				if(strcmp(end + 1, "bytes") && strcmp(end + 1, "B") && strcmp(end + 1, "b"))
					return 0;

			break;
		case '\0':
			break;
		default:
			/* trailing junk after number */
			return 0;
		}
	} else if(size == 2) {
		/*
		 * Allow number to be followed by %
		 * But first check that a number exists before any possible %
		 */
		if(end == start)
			return 0;

		if(end[0] != '\0' && (end[0] != '%' || end[1] != '\0'))
			/* trailing junk after number */
			return 0;
	} else if(end[0] != '\0')
		/* trailing junk after number */
		return 0;

	*res = number;
	return 1;
}


static int parse_number(char *start, int *res, int size)
{
	long long number;

	if(!parse_numberll(start, &number, size))
		return 0;
	
	/* check if long result will overflow signed int */
	if(number > INT_MAX)
		return 0;

	*res = (int) number;
	return 1;
}


static int parse_number_unsigned(char *start, unsigned int *res, int size)
{
	long long number;

	if(!parse_numberll(start, &number, size))
		return 0;
	
	/* check if long result will overflow unsigned int */
	if(number > UINT_MAX)
		return 0;

	*res = (unsigned int) number;
	return 1;
}


static int parse_num(char *arg, int *res)
{
	return parse_number(arg, res, 0);
}


static int parse_num_unsigned(char *arg, unsigned int *res)
{
	return parse_number_unsigned(arg, res, 0);
}


static int get_default_phys_mem()
{
	/*
	 * get_physical_memory() relies on /proc being mounted.
	 * If it fails, issue a warning, and use
	 * SQUASHFS_UNKNOWN_MEM / SQUASHFS_TAKE as default.
	 */
	int mem = get_physical_memory();

	if(mem == 0) {
		mem = SQUASHFS_UNKNOWN_MEM / SQUASHFS_TAKE;

		ERROR("Warning: Cannot get size of physical memory, probably "
				"because /proc is missing.\n");
		ERROR("Warning: Defaulting to use of %d Mbytes, fix "
				"/proc to get a better value,\n", mem);
		mem_options_disabled = TRUE;
	} else
		mem /= SQUASHFS_TAKE;

	if(sizeof(void *) == 4 && mem > 640) {
		/*
		 * If we're running on a kernel with PAE or on a 64-bit kernel,
		 * the default memory usage can exceed the addressable
		 * memory by this process.
		 * Due to the typical kernel/user-space split (1GB/3GB, or
		 * 2GB/2GB), we have to conservatively assume the 32-bit
		 * processes can only address 2-3GB.  So limit the  default
		 * usage to 640M, which gives room for other data.
		 */
		mem = 640;
	}

	return mem;
}


static void calculate_queue_sizes(int mem, int *readq, int *fragq, int *bwriteq,
							int *fwriteq)
{
	*readq = mem / SQUASHFS_READQ_MEM;
	*bwriteq = mem / SQUASHFS_BWRITEQ_MEM;
	*fwriteq = mem / SQUASHFS_FWRITEQ_MEM;
	*fragq = mem - *readq - *bwriteq - *fwriteq;
}


static void open_log_file(char *filename)
{
	log_fd=fopen(filename, "w");
	if(log_fd == NULL)
		BAD_ERROR("Failed to open log file \"%s\" because %s\n", filename, strerror(errno));

	logging=TRUE;
}


static void check_source_date_epoch()
{
	char *time_string = getenv("SOURCE_DATE_EPOCH");
	unsigned int time;

	if(time_string != NULL) {
		/*
		 * We cannot have both command-line options and environment
		 * variable trying to set the timestamp(s) at the same
		 * time.  Semantically both are FORCE options which cannot be
		 * over-ridden elsewhere (otherwise they can't be relied on).
		 *
		 * So refuse to continue if both are set.
		 */
		if(mkfs_time_opt || inode_time_opt)
			BAD_ERROR("SOURCE_DATE_EPOCH and command line options "
				"can't be used at the same time to set "
				"timestamp(s)\n");

		if(!parse_num_unsigned(time_string, &time)) {
			ERROR("Env Var SOURCE_DATE_EPOCH has invalid time value\n");
			EXIT_MKSQUASHFS();
		}

		inode_time = mkfs_time = time;
		inode_time_opt = mkfs_time_opt = TRUE;
	}
}


static void check_pager()
{
	char * string = getenv("PAGER");

	if(string != NULL) {
		int res = check_and_set_pager(string);

		if(res == FALSE)
			EXIT_MKSQUASHFS();
	}
}


static void check_sqfs_cmdline(int argc, char *argv[])
{
	char *dirname = getenv("SQFS_CMDLINE"), *filename, *arg;
	int file, i, res;
	struct stat buf;

	if(dirname != NULL) {
		ASPRINTF(&filename, "%s/%s", dirname, "sqfs_cmdline");
		file = open(filename, O_CREAT | O_APPEND | O_NOFOLLOW | O_WRONLY,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

		if(file == -1) {
			if(errno == ELOOP)
				BAD_ERROR("Failed to append to SQFS_CMDLINE "
					"filename \"%s\" because it is a symbolic "
					"link or too many symbolic links were "
					"encountered\n", filename);
			else
				BAD_ERROR("Failed to append to SQFS_CMDLINE filename "
					"\"%s\" because %s\n", filename,
					strerror(errno));
		}

		res = fstat(file, &buf);
		if(res == -1)
			BAD_ERROR("Failed to fstat SQFS_CMDLINE filename "
				"\"%s\" because %s\n", filename, strerror(errno));

		if(buf.st_nlink > 1)
			BAD_ERROR("SQFS_CMDLINE filename \"%s\" is a hard "
				"link, refusing to append to it\n", filename);

		if(buf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH))
			BAD_ERROR("SQFS_CMDLINE filename \"%s\" has execute "
				"permissions, refusing to append to it\n", filename);

		for(i = 0;  i < argc; i++) {
			ASPRINTF(&arg, "\"%s\" ", argv[i]);
			res = write_bytes(file, arg, strlen(arg));
			if(res == -1)
				BAD_ERROR("write failed in check_sqfs_cmdline\n");

			free(arg);
		}

		res = write_bytes(file, "\n", 1);
		if(res == -1)
			BAD_ERROR("write failed in check_sqfs_cmdline\n");

		close(file);
		free(filename);
	}
}


static void print_version(char *string)
{
	printf("%s version " VERSION " (" DATE ")\n", string);
	printf("copyright (C) " YEAR " Phillip Lougher ");
	printf("<phillip@squashfs.org.uk>\n\n");
	printf("This program is free software; you can redistribute it and/or\n");
	printf("modify it under the terms of the GNU General Public License\n");
	printf("as published by the Free Software Foundation; either version ");
	printf("2,\n");
	printf("or (at your option) any later version.\n\n");
	printf("This program is distributed in the hope that it will be ");
	printf("useful,\n");
	printf("but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
	printf("MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
	printf("GNU General Public License for more details.\n");
}


static void print_summary()
{
	int i;

	printf("\n%sSquashfs %d.%d filesystem, %s compressed, data block size"
		" %d\n", exportable ? "Exportable " : "", SQUASHFS_MAJOR,
		SQUASHFS_MINOR, comp->name, block_size);
	printf("\t%s data, %s metadata, %s fragments,\n\t%s xattrs, %s ids\n",
		noD ? "uncompressed" : "compressed", noI ?  "uncompressed" :
		"compressed", no_fragments ? "no" : noF ? "uncompressed" :
		"compressed", no_xattrs ? "no" : noX ? "uncompressed" :
		"compressed", noI || noId ? "uncompressed" : "compressed");
	printf("\tduplicates are %sremoved\n", duplicate_checking ? "" :
		"not ");
	printf("Filesystem size %.2f Kbytes (%.2f Mbytes)\n", get_dpos() / 1024.0,
		get_dpos() / (1024.0 * 1024.0));
	printf("\t%.2f%% of uncompressed filesystem size (%.2f Kbytes)\n",
		((float) get_dpos() / total_bytes) * 100.0, total_bytes / 1024.0);
	printf("Inode table size %lld bytes (%.2f Kbytes)\n",
		inode_bytes, inode_bytes / 1024.0);
	printf("\t%.2f%% of uncompressed inode table size (%lld bytes)\n",
		((float) inode_bytes / total_inode_bytes) * 100.0,
		total_inode_bytes);
	printf("Directory table size %lld bytes (%.2f Kbytes)\n",
		directory_bytes, directory_bytes / 1024.0);
	if(total_directory_bytes)
		printf("\t%.2f%% of uncompressed directory table size"
			" (%lld bytes)\n", ((float) directory_bytes /
			total_directory_bytes) * 100.0, total_directory_bytes);
	else
		printf("\t100%% of uncompressed directory table size"
			" (%lld bytes)\n", total_directory_bytes);
	if(total_xattr_bytes) {
		printf("Xattr table size %d bytes (%.2f Kbytes)\n",
			xattr_bytes, xattr_bytes / 1024.0);
		printf("\t%.2f%% of uncompressed xattr table size (%d bytes)\n",
			((float) xattr_bytes / total_xattr_bytes) * 100.0,
			total_xattr_bytes);
	}
	if(duplicate_checking)
		printf("Number of duplicate files found %u\n", file_count -
			dup_files);
	else
		printf("No duplicate files removed\n");
	printf("Number of inodes %u\n", inode_count);
	printf("Number of files %u\n", file_count);
	if(!no_fragments)
		printf("Number of fragments %u\n", fragments);
	printf("Number of symbolic links %u\n", sym_count);
	printf("Number of device nodes %u\n", dev_count);
	printf("Number of fifo nodes %u\n", fifo_count);
	printf("Number of socket nodes %u\n", sock_count);
	printf("Number of directories %u\n", dir_count);
	printf("Number of hard-links %lld\n", hardlnk_count);
	printf("Number of ids (unique uids + gids) %d\n", id_count);
	printf("Number of uids %d\n", uid_count);

	for(i = 0; i < id_count; i++) {
		if(id_table[i]->flags & ISA_UID) {
			struct passwd *user = getpwuid(id_table[i]->id);
			printf("\t%s (%u)\n", user == NULL ? "unknown" :
				user->pw_name, id_table[i]->id);
		}
	}

	printf("Number of gids %d\n", guid_count);

	for(i = 0; i < id_count; i++) {
		if(id_table[i]->flags & ISA_GID) {
			struct group *group = getgrgid(id_table[i]->id);
			printf("\t%s (%d)\n", group == NULL ? "unknown" :
				group->gr_name, id_table[i]->id);
		}
	}
}


static int option_with_arg(char *string, char *table[])
{
	int i;

	if(*string != '-')
		return FALSE;

	for(i = 0; table[i] != NULL; i++)
		if(strcmp(string + 1, table[i]) == 0)
			break;

	if(table[i] != NULL)
		return TRUE;

	return compressor_option_args(comp, string);
}


static int get_uid_from_arg(char *arg, unsigned int *uid)
{
	char *last;
	long long res;

	res = strtoll(arg, &last, 10);
	if(*last == '\0') {
		if(res < 0 || res > (((long long) 1 << 32) - 1))
			return -2;

		*uid = res;
		return 0;
	} else {
		struct passwd *id = getpwnam(arg);

		if(id) {
			*uid = id->pw_uid;
			return 0;
		}
	}

	return -1;
}


static int get_gid_from_arg(char *arg, unsigned int *gid)
{
	char *last;
	long long res;

	res = strtoll(arg, &last, 10);
	if(*last == '\0') {
		if(res < 0 || res > (((long long) 1 << 32) - 1))
			return -2;

		*gid = res;
		return 0;
	} else {
		struct group *id = getgrnam(arg);

		if(id) {
			*gid = id->gr_gid;
			return 0;
		}
	}

	return -1;
}


static int get_uid_gid_offset_from_arg(char *arg, unsigned int *offset)
{
	char *last;
	long long res;

	res = strtoll(arg, &last, 10);
	if(*last == '\0') {
		if(res < 0 || res > (((long long) 1 << 32) - 1))
			return -2;

		*offset = res;
		return 0;
    }

    return -1;
}


FILE *open_info_file(char *filename)
{
	FILE *file;
	struct stat buf;
	int res;

	res = stat(filename, &buf);
	if(res == -1) {
		if(errno != ENOENT)
			BAD_ERROR("Failed to stat info_file filename \"%s\" because %s\n", filename, strerror(errno));

		file = fopen(filename, "w");
		if(file == NULL)
			BAD_ERROR("Failed to create info_file filename \"%s\" because %s\n", filename, strerror(errno));
	} else
		BAD_ERROR("Info_file filename \"%s\" already exists!\n", filename);

	return file;
}


static int sqfstar(int argc, char *argv[])
{
	struct stat buf;
	int res, i;
	squashfs_inode inode;
	int readq;
	int fragq;
	int bwriteq;
	int fwriteq;
	int total_mem = get_default_phys_mem();
	int progress = TRUE;
	int force_progress = FALSE;
	int percentage = FALSE;
	int Xhelp = FALSE;
	int dest_index;
	struct file_buffer **fragment = NULL;
	int size;
	void *comp_data;
	int overcommit = OVERCOMMIT_DEFAULT;

	/* Scan the command line for options that will immediately quit afterwards */
	for(i = 1; i < argc; i++) {
		if(strcmp(argv[i], "-version") == 0) {
			print_version("sqfstar");
			exit(0);
		} else if(strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "-h") == 0)
			sqfstar_help(NULL);
		else if(strcmp(argv[i], "-help-all") == 0 || strcmp(argv[i], "-ha") == 0)
			sqfstar_help_all();
		else if(strcmp(argv[i], "-help-option") == 0 || strcmp(argv[i], "-ho") == 0) {
			if(++i == argc)
				sqfstar_option_help(argv[i - 1], "sqfstar: %s missing regex\n", argv[i - 1]);
			sqfstar_option(argv[i - 1], argv[i]);
		} else if(strcmp(argv[i], "-help-section") == 0 || strcmp(argv[i], "-hs") == 0) {
			if(++i == argc)
				sqfstar_option_help(argv[i - 1], "sqfstar: %s missing section\n", argv[i - 1]);
			sqfstar_section(argv[i - 1], argv[i]);
		} else if(strcmp(argv[i], "-help-comp") == 0) {
			if(++i == argc)
				sqfstar_option_help(argv[i - 1], "sqfstar: -help-comp missing compressor name\n");
			print_compressor_options(argv[i], "sqfstar");
			exit(0);
		} else if(strcmp(argv[1], "-mem-default") == 0) {
			printf("%d\n", total_mem);
			exit(0);
		} else if(argv[i][0] != '-')
			break;
		else if(option_with_arg(argv[i], sqfstar_option_table))
			i++;
	}

	block_log = slog(block_size);
	calculate_queue_sizes(total_mem, &readq, &fragq, &bwriteq, &fwriteq);

	comp = lookup_compressor(COMP_DEFAULT);

	/*
	 * Scan the command line for -comp xxx option, this should occur before
	 * any -X compression specific options to ensure these options are passed
	 * to the correct compressor
	 *
	 * Also scan for -Xhelp
	 */
	for(i = 1; i < argc; i++) {
		if(strncmp(argv[i], "-X", 2) == 0)
			X_opt_parsed = 1;

		if(strcmp(argv[i], "-comp") == 0) {
			struct compressor *prev_comp = comp;

			if(++i == argc)
				sqfstar_option_help(argv[i - 1], "sqfstar: -comp missing compression type\n");
			comp = lookup_compressor(argv[i]);
			if(!comp->supported) {
				ERROR("sqfstar: Compressor \"%s\" is not supported!\n", argv[i]);
				ERROR("sqfstar: Compressors available:\n");
				display_compressors();
				exit(1);
			}
			if(compressor_opt_parsed) {
				ERROR("sqfstar: -comp multiple conflicting -comp"
					" options specified on command line"
					", previously %s, now %s\n",
					prev_comp->name, comp->name);
				exit(1);
			}
			compressor_opt_parsed = 1;
			if(X_opt_parsed) {
				ERROR("sqfstar: -comp option should be before any "
					"-X option\n");
				exit(1);
			}
		} else if(strcmp(argv[i], "-Xhelp") == 0)
			Xhelp = TRUE;
		else if(argv[i][0] != '-')
			break;
		else if(option_with_arg(argv[i], sqfstar_option_table))
			i++;
	}

	if(Xhelp) {
		print_selected_comp_options(stdout, comp, "sqfstar");
		exit(0);
	}

	if(i >= argc)
		dest_index = argc;
	else
		dest_index = i;

	source_path = NULL;
	source = 0;
	old_exclude = FALSE;
	tarfile = TRUE;

	/* By default images generated from tar files are not exportable.
	 * Exportable by default is a "legacy" setting in Mksquashfs, which
	 * will cause too many problems to change now.  But tarfile reading
	 * has no such issues */
	exportable = FALSE;

	/* By default images generated from tar files use tail-end packing.
	 * No tailend packing is a "legacy" setting in Mksquashfs, which
	 * will cause too many problems to change now.  But tarfile reading
	 * has no such issues */
	always_use_fragments = TRUE;

	for(i = 1; i < dest_index; i++) {
		if(strcmp(argv[i], "-ignore-zeros") == 0)
			ignore_zeros = TRUE;
		else if(strcmp(argv[i], "-no-hardlinks") == 0)
			no_hardlinks = TRUE;
		else if(strcmp(argv[i], "-throttle") == 0) {
			if((++i == dest_index) || !parse_number(argv[i], &res, 2))
				sqfstar_option_help(argv[i - 1], "sqfstar: -throttle missing or invalid value\n");
			if(res > 99)
				sqfstar_option_help(argv[i - 1], "sqfstar: -throttle value should be between 0 and 99\n");
			set_sleep_time(res);
			readq = 4;
		} else if(strcmp(argv[i], "-limit") == 0) {
			if((++i == dest_index) || !parse_number(argv[i], &res, 0))
				sqfstar_option_help(argv[i - 1], "sqfstar: -limit missing or invalid value\n");
			if(res < 1 || res > 100)
				sqfstar_option_help(argv[i - 1], "sqfstar: -limit value should be between 1 and 100\n");
			set_sleep_time(100 - res);
			readq = 4;
		} else if(strcmp(argv[i], "-mkfs-time") == 0 ||
				strcmp(argv[i], "-fstime") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: %s missing time value\n", argv[i - 1]);
			else if(strcmp(argv[i], "inode") == 0)
				mkfs_inode_opt = TRUE;
			else if(!parse_num_unsigned(argv[i], &mkfs_time) &&
					!exec_date(argv[i], &mkfs_time))
				sqfstar_option_help(argv[i - 1], "sqfstar: %s invalid time value\n", argv[i - 1]);
			else
				mkfs_time_opt = TRUE;
		} else if(strcmp(argv[i], "-all-time") == 0) {
			if((++i == dest_index) ||
					(!parse_num_unsigned(argv[i], &inode_time) &&
					!exec_date(argv[i], &inode_time)))
				sqfstar_option_help(argv[i - 1], "sqfstar: -all-time missing or invalid time value\n");
			inode_time_opt = TRUE;
			clamping = FALSE;
		} else if(strcmp(argv[i], "-inode-time") == 0) {
			if((++i == dest_index) ||
					(!parse_num_unsigned(argv[i], &inode_time) &&
					!exec_date(argv[i], &inode_time)))
				sqfstar_option_help(argv[i - 1], "sqfstar: -inode-time missing or invalid time value\n");
			inode_time_opt = TRUE;
			clamping = FALSE;
		} else if(strcmp(argv[i], "-reproducible") == 0);
			/* obsolete option, ignored and retained for backwards
			 * compatibility */
		else if(strcmp(argv[i], "-not-reproducible") == 0);
			/* obsolete option, ignored and retained for backwards
			 * compatibility */
		else if(strcmp(argv[i], "-root-mode") == 0) {
			if((++i == dest_index) || !parse_mode(argv[i], &root_mode))
				sqfstar_option_help(argv[i - 1], "sqfstar: -root-mode missing or invalid mode, symbolic mode or octal number expected\n");
			root_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-root-uid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -root-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &root_uid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -root-uid uid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -root-uid invalid uid or unknown user name\n");
			}
			root_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-root-gid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -root-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &root_gid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -root-gid gid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -root-gid invalid gid or unknown group name\n");
			}
			root_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-uid-gid-offset") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -uid-gid-offset missing offset\n");
			res = get_uid_gid_offset_from_arg(argv[i], &uid_gid_offset);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -uid-gid-offset out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -uid-gid-offset invalid number\n");
			}
		} else if(strcmp(argv[i], "-root-time") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -root-time missing time value\n");
			else if(strcmp(argv[i], "inode") == 0)
				root_inode_opt = TRUE;
			else if(!parse_num_unsigned(argv[i], &root_time) &&
					!exec_date(argv[i], &root_time))
				sqfstar_option_help(argv[i - 1], "sqfstar: -root-time time value\n");
			else
				root_time_opt = TRUE;
		} else if(strcmp(argv[i], "-default-mode") == 0) {
			if((++i == dest_index) || !parse_mode(argv[i], &default_mode))
				sqfstar_option_help(argv[i - 1], "sqfstar: -default-mode missing or invalid mode, symbolic mode or octal number expected\n");
			root_mode = default_mode;
			default_mode_opt = root_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-default-uid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -default-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &default_uid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -default-uid uid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -default-uid invalid uid or unknown user name\n");
			}
			root_uid = default_uid;
			default_uid_opt = root_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-default-gid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -default-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &default_gid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -default-gid gid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -default-gid invalid gid or unknown group name\n");
			}
			root_gid = default_gid;
			default_gid_opt = root_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-comp") == 0)
			/* parsed previously */
			i++;
		else if(strncmp(argv[i], "-X", 2) == 0) {
			int args = compressor_options(comp, argv + i, dest_index - i);

			if(args < 0) {
				if(args == -1) {
					ERROR("sqfstar: Unrecognised compressor"
						" option %s\n", argv[i]);
					if(!compressor_opt_parsed)
						ERROR("sqfstar: Did you forget to"
							" specify -comp, or "
							"specify it after the"
							" -X options?\n");
					print_selected_comp_options(stderr, comp, "sqfstar");
				}
				exit(1);
			}
			i += args;

		} else if(strcmp(argv[i], "-pf") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -pf missing filename\n");
			if(read_pseudo_file(argv[i], argv[dest_index]) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-p") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -p missing pseudo file definition\n");
			if(read_pseudo_definition(argv[i], argv[dest_index]) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-pd") == 0 || strcmp(argv[i], "-pseudo-dir") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: %s missing pseudo file definition\n", argv[i-1]);
			pseudo_dir = read_pseudo_dir(argv[i]);
			if(pseudo_dir == NULL)
				exit(1);
		} else if(strcmp(argv[i], "-regex") == 0)
			use_regex = TRUE;
		else if(strcmp(argv[i], "-no-sparse") == 0)
			sparse_files = FALSE;
		else if(strcmp(argv[i], "-no-progress") == 0)
			progress = FALSE;
		else if(strcmp(argv[i], "-progress") == 0)
			force_progress = TRUE;
		else if(strcmp(argv[i], "-exports") == 0)
			exportable = TRUE;
		else if(strcmp(argv[i], "-offset") == 0 ||
						strcmp(argv[i], "-o") == 0) {
			if((++i == dest_index) ||
					!parse_numberll(argv[i], &start_offset, 1))
				sqfstar_option_help(argv[i - 1], "sqfstar: %s missing or invalid offset size\n", argv[i - 1]);
		} else if(strcmp(argv[i], "-processors") == 0) {
			if((++i == dest_index) || !parse_num(argv[i], &processors))
				sqfstar_option_help(argv[i - 1], "sqfstar: -processors missing or invalid processor number\n");
			if(processors < 1)
				sqfstar_option_help(argv[i - 1], "sqfstar: -processors should be 1 or larger\n");
		} else if(strcmp(argv[i], "-mem") == 0) {
			long long number = 0;

			if(mem_options_disabled) {
				ERROR("Ignoring -mem option because amount of "
					"system memory unknown!\n)");
				continue;
			}

			if((++i == dest_index) ||
					!parse_numberll(argv[i], &number, 1))
				sqfstar_option_help(argv[i - 1], "sqfstar: -mem missing or invalid mem size\n");

			/*
			 * convert from bytes to Mbytes, ensuring the value
			 * does not overflow a signed int
			 */
			if(number >= (1LL << 51))
				sqfstar_option_help(argv[i - 1], "sqfstar: -mem invalid mem size\n");

			total_mem = number / 1048576;
			calculate_queue_sizes(total_mem, &readq, &fragq,
				&bwriteq, &fwriteq);
		} else if(strcmp(argv[i], "-mem-percent") == 0) {
			int percent, phys_mem;

			if(mem_options_disabled) {
				ERROR("Ignoring -mem-percent option because amount of "
					"system memory unknown!\n)");
				continue;
			}

			/*
			 * Percentage of 75% and larger is dealt with later.
			 * In the same way a fixed mem size if more than 75%
			 * of memory is dealt with later.
			 */
			if((++i == dest_index) ||
					!parse_number(argv[i], &percent, 2) ||
					(percent < 1))
				sqfstar_option_help(argv[i - 1], "sqfstar: -mem-percent missing or invalid percentage: it should be 1 - 75%%\n");

			phys_mem = get_physical_memory();

			if(phys_mem == 0) {
				ERROR("sqfstar: -mem-percent unable to get physical "
					"memory\n");
				exit(1);
			}

			if(multiply_overflow(phys_mem, percent))
				sqfstar_option_help(argv[i - 1], "sqfstar: -mem-percent requested phys mem too large\n");

			total_mem = phys_mem * percent / 100;

			calculate_queue_sizes(total_mem, &readq, &fragq,
				&bwriteq, &fwriteq);
		} else if(strcmp(argv[i], "-mem-default") == 0) {
			printf("%d\n", total_mem);
			exit(0);
		} else if(strcmp(argv[i], "-b") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -b missing block size\n");
			if(!parse_number(argv[i], &block_size, 1))
				sqfstar_option_help(argv[i - 1], "sqfstar: -b invalid block size\n");
			if((block_log = slog(block_size)) == 0)
				sqfstar_option_help(argv[i - 1], "sqfstar: -b block size not power of two or not between 4096 and 1Mbyte\n");
		} else if(strcmp(argv[i], "-ef") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -ef missing filename\n");
		} else if(strcmp(argv[i], "-no-duplicates") == 0)
			duplicate_checking = FALSE;

		else if(strcmp(argv[i], "-no-fragments") == 0)
			no_fragments = TRUE;

		 else if(strcmp(argv[i], "-no-tailends") == 0)
			always_use_fragments = FALSE;

		else if(strcmp(argv[i], "-all-root") == 0 ||
				strcmp(argv[i], "-root-owned") == 0) {
			global_uid = global_gid = 0;
			global_uid_opt = global_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-force-file-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &global_file_mode))
				sqfstar_option_help(argv[i - 1], "sqfstar: -force-file-mode missing or invalid mode, symbolic mode or octal number expected\n");
			global_file_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-force-dir-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &global_dir_mode))
				sqfstar_option_help(argv[i - 1], "sqfstar: -force-dir-mode missing or invalid mode, symbolic mode or octal number expected\n");
			global_dir_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-force-uid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -force-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &global_uid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -force-uid uid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -force-uid invalid uid or unknown user name\n");
			}
			global_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-force-gid") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -force-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &global_gid);
			if(res) {
				if(res == -2)
					sqfstar_option_help(argv[i - 1], "sqfstar: -force-gid gid out of range\n");
				else
					sqfstar_option_help(argv[i - 1], "sqfstar: -force-gid invalid gid or unknown group name\n");
			}
			global_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-pseudo-override") == 0)
			pseudo_override = TRUE;
		else if(strcmp(argv[i], "-noI") == 0 ||
				strcmp(argv[i], "-noInodeCompression") == 0)
			noI = TRUE;

		else if(strcmp(argv[i], "-noId") == 0 ||
				strcmp(argv[i], "-noIdTableCompression") == 0)
			noId = TRUE;

		else if(strcmp(argv[i], "-noD") == 0 ||
				strcmp(argv[i], "-noDataCompression") == 0)
			noD = TRUE;

		else if(strcmp(argv[i], "-noF") == 0 ||
				strcmp(argv[i], "-noFragmentCompression") == 0)
			noF = TRUE;

		else if(strcmp(argv[i], "-noX") == 0 ||
				strcmp(argv[i], "-noXattrCompression") == 0)
			noX = TRUE;

		else if(strcmp(argv[i], "-no-compression") == 0)
			noI = noD = noF = noX = TRUE;

		else if(strcmp(argv[i], "-no-xattrs") == 0) {
			if(xattr_exclude_preg || xattr_include_preg ||
							add_xattrs())
				sqfstar_option_help(argv[i - 1], "sqfstar: -no-xattrs should not be used in combination with -xattrs-* options\n");
			no_xattrs = TRUE;

		} else if(strcmp(argv[i], "-xattrs") == 0) {
			if(xattrs_supported())
				no_xattrs = FALSE;
			else {
				ERROR("sqfstar: xattrs are unsupported in "
					"this build\n");
				exit(1);
			}

		} else if(strcmp(argv[i], "-xattrs-exclude") == 0) {
			if(!xattrs_supported()) {
				ERROR("sqfstar: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -xattrs-exclude missing regex pattern\n");
			else {
				xattr_exclude_preg = xattr_regex(argv[i], "exclude");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-xattrs-include") == 0) {
			if(!xattrs_supported()) {
				ERROR("sqfstar: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -xattrs-include missing regex pattern\n");
			else {
				xattr_include_preg = xattr_regex(argv[i], "include");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-xattrs-add") == 0) {
			if(!xattrs_supported()) {
				ERROR("sqfstar: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == dest_index) 
				sqfstar_option_help(argv[i - 1], "sqfstar: -xattrs-add missing xattr argument\n");
			else {
				xattrs_add(argv[i]);
				no_xattrs = FALSE;
			}

		} else if(strcmp(argv[i], "-nopad") == 0)
			nopad = TRUE;

		else if(strcmp(argv[i], "-info") == 0)
			display_info = TRUE;

		else if(strcmp(argv[i], "-info-file") == 0) {
			if(++i == dest_index)
				sqfstar_option_help(argv[i - 1], "sqfstar: -info-file missing filename\n");
			display_info = TRUE;
			info_file = open_info_file(argv[i]);

		} else if(strcmp(argv[i], "-force") == 0)
			appending = FALSE;

		else if(strcmp(argv[i], "-quiet") == 0)
			quiet = TRUE;

		else if(strcmp(argv[i], "-exit-on-error") == 0)
			exit_on_error = TRUE;

		else if(strcmp(argv[i], "-percentage") == 0) {
			progressbar_percentage();
			percentage = TRUE;
		} else if(strcmp(argv[i], "-overcommit") == 0) {
			if((++i == dest_index) ||
					!parse_number(argv[i], &overcommit, 2) ||
					(overcommit > 100))
				sqfstar_option_help(argv[i - 1], "sqfstar: -overcommit missing or invalid percentage: it should be 0 - 100%%\n");
		} else
			sqfstar_invalid_option(argv[i]);
	}

	if(i == argc)
		sqfstar_help("sqfstar: fatal error: no output filesystem specified on command line\n\n");

	set_single_threaded();

	check_source_date_epoch();

	/*
	 * The -noI option implies -noId for backwards compatibility, so reset noId
	 * if both have been specified
	 */
	if(noI && noId)
		noId = FALSE;

	/*
	 * Some compressors may need the options to be checked for validity
	 * once all the options have been processed
	 */
	res = compressor_options_post(comp, block_size);
	if(res)
		EXIT_MKSQUASHFS();

	/*
	 * Selecting both -no-progress and -percentage produces a conflict,
	 * and so reject such command lines
	 */
	if(!progress && percentage)
		BAD_ERROR("Only one of -no-progress and -percentage can be "
			"specified.  Both causes a conflict.\n");

	/*
	 * Selecting both -no-progress and -progress produces a conflict,
	 * and so reject such command lines
	 */
	if(!progress && force_progress)
		BAD_ERROR("Only one of -no-progress and -progress can be "
			"specified.  Both causes a conflict.\n");

	/*
	 * If the -info option has been selected then disable the
	 * progress bar unless it has been explicitly enabled with
	 * the -progress option
	 */
	if(display_info && !info_file)
		progress = force_progress;

	/*
	 * Sort all the xattr-add options now they're all processed
	 */
	sort_xattr_add_list();

	/*
	 * If -pseudo-override option has been specified and there are
	 * no pseudo files then reset option.  -pseudo-override relies
	 * on dir_scan2() being run, which won't be if there's no
	 * actions or pseudo files
	 */
	if(pseudo_override && !get_pseudo())
		pseudo_override = FALSE;

#ifdef SQUASHFS_TRACE
	/*
	 * Disable progress bar if full debug tracing is enabled.
	 * The progress bar in this case just gets in the way of the
	 * debug trace output
	 */
	progress = FALSE;
#endif

	destination_file =  argv[dest_index];
	if(stat(destination_file, &buf) == -1) {
		if(errno == ENOENT) { /* Does not exist */
			appending = FALSE;
			fd = open(destination_file, O_CREAT | O_TRUNC | O_RDWR,
				S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
			if(fd == -1) {
				perror("Could not create destination file");
				exit(1);
			}

			/* ensure Sqfstar doesn't try to read
			 * the destination file as input, which
			 * will result in an I/O loop */
			if(stat(destination_file, &buf) == -1) {
				/* disappered after creating? */
				perror("Could not stat destination file");
				exit(1);
			}
			ADD_ENTRY(buf);
		} else {
			perror("Could not stat destination file");
			exit(1);
		}

	} else {
		if(!S_ISBLK(buf.st_mode) && !S_ISREG(buf.st_mode)) {
			ERROR("Destination not block device or regular file\n");
			exit(1);
		}

		if(appending) {
			ERROR("Appending is not supported reading tar files\n");
			ERROR("To force Sqfstar to write to this %s "
				"use -force\n", S_ISBLK(buf.st_mode) ?
				"block device" : "file");
			EXIT_MKSQUASHFS();
		}

		if(S_ISBLK(buf.st_mode)) {
			if((fd = open(destination_file, O_RDWR)) == -1) {
				perror("Could not open block device as "
					"destination");
				exit(1);
			}
			block_device = 1;

		} else {
			fd = open(destination_file, O_TRUNC | O_RDWR);
			if(fd == -1) {
				perror("Could not open regular file for "
					"writing as destination");
				exit(1);
			}
			/* ensure Sqfstar doesn't try to read
			 * the destination file as input, which
			 * will result in an I/O loop */
			ADD_ENTRY(buf);
		}
	}

	/*
	 * process the exclude files - must be done afer destination file has
	 * been possibly created
	 */
	for(i = 1; i < dest_index; i++) {
		if(strcmp(argv[i], "-ef") == 0)
			/*
			 * Note presence of filename arg has already
			 * been checked
			 */
			process_exclude_file(argv[++i]);
		else if(option_with_arg(argv[i], sqfstar_option_table))
			i++;
	}

	for(i = dest_index + 1; i < argc; i++)
		add_exclude(argv[i]);

	initialise_threads(readq, fragq, bwriteq, fwriteq, !appending,
		destination_file, "Sqfstar", overcommit);

	res = compressor_init(comp, &stream, SQUASHFS_METADATA_SIZE, 0);
	if(res)
		BAD_ERROR("compressor_init failed\n");

	dupl_block = MALLOC(1048576 * sizeof(struct file_info *));
	dupl_frag = MALLOC(block_size * sizeof(struct file_info *));
	memset(dupl_block, 0, 1048576 * sizeof(struct file_info *));
	memset(dupl_frag, 0, block_size * sizeof(struct file_info *));

	comp_data = compressor_dump_options(comp, block_size, &size);

	if(!quiet)
		printf("Creating %d.%d filesystem on %s, block size %d.\n",
			SQUASHFS_MAJOR, SQUASHFS_MINOR,
			destination_file, block_size);

	/*
	 * store any compressor specific options after the superblock,
	 * and set the COMP_OPT flag to show that the filesystem has
	 * compressor specfic options
	 */
	if(comp_data) {
		unsigned short c_byte = size | SQUASHFS_COMPRESSED_BIT;

		SQUASHFS_INSWAP_SHORTS(&c_byte, 1);
		write_destination(fd, sizeof(struct squashfs_super_block),
			sizeof(c_byte), &c_byte);
		write_destination(fd, sizeof(struct squashfs_super_block) +
			sizeof(c_byte), size, comp_data);
		set_pos(sizeof(struct squashfs_super_block) + sizeof(c_byte) + size);
		comp_opts = TRUE;
	} else
		set_pos(sizeof(struct squashfs_super_block));

	if(path)
		paths = add_subdir(paths, path);

	dump_actions();
	dump_pseudos();

	set_progressbar_state(progress);

	inode = process_tar_file(progress);

	sBlk.root_inode = inode;
	sBlk.inodes = inode_count;
	sBlk.s_magic = SQUASHFS_MAGIC;
	sBlk.s_major = SQUASHFS_MAJOR;
	sBlk.s_minor = SQUASHFS_MINOR;
	sBlk.block_size = block_size;
	sBlk.block_log = block_log;
	sBlk.flags = SQUASHFS_MKFLAGS(noI, noD, noF, noX, noId, no_fragments,
		always_use_fragments, duplicate_checking, exportable,
		no_xattrs, comp_opts);
	if(mkfs_time_opt)
		sBlk.mkfs_time = mkfs_time;
	else if(mkfs_inode_opt)
		sBlk.mkfs_time = inode_time_latest;
	else
		sBlk.mkfs_time = time(NULL);

	disable_info();

	while((fragment = get_frag_action(fragment)))
		write_fragment(*fragment);

	sync_writer_thread();
	pthread_cancel(writer_thread);

	if(!check_id_table_offset())
		BAD_ERROR("id entry out of range after applying -uid-gid-offset offset\n");

	write_filesystem_tables(&sBlk);

	progressbar_finish();

	if(!block_device) {
		res = ftruncate(fd, get_dpos());
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}

	if(!nopad && (i = get_dpos() & (4096 - 1))) {
		char temp[4096] = {0};
		write_destination(fd, get_dpos(), 4096 - i, temp);
	}

	res = close(fd);

	if(res == -1)
		BAD_ERROR("Failed to close output filesystem, close returned %s\n",
				strerror(errno));

	if(recovery_file)
		unlink(recovery_file);

	if(!quiet)
		print_summary();

	if(logging)
		fclose(log_fd);

	return 0;
}


int main(int argc, char *argv[])
{
	struct stat buf, source_buf;
	int res, i, j;
	char *root_name = NULL;
	squashfs_inode inode;
	int readq;
	int fragq;
	int bwriteq;
	int fwriteq;
	int total_mem = get_default_phys_mem();
	int progress = TRUE;
	int force_progress = FALSE;
	int percentage = FALSE;
	int exclude_option = FALSE;
	int Xhelp = FALSE;
	struct file_buffer **fragment = NULL;
	char *command;
	int single_threaded = FALSE;
	int overcommit = OVERCOMMIT_DEFAULT;


	check_sqfs_cmdline(argc, argv);
	check_pager();

	/* skip leading path components in invocation command */
	for(command = argv[0] + strlen(argv[0]) - 1;
			command >= argv[0] && command[0] != '/'; command--);

	if(command < argv[0])
		command = argv[0];
	else
		command++;

	if(strcmp(command, "sqfstar") == 0)
		return sqfstar(argc, argv);

	if(argc > 1 && strcmp(argv[1], "-version") == 0) {
		print_version("mksquashfs");
		exit(0);
	}

	block_log = slog(block_size);
	calculate_queue_sizes(total_mem, &readq, &fragq, &bwriteq, &fwriteq);

	/* Find the first option */
        for(i = 1; i < argc && (argv[i][0] != '-' || strcmp(argv[i], "-") == 0);
									i++);

	/* Scan the command line for options that will immediately quit afterwards */
	for(j = i; j < argc; j++) {
		if(strcmp(argv[j], "-help") == 0 || strcmp(argv[j], "-h") == 0)
			mksquashfs_help(NULL);
		else if(strcmp(argv[j], "-help-all") == 0 || strcmp(argv[j], "-ha") == 0)
			mksquashfs_help_all();
		else if(strcmp(argv[j], "-help-option") == 0 || strcmp(argv[j], "-ho") == 0) {
			if(++j == argc)
				mksquashfs_option_help(argv[j - 1], "mksquashfs: %s missing regex\n", argv[j - 1]);
			mksquashfs_option(argv[j - 1], argv[j]);
		} else if(strcmp(argv[j], "-help-section") == 0 || strcmp(argv[j], "-hs") == 0) {
			if(++j == argc)
				mksquashfs_option_help(argv[j - 1], "mksquashfs: %s missing section\n", argv[j - 1]);
			mksquashfs_section(argv[j - 1], argv[j]);
		} else if(strcmp(argv[j], "-help-comp") == 0) {
			if(++j == argc)
				mksquashfs_option_help(argv[j - 1], "mksquashfs: -help-comp missing compressor name\n");
			print_compressor_options(argv[j], "mksquashfs");
			exit(0);
		} else if(strcmp(argv[j], "-mem-default") == 0) {
			printf("%d\n", total_mem);
			exit(0);
		} else if(strcmp(argv[j], "-e") == 0)
			break;
		else if(option_with_arg(argv[j], option_table))
			j++;
	}

	/*
	 * Scan the command line for -comp xxx option, this is to ensure
	 * any -X compressor specific options are passed to the
	 * correct compressor.
	 *
	 * Also scan for -Xhelp and -help-comp specified on command line,
	 */
	for(j = i; j < argc; j++) {
		struct compressor *prev_comp = comp;
		
		if(strcmp(argv[j], "-comp") == 0) {
			if(++j == argc)
				mksquashfs_option_help(argv[j - 1], "mksquashfs: -comp missing compression type\n");
			comp = lookup_compressor(argv[j]);
			if(!comp->supported) {
				ERROR("mksquashfs: Compressor \"%s\" is not "
					"supported!\n", argv[j]);
				ERROR("mksquashfs: Compressors available:\n");
				display_compressors();
				exit(1);
			}
			if(prev_comp != NULL && prev_comp != comp) {
				ERROR("mksquashfs: -comp multiple conflicting "
					"-comp options specified on command "
					"line, previously %s, now %s\n",
					prev_comp->name, comp->name);
				exit(1);
			}
			compressor_opt_parsed = 1;

		} else if(strcmp(argv[j], "-Xhelp") == 0)
			Xhelp = TRUE;
		else if(strcmp(argv[j], "-e") == 0)
			break;
		else if(option_with_arg(argv[j], option_table))
			j++;
	}

	/*
	 * if no -comp option specified lookup default compressor.  Note the
	 * Makefile ensures the default compressor has been built, and so we
	 * don't need to to check for failure here
	 */
	if(comp == NULL)
		comp = lookup_compressor(COMP_DEFAULT);

	if(Xhelp) {
		print_selected_comp_options(stdout, comp, "mksquashfs");
		exit(0);
	}

	if(i < 3) {
		if(i == 1)
			mksquashfs_help("mksquashfs: fatal error: no source or output filesystem specified on command line\n\n");
		else
			mksquashfs_help("mksquashfs: fatal error: no output filesystem specified on command line\n\n");
	}

	option_offset = i;
	destination_file = argv[i - 1];

	if(argv[1][0] != '-') {
		source_path = argv + 1;
		source = i - 2;
	} else {
		source_path = NULL;
		source = 0;
	}

	/*
	 * Scan the command line for -cpiostyle, -tar and -pf xxx options, this
	 * is to ensure only one thing is trying to read from stdin
	 */
	for(i = option_offset; i < argc; i++) {
		if(strcmp(argv[i], "-cpiostyle") == 0)
			cpiostyle = TRUE;
		else if(strcmp(argv[i], "-cpiostyle0") == 0) {
			cpiostyle = TRUE;
			filename_terminator = '\0';
		} else if(strcmp(argv[i], "-tar") == 0) {
			tarfile = TRUE;
			always_use_fragments = TRUE;
			force_single_threaded = TRUE;
		} else if(strcmp(argv[i], "-pf") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -pf missing filename\n");
			if(strcmp(argv[i], "-") == 0)
				pseudo_stdin = TRUE;
		} else if(strcmp(argv[i], "-e") == 0)
			break;
		else if(option_with_arg(argv[i], option_table))
			i++;
	}

	/*
	 * Only one of cpiostyle, tar and pseudo file reading from stdin can
	 * be specified
	 */
	if((!cpiostyle || tarfile || pseudo_stdin) &&
				(!tarfile || cpiostyle || pseudo_stdin) &&
				(!pseudo_stdin || cpiostyle || tarfile) &&
				(cpiostyle || tarfile || pseudo_stdin))
		BAD_ERROR("Only one of cpiostyle, tar file or pseudo file "
				"reading from stdin can be specified\n");

	for(i = option_offset; i < argc; i++) {
		if(strcmp(argv[i], "-ignore-zeros") == 0)
			ignore_zeros = TRUE;
		else if(strcmp(argv[i], "-one-file-system") == 0)
			one_file_system = TRUE;
		else if(strcmp(argv[i], "-one-file-system-x") == 0)
			one_file_system = one_file_system_x = TRUE;
		else if(strcmp(argv[i], "-recovery-path") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -recovery-path missing pathname\n");
			recovery_pathname = argv[i];
		} else if(strcmp(argv[i], "-no-hardlinks") == 0)
			no_hardlinks = TRUE;
		else if(strcmp(argv[i], "-no-strip") == 0 ||
					strcmp(argv[i], "-tarstyle") == 0)
			tarstyle = TRUE;
		else if(strcmp(argv[i], "-max-depth") == 0) {
			if((++i == argc) || !parse_num_unsigned(argv[i], &max_depth))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -max-depth missing or invalid value\n");
		} else if(strcmp(argv[i], "-throttle") == 0) {
			if((++i == argc) || !parse_number(argv[i], &res, 2))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -throttle missing or invalid value\n");
			if(res > 99)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -throttle value should be between 0 and 99\n");
			set_sleep_time(res);
			readq = 4;
			force_single_threaded = TRUE;
		} else if(strcmp(argv[i], "-limit") == 0) {
			if((++i == argc) || !parse_number(argv[i], &res, 2))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -limit missing or invalid value\n");
			if(res < 1 || res > 100)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -limit value should be between 1 and 100\n");
			set_sleep_time(100 - res);;
			readq = 4;
			force_single_threaded = TRUE;
		} else if(strcmp(argv[i], "-mkfs-time") == 0 ||
				strcmp(argv[i], "-fstime") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing time value\n", argv[i - 1]);
			else if(strcmp(argv[i], "inode") == 0)
				mkfs_inode_opt = TRUE;
			else if(!parse_num_unsigned(argv[i], &mkfs_time) &&
					!exec_date(argv[i], &mkfs_time))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s invalid time value\n", argv[i - 1]);
			else
				mkfs_time_opt = TRUE;
		} else if(strcmp(argv[i], "-all-time") == 0) {
			if((++i == argc) ||
					(!parse_num_unsigned(argv[i], &inode_time) &&
					!exec_date(argv[i], &inode_time)))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -all-time missing or invalid time value\n");
			inode_time_opt = TRUE;
			clamping = FALSE;
		} else if(strcmp(argv[i], "-inode-time") == 0) {
			if((++i == argc) ||
					(!parse_num_unsigned(argv[i], &inode_time) &&
					!exec_date(argv[i], &inode_time)))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -inode-time missing or invalid time value\n");
			inode_time_opt = TRUE;
			clamping = FALSE;
		} else if(strcmp(argv[i], "-reproducible") == 0);
			/* obsolete option, ignored and retained for backwards
			 * compatibility */
		else if(strcmp(argv[i], "-not-reproducible") == 0);
			/* obsolete option, ignored and retained for backwards
			 * compatibility */
		else if(strcmp(argv[i], "-root-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &root_mode))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-mode missing or invalid mode, symbolic mode or octal number expected\n");
			root_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-root-uid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &root_uid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-uid uid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-uid invalid uid or unknown user name\n");
			}
			root_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-root-gid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &root_gid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-gid gid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-gid invalid gid or unknown group name\n");
			}
			root_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-uid-gid-offset") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -uid-gid-offset missing offset\n");
			res = get_uid_gid_offset_from_arg(argv[i], &uid_gid_offset);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -uid-gid-offset out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -uid-gid-offset invalid number\n");
			}
		} else if(strcmp(argv[i], "-root-time") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-time missing time value\n");
			else if(strcmp(argv[i], "inode") == 0)
				root_inode_opt = TRUE;
			else if(!parse_num_unsigned(argv[i], &root_time) &&
					!exec_date(argv[i], &root_time))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-time invalid time value\n");
			else
				root_time_opt = TRUE;
		} else if(strcmp(argv[i], "-default-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &default_mode))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-mode missing or invalid mode, symbolic mode or octal number expected\n");
			root_mode = default_mode;
			default_mode_opt = root_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-default-uid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &default_uid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-uid uid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-uid invalid uid or unknown user name\n");
			}
			root_uid = default_uid;
			default_uid_opt = root_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-default-gid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &default_gid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-gid gid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -default-gid invalid gid or unknown group name\n");
			}
			root_gid = default_gid;
			default_gid_opt = root_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-log") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -log missing log file\n");
			open_log_file(argv[i]);

		} else if(strcmp(argv[i], "-action") == 0 ||
				strcmp(argv[i], "-a") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing action\n", argv[i - 1]);
			res = parse_action(argv[i], ACTION_LOG_NONE);
			if(res == 0)
				exit(1);

		} else if(strcmp(argv[i], "-log-action") == 0 ||
				strcmp(argv[i], "-va") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing action\n", argv[i - 1]);
			res = parse_action(argv[i], ACTION_LOG_VERBOSE);
			if(res == 0)
				exit(1);

		} else if(strcmp(argv[i], "-true-action") == 0 ||
				strcmp(argv[i], "-ta") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing action\n", argv[i - 1]);
			res = parse_action(argv[i], ACTION_LOG_TRUE);
			if(res == 0)
				exit(1);

		} else if(strcmp(argv[i], "-false-action") == 0 ||
				strcmp(argv[i], "-fa") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing action\n", argv[i - 1]);
			res = parse_action(argv[i], ACTION_LOG_FALSE);
			if(res == 0)
				exit(1);

		} else if(strcmp(argv[i], "-action-file") == 0 ||
				strcmp(argv[i], "-af") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing filename\n", argv[i - 1]);
			if(read_action_file(argv[i], ACTION_LOG_NONE) == FALSE)
				exit(1);

		} else if(strcmp(argv[i], "-log-action-file") == 0 ||
				strcmp(argv[i], "-vaf") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing filename\n", argv[i - 1]);
			if(read_action_file(argv[i], ACTION_LOG_VERBOSE) == FALSE)
				exit(1);

		} else if(strcmp(argv[i], "-true-action-file") == 0 ||
				strcmp(argv[i], "-taf") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing filename\n", argv[i - 1]);
			if(read_action_file(argv[i], ACTION_LOG_TRUE) == FALSE)
				exit(1);

		} else if(strcmp(argv[i], "-false-action-file") == 0 ||
				strcmp(argv[i], "-faf") ==0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing filename\n", argv[i - 1]);
			if(read_action_file(argv[i], ACTION_LOG_FALSE) == FALSE)
				exit(1);

		} else if(strncmp(argv[i], "-X", 2) == 0) {
			int args = compressor_options(comp, argv + i, argc - i);

			if(args < 0) {
				if(args == -1) {
					ERROR("mksquashfs: Unrecognised compressor"
						" option %s\n", argv[i]);
					if(!compressor_opt_parsed)
						ERROR("mksquashfs: Did you forget to"
							" specify -comp?\n");
					print_selected_comp_options(stderr, comp, "mksquashfs");
				}
				exit(1);
			}
			i += args;

		} else if(strcmp(argv[i], "-pf") == 0) {
			if(read_pseudo_file(argv[++i], destination_file) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-p") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -p missing pseudo file definition\n");
			if(read_pseudo_definition(argv[i], destination_file) == FALSE)
				exit(1);
		} else if(strcmp(argv[i], "-pd") == 0 || strcmp(argv[i], "-pseudo-dir") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing pseudo file definition\n", argv[i - 1]);
			pseudo_dir = read_pseudo_dir(argv[i]);
			if(pseudo_dir == NULL)
				exit(1);
		} else if(strcmp(argv[i], "-recover") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -recover missing recovery file\n");
			read_recovery_data(argv[i], destination_file);
		} else if(strcmp(argv[i], "-no-recovery") == 0)
			recover = FALSE;
		else if(strcmp(argv[i], "-wildcards") == 0) {
			old_exclude = FALSE;
			use_regex = FALSE;
		} else if(strcmp(argv[i], "-regex") == 0) {
			old_exclude = FALSE;
			use_regex = TRUE;
		} else if(strcmp(argv[i], "-no-sparse") == 0)
			sparse_files = FALSE;
		else if(strcmp(argv[i], "-no-progress") == 0)
			progress = FALSE;
		else if(strcmp(argv[i], "-progress") == 0)
			force_progress = TRUE;
		else if(strcmp(argv[i], "-exports") == 0)
			exportable = TRUE;
		else if(strcmp(argv[i], "-no-exports") == 0)
			exportable = FALSE;
		else if(strcmp(argv[i], "-offset") == 0 ||
						strcmp(argv[i], "-o") == 0) {
			if((++i == argc) ||
					!parse_numberll(argv[i], &start_offset, 1))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: %s missing or invalid offset size\n", argv[i - 1]);
		} else if(strcmp(argv[i], "-processors") == 0) {
			if((++i == argc) || !parse_num(argv[i], &processors))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -processors missing or invalid processor number\n");
			if(processors < 1)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -processors should be 1 or larger\n");
		} else if(strcmp(argv[i], "-read-queue") == 0) {
			if((++i == argc) || !parse_num(argv[i], &readq)) {
				ERROR("mksquashfs: -read-queue missing or invalid "
					"queue size\n");
				exit(1);
			}
			if(readq < 1) {
				ERROR("mksquashfs: -read-queue should be 1 megabyte or "
					"larger\n");
				exit(1);
			}
		} else if(strcmp(argv[i], "-write-queue") == 0) {
			if((++i == argc) || !parse_num(argv[i], &bwriteq)) {
				ERROR("mksquashfs: -write-queue missing or invalid "
					"queue size\n");
				exit(1);
			}
			if(bwriteq < 2) {
				ERROR("mksquashfs: -write-queue should be 2 megabytes "
					"or larger\n");
				exit(1);
			}
			fwriteq = bwriteq >> 1;
			bwriteq -= fwriteq;
		} else if(strcmp(argv[i], "-fragment-queue") == 0) {
			if((++i == argc) || !parse_num(argv[i], &fragq)) {
				ERROR("mksquashfs: -fragment-queue missing or invalid "
					"queue size\n");
				exit(1);
			}
			if(fragq < 1) {
				ERROR("mksquashfs: -fragment-queue should be 1 "
					"megabyte or larger\n");
				exit(1);
			}
		} else if(strcmp(argv[i], "-mem") == 0) {
			long long number = 0;

			if(mem_options_disabled) {
				ERROR("Ignoring -mem option because amount of "
					"system memory unknown!\n)");
				continue;
			}

			if((++i == argc) ||
					!parse_numberll(argv[i], &number, 1))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -mem missing or invalid mem size\n");

			/*
			 * convert from bytes to Mbytes, ensuring the value
			 * does not overflow a signed int
			 */
			if(number >= (1LL << 51))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -mem invalid mem size\n");

			total_mem = number / 1048576;
			calculate_queue_sizes(total_mem, &readq, &fragq,
				&bwriteq, &fwriteq);
		} else if(strcmp(argv[i], "-mem-percent") == 0) {
			int percent, phys_mem;

			if(mem_options_disabled) {
				ERROR("Ignoring -mem-percent option because amount of "
					"system memory unknown!\n)");
				continue;
			}
			/*
			 * Percentage of 75% and larger is dealt with later.
			 * In the same way a fixed mem size if more than 75%
			 * of memory is dealt with later.
			 */
			if((++i == argc) ||
					!parse_number(argv[i], &percent, 2) ||
					(percent < 1))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -mem-percent missing or invalid percentage: it should be 1 - 75%%\n");

			phys_mem = get_physical_memory();

			if(phys_mem == 0) {
				ERROR("mksquashfs: -mem-percent unable to get physical "
					"memory\n");
				exit(1);
			}

			if(multiply_overflow(phys_mem, percent))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -mem-percent requested phys mem too large\n");

			total_mem = phys_mem * percent / 100;

			calculate_queue_sizes(total_mem, &readq, &fragq,
				&bwriteq, &fwriteq);
		} else if(strcmp(argv[i], "-b") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -b missing block size\n");
			if(!parse_number(argv[i], &block_size, 1))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -b invalid block size\n");
			if((block_log = slog(block_size)) == 0)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -b block size not power of two or not between 4096 and 1Mbyte\n");
		} else if(strcmp(argv[i], "-ef") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -ef missing filename\n");
			exclude_option = TRUE;
		} else if(strcmp(argv[i], "-no-duplicates") == 0)
			duplicate_checking = FALSE;

		else if(strcmp(argv[i], "-no-fragments") == 0)
			no_fragments = TRUE;

		 else if(strcmp(argv[i], "-tailends") == 0 ||
				 strcmp(argv[i], "-always-use-fragments") == 0)
			always_use_fragments = TRUE;

		else if(strcmp(argv[i], "-no-tailends") == 0)
			always_use_fragments = FALSE;

		else if(strcmp(argv[i], "-sort") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -sort missing filename\n");
		} else if(strcmp(argv[i], "-all-root") == 0 ||
				strcmp(argv[i], "-root-owned") == 0) {
			global_uid = global_gid = 0;
			global_uid_opt = global_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-force-file-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &global_file_mode))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-file-mode missing or invalid mode, symbolic mode or octal number expected\n");
			global_file_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-force-dir-mode") == 0) {
			if((++i == argc) || !parse_mode(argv[i], &global_dir_mode))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-dir-mode missing or invalid mode, symbolic mode or octal number expected\n");
			global_dir_mode_opt = TRUE;
		} else if(strcmp(argv[i], "-force-uid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-uid missing uid or user name\n");
			res = get_uid_from_arg(argv[i], &global_uid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-uid uid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-uid invalid uid or unknown user name\n");
			}
			global_uid_opt = TRUE;
		} else if(strcmp(argv[i], "-force-gid") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-gid missing gid or group name\n");
			res = get_gid_from_arg(argv[i], &global_gid);
			if(res) {
				if(res == -2)
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-gid gid out of range\n");
				else
					mksquashfs_option_help(argv[i - 1], "mksquashfs: -force-gid invalid gid or unknown group name\n");
			}
			global_gid_opt = TRUE;
		} else if(strcmp(argv[i], "-pseudo-override") == 0)
			pseudo_override = TRUE;
		else if(strcmp(argv[i], "-noI") == 0 ||
				strcmp(argv[i], "-noInodeCompression") == 0)
			noI = TRUE;

		else if(strcmp(argv[i], "-noId") == 0 ||
				strcmp(argv[i], "-noIdTableCompression") == 0)
			noId = TRUE;

		else if(strcmp(argv[i], "-noD") == 0 ||
				strcmp(argv[i], "-noDataCompression") == 0)
			noD = TRUE;

		else if(strcmp(argv[i], "-noF") == 0 ||
				strcmp(argv[i], "-noFragmentCompression") == 0)
			noF = TRUE;

		else if(strcmp(argv[i], "-noX") == 0 ||
				strcmp(argv[i], "-noXattrCompression") == 0)
			noX = TRUE;

		else if(strcmp(argv[i], "-no-compression") == 0)
			noI = noD = noF = noX = TRUE;

		else if(strcmp(argv[i], "-no-xattrs") == 0) {
			if(xattr_exclude_preg || xattr_include_preg ||
							add_xattrs())
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -no-xattrs should not be used in combination with -xattrs-* options\n");
			no_xattrs = TRUE;

		} else if(strcmp(argv[i], "-xattrs") == 0) {
			if(xattrs_supported())
				no_xattrs = FALSE;
			else {
				ERROR("mksquashfs: xattrs are unsupported in "
					"this build\n");
				exit(1);
			}

		} else if(strcmp(argv[i], "-xattrs-exclude") == 0) {
			if(!xattrs_supported()) {
				ERROR("mksquashfs: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -xattrs-exclude missing regex pattern\n");
			else {
				xattr_exclude_preg = xattr_regex(argv[i], "exclude");
				no_xattrs = FALSE;
			}

		} else if(strcmp(argv[i], "-xattrs-include") == 0) {
			if(!xattrs_supported()) {
				ERROR("mksquashfs: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -xattrs-include missing regex pattern\n");
			else {
				xattr_include_preg = xattr_regex(argv[i], "include");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-xattrs-add") == 0) {
			if(!xattrs_supported()) {
				ERROR("mksquashfs: xattrs are unsupported in "
					"this build\n");
				exit(1);
			} else if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -xattrs-add missing xattr argument\n");
			else {
				xattrs_add(argv[i]);
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-nopad") == 0)
			nopad = TRUE;

		else if(strcmp(argv[i], "-info") == 0)
			display_info = TRUE;

		else if(strcmp(argv[i], "-info-file") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -info-file missing filename\n");
			display_info = TRUE;
			info_file = open_info_file(argv[i]);

		} else if(strcmp(argv[i], "-e") == 0) {
			exclude_option = TRUE;
			break;

		} else if(strcmp(argv[i], "-noappend") == 0)
			appending = FALSE;

		else if(strcmp(argv[i], "-quiet") == 0)
			quiet = TRUE;

		else if(strcmp(argv[i], "-keep-as-directory") == 0)
			keep_as_directory = TRUE;

		else if(strcmp(argv[i], "-exit-on-error") == 0)
			exit_on_error = TRUE;

		else if(strcmp(argv[i], "-root-becomes") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -root-becomes: missing name\n");
			root_name = argv[i];
		} else if(strcmp(argv[i], "-percentage") == 0) {
			progressbar_percentage();
			percentage = TRUE;
		} else if(strcmp(argv[i], "-version") == 0) {
			print_version("mksquashfs");
		} else if(strcmp(argv[i], "-cpiostyle") == 0 ||
				strcmp(argv[i], "-cpiostyle0") == 0 ||
				strcmp(argv[i], "-tar") == 0) {
			/* parsed previously */
		} else if(strcmp(argv[i], "-comp") == 0) {
			/* parsed previously */
			i++;
		} else if(strcmp(argv[i], "-small-readers") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -small-readers missing thread count\n");
			if(force_single_threaded)
				ERROR("Warning: ignoring -small-readers option because you're reading a tar file, using an Unsquashfs pseudo file or throttling I/O\n");
			else if(!parse_num(argv[i], &res) || res == 0)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -small-readers invalid thread count\n");
			else if(res > MAX_READER_THREADS) {
				ERROR("mksquashfs: -small-readers thread count too large, it should be between 1 and %d\n", MAX_READER_THREADS);
				if(file_limit() != -1 && MAX_READER_THREADS * 2 > file_limit())
					ERROR("Note total reader threads (small and block readers) above %d will exceed your open file limit (ulimit -n less margin of %d)\n",
							file_limit(), OPEN_FILE_MARGIN);
				exit(1);
			}
			set_read_frag_threads(res);
		} else if(strcmp(argv[i], "-block-readers") == 0) {
			if(++i == argc)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -block-readers missing thread count\n");
			if(force_single_threaded)
				ERROR("Warning: ignoring -block-readers option because you're reading a tar file, using an Unsquashfs pseudo file or throttling I/O\n");
			else if(!parse_num(argv[i], &res) || res == 0)
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -block-readers invalid thread count\n");
			else if(res > MAX_READER_THREADS) {
				ERROR("mksquashfs: -block-readers thread count too large, it should be between 1 and %d\n", MAX_READER_THREADS);
				if(file_limit() != -1 && MAX_READER_THREADS * 2 > file_limit())
					ERROR("Note total reader threads (small and block readers) above %d will exceed your open file limit (ulimit -n less margin of %d)\n",
							file_limit(), OPEN_FILE_MARGIN);
				exit(1);
			}
			set_read_block_threads(res);
		} else if(strcmp(argv[i], "-single-reader") == 0)
			single_threaded = TRUE;
		else if(strcmp(argv[i], "-overcommit") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i], &overcommit, 2) ||
					(overcommit > 100))
				mksquashfs_option_help(argv[i - 1], "mksquashfs: -overcommit missing or invalid percentage: it should be 0 - 100%%\n");
		} else
			mksquashfs_invalid_option(argv[i]);
	}

	check_source_date_epoch();

	/* If cpiostyle is set, then file names  will be read-in
	 * from standard in.  We do not expect to have any sources
	 * specified on the command line */
	if(cpiostyle && source)
		BAD_ERROR("Sources on the command line should be - when using "
			"-cpiostyle[0] options, i.e. mksquashfs - image.sqfs "
			"-cpiostyle\n");

	/* If -tar option is set, then files will be read-in
	 * from standard in.  We do not expect to have any sources
	 * specified on the command line */
	if(tarfile && source)
		BAD_ERROR("Sources on the command line should be - when using "
			"-tar option, i.e. mksquashfs - image.sqfs -tar\n");

	/* If -tar option is set, then check that actions have not been
	 * specified, which are unsupported with tar file reading
	 */
	if(tarfile && any_actions())
		BAD_ERROR("Actions are unsupported when reading tar files\n");

	/* If -tar option is set and there are exclude files (either -ef or -e),
	 * then -wildcards must be set too.  The older legacy exclude code
	 * cannot be used with tar files */
	if(tarfile && exclude_option && old_exclude)
		BAD_ERROR("-wildcards must be specified with tar files and -ef/-e\n");

	/*
	 * The -noI option implies -noId for backwards compatibility, so reset
	 * noId if both have been specified
	 */
	if(noI && noId)
		noId = FALSE;

	/*
	 * Some compressors may need the options to be checked for validity
	 * once all the options have been processed
	 */
	res = compressor_options_post(comp, block_size);
	if(res)
		EXIT_MKSQUASHFS();

	/*
	 * Selecting both -no-progress and -percentage produces a conflict,
	 * and so reject such command lines
	 */
	if(!progress && percentage)
			BAD_ERROR("Only one of -no-progress and -percentage can be "
				"specified.  Both causes a conflict.\n");

		/*
		 * Selecting both -no-progress and -progress produces a conflict,
		 * and so reject such command lines
		 */
		if(!progress && force_progress)
			BAD_ERROR("Only one of -no-progress and -progress can be "
				"specified.  Both causes a conflict.\n");

		/*
		 * If the -info option has been selected then disable the
		 * progress bar unless it has been explicitly enabled with
		 * the -progress option
		 */
		if(display_info && !info_file)
			progress = force_progress;
			
		/*
		 * Sort all the xattr-add options now they're all processed
		 */
		sort_xattr_add_list();

		/*
		 * If -pseudo-override option has been specified and there are
		 * no pseudo files then reset option.  -pseudo-override relies
		 * on dir_scan2() being run, which won't be if there's no
		 * actions or pseudo files
		 */
		if(pseudo_override && !get_pseudo())
			pseudo_override = FALSE;

#ifdef SQUASHFS_TRACE
		/*
		 * Disable progress bar if full debug tracing is enabled.
		 * The progress bar in this case just gets in the way of the
		 * debug trace output
		 */
		progress = FALSE;
#endif


		if(!readers_sane())
			BAD_ERROR("Changing from single reader default requires both -small-readers and -block-readers options to be specified\n");

		/*
		 * Some options only make sense with a single reader thread and
		 * so override the default
		 * */
		if(single_threaded || force_single_threaded)
			set_single_threaded();

		/*
		 * Ensure the specified (or default) number of reader threads doesn't
		 * exceed the maximum open file limit
		 */
		if(file_limit() != -1 && get_reader_num() > file_limit())
			BAD_ERROR("Reader threads exceed open file limit. Please "
				"increase open file limit with ulimit or decrease "
				"number of reader threads (ulimit -n must be %d "
				"more than number of reader threads)\n",
				OPEN_FILE_MARGIN);

		if(one_file_system && source > 1)
			source_dev = MALLOC(source * sizeof(dev_t));

		for(i = 0; i < source; i++) {
			if(lstat(source_path[i], &source_buf) == -1) {
				fprintf(stderr, "Cannot stat source directory \"%s\" "
					"because %s\n", source_path[i],
					strerror(errno));
				EXIT_MKSQUASHFS();
			}

			if(one_file_system) {
				if(source > 1)
					source_dev[i] = source_buf.st_dev;
				else
					cur_dev = source_buf.st_dev;
			}
		}

		if(stat(destination_file, &buf) == -1) {
			if(errno == ENOENT) { /* Does not exist */
				appending = FALSE;
				fd = open(destination_file, O_CREAT | O_TRUNC | O_RDWR,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
				if(fd == -1) {
					perror("Could not create destination file");
					exit(1);
				}

				/* ensure Mksquashfs doesn't try to read
				 * the destination file as input, which
				 * will result in an I/O loop */
				if(stat(destination_file, &buf) == -1) {
					/* disappered after creating? */
					perror("Could not stat destination file");
					exit(1);
				}
				ADD_ENTRY(buf);
			} else {
				perror("Could not stat destination file");
				exit(1);
			}

		} else {
			if(!S_ISBLK(buf.st_mode) && !S_ISREG(buf.st_mode)) {
				ERROR("Destination not block device or regular file\n");
				exit(1);
			}

			if(tarfile && appending) {
				ERROR("Appending is not supported reading tar files\n");
				ERROR("To force Mksquashfs to write to this %s "
					"use -noappend\n", S_ISBLK(buf.st_mode) ?
					"block device" : "file");
				EXIT_MKSQUASHFS();
			}

			if(S_ISBLK(buf.st_mode)) {
				if((fd = open(destination_file, O_RDWR)) == -1) {
					perror("Could not open block device as "
						"destination");
					exit(1);
				}
				block_device = 1;

			} else {
				fd = open(destination_file, (!appending ? O_TRUNC : 0) |
					O_RDWR);
				if(fd == -1) {
					perror("Could not open regular file for "
						"writing as destination");
					exit(1);
				}
				/* ensure Mksquashfs doesn't try to read
				 * the destination file as input, which
				 * will result in an I/O loop */
				ADD_ENTRY(buf);
			}
		}

		/*
		 * process the exclude files - must be done afer destination file has
		 * been possibly created
		 */
		for(i = option_offset; i < argc; i++)
			if(strcmp(argv[i], "-ef") == 0)
				/*
				 * Note presence of filename arg has already
				 * been checked
				 */
				process_exclude_file(argv[++i]);
			else if(strcmp(argv[i], "-e") == 0)
				break;
			else if(option_with_arg(argv[i], option_table))
				i++;

		if(i != argc) {
			if(++i == argc) {
				ERROR("mksquashfs: -e missing arguments\n");
				EXIT_MKSQUASHFS();
			}
			while(i < argc)
				if(old_exclude)
					old_add_exclude(argv[i++]);
				else
					add_exclude(argv[i++]);
		}

		/* process the sort files - must be done afer the exclude files  */
		for(i = option_offset; i < argc; i++)
			if(strcmp(argv[i], "-sort") == 0) {
				if(tarfile)
					BAD_ERROR("Sorting files is unsupported when "
						"reading tar files\n");

				res = read_sort_file(argv[++i], source, source_path);
				if(res == FALSE)
					BAD_ERROR("Failed to read sort file\n");
				sorted ++;
			} else if(strcmp(argv[i], "-e") == 0)
				break;
			else if(option_with_arg(argv[i], option_table))
				i++;

		if(appending) {
			comp = read_super(fd, &sBlk, destination_file);
			if(comp == NULL) {
				ERROR("Failed to read existing filesystem - will not "
					"overwrite - ABORTING!\n");
				ERROR("To force Mksquashfs to write to this %s "
					"use -noappend\n", block_device ?
					"block device" : "file");
				EXIT_MKSQUASHFS();
			}

			block_log = slog(block_size = sBlk.block_size);
			noI = SQUASHFS_UNCOMPRESSED_INODES(sBlk.flags);
			noD = SQUASHFS_UNCOMPRESSED_DATA(sBlk.flags);
			noF = SQUASHFS_UNCOMPRESSED_FRAGMENTS(sBlk.flags);
			noX = SQUASHFS_UNCOMPRESSED_XATTRS(sBlk.flags);
			noId = SQUASHFS_UNCOMPRESSED_IDS(sBlk.flags);
			no_fragments = SQUASHFS_NO_FRAGMENTS(sBlk.flags);
			always_use_fragments = SQUASHFS_ALWAYS_FRAGMENTS(sBlk.flags);
			duplicate_checking = SQUASHFS_DUPLICATES(sBlk.flags);
			exportable = SQUASHFS_EXPORTABLE(sBlk.flags);
			no_xattrs = SQUASHFS_NO_XATTRS(sBlk.flags);
			comp_opts = SQUASHFS_COMP_OPTS(sBlk.flags);
		}

		initialise_threads(readq, fragq, bwriteq, fwriteq, !appending,
			destination_file, "Mksquashfs", overcommit);

		res = compressor_init(comp, &stream, SQUASHFS_METADATA_SIZE, 0);
		if(res)
			BAD_ERROR("compressor_init failed\n");

		dupl_block = MALLOC(1048576 * sizeof(struct file_info *));
		dupl_frag = MALLOC(block_size * sizeof(struct file_info *));
		memset(dupl_block, 0, 1048576 * sizeof(struct file_info *));
		memset(dupl_frag, 0, block_size * sizeof(struct file_info *));

		if(!appending) {
			int size;
			void *comp_data = compressor_dump_options(comp, block_size,
				&size);

			if(!quiet)
				printf("Creating %d.%d filesystem on %s, block size %d.\n",
					SQUASHFS_MAJOR, SQUASHFS_MINOR,
					destination_file, block_size);

			/*
			 * store any compressor specific options after the superblock,
			 * and set the COMP_OPT flag to show that the filesystem has
			 * compressor specfic options
			 */
			if(comp_data) {
				unsigned short c_byte = size | SQUASHFS_COMPRESSED_BIT;
		
				SQUASHFS_INSWAP_SHORTS(&c_byte, 1);
				write_destination(fd, sizeof(struct squashfs_super_block),
					sizeof(c_byte), &c_byte);
				write_destination(fd, sizeof(struct squashfs_super_block) +
					sizeof(c_byte), size, comp_data);
				set_pos(sizeof(struct squashfs_super_block) + sizeof(c_byte) + size);
				comp_opts = TRUE;
			} else			
				set_pos(sizeof(struct squashfs_super_block));
		} else {
			unsigned int last_directory_block, inode_dir_file_size,
				root_inode_size, inode_dir_start_block,
				compressed_data, inode_dir_inode_number,
				inode_dir_parent_inode;
			unsigned int root_inode_start =
				SQUASHFS_INODE_BLK(sBlk.root_inode),
				root_inode_offset =
				SQUASHFS_INODE_OFFSET(sBlk.root_inode);
			int inode_dir_offset, uncompressed_data;
			long long bytes = read_filesystem(root_name, fd, &sBlk, &inode_table,
					&data_cache, &directory_table,
					&directory_data_cache, &last_directory_block,
					&inode_dir_offset, &inode_dir_file_size,
					&root_inode_size, &inode_dir_start_block,
					&file_count, &sym_count, &dev_count, &dir_count,
					&fifo_count, &sock_count, &total_bytes,
					&total_inode_bytes, &total_directory_bytes,
					&inode_dir_inode_number,
					&inode_dir_parent_inode, add_old_root_entry,
					&fragment_table, &inode_lookup_table);

			if(bytes == 0) {
				ERROR("Failed to read existing filesystem - will not "
					"overwrite - ABORTING!\n");
				ERROR("To force Mksquashfs to write to this block "
					"device or file use -noappend\n");
				EXIT_MKSQUASHFS();
			}

			set_pos(bytes);

			if((fragments = sBlk.fragments))
				fragment_table = REALLOC((char *) fragment_table,
					((fragments + FRAG_SIZE - 1) & ~(FRAG_SIZE - 1))
					 * sizeof(struct squashfs_fragment_entry)); 

			if(!quiet) {
				printf("Appending to existing %d.%d filesystem on "
					"%s, block size %d\n", SQUASHFS_MAJOR,
					SQUASHFS_MINOR, destination_file, block_size);
				printf("All -b, -noI, -noD, -noF, -noX, -noId, "
					"-no-duplicates, -no-fragments,\n"
					"-always-use-fragments, -exportable and "
					"-comp options ignored\n");
				printf("\nIf appending is not wanted, please re-run "
					"with -noappend specified!\n\n");
			}

			compressed_data = ((long long) inode_dir_offset +
				inode_dir_file_size) & ~(SQUASHFS_METADATA_SIZE - 1);
			uncompressed_data = ((long long) inode_dir_offset +
				inode_dir_file_size) & (SQUASHFS_METADATA_SIZE - 1);
			
			/* save original filesystem state for restoring ... */
			sfragments = fragments;
			sbytes = bytes;
			sinode_count = sBlk.inodes;
			scache_bytes = root_inode_offset + root_inode_size;
			sdirectory_cache_bytes = uncompressed_data;
			sdata_cache = MALLOC(scache_bytes);
			sdirectory_data_cache = MALLOC(sdirectory_cache_bytes);
			memcpy(sdata_cache, data_cache, scache_bytes);
			memcpy(sdirectory_data_cache, directory_data_cache +
				compressed_data, sdirectory_cache_bytes);
			sinode_bytes = root_inode_start;
			stotal_bytes = total_bytes;
			stotal_inode_bytes = total_inode_bytes;
			stotal_directory_bytes = total_directory_bytes +
				compressed_data;
			sfile_count = file_count;
			ssym_count = sym_count;
			sdev_count = dev_count;
			sdir_count = dir_count + 1;
			sfifo_count = fifo_count;
			ssock_count = sock_count;
			sdup_files = dup_files;
			sid_count = id_count;
			write_recovery_data(&sBlk);
			save_xattrs();

			/*
			 * set the filesystem state up to be able to append to the
			 * original filesystem.  The filesystem state differs depending
			 * on whether we're appending to the original root directory, or
			 * if the original root directory becomes a sub-directory
			 * (root-becomes specified on command line, here root_name !=
			 * NULL)
			 */
			inode_bytes = inode_size = root_inode_start;
			directory_size = last_directory_block;
			cache_size = root_inode_offset + root_inode_size;
			directory_cache_size = inode_dir_offset + inode_dir_file_size;
			if(root_name) {
				sdirectory_bytes = last_directory_block;
				sdirectory_compressed_bytes = 0;
				root_inode_number = inode_dir_parent_inode;
				inode_no = sBlk.inodes + 2;
				inode_start_no = sBlk.inodes + 1;
				directory_bytes = last_directory_block;
				directory_cache_bytes = uncompressed_data;
				memmove(directory_data_cache, directory_data_cache +
					compressed_data, uncompressed_data);
				cache_bytes = root_inode_offset + root_inode_size;
				add_old_root_entry(root_name, sBlk.root_inode,
					inode_dir_inode_number, SQUASHFS_DIR_TYPE);
				total_directory_bytes += compressed_data;
				dir_count ++;
			} else {
				sdirectory_compressed_bytes = last_directory_block -
					inode_dir_start_block;
				sdirectory_compressed =
					MALLOC(sdirectory_compressed_bytes);
				memcpy(sdirectory_compressed, directory_table +
					inode_dir_start_block,
					sdirectory_compressed_bytes); 
				sdirectory_bytes = inode_dir_start_block;
				root_inode_number = inode_dir_inode_number;
				inode_no = sBlk.inodes + 1;
				inode_start_no = sBlk.inodes;
				directory_bytes = inode_dir_start_block;
				directory_cache_bytes = inode_dir_offset;
				cache_bytes = root_inode_offset;
			}

			inode_count = file_count + dir_count + sym_count + dev_count +
				fifo_count + sock_count;
		}

		if(path)
			paths = add_subdir(paths, path);

		dump_actions(); 
		dump_pseudos();

		set_progressbar_state(progress);

		if(tarfile)
			inode = process_tar_file(progress);
		else if(tarstyle || cpiostyle)
			inode = process_source(progress);
		else if(!source)
			inode = no_sources(progress);
		else
			inode = dir_scan(S_ISDIR(source_buf.st_mode), progress);

		sBlk.root_inode = inode;
		sBlk.inodes = inode_count;
		sBlk.s_magic = SQUASHFS_MAGIC;
		sBlk.s_major = SQUASHFS_MAJOR;
		sBlk.s_minor = SQUASHFS_MINOR;
		sBlk.block_size = block_size;
		sBlk.block_log = block_log;
		sBlk.flags = SQUASHFS_MKFLAGS(noI, noD, noF, noX, noId, no_fragments,
			always_use_fragments, duplicate_checking, exportable,
			no_xattrs, comp_opts);
		if(mkfs_time_opt)
			sBlk.mkfs_time = mkfs_time;
		else if(mkfs_inode_opt)
			sBlk.mkfs_time = inode_time_latest;
		else
			sBlk.mkfs_time = time(NULL);

		disable_info();

	while((fragment = get_frag_action(fragment)))
		write_fragment(*fragment);

	sync_writer_thread();
	pthread_cancel(writer_thread);

	if(!check_id_table_offset())
		BAD_ERROR("id entry out of range after applying -uid-gid-offset offset\n");

	write_filesystem_tables(&sBlk);

	progressbar_finish();

	if(!block_device) {
		res = ftruncate(fd, get_dpos());
		if(res != 0)
			BAD_ERROR("Failed to truncate dest file because %s\n",
				strerror(errno));
	}

	if(!nopad && (i = get_dpos() & (4096 - 1))) {
		char temp[4096] = {0};
		write_destination(fd, get_dpos(), 4096 - i, temp);
	}

	res = close(fd);

	if(res == -1)
		BAD_ERROR("Failed to close output filesystem, close returned %s\n",
				strerror(errno));

	if(recovery_file)
		unlink(recovery_file);

	if(!quiet)
		print_summary();

	if(logging)
		fclose(log_fd);

	return 0;
}
