/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011,
 * 2012, 2013, 2014, 2017, 2019, 2020, 2021, 2022, 2023
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
 * unsquashfs.c
 */

#include "unsquashfs.h"
#include "squashfs_compat.h"
#include "squashfs_swap.h"
#include "compressor.h"
#include "xattr.h"
#include "unsquashfs_info.h"
#include "stdarg.h"
#include "fnmatch_compat.h"

#ifdef __linux__
#include <sched.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#else
#include <sys/sysctl.h>
#endif

#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <limits.h>
#include <ctype.h>

struct cache *fragment_cache, *data_cache;
struct queue *to_reader, *to_inflate, *to_writer, *from_writer;
pthread_t *thread, *inflator_thread;
pthread_mutex_t	fragment_mutex;
static long long start_offset = 0;

/* user options that control parallelisation */
int processors = -1;

struct super_block sBlk;
squashfs_operations *s_ops;
struct compressor *comp;

int bytes = 0, swap, file_count = 0, dir_count = 0, sym_count = 0,
	dev_count = 0, fifo_count = 0, socket_count = 0, hardlnk_count = 0;
struct hash_table_entry *inode_table_hash[65536], *directory_table_hash[65536];
int fd;
unsigned int cached_frag = SQUASHFS_INVALID_FRAG;
unsigned int block_size;
unsigned int block_log;
int lsonly = FALSE, info = FALSE, force = FALSE, short_ls = TRUE;
int concise = FALSE, quiet = FALSE, numeric = FALSE;
int use_regex = FALSE;
int root_process;
int columns;
int rotate = 0;
pthread_mutex_t	screen_mutex;
pthread_mutex_t pos_mutex = PTHREAD_MUTEX_INITIALIZER;
int progress = TRUE, progress_enabled = FALSE, percent = FALSE;
unsigned int total_files = 0, total_inodes = 0;
long long total_blocks = 0;
long long cur_blocks = 0;
int inode_number = 1;
int ignore_errors = FALSE;
int strict_errors = FALSE;
int use_localtime = TRUE;
int max_depth = -1; /* unlimited */
int follow_symlinks = FALSE;
int missing_symlinks = FALSE;
int no_wildcards = FALSE;
int set_exit_code = TRUE;
int treat_as_excludes = FALSE;
int stat_sys = FALSE;
int version = FALSE;
int mkfs_time_opt = FALSE;
int cat_files = FALSE;
int fragment_buffer_size = FRAGMENT_BUFFER_DEFAULT;
int data_buffer_size = DATA_BUFFER_DEFAULT;
char *dest = "squashfs-root";
struct pathnames *extracts = NULL, *excludes = NULL;
struct pathname *extract = NULL, *exclude = NULL, *stickypath = NULL;
int writer_fd = 1;
int pseudo_file = FALSE;
int pseudo_stdout = FALSE;
char *pseudo_name;
unsigned int timeval;
int time_opt = FALSE;
int full_precision = FALSE;

/* extended attribute flags */
int no_xattrs = XATTR_DEF;
regex_t *xattr_exclude_preg = NULL;
regex_t *xattr_include_preg = NULL;

int lookup_type[] = {
	0,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK,
	S_IFDIR,
	S_IFREG,
	S_IFLNK,
	S_IFBLK,
	S_IFCHR,
	S_IFIFO,
	S_IFSOCK
};

struct test table[] = {
	{ S_IFMT, S_IFSOCK, 0, 's' },
	{ S_IFMT, S_IFLNK, 0, 'l' },
	{ S_IFMT, S_IFBLK, 0, 'b' },
	{ S_IFMT, S_IFDIR, 0, 'd' },
	{ S_IFMT, S_IFCHR, 0, 'c' },
	{ S_IFMT, S_IFIFO, 0, 'p' },
	{ S_IRUSR, S_IRUSR, 1, 'r' },
	{ S_IWUSR, S_IWUSR, 2, 'w' },
	{ S_IRGRP, S_IRGRP, 4, 'r' },
	{ S_IWGRP, S_IWGRP, 5, 'w' },
	{ S_IROTH, S_IROTH, 7, 'r' },
	{ S_IWOTH, S_IWOTH, 8, 'w' },
	{ S_IXUSR | S_ISUID, S_IXUSR | S_ISUID, 3, 's' },
	{ S_IXUSR | S_ISUID, S_ISUID, 3, 'S' },
	{ S_IXUSR | S_ISUID, S_IXUSR, 3, 'x' },
	{ S_IXGRP | S_ISGID, S_IXGRP | S_ISGID, 6, 's' },
	{ S_IXGRP | S_ISGID, S_ISGID, 6, 'S' },
	{ S_IXGRP | S_ISGID, S_IXGRP, 6, 'x' },
	{ S_IXOTH | S_ISVTX, S_IXOTH | S_ISVTX, 9, 't' },
	{ S_IXOTH | S_ISVTX, S_ISVTX, 9, 'T' },
	{ S_IXOTH | S_ISVTX, S_IXOTH, 9, 'x' },
	{ 0, 0, 0, 0}
};

void progress_bar(long long current, long long max, int columns);

#define MAX_LINE 16384

void sigwinch_handler(int arg)
{
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
}


void sigalrm_handler(int arg)
{
	rotate = (rotate + 1) % 4;
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


struct queue *queue_init(int size)
{
	struct queue *queue = malloc(sizeof(struct queue));
	if(queue == NULL)
		MEM_ERROR();

	if(add_overflow(size, 1) ||
				multiply_overflow(size + 1, sizeof(void *)))
		EXIT_UNSQUASH("Size too large in queue_init\n");

	queue->data = malloc(sizeof(void *) * (size + 1));
	if(queue->data == NULL)
		MEM_ERROR();

	queue->size = size + 1;
	queue->readp = queue->writep = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->empty, NULL);
	pthread_cond_init(&queue->full, NULL);

	return queue;
}


void queue_put(struct queue *queue, void *data)
{
	int nextp;

	pthread_mutex_lock(&queue->mutex);

	while((nextp = (queue->writep + 1) % queue->size) == queue->readp)
		pthread_cond_wait(&queue->full, &queue->mutex);

	queue->data[queue->writep] = data;
	queue->writep = nextp;
	pthread_cond_signal(&queue->empty);
	pthread_mutex_unlock(&queue->mutex);
}


void *queue_get(struct queue *queue)
{
	void *data;
	pthread_mutex_lock(&queue->mutex);

	while(queue->readp == queue->writep)
		pthread_cond_wait(&queue->empty, &queue->mutex);

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_mutex_unlock(&queue->mutex);

	return data;
}


void dump_queue(struct queue *queue)
{
	pthread_mutex_lock(&queue->mutex);

	printf("Max size %d, size %d%s\n", queue->size - 1,  
		queue->readp <= queue->writep ? queue->writep - queue->readp :
			queue->size - queue->readp + queue->writep,
		queue->readp == queue->writep ? " (EMPTY)" :
			((queue->writep + 1) % queue->size) == queue->readp ?
			" (FULL)" : "");

	pthread_mutex_unlock(&queue->mutex);
}


/* Called with the cache mutex held */
void insert_hash_table(struct cache *cache, struct cache_entry *entry)
{
	int hash = TABLE_HASH(entry->block);

	entry->hash_next = cache->hash_table[hash];
	cache->hash_table[hash] = entry;
	entry->hash_prev = NULL;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry;
}


/* Called with the cache mutex held */
void remove_hash_table(struct cache *cache, struct cache_entry *entry)
{
	if(entry->hash_prev)
		entry->hash_prev->hash_next = entry->hash_next;
	else
		cache->hash_table[TABLE_HASH(entry->block)] =
			entry->hash_next;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry->hash_prev;

	entry->hash_prev = entry->hash_next = NULL;
}


/* Called with the cache mutex held */
void insert_free_list(struct cache *cache, struct cache_entry *entry)
{
	if(cache->free_list) {
		entry->free_next = cache->free_list;
		entry->free_prev = cache->free_list->free_prev;
		cache->free_list->free_prev->free_next = entry;
		cache->free_list->free_prev = entry;
	} else {
		cache->free_list = entry;
		entry->free_prev = entry->free_next = entry;
	}
}


/* Called with the cache mutex held */
void remove_free_list(struct cache *cache, struct cache_entry *entry)
{
	if(entry->free_prev == NULL || entry->free_next == NULL)
		/* not in free list */
		return;
	else if(entry->free_prev == entry && entry->free_next == entry) {
		/* only this entry in the free list */
		cache->free_list = NULL;
	} else {
		/* more than one entry in the free list */
		entry->free_next->free_prev = entry->free_prev;
		entry->free_prev->free_next = entry->free_next;
		if(cache->free_list == entry)
			cache->free_list = entry->free_next;
	}

	entry->free_prev = entry->free_next = NULL;
}


struct cache *cache_init(int buffer_size, int max_buffers)
{
	struct cache *cache = malloc(sizeof(struct cache));
	if(cache == NULL)
		MEM_ERROR();

	cache->max_buffers = max_buffers;
	cache->buffer_size = buffer_size;
	cache->count = 0;
	cache->used = 0;
	cache->free_list = NULL;
	memset(cache->hash_table, 0, sizeof(struct cache_entry *) * 65536);
	cache->wait_free = FALSE;
	cache->wait_pending = FALSE;
	pthread_mutex_init(&cache->mutex, NULL);
	pthread_cond_init(&cache->wait_for_free, NULL);
	pthread_cond_init(&cache->wait_for_pending, NULL);

	return cache;
}


struct cache_entry *cache_get(struct cache *cache, long long block, int size)
{
	/*
	 * Get a block out of the cache.  If the block isn't in the cache
 	 * it is added and queued to the reader() and inflate() threads for
 	 * reading off disk and decompression.  The cache grows until max_blocks
 	 * is reached, once this occurs existing discarded blocks on the free
 	 * list are reused
 	 */
	int hash = TABLE_HASH(block);
	struct cache_entry *entry;

	pthread_mutex_lock(&cache->mutex);

	for(entry = cache->hash_table[hash]; entry; entry = entry->hash_next)
		if(entry->block == block)
			break;

	if(entry) {
		/*
		 * found the block in the cache.  If the block is currently
		 * unused remove it from the free list and increment cache
		 * used count.
 		 */
		if(entry->used == 0) {
			cache->used ++;
			remove_free_list(cache, entry);
		}
		entry->used ++;
		pthread_mutex_unlock(&cache->mutex);
	} else {
		/*
 		 * not in the cache
		 *
		 * first try to allocate new block
		 */
		if(cache->count < cache->max_buffers) {
			entry = malloc(sizeof(struct cache_entry));
			if(entry == NULL)
				MEM_ERROR();

			entry->data = malloc(cache->buffer_size);
			if(entry->data == NULL)
				MEM_ERROR();

			entry->cache = cache;
			entry->free_prev = entry->free_next = NULL;
			cache->count ++;
		} else {
			/*
			 * try to get from free list
			 */
			while(cache->free_list == NULL) {
				cache->wait_free = TRUE;
				pthread_cond_wait(&cache->wait_for_free,
					&cache->mutex);
			}
			entry = cache->free_list;
			remove_free_list(cache, entry);
			remove_hash_table(cache, entry);
		}

		/*
		 * Initialise block and insert into the hash table.
		 * Increment used which tracks how many buffers in the
		 * cache are actively in use (the other blocks, count - used,
		 * are in the cache and available for lookup, but can also be
		 * re-used).
		 */
		entry->block = block;
		entry->size = size;
		entry->used = 1;
		entry->error = FALSE;
		entry->pending = TRUE;
		insert_hash_table(cache, entry);
		cache->used ++;

		/*
		 * queue to read thread to read and ultimately (via the
		 * decompress threads) decompress the buffer
 		 */
		pthread_mutex_unlock(&cache->mutex);
		queue_put(to_reader, entry);
	}

	return entry;
}

	
void cache_block_ready(struct cache_entry *entry, int error)
{
	/*
	 * mark cache entry as being complete, reading and (if necessary)
 	 * decompression has taken place, and the buffer is valid for use.
 	 * If an error occurs reading or decompressing, the buffer also 
 	 * becomes ready but with an error...
 	 */
	pthread_mutex_lock(&entry->cache->mutex);
	entry->pending = FALSE;
	entry->error = error;

	/*
	 * if the wait_pending flag is set, one or more threads may be waiting
	 * on this buffer
	 */
	if(entry->cache->wait_pending) {
		entry->cache->wait_pending = FALSE;
		pthread_cond_broadcast(&entry->cache->wait_for_pending);
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}


void cache_block_wait(struct cache_entry *entry)
{
	/*
	 * wait for this cache entry to become ready, when reading and (if
	 * necessary) decompression has taken place
	 */
	pthread_mutex_lock(&entry->cache->mutex);

	while(entry->pending) {
		entry->cache->wait_pending = TRUE;
		pthread_cond_wait(&entry->cache->wait_for_pending,
			&entry->cache->mutex);
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}


void cache_block_put(struct cache_entry *entry)
{
	/*
	 * finished with this cache entry, once the usage count reaches zero it
 	 * can be reused and is put onto the free list.  As it remains
 	 * accessible via the hash table it can be found getting a new lease of
 	 * life before it is reused.
 	 */
	pthread_mutex_lock(&entry->cache->mutex);

	entry->used --;
	if(entry->used == 0) {
		insert_free_list(entry->cache, entry);
		entry->cache->used --;

		/*
		 * if the wait_free flag is set, one or more threads may be
		 * waiting on this buffer
		 */
		if(entry->cache->wait_free) {
			entry->cache->wait_free = FALSE;
			pthread_cond_broadcast(&entry->cache->wait_for_free);
		}
	}

	pthread_mutex_unlock(&entry->cache->mutex);
}


void dump_cache(struct cache *cache)
{
	pthread_mutex_lock(&cache->mutex);

	printf("Max buffers %d, Current size %d, Used %d,  %s\n",
		cache->max_buffers, cache->count, cache->used,
		cache->free_list ?  "Free buffers" : "No free buffers");

	pthread_mutex_unlock(&cache->mutex);
}


char *modestr(char *str, int mode)
{
	int i;

	strcpy(str, "----------");

	for(i = 0; table[i].mask != 0; i++) {
		if((mode & table[i].mask) == table[i].value)
			str[table[i].position] = table[i].mode;
	}

	return str;
}


#define TOTALCHARS  25
void print_filename(char *pathname, struct inode *inode)
{
	char str[11], dummy[12], dummy2[12]; /* overflow safe */
	char *userstr, *groupstr;
	int padchars;
	struct passwd *user;
	struct group *group;
	struct tm *t;

	if(short_ls) {
		printf("%s\n", pathname);
		return;
	}

	user = numeric ? NULL : getpwuid(inode->uid);
	if(user == NULL) {
		int res = snprintf(dummy, 12, "%u", inode->uid);
		if(res < 0)
			EXIT_UNSQUASH("snprintf failed in print_filename()\n");
		else if(res >= 12)
			/* unsigned int shouldn't ever need more than 11 bytes
			 * (including terminating '\0') to print in base 10 */
			userstr = "*";
		else
			userstr = dummy;
	} else
		userstr = user->pw_name;
		 
	group = numeric ? NULL : getgrgid(inode->gid);
	if(group == NULL) {
		int res = snprintf(dummy2, 12, "%u", inode->gid);
		if(res < 0)
			EXIT_UNSQUASH("snprintf failed in print_filename()\n");
		else if(res >= 12)
			/* unsigned int shouldn't ever need more than 11 bytes
			 * (including terminating '\0') to print in base 10 */
			groupstr = "*";
		else
			groupstr = dummy2;
	} else
		groupstr = group->gr_name;

	printf("%s %s/%s ", modestr(str, inode->mode), userstr, groupstr);

	switch(inode->mode & S_IFMT) {
		case S_IFREG:
		case S_IFDIR:
		case S_IFSOCK:
		case S_IFIFO:
		case S_IFLNK:
			padchars = TOTALCHARS - strlen(userstr) -
				strlen(groupstr);

			printf("%*lld ", padchars > 0 ? padchars : 0,
				inode->data);
			break;
		case S_IFCHR:
		case S_IFBLK:
			padchars = TOTALCHARS - strlen(userstr) -
				strlen(groupstr) - 7; 

			printf("%*s%3d,%3d ", padchars > 0 ? padchars : 0, " ",
				(int) inode->data >> 8, (int) inode->data &
				0xff);
			break;
	}

	t = use_localtime ? localtime(&inode->time) : gmtime(&inode->time);

	if(full_precision)
		printf("%d-%02d-%02d %02d:%02d:%02d %s", t->tm_year + 1900,
			t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min,
			t->tm_sec, pathname);
	else
		printf("%d-%02d-%02d %02d:%02d %s", t->tm_year + 1900,
			t->tm_mon + 1, t->tm_mday, t->tm_hour, t->tm_min, pathname);
	if((inode->mode & S_IFMT) == S_IFLNK)
		printf(" -> %s", inode->symlink);
	printf("\n");
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
				break;
			else if(errno != EINTR) {
				ERROR("Read failed because %s\n",
						strerror(errno));
				return -1;
			} else
				res = 0;
		}
	}

	return count;
}


int read_fs_bytes(int fd, long long byte, long long bytes, void *buff)
{
	off_t off = byte;
	long long res;

	TRACE("read_bytes: reading from position 0x%llx, bytes %lld\n", byte,
		bytes);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &pos_mutex);
	pthread_mutex_lock(&pos_mutex);
	if(lseek(fd, start_offset + off, SEEK_SET) == -1) {
		ERROR("Lseek failed because %s\n", strerror(errno));
		res = FALSE;
		goto done;
	}

	res = read_bytes(fd, buff, bytes);

	if(res != -1 && res < bytes)
		ERROR("Read on filesystem failed because EOF\n");

	res = res == bytes;

done:
	pthread_cleanup_pop(1);
	return res;
}


int read_block(int fd, long long start, long long *next, int expected,
								void *block)
{
	unsigned short c_byte;
	int offset = 2, res, compressed;
	int outlen = expected ? expected : SQUASHFS_METADATA_SIZE;
	static char *buffer = NULL;

	if(outlen > SQUASHFS_METADATA_SIZE)
		return FALSE;

	if(swap) {
		if(read_fs_bytes(fd, start, 2, &c_byte) == FALSE)
			goto failed;
		c_byte = (c_byte >> 8) | ((c_byte & 0xff) << 8);
	} else 
		if(read_fs_bytes(fd, start, 2, &c_byte) == FALSE)
			goto failed;

	TRACE("read_block: block @0x%llx, %d %s bytes\n", start,
		SQUASHFS_COMPRESSED_SIZE(c_byte), SQUASHFS_COMPRESSED(c_byte) ?
		"compressed" : "uncompressed");

	if(SQUASHFS_CHECK_DATA(sBlk.s.flags))
		offset = 3;

	compressed = SQUASHFS_COMPRESSED(c_byte);
	c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);

	/*
	 * The block size should not be larger than
	 * the uncompressed size (or max uncompressed size if
	 * expected is 0)
	 */
	if(c_byte > outlen)
		return FALSE;

	if(compressed) {
		int error;

		if(buffer == NULL) {
			buffer = malloc(SQUASHFS_METADATA_SIZE);
			if(buffer == NULL)
				MEM_ERROR();
		}

		res = read_fs_bytes(fd, start + offset, c_byte, buffer);
		if(res == FALSE)
			goto failed;

		res = compressor_uncompress(comp, block, buffer, c_byte,
			outlen, &error);

		if(res == -1) {
			ERROR("%s uncompress failed with error code %d\n",
				comp->name, error);
			goto failed;
		}
	} else {
		res = read_fs_bytes(fd, start + offset, c_byte, block);
		if(res == FALSE)
			goto failed;
		res = c_byte;
	}

	if(next)
		*next = start + offset + c_byte;

	/*
	 * if expected, then check the (uncompressed) return data
	 * is of the expected size
	 */
	if(expected && expected != res)
		return FALSE;
	else
		return res;

failed:
	ERROR("read_block: failed to read block @0x%llx\n", start);
	return FALSE;
}


static struct hash_table_entry *get_metadata(struct hash_table_entry *hash_table[],
							long long start)
{
	int res, hash = TABLE_HASH(start);
	struct hash_table_entry *entry;
	void *buffer;
	long long next;

	for(entry = hash_table[hash]; entry; entry = entry->next)
		if(entry->start == start)
			return entry;

	buffer = malloc(SQUASHFS_METADATA_SIZE);
	if(buffer == NULL)
		MEM_ERROR();

	res = read_block(fd, start, &next, 0, buffer);
	if(res == 0) {
		ERROR("get_metadata: failed to read block\n");
		free(buffer);
		return NULL;
	}

	entry = malloc(sizeof(struct hash_table_entry));
	if(entry == NULL)
		MEM_ERROR();

	entry->start = start;
	entry->length = res;
	entry->buffer = buffer;
	entry->next_index = next;
	entry->next = hash_table[hash];
	hash_table[hash] = entry;

	return entry;
}

/*
 * Read length bytes from metadata position <block, offset> (block is the
 * start of the compressed block on disk, and offset is the offset into
 * the block once decompressed).  Data is packed into consecutive blocks,
 * and length bytes may require reading more than one block.
 */
static int read_metadata(struct hash_table_entry *hash_table[], void *buffer,
			long long *blk, unsigned int *off, int length)
{
	int res = length;
	struct hash_table_entry *entry;
	long long block = *blk;
	unsigned int offset = *off;

	while (1) {
		entry = get_metadata(hash_table, block);
		if (entry == NULL || offset >= entry->length)
			return FALSE;

		if((entry->length - offset) < length) {
			int copy = entry->length - offset;
			memcpy(buffer, entry->buffer + offset, copy);
			buffer += copy;
			length -= copy;
			block = entry->next_index;
			offset = 0;
		} else if((entry->length - offset) == length) {
			memcpy(buffer, entry->buffer + offset, length);
			*blk = entry->next_index;
			*off = 0;
			break;
		} else {
			memcpy(buffer, entry->buffer + offset, length);
			*blk = block;
			*off = offset + length;
			break;
		}
	}

	return res;
}


int read_inode_data(void *buffer, long long *blk, unsigned int *off, int length)
{
	return read_metadata(inode_table_hash, buffer, blk, off, length);
}


int read_directory_data(void *buffer, long long *blk, unsigned int *off, int length)
{
	return read_metadata(directory_table_hash, buffer, blk, off, length);
}


int set_attributes(char *pathname, int mode, uid_t uid, gid_t guid, time_t time,
	unsigned int xattr, unsigned int set_mode)
{
	struct utimbuf times = { time, time };
	int failed = FALSE;

	if(utime(pathname, &times) == -1) {
		EXIT_UNSQUASH_STRICT("set_attributes: failed to set time on "
			"%s, because %s\n", pathname, strerror(errno));
		failed = TRUE;
	}

	if(root_process) {
		if(chown(pathname, uid, guid) == -1) {
			EXIT_UNSQUASH_STRICT("set_attributes: failed to change"
				" uid and gids on %s, because %s\n", pathname,
				strerror(errno));
			failed = TRUE;
		}
	} else
		mode &= ~06000;

	if(write_xattr(pathname, xattr) == FALSE)
		failed = TRUE;

	if((set_mode || (mode & 07000)) &&
					chmod(pathname, (mode_t) mode) == -1) {
		/*
		 * Some filesystems require root privileges to use the sticky
		 * bit. If we're not root and chmod() failed with EPERM when the
		 * sticky bit was included in the mode, try again without the
		 * sticky bit. Otherwise, fail with an error message.
		 */
		if (root_process || errno != EPERM || !(mode & 01000) ||
				chmod(pathname, (mode_t) (mode & ~01000)) == -1) {
			EXIT_UNSQUASH_STRICT("set_attributes: failed to change"
				" mode %s, because %s\n", pathname,
				strerror(errno));
			failed = TRUE;
		}
	}

	return !failed;
}


int write_bytes(int fd, char *buff, int bytes)
{
	int res, count;

	for(count = 0; count < bytes; count += res) {
		res = write(fd, buff + count, bytes - count);
		if(res == -1) {
			if(errno != EINTR) {
				ERROR("Write on output file failed because "
					"%s\n", strerror(errno));
				return -1;
			}
			res = 0;
		}
	}

	return 0;
}


int lseek_broken = FALSE;
char *zero_data = NULL;

int write_block(int file_fd, char *buffer, int size, long long hole, int sparse)
{
	off_t off = hole;

	if(hole) {
		if(sparse && lseek_broken == FALSE) {
			 int error = lseek(file_fd, off, SEEK_CUR);
			 if(error == -1)
				/* failed to seek beyond end of file */
				lseek_broken = TRUE;
		}

		if((sparse == FALSE || lseek_broken) && zero_data == NULL) {
			zero_data = malloc(block_size);
			if(zero_data == NULL)
				MEM_ERROR();
			memset(zero_data, 0, block_size);
		}

		if(sparse == FALSE || lseek_broken) {
			int blocks = (hole + block_size -1) / block_size;
			int avail_bytes, i;
			for(i = 0; i < blocks; i++, hole -= avail_bytes) {
				avail_bytes = hole > block_size ? block_size :
					hole;
				if(write_bytes(file_fd, zero_data, avail_bytes)
						== -1)
					goto failure;
			}
		}
	}

	if(write_bytes(file_fd, buffer, size) == -1)
		goto failure;

	return TRUE;

failure:
	return FALSE;
}


pthread_mutex_t open_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t open_empty = PTHREAD_COND_INITIALIZER;
int open_unlimited, open_count;
#define OPEN_FILE_MARGIN 10


void open_init(int count)
{
	open_count = count;
	open_unlimited = count == -1;
}


int open_wait(char *pathname, int flags, mode_t mode)
{
	if (!open_unlimited) {
		pthread_mutex_lock(&open_mutex);
		while (open_count == 0)
			pthread_cond_wait(&open_empty, &open_mutex);
		open_count --;
		pthread_mutex_unlock(&open_mutex);
	}

	return open(pathname, flags, mode);
}


void close_wake(int fd)
{
	close(fd);

	if (!open_unlimited) {
		pthread_mutex_lock(&open_mutex);
		open_count ++;
		pthread_cond_signal(&open_empty);
		pthread_mutex_unlock(&open_mutex);
	}
}


void queue_file(char *pathname, int file_fd, struct inode *inode)
{
	struct squashfs_file *file = malloc(sizeof(struct squashfs_file));
	if(file == NULL)
		MEM_ERROR();

	file->fd = file_fd;
	file->file_size = inode->data;
	file->mode = inode->mode;
	file->gid = inode->gid;
	file->uid = inode->uid;
	file->time = inode->time;
	file->pathname = strdup(pathname);
	file->blocks = inode->blocks + (inode->frag_bytes > 0);
	file->sparse = inode->sparse;
	file->xattr = inode->xattr;
	queue_put(to_writer, file);
}


void queue_dir(char *pathname, struct dir *dir)
{
	struct squashfs_file *file = malloc(sizeof(struct squashfs_file));
	if(file == NULL)
		MEM_ERROR();

	file->fd = -1;
	file->mode = dir->mode;
	file->gid = dir->guid;
	file->uid = dir->uid;
	file->time = dir->mtime;
	file->pathname = strdup(pathname);
	file->xattr = dir->xattr;
	queue_put(to_writer, file);
}


int write_file(struct inode *inode, char *pathname)
{
	unsigned int file_fd, i;
	unsigned int *block_list = NULL;
	int file_end = inode->data / block_size, res;
	long long start = inode->start;
	mode_t mode = inode->mode;
	struct stat buf;

	TRACE("write_file: regular file, blocks %d\n", inode->blocks);

	if(!root_process && !(mode & S_IWUSR) && has_xattrs(inode->xattr))
		mode |= S_IWUSR;

	res = lstat(pathname, &buf);
	if(res != -1 && force) {
		res = unlink(pathname);
		if(res == -1)
			EXIT_UNSQUASH("write_file: failed to unlink file %s,"
				" because %s\n", pathname, strerror(errno));
	} else if(res != -1)
		EXIT_UNSQUASH("write_file: file %s already exists\n", pathname);
	else if(errno != ENOENT)
		EXIT_UNSQUASH("write_file: failed to lstat file %s,"
			" because %s\n", pathname, strerror(errno));

	file_fd = open_wait(pathname, O_CREAT | O_WRONLY, mode & 0777);
	if(file_fd == -1) {
		EXIT_UNSQUASH_IGNORE("write_file: failed to create file %s,"
			" because %s\n", pathname, strerror(errno));
		return FALSE;
	}

	if(inode->blocks) {
		block_list = malloc(inode->blocks * sizeof(unsigned int));
		if(block_list == NULL)
			MEM_ERROR();

		s_ops->read_block_list(block_list, inode->block_start,
					inode->block_offset, inode->blocks);
	}

	/*
	 * the writer thread is queued a squashfs_file structure describing the
 	 * file.  If the file has one or more blocks or a fragment they are
 	 * queued separately (references to blocks in the cache).
 	 */
	queue_file(pathname, file_fd, inode);

	for(i = 0; i < inode->blocks; i++) {
		int c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(block_list[i]);
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			MEM_ERROR();

		block->offset = 0;
		block->size = i == file_end ? inode->data & (block_size - 1) :
			block_size;
		if(block_list[i] == 0) /* sparse block */
			block->buffer = NULL;
		else {
			block->buffer = cache_get(data_cache, start,
				block_list[i]);
			start += c_byte;
		}
		queue_put(to_writer, block);
	}

	if(inode->frag_bytes) {
		int size;
		long long start;
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			MEM_ERROR();

		s_ops->read_fragment(inode->fragment, &start, &size);
		block->buffer = cache_get(fragment_cache, start, size);
		block->offset = inode->offset;
		block->size = inode->frag_bytes;
		queue_put(to_writer, block);
	}

	free(block_list);
	return TRUE;
}


int cat_file(struct inode *inode, char *pathname)
{
	unsigned int i;
	unsigned int *block_list = NULL;
	int file_end = inode->data / block_size;
	long long start = inode->start;

	TRACE("cat_file: regular file, blocks %d\n", inode->blocks);

	if(inode->blocks) {
		block_list = malloc(inode->blocks * sizeof(unsigned int));
		if(block_list == NULL)
			MEM_ERROR();

		s_ops->read_block_list(block_list, inode->block_start,
					inode->block_offset, inode->blocks);
	}

	/*
	 * the writer thread is queued a squashfs_file structure describing the
	 * file.  If the file has one or more blocks or a fragment they are
	 * queued separately (references to blocks in the cache).
	 */
	queue_file(pathname, 0, inode);

	for(i = 0; i < inode->blocks; i++) {
		int c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(block_list[i]);
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			MEM_ERROR();

		block->offset = 0;
		block->size = i == file_end ? inode->data & (block_size - 1) :
			block_size;
		if(block_list[i] == 0) /* sparse block */
			block->buffer = NULL;
		else {
			block->buffer = cache_get(data_cache, start,
				block_list[i]);
			start += c_byte;
		}
		queue_put(to_writer, block);
	}

	if(inode->frag_bytes) {
		int size;
		long long start;
		struct file_entry *block = malloc(sizeof(struct file_entry));

		if(block == NULL)
			MEM_ERROR();

		s_ops->read_fragment(inode->fragment, &start, &size);
		block->buffer = cache_get(fragment_cache, start, size);
		block->offset = inode->offset;
		block->size = inode->frag_bytes;
		queue_put(to_writer, block);
	}

	free(block_list);
	return TRUE;
}


int create_inode(char *pathname, struct inode *i)
{
	int res;
	int failed = FALSE;
	char *link_path = lookup(i->inode_number);

	TRACE("create_inode: pathname %s\n", pathname);

	if(link_path) {
		TRACE("create_inode: hard link\n");
		if(force)
			unlink(pathname);

		if(link(link_path, pathname) == -1) {
			EXIT_UNSQUASH_IGNORE("create_inode: failed to create"
				" hardlink, because %s\n", strerror(errno));
			return FALSE;
		}

		hardlnk_count++;
		return TRUE;
	}

	switch(i->type) {
		case SQUASHFS_FILE_TYPE:
		case SQUASHFS_LREG_TYPE:
			TRACE("create_inode: regular file, file_size %lld, "
				"blocks %d\n", i->data, i->blocks);

			res = write_file(i, pathname);
			if(res == FALSE)
				goto failed;

			file_count ++;
			break;
		case SQUASHFS_SYMLINK_TYPE:
		case SQUASHFS_LSYMLINK_TYPE: {
			struct timeval times[2] = {
				{ i->time, 0 },
				{ i->time, 0 }
			};

			TRACE("create_inode: symlink, symlink_size %lld\n",
				i->data);

			if(force)
				unlink(pathname);

			res = symlink(i->symlink, pathname);
			if(res == -1) {
				EXIT_UNSQUASH_STRICT("create_inode: failed to"
					" create symlink %s, because %s\n",
					pathname, strerror(errno));
				goto failed;
			}

			res = lutimes(pathname, times);
			if(res == -1) {
				EXIT_UNSQUASH_STRICT("create_inode: failed to"
					" set time on %s, because %s\n",
					pathname, strerror(errno));
			}

			if(root_process) {
				res = lchown(pathname, i->uid, i->gid);
				if(res == -1) {
					EXIT_UNSQUASH_STRICT("create_inode: "
						"failed to change uid and "
						"gids on %s, because %s\n",
						pathname, strerror(errno));
					failed = TRUE;
				}
			}

			res = write_xattr(pathname, i->xattr);
			if(res == FALSE)
				failed = TRUE;

			if(failed)
				goto failed;

			sym_count ++;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE:
 		case SQUASHFS_LBLKDEV_TYPE:
	 	case SQUASHFS_LCHRDEV_TYPE: {
			int chrdev = 0;
			unsigned major, minor;
			if ( i->type == SQUASHFS_CHRDEV_TYPE ||
					i->type == SQUASHFS_LCHRDEV_TYPE)
				chrdev = 1;

			TRACE("create_inode: dev, rdev 0x%llx\n", i->data);
			if(root_process) {
				if(force)
					unlink(pathname);

				/* Based on new_decode_dev() in kernel source */
				major = (i->data & 0xfff00) >> 8;
				minor = (i->data & 0xff) | ((i->data >> 12)
								& 0xfff00);

				res = mknod(pathname, chrdev ? S_IFCHR :
						S_IFBLK, makedev(major, minor));
				if(res == -1) {
					EXIT_UNSQUASH_STRICT("create_inode: "
						"failed to create %s device "
						"%s, because %s\n", chrdev ?
						"character" : "block", pathname,
						strerror(errno));
					goto failed;
				}
				res = set_attributes(pathname, i->mode, i->uid,
					i->gid, i->time, i->xattr, TRUE);
				if(res == FALSE)
					goto failed;

				dev_count ++;
			} else {
				EXIT_UNSQUASH_STRICT("create_inode: could not"
					" create %s device %s, because you're"
					" not superuser!\n", chrdev ?
					"character" : "block", pathname);
				goto failed;
			}
			break;
		}
		case SQUASHFS_FIFO_TYPE:
		case SQUASHFS_LFIFO_TYPE:
			TRACE("create_inode: fifo\n");

			if(force)
				unlink(pathname);

			res = mknod(pathname, S_IFIFO, 0);
			if(res == -1) {
				ERROR("create_inode: failed to create fifo %s, "
					"because %s\n", pathname,
					strerror(errno));
				goto failed;
			}
			res = set_attributes(pathname, i->mode, i->uid, i->gid,
				i->time, i->xattr, TRUE);
			if(res == FALSE)
				goto failed;

			fifo_count ++;
			break;
		case SQUASHFS_SOCKET_TYPE:
		case SQUASHFS_LSOCKET_TYPE:
			TRACE("create_inode: socket\n");

			res = mknod(pathname, S_IFSOCK, 0);
			if (res == -1) {
				ERROR("create_inode: failed to create socket "
					"%s, because %s\n", pathname,
					strerror(errno));
				goto failed;
			}
			res = set_attributes(pathname, i->mode, i->uid, i->gid,
				i->time, i->xattr, TRUE);
			if(res == FALSE)
				goto failed;

			socket_count++;
			break;
		default:
			EXIT_UNSQUASH_STRICT("Unknown inode type %d in "
				"create_inode_table!\n", i->type);
			return FALSE;
	}

	insert_lookup(i->inode_number, strdup(pathname));

	return TRUE;

failed:
	/*
	 * Mark the file as created (even though it may not have been), so
	 * any future hard links to it fail with a file not found, which
	 * is correct as the file *is* missing.
	 *
	 * If we don't mark it here as created, then any future hard links
	 * will try to create the file as a separate unlinked file.
	 * If we've had some transitory errors, this may produce files
	 * in various states, which should be hard-linked, but are not.
	 */
	insert_lookup(i->inode_number, strdup(pathname));

	return FALSE;
}


int squashfs_readdir(struct dir *dir, char **name, unsigned int *start_block,
unsigned int *offset, unsigned int *type)
{
	if(dir->cur_entry == NULL)
		dir->cur_entry = dir->dirs;
	else
		dir->cur_entry = dir->cur_entry->next;

	if(dir->cur_entry == NULL)
		return FALSE;

	*name = dir->cur_entry->name;
	*start_block = dir->cur_entry->start_block;
	*offset = dir->cur_entry->offset;
	*type = dir->cur_entry->type;

	return TRUE;
}


char *get_component(char *target, char **targname)
{
	char *start;

	while(*target == '/')
		target ++;

	if(*target == '\0')
		return NULL;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = strndup(start, target - start);

	while(*target == '/')
		target ++;

	return target;
}


void free_path(struct pathname *paths)
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


struct pathname *add_path(struct pathname *paths, int type, char *target,
							char *alltarget)
{
	char *targname;
	int i, error;

	if(type == PATH_TYPE_EXTRACT)
		TRACE("add_path: adding \"%s\" extract file\n", target);
	else
		TRACE("add_path: adding \"%s\" exclude file\n", target);

	target = get_component(target, &targname);

	if(target == NULL) {
		if(type == PATH_TYPE_EXTRACT)
			EXIT_UNSQUASH("Invalid extract file %s\n", alltarget);
		else
			EXIT_UNSQUASH("Invalid exclude file %s\n", alltarget);
	}

	if(paths == NULL) {
		paths = malloc(sizeof(struct pathname));
		if(paths == NULL)
			MEM_ERROR();

		paths->names = 0;
		paths->name = NULL;
	}

	for(i = 0; i < paths->names; i++)
		if(strcmp(paths->name[i].name, targname) == 0)
			break;

	if(i == paths->names) {
		/*
		 * allocate new name entry
		 */
		paths->names ++;
		paths->name = realloc(paths->name, (i + 1) *
			sizeof(struct path_entry));
		if(paths->name == NULL)
			MEM_ERROR();

		paths->name[i].name = targname;
		paths->name[i].paths = NULL;
		if(use_regex) {
			paths->name[i].preg = malloc(sizeof(regex_t));
			if(paths->name[i].preg == NULL)
				MEM_ERROR();
			error = regcomp(paths->name[i].preg, targname,
				REG_EXTENDED|REG_NOSUB);
			if(error) {
				char str[1024]; /* overflow safe */

				regerror(error, paths->name[i].preg, str, 1024);
				if(type == PATH_TYPE_EXTRACT)
					EXIT_UNSQUASH("invalid regex %s in extract %s, "
						"because %s\n", targname, alltarget,
						str);
				else
					EXIT_UNSQUASH("invalid regex %s in exclude %s, "
						"because %s\n", targname, alltarget,
						str);
			}
		} else
			paths->name[i].preg = NULL;

		if(target[0] == '\0') {
			/*
			 * at leaf pathname component
			 */
			paths->name[i].paths = NULL;
			paths->name[i].type = type;
		} else {
			/*
			 * recurse adding child components
			 */
			paths->name[i].type = PATH_TYPE_LINK;
			paths->name[i].paths = add_path(NULL, type, target,
								alltarget);
		}
	} else {
		/*
		 * existing matching entry
		 */
		free(targname);

		if(paths->name[i].type != PATH_TYPE_LINK) {
			/*
			 * This is the leaf component of a pre-existing
			 * extract/exclude which is either the same as the one
			 * we're adding, or encompasses it (if the one we're
			 * adding still has some path to walk).  In either case
			 * we don't need to add this extract/exclude file
			 */
		} else if(target[0] == '\0') {
			/*
			 * at leaf pathname component of the extract/exclude
			 * being added, but, child components exist from more
			 * specific extracts/excludes.  Delete as they're
			 * encompassed by this
			 */
			free_path(paths->name[i].paths);
			paths->name[i].paths = NULL;
			paths->name[i].type = type;
		} else
			/*
			 * recurse adding child components
			 */
			add_path(paths->name[i].paths, type, target, alltarget);
	}

	return paths;
}


void add_extract(char *target)
{
	extract = add_path(extract, PATH_TYPE_EXTRACT, target, target);
}


void add_exclude(char *str)
{
	if(strncmp(str, "... ", 4) == 0)
		stickypath = add_path(stickypath, PATH_TYPE_EXCLUDE, str + 4, str + 4);
	else
		exclude = add_path(exclude, PATH_TYPE_EXCLUDE, str, str);
}


struct pathnames *init_subdir()
{
	struct pathnames *new = malloc(sizeof(struct pathnames));
	if(new == NULL)
		MEM_ERROR();

	new->count = 0;
	return new;
}


struct pathnames *add_subdir(struct pathnames *paths, struct pathname *path)
{
	if(paths->count % PATHS_ALLOC_SIZE == 0) {
		paths = realloc(paths, sizeof(struct pathnames *) +
			(paths->count + PATHS_ALLOC_SIZE) *
			sizeof(struct pathname *));
		if(paths == NULL)
			MEM_ERROR();
	}

	paths->path[paths->count++] = path;
	return paths;
}


void free_subdir(struct pathnames *paths)
{
	free(paths);
}


int extract_matches(struct pathnames *paths, char *name, struct pathnames **new)
{
	int i, n;

	/* nothing to match, extract */
	if(paths == NULL) {
		*new = NULL;
		return TRUE;
	}

	*new = init_subdir();

	for(n = 0; n < paths->count; n++) {
		struct pathname *path = paths->path[n];
		for(i = 0; i < path->names; i++) {
			int match;

			if(no_wildcards)
				match = strcmp(path->name[i].name, name) == 0;
			else if(use_regex)
				match = regexec(path->name[i].preg, name,
					(size_t) 0, NULL, 0) == 0;
			else
				match = fnmatch(path->name[i].name,
					name, FNM_PATHNAME|FNM_PERIOD|
					FNM_EXTMATCH) == 0;

			if(match && path->name[i].type == PATH_TYPE_EXTRACT)
				/*
				 * match on a leaf component, any subdirectories
				 * will implicitly match, therefore return an
				 * empty new search set
				 */
				goto empty_set;

			if(match)
				/*
				 * match on a non-leaf component, add any
				 * subdirectories to the new set of
				 * subdirectories to scan for this name
				 */
				*new = add_subdir(*new, path->name[i].paths);
		}
	}

	if((*new)->count == 0) {
		/*
		 * no matching names found, delete empty search set, and return
		 * FALSE
		 */
		free_subdir(*new);
		*new = NULL;
		return FALSE;
	}

	/*
	 * one or more matches with sub-directories found (no leaf matches),
	 * return new search set and return TRUE
	 */
	return TRUE;

empty_set:
	/*
	 * found matching leaf extract, return empty search set and return TRUE
	 */
	free_subdir(*new);
	*new = NULL;
	return TRUE;
}


int exclude_match(struct pathname *path, char *name, struct pathnames **new)
{
	int i, match;

	for(i = 0; i < path->names; i++) {
		if(no_wildcards)
			match = strcmp(path->name[i].name, name) == 0;
		else if(use_regex)
			match = regexec(path->name[i].preg, name,
				(size_t) 0, NULL, 0) == 0;
		else
			match = fnmatch(path->name[i].name, name,
				FNM_PATHNAME|FNM_PERIOD| FNM_EXTMATCH) == 0;

		if(match && path->name[i].type == PATH_TYPE_EXCLUDE) {
			/*
			 * match on a leaf component, any subdirectories
			 * will implicitly match, therefore return an
			 * empty new search set
			 */
			free(*new);
			*new = NULL;
			return TRUE;
		}

		if(match)
			/*
			 * match on a non-leaf component, add any
			 * subdirectories to the new set of
			 * subdirectories to scan for this name
			 */
			*new = add_subdir(*new, path->name[i].paths);
	}

	return FALSE;
}


int exclude_matches(struct pathnames *paths, char *name, struct pathnames **new)
{
	int n;

	/* nothing to match, don't exclude */
	if(paths == NULL && stickypath == NULL) {
		*new = NULL;
		return FALSE;
	}

	*new = init_subdir();

	if(stickypath && exclude_match(stickypath, name, new))
		return TRUE;

	for(n = 0; paths && n < paths->count; n++) {
		int res = exclude_match(paths->path[n], name, new);

		if(res)
			return TRUE;
	}

	if((*new)->count == 0) {
		/*
		 * no matching names found, don't exclude.  Delete empty search
		 * set, and return FALSE
		 */
		free_subdir(*new);
		*new = NULL;
		return FALSE;
	}

	/*
	 * one or more matches with sub-directories found (no leaf matches),
	 * return new search set and return FALSE
	 */
	return FALSE;
}


struct directory_stack *create_stack()
{
	struct directory_stack *stack = malloc(sizeof(struct directory_stack));
	if(stack == NULL)
		MEM_ERROR();

	stack->size = 0;
	stack->stack = NULL;
	stack->symlink = NULL;
	stack->name = NULL;

	return stack;
}


void add_stack(struct directory_stack *stack, unsigned int start_block,
	unsigned int offset, char *name, int depth)
{
	if((depth - 1) == stack->size) {
		/* Stack growing an extra level */
		stack->stack = realloc(stack->stack, depth *
					sizeof(struct directory_level));

		if(stack->stack == NULL)
			MEM_ERROR();

		stack->stack[depth - 1].start_block = start_block;
		stack->stack[depth - 1].offset = offset;
		stack->stack[depth - 1].name = strdup(name);
	} else if((depth + 1) == stack->size)
			/* Stack shrinking a level */
			free(stack->stack[depth].name);
	else if(depth == stack->size)
		/* Stack staying same size - nothing to do */
		return;
	else
		/* Any other change in size is invalid */
		EXIT_UNSQUASH("Invalid state in add_stack\n");

	stack->size = depth;
}


struct directory_stack *clone_stack(struct directory_stack *stack)
{
	int i;
	struct directory_stack *new = malloc(sizeof(struct directory_stack));
	if(stack == NULL)
		MEM_ERROR();

	new->stack = malloc(stack->size * sizeof(struct directory_level));
	if(new->stack == NULL)
		MEM_ERROR();

	for(i = 0; i < stack->size; i++) {
		new->stack[i].start_block = stack->stack[i].start_block;
		new->stack[i].offset = stack->stack[i].offset;
		new->stack[i].name = strdup(stack->stack[i].name);
	}

	new->size = stack->size;
	new->symlink = NULL;
	new->name = NULL;

	return new;
}


void pop_stack(struct directory_stack *stack)
{
	free(stack->stack[--stack->size].name);
}


void free_stack(struct directory_stack *stack)
{
	int i;
	struct symlink *symlink = stack->symlink;

	for(i = 0; i < stack->size; i++)
		free(stack->stack[i].name);

	while(symlink) {
		struct symlink *s = symlink;

		symlink = symlink->next;
		free(s->pathname);
		free(s);
	}

	free(stack->stack);
	free(stack->name);
	free(stack);
}


char *stack_pathname(struct directory_stack *stack, char *name)
{
	int i, size = 0;
	char *pathname;

	/* work out how much space is needed for the pathname */
	for(i = 1; i < stack->size; i++)
		size += strlen(stack->stack[i].name);

	/* add room for leaf name, slashes and '\0' terminator */
	size += strlen(name) + stack->size;

	pathname = malloc(size);
	if (pathname == NULL)
		MEM_ERROR();

	pathname[0] = '\0';

	/* concatenate */
	for(i = 1; i < stack->size; i++) {
		strcat(pathname, stack->stack[i].name);
		strcat(pathname, "/");
	}

	strcat(pathname, name);

	return pathname;
}


void add_symlink(struct directory_stack *stack, char *name)
{
	struct symlink *symlink = malloc(sizeof(struct symlink));
	if(symlink == NULL)
		MEM_ERROR();

	symlink->pathname = stack_pathname(stack, name);
	symlink->next = stack->symlink;
	stack->symlink = symlink;
}


/*
 * Walk the supplied pathname.   If any symlinks are encountered whilst walking
 * the pathname, then recursively walk those, to obtain the fully
 * dereferenced canonicalised pathname.  Return that and the pathnames
 * of all symlinks found during the walk.
 *
 * follow_path (-follow-symlinks option) implies no wildcard matching,
 * due to the fact that with wildcards there is no single canonical pathname
 * to be found.  Many pathnames may match or none at all.
 *
 * If follow_path fails to walk a pathname either because a component
 * doesn't exist, it is a non directory component when a directory
 * component is expected, a symlink with an absolute path is encountered,
 * or a symlink is encountered which cannot be recursively walked due to
 * the above failures, then return FALSE.
 */
int follow_path(char *path, char *name, unsigned int start_block,
	unsigned int offset, int depth, int symlinks,
	struct directory_stack *stack)
{
	struct inode *i;
	struct dir *dir;
	char *target, *symlink;
	unsigned int type;
	int traversed = FALSE;
	unsigned int entry_start, entry_offset;

	while((path = get_component(path, &target))) {
		if(strcmp(target, ".") != 0)
			break;

		free(target);
	}

	if(path == NULL)
		return FALSE;

	add_stack(stack, start_block, offset, name, depth);

	if(strcmp(target, "..") == 0) {
		if(depth > 1) {
			start_block = stack->stack[depth - 2].start_block;
			offset = stack->stack[depth - 2].offset;

			traversed = follow_path(path, "", start_block, offset,
					depth - 1, symlinks, stack);
		}

		free(target);
		return traversed;
	}

	dir = s_ops->opendir(start_block, offset, &i);
	if(dir == NULL) {
		free(target);
		return FALSE;
	}

	while(squashfs_readdir(dir, &name, &entry_start, &entry_offset, &type)) {
		if(strcmp(name, target) == 0) {
			switch(type) {
			case SQUASHFS_SYMLINK_TYPE:
				i = s_ops->read_inode(entry_start, entry_offset);
				symlink = i->symlink;

				/* Symlink must be relative to current
				 * directory and not be absolute, otherwise
				 * we can't follow it, as it is probably
				 * outside the Squashfs filesystem */
				if(symlink[0] == '/') {
					traversed = FALSE;
					free(symlink);
					break;
				}

				/* Detect circular symlinks */
				if(symlinks >= MAX_FOLLOW_SYMLINKS) {
					ERROR("Too many levels of symbolic "
								"links\n");
					traversed = FALSE;
					free(symlink);
					break;
				}

				/* Add symlink to list of symlinks found
				 * traversing the pathname */
				add_symlink(stack, name);

				traversed = follow_path(symlink, "",
					start_block, offset, depth,
					symlinks + 1, stack);

				free(symlink);

				if(traversed == TRUE) {
					/* If we still have some path to
					 * walk, then walk it from where
					 * the symlink traversal left us
					 *
					 * Obviously symlink traversal must
					 * have left us at a directory to do
					 * this */
					if(path[0] != '\0') {
						if(stack->type !=
							SQUASHFS_DIR_TYPE) {
							traversed = FALSE;
							break;
						}

						/* "Jump" to the traversed
						 * point */
						depth = stack->size;
						start_block = stack->start_block;
						offset = stack->offset;
						name = stack->name;

						/* continue following path */
						traversed = follow_path(path,
							name, start_block,
							offset, depth + 1,
							symlinks, stack);
					}
				}

				break;
			case SQUASHFS_DIR_TYPE:
				/* if at end of path, traversed OK */
				if(path[0] == '\0') {
					traversed = TRUE;
					stack->name = strdup(name);
					stack->type = type;
					stack->start_block = entry_start;
					stack->offset = entry_offset;
				} else /* follow the path */
					traversed = follow_path(path, name,
						entry_start, entry_offset,
						depth + 1, symlinks, stack);
				break;
			default:
				/* leaf directory entry, can't go any further,
				 * and so path must not continue */
				if(path[0] == '\0') {
					traversed = TRUE;
					stack->name = strdup(name);
					stack->type = type;
					stack->start_block = entry_start;
					stack->offset = entry_offset;
				} else
					traversed = FALSE;
			}
		}
	}

	free(target);
	squashfs_closedir(dir);

	return traversed;
}


int pre_scan(char *parent_name, unsigned int start_block, unsigned int offset,
	struct pathnames *extracts, struct pathnames *excludes, int depth)
{
	unsigned int type;
	int scan_res = TRUE;
	char *name;
	struct pathnames *newt, *newc = NULL;
	struct inode *i;
	struct dir *dir;

	if(max_depth != -1 && depth > max_depth)
		return TRUE;

	dir = s_ops->opendir(start_block, offset, &i);
	if(dir == NULL)
		return FALSE;

	if(inumber_lookup(i->inode_number))
		EXIT_UNSQUASH("File System corrupted: directory loop detected\n");

	while(squashfs_readdir(dir, &name, &start_block, &offset, &type)) {
		struct inode *i;
		char *pathname;
		int res;

		TRACE("pre_scan: name %s, start_block %d, offset %d, type %d\n",
			name, start_block, offset, type);

		if(!extract_matches(extracts, name, &newt))
			continue;

		if(exclude_matches(excludes, name, &newc)) {
			free_subdir(newt);
			continue;
		}

		res = asprintf(&pathname, "%s/%s", parent_name, name);
		if(res == -1)
			MEM_ERROR();

		if(type == SQUASHFS_DIR_TYPE) {
			res = pre_scan(parent_name, start_block, offset, newt,
							newc, depth + 1);
			if(res == FALSE)
				scan_res = FALSE;
		} else if(newt == NULL) {
			if(type == SQUASHFS_FILE_TYPE) {
				i = s_ops->read_inode(start_block, offset);
				if(lookup(i->inode_number) == NULL) {
					insert_lookup(i->inode_number, (char *) i);
					total_blocks += (i->data +
						(block_size - 1)) >> block_log;
				}
				total_files ++;
			}
			total_inodes ++;
		}

		free_subdir(newt);
		free_subdir(newc);
		free(pathname);
	}

	squashfs_closedir(dir);

	return scan_res;
}


int dir_scan(char *parent_name, unsigned int start_block, unsigned int offset,
	struct pathnames *extracts, struct pathnames *excludes, int depth)
{
	unsigned int type;
	int scan_res = TRUE;
	char *name;
	struct pathnames *newt, *newc = NULL;
	struct inode *i;
	struct dir *dir = s_ops->opendir(start_block, offset, &i);

	if(dir == NULL) {
		EXIT_UNSQUASH_IGNORE("dir_scan: failed to read directory %s\n",
			parent_name);
		return FALSE;
	}

	if(inumber_lookup(i->inode_number))
		EXIT_UNSQUASH("File System corrupted: directory loop detected\n");

	if((lsonly || info) && (!concise || dir->dir_count ==0))
		print_filename(parent_name, i);

	if(!lsonly) {
		/*
		 * Make directory with default User rwx permissions rather than
		 * the permissions from the filesystem, as these may not have
		 * write/execute permission.  These are fixed up later in
		 * set_attributes().
		 */
		int res = mkdir(parent_name, S_IRUSR|S_IWUSR|S_IXUSR);
		if(res == -1) {
			/*
			 * Skip directory if mkdir fails, unless we're
			 * forcing and the error is -EEXIST
			 */
			if((depth != 1 && !force) || errno != EEXIST) {
				EXIT_UNSQUASH_IGNORE("dir_scan: failed to make"
					" directory %s, because %s\n",
					parent_name, strerror(errno));
				squashfs_closedir(dir);
				return FALSE;
			} 

			/*
			 * Try to change permissions of existing directory so
			 * that we can write to it
			 */
			res = chmod(parent_name, S_IRUSR|S_IWUSR|S_IXUSR);
			if (res == -1) {
				EXIT_UNSQUASH_IGNORE("dir_scan: failed to "
					"change permissions for directory %s,"
					" because %s\n", parent_name,
					strerror(errno));
				squashfs_closedir(dir);
				return FALSE;
			}
		}
	}

	if(max_depth == -1 || depth <= max_depth) {
		while(squashfs_readdir(dir, &name, &start_block, &offset,
								&type)) {
			char *pathname;
			int res;

			TRACE("dir_scan: name %s, start_block %d, offset %d,"
				" type %d\n", name, start_block, offset, type);


			if(!extract_matches(extracts, name, &newt))
				continue;

			if(exclude_matches(excludes, name, &newc)) {
				free_subdir(newt);
				continue;
			}

			res = asprintf(&pathname, "%s/%s", parent_name, name);
			if(res == -1)
				MEM_ERROR();

			if(type == SQUASHFS_DIR_TYPE) {
				res = dir_scan(pathname, start_block, offset,
							newt, newc, depth + 1);
				if(res == FALSE)
					scan_res = FALSE;
				free(pathname);
			} else if(newt == NULL) {
				update_info(pathname);

				i = s_ops->read_inode(start_block, offset);

				if(lsonly || info)
					print_filename(pathname, i);

				if(!lsonly) {
					res = create_inode(pathname, i);
					if(res == FALSE)
						scan_res = FALSE;
				}

				if(i->type == SQUASHFS_SYMLINK_TYPE ||
						i->type == SQUASHFS_LSYMLINK_TYPE)
					free(i->symlink);
			} else {
				free(pathname);

				if(i->type == SQUASHFS_SYMLINK_TYPE ||
						i->type == SQUASHFS_LSYMLINK_TYPE)
					free(i->symlink);
			}

			free_subdir(newt);
			free_subdir(newc);
		}
	}

	if(!lsonly)
		queue_dir(parent_name, dir);

	squashfs_closedir(dir);
	dir_count ++;

	return scan_res;
}


int check_compression(struct compressor *comp)
{
	int res, bytes = 0;
	char buffer[SQUASHFS_METADATA_SIZE] __attribute__ ((aligned));

	if(!comp->supported) {
		ERROR("Filesystem uses %s compression, this is "
			"unsupported by this version\n", comp->name);
		ERROR("Decompressors available:\n");
		display_compressors(stderr, "", "");
		return FALSE;
	}

	/*
	 * Read compression options from disk if present, and pass to
	 * the compressor to ensure we know how to decompress a filesystem
	 * compressed with these compression options.
	 *
	 * Note, even if there is no compression options we still call the
	 * compressor because some compression options may be mandatory
	 * for some compressors.
	 */
	if(SQUASHFS_COMP_OPTS(sBlk.s.flags)) {
		bytes = read_block(fd, sizeof(sBlk.s), NULL, 0, buffer);
		if(bytes == 0) {
			ERROR("Failed to read compressor options\n");
			return FALSE;
		}
	}

	res = compressor_check_options(comp, sBlk.s.block_size, buffer, bytes);

	return res != -1;
}


int read_super(char *source)
{
	squashfs_super_block_3 sBlk_3;

	/*
	 * Try to read a Squashfs 4 superblock
	 */
	int res = read_super_4(&s_ops);

	if(res != -1)
		return res;
	res = read_super_3(source, &s_ops, &sBlk_3);
	if(res != -1)
		return res;
	res = read_super_2(&s_ops, &sBlk_3);
	if(res != -1)
		return res;
	res = read_super_1(&s_ops, &sBlk_3);
	if(res != -1)
		return res;

	return FALSE;
}


void process_extract_files(char *filename)
{
	FILE *fd;
	char buffer[MAX_LINE + 1]; /* overflow safe */
	char *name;

	fd = fopen(filename, "r");
	if(fd == NULL)
		EXIT_UNSQUASH("Failed to open extract file \"%s\" because %s\n",
			filename, strerror(errno));

	while(fgets(name = buffer, MAX_LINE + 1, fd) != NULL) {
		int len = strlen(name);

		if(len == MAX_LINE && name[len - 1] != '\n')
			/* line too large */
			EXIT_UNSQUASH("Line too long when reading "
				"extract file \"%s\", larger than %d "
				"bytes\n", filename, MAX_LINE);

		/*
		 * Remove '\n' terminator if it exists (the last line
		 * in the file may not be '\n' terminated)
		 */
		if(len && name[len - 1] == '\n')
			name[len - 1] = '\0';

		/* Skip any leading whitespace */
		while(isspace(*name))
			name ++;

		/* if comment line, skip */
		if(*name == '#')
			continue;

		/* check for initial backslash, to accommodate
		 * filenames with leading space or leading # character
		 */
		if(*name == '\\')
			name ++;

		/* if line is now empty after skipping characters, skip it */
		if(*name == '\0')
			continue;

		add_extract(name);
	}

	if(ferror(fd))
		EXIT_UNSQUASH("Reading extract file \"%s\" failed because %s\n",
			filename, strerror(errno));

	fclose(fd);
}


void process_exclude_files(char *filename)
{
	FILE *fd;
	char buffer[MAX_LINE + 1]; /* overflow safe */
	char *name;

	fd = fopen(filename, "r");
	if(fd == NULL)
		EXIT_UNSQUASH("Failed to open exclude file \"%s\" because %s\n",
			filename, strerror(errno));

	while(fgets(name = buffer, MAX_LINE + 1, fd) != NULL) {
		int len = strlen(name);

		if(len == MAX_LINE && name[len - 1] != '\n')
			/* line too large */
			EXIT_UNSQUASH("Line too long when reading "
				"exclude file \"%s\", larger than %d "
				"bytes\n", filename, MAX_LINE);

		/*
		 * Remove '\n' terminator if it exists (the last line
		 * in the file may not be '\n' terminated)
		 */
		if(len && name[len - 1] == '\n')
			name[len - 1] = '\0';

		/* Skip any leading whitespace */
		while(isspace(*name))
			name ++;

		/* if comment line, skip */
		if(*name == '#')
			continue;

		/* check for initial backslash, to accommodate
		 * filenames with leading space or leading # character
		 */
		if(*name == '\\')
			name ++;

		/* if line is now empty after skipping characters, skip it */
		if(*name == '\0')
			continue;

		add_exclude(name);
	}

	if(ferror(fd))
		EXIT_UNSQUASH("Reading exclude file \"%s\" failed because %s\n",
			filename, strerror(errno));

	fclose(fd);
}


/*
 * reader thread.  This thread processes read requests queued by the
 * cache_get() routine.
 */
void *reader(void *arg)
{
	while(1) {
		struct cache_entry *entry = queue_get(to_reader);
		int res = read_fs_bytes(fd, entry->block,
			SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size),
			entry->data);

		if(res && SQUASHFS_COMPRESSED_BLOCK(entry->size))
			/*
			 * queue successfully read block to the inflate
			 * thread(s) for further processing
 			 */
			queue_put(to_inflate, entry);
		else
			/*
			 * block has either been successfully read and is
			 * uncompressed, or an error has occurred, clear pending
			 * flag, set error appropriately, and wake up any
			 * threads waiting on this buffer
			 */
			cache_block_ready(entry, !res);
	}
}


/*
 * writer thread.  This processes file write requests queued by the
 * write_file() routine.
 */
void *writer(void *arg)
{
	int i;
	long exit_code = FALSE;

	while(1) {
		struct squashfs_file *file = queue_get(to_writer);
		int file_fd;
		long long hole = 0;
		int local_fail = FALSE;
		int res;

		if(file == NULL) {
			queue_put(from_writer, (void *) exit_code);
			continue;
		} else if(file->fd == -1) {
			/* write attributes for directory file->pathname */
			res = set_attributes(file->pathname, file->mode,
				file->uid, file->gid, file->time, file->xattr,
				TRUE);
			if(res == FALSE)
				exit_code = TRUE;
			free(file->pathname);
			free(file);
			continue;
		}

		TRACE("writer: regular file, blocks %d\n", file->blocks);

		file_fd = file->fd;

		for(i = 0; i < file->blocks; i++, cur_blocks ++) {
			struct file_entry *block = queue_get(to_writer);

			if(block->buffer == 0) { /* sparse file */
				hole += block->size;
				free(block);
				continue;
			}

			cache_block_wait(block->buffer);

			if(block->buffer->error) {
				EXIT_UNSQUASH_IGNORE("writer: failed to "
					"read/uncompress file %s\n",
					file->pathname);
				exit_code = local_fail = TRUE;
			}

			if(local_fail == FALSE) {
				res = write_block(file_fd,
					block->buffer->data + block->offset,
					block->size, hole, file->sparse);

				if(res == FALSE) {
					EXIT_UNSQUASH_IGNORE("writer: failed "
						"to write file %s\n",
						file->pathname);
					exit_code = local_fail = TRUE;
				}
			}

			hole = 0;
			cache_block_put(block->buffer);
			free(block);
		}

		if(hole && local_fail == FALSE) {
			/*
			 * corner case for hole extending to end of file
			 */
			if(file->sparse == FALSE ||
					lseek(file_fd, hole, SEEK_CUR) == -1) {
				/*
				 * for files which we don't want to write
				 * sparsely, or for broken lseeks which cannot
				 * seek beyond end of file, write_block will do
				 * the right thing
				 */
				hole --;
				if(write_block(file_fd, "\0", 1, hole,
						file->sparse) == FALSE) {
					EXIT_UNSQUASH_IGNORE("writer: failed "
						"to write sparse data block "
						"for file %s\n",
						file->pathname);
					exit_code = local_fail = TRUE;
				}
			} else if(ftruncate(file_fd, file->file_size) == -1) {
				EXIT_UNSQUASH_IGNORE("writer: failed to write "
					"sparse data block for file %s\n",
					file->pathname);
				exit_code = local_fail = TRUE;
			}
		}

		close_wake(file_fd);
		if(local_fail == FALSE) {
			int set = !root_process && !(file->mode & S_IWUSR) && has_xattrs(file->xattr);

			res = set_attributes(file->pathname, file->mode,
				file->uid, file->gid, file->time, file->xattr,
				force || set);
			if(res == FALSE)
				exit_code = TRUE;
		} else
			unlink(file->pathname);
		free(file->pathname);
		free(file);

	}
}


void *cat_writer(void *arg)
{
	int i;
	long exit_code = FALSE;

	while(1) {
		struct squashfs_file *file = queue_get(to_writer);
		long long hole = 0;
		int local_fail = FALSE;
		int res;

		if(file == NULL) {
			queue_put(from_writer, (void *) exit_code);
			continue;
		}

		TRACE("cat_writer: regular file, blocks %d\n", file->blocks);

		for(i = 0; i < file->blocks; i++, cur_blocks ++) {
			struct file_entry *block = queue_get(to_writer);

			if(block->buffer == 0) { /* sparse file */
				hole += block->size;
				free(block);
				continue;
			}

			cache_block_wait(block->buffer);

			if(block->buffer->error) {
				EXIT_UNSQUASH_IGNORE("cat: failed to "
					"read/uncompress file %s\n",
					file->pathname);
				exit_code = local_fail = TRUE;
			}

			if(local_fail == FALSE) {
				res = write_block(writer_fd,
					block->buffer->data + block->offset,
					block->size, hole, FALSE);

				if(res == FALSE) {
					EXIT_UNSQUASH_IGNORE("cat: failed "
						"to write file %s\n",
						file->pathname);
					exit_code = local_fail = TRUE;
				}
			}

			hole = 0;
			cache_block_put(block->buffer);
			free(block);
		}

		if(hole && local_fail == FALSE) {
			/*
			 * corner case for hole extending to end of file
			 */
			hole --;
			if(write_block(writer_fd, "\0", 1, hole,
					file->sparse) == FALSE) {
				EXIT_UNSQUASH_IGNORE("cat: failed "
					"to write sparse data block "
					"for file %s\n",
					file->pathname);
				exit_code = local_fail = TRUE;
			}
		}

		free(file->pathname);
		free(file);
	}
}


/*
 * decompress thread.  This decompresses buffers queued by the read thread
 */
void *inflator(void *arg)
{
	char *tmp = malloc(block_size);
	if(tmp == NULL)
		MEM_ERROR();

	while(1) {
		struct cache_entry *entry = queue_get(to_inflate);
		int error, res;

		res = compressor_uncompress(comp, tmp, entry->data,
			SQUASHFS_COMPRESSED_SIZE_BLOCK(entry->size), block_size,
			&error);

		if(res == -1)
			ERROR("%s uncompress failed with error code %d\n",
				comp->name, error);
		else
			memcpy(entry->data, tmp, res);

		/*
		 * block has been either successfully decompressed, or an error
 		 * occurred, clear pending flag, set error appropriately and
 		 * wake up any threads waiting on this block
 		 */ 
		cache_block_ready(entry, res == -1);
	}
}


void *progress_thread(void *arg)
{
	struct timespec requested_time, remaining;
	struct itimerval itimerval;
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
	signal(SIGWINCH, sigwinch_handler);
	signal(SIGALRM, sigalrm_handler);

	itimerval.it_value.tv_sec = 0;
	itimerval.it_value.tv_usec = 250000;
	itimerval.it_interval.tv_sec = 0;
	itimerval.it_interval.tv_usec = 250000;
	setitimer(ITIMER_REAL, &itimerval, NULL);

	requested_time.tv_sec = 0;
	requested_time.tv_nsec = 250000000;

	while(1) {
		int res = nanosleep(&requested_time, &remaining);

		if(res == -1 && errno != EINTR)
			EXIT_UNSQUASH("nanosleep failed in progress thread\n");

		if(progress_enabled) {
			pthread_mutex_lock(&screen_mutex);
			progress_bar(sym_count + dev_count + fifo_count +
				socket_count + file_count + hardlnk_count +
				cur_blocks, total_inodes + total_blocks,
				columns);
			pthread_mutex_unlock(&screen_mutex);
		}
	}
}


void initialise_threads(int fragment_buffer_size, int data_buffer_size, int cat_file)
{
	struct rlimit rlim;
	int i, max_files, res;
	sigset_t sigmask, old_mask;

	if(cat_file == FALSE) {
		/* block SIGQUIT and SIGHUP, these are handled by the info thread */
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGQUIT);
		sigaddset(&sigmask, SIGHUP);
		if(pthread_sigmask(SIG_BLOCK, &sigmask, NULL) != 0)
			EXIT_UNSQUASH("Failed to set signal mask in initialise_threads\n");

		/*
		 * temporarily block these signals so the created sub-threads will
		 * ignore them, ensuring the main thread handles them
		 */
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGINT);
		sigaddset(&sigmask, SIGTERM);
		if(pthread_sigmask(SIG_BLOCK, &sigmask, &old_mask) != 0)
			EXIT_UNSQUASH("Failed to set signal mask in initialise_threads\n");
	} else {
		/*
		 * temporarily block these signals so the created sub-threads will
		 * ignore them, ensuring the main thread handles them
		 */
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGQUIT);
		sigaddset(&sigmask, SIGHUP);
		sigaddset(&sigmask, SIGINT);
		sigaddset(&sigmask, SIGTERM);
		if(pthread_sigmask(SIG_BLOCK, &sigmask, &old_mask) != 0)
			EXIT_UNSQUASH("Failed to set signal mask in initialise_threads\n");
	}

	if(processors == -1) {
#ifdef __linux__
		cpu_set_t cpu_set;
		CPU_ZERO(&cpu_set);

		if(sched_getaffinity(0, sizeof cpu_set, &cpu_set) == -1)
			processors = sysconf(_SC_NPROCESSORS_ONLN);
		else
			processors = CPU_COUNT(&cpu_set);
#else
		int mib[2];
		size_t len = sizeof(processors);

		mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
		mib[1] = HW_AVAILCPU;
#else
		mib[1] = HW_NCPU;
#endif

		if(sysctl(mib, 2, &processors, &len, NULL, 0) == -1) {
			ERROR("Failed to get number of available processors.  "
				"Defaulting to 1\n");
			processors = 1;
		}
#endif
	}

	if(add_overflow(processors, 3) ||
			multiply_overflow(processors + 3, sizeof(pthread_t)))
		EXIT_UNSQUASH("Processors too large\n");

	thread = malloc((3 + processors) * sizeof(pthread_t));
	if(thread == NULL)
		MEM_ERROR();

	inflator_thread = &thread[3];

	/*
	 * dimensioning the to_reader and to_inflate queues.  The size of
	 * these queues is directly related to the amount of block
	 * read-ahead possible.  To_reader queues block read requests to
	 * the reader thread and to_inflate queues block decompression
	 * requests to the inflate thread(s) (once the block has been read by
	 * the reader thread).  The amount of read-ahead is determined by
	 * the combined size of the data_block and fragment caches which
	 * determine the total number of blocks which can be "in flight"
	 * at any one time (either being read or being decompressed)
	 *
	 * The maximum file open limit, however, affects the read-ahead
	 * possible, in that for normal sizes of the fragment and data block
	 * caches, where the incoming files have few data blocks or one fragment
	 * only, the file open limit is likely to be reached before the
	 * caches are full.  This means the worst case sizing of the combined
	 * sizes of the caches is unlikely to ever be necessary.  However, is is
	 * obvious read-ahead up to the data block cache size is always possible
	 * irrespective of the file open limit, because a single file could
	 * contain that number of blocks.
	 *
	 * Choosing the size as "file open limit + data block cache size" seems
	 * to be a reasonable estimate.  We can reasonably assume the maximum
	 * likely read-ahead possible is data block cache size + one fragment
	 * per open file.
	 *
	 * dimensioning the to_writer queue.  The size of this queue is
	 * directly related to the amount of block read-ahead possible.
	 * However, unlike the to_reader and to_inflate queues, this is
	 * complicated by the fact the to_writer queue not only contains
	 * entries for fragments and data_blocks but it also contains
	 * file entries, one per open file in the read-ahead.
	 *
	 * Choosing the size as "2 * (file open limit) +
	 * data block cache size" seems to be a reasonable estimate.
	 * We can reasonably assume the maximum likely read-ahead possible
	 * is data block cache size + one fragment per open file, and then
	 * we will have a file_entry for each open file.
	 */
	res = getrlimit(RLIMIT_NOFILE, &rlim);
	if (res == -1) {
		ERROR("failed to get open file limit!  Defaulting to 1\n");
		rlim.rlim_cur = 1;
	}

	if (rlim.rlim_cur != RLIM_INFINITY) {
		/*
		 * leave OPEN_FILE_MARGIN free (rlim_cur includes fds used by
		 * stdin, stdout, stderr and filesystem fd
		 */
		if (rlim.rlim_cur <= OPEN_FILE_MARGIN)
			/* no margin, use minimum possible */
			max_files = 1;
		else
			max_files = rlim.rlim_cur - OPEN_FILE_MARGIN;
	} else
		max_files = -1;

	/* set amount of available files for use by open_wait and close_wake */
	open_init(max_files);

	/*
	 * allocate to_reader, to_inflate and to_writer queues.  Set based on
	 * cache limits, unless there is an open file limit which would produce
	 * smaller queues
	 *
	 * In doing so, check that the user supplied values do not overflow
	 * a signed int
	 */
	if (max_files != -1 && max_files < fragment_buffer_size) {
		if(add_overflow(data_buffer_size, max_files) ||
				add_overflow(data_buffer_size, max_files * 2))
			EXIT_UNSQUASH("Data queue size is too large\n");

		to_reader = queue_init(max_files + data_buffer_size);
		to_inflate = queue_init(max_files + data_buffer_size);
		to_writer = queue_init(max_files * 2 + data_buffer_size);
	} else {
		int all_buffers_size;

		if(add_overflow(fragment_buffer_size, data_buffer_size))
			EXIT_UNSQUASH("Data and fragment queues combined are"
							" too large\n");

		all_buffers_size = fragment_buffer_size + data_buffer_size;

		if(add_overflow(all_buffers_size, all_buffers_size))
			EXIT_UNSQUASH("Data and fragment queues combined are"
							" too large\n");

		to_reader = queue_init(all_buffers_size);
		to_inflate = queue_init(all_buffers_size);
		to_writer = queue_init(all_buffers_size * 2);
	}

	from_writer = queue_init(1);

	fragment_cache = cache_init(block_size, fragment_buffer_size);
	data_cache = cache_init(block_size, data_buffer_size);

	pthread_create(&thread[0], NULL, reader, NULL);
	pthread_create(&thread[2], NULL, progress_thread, NULL);

	if(pseudo_file) {
		pthread_create(&thread[1], NULL, cat_writer, NULL);
		init_info();
	} else if(cat_files)
		pthread_create(&thread[1], NULL, cat_writer, NULL);
	else {
		pthread_create(&thread[1], NULL, writer, NULL);
		init_info();
	}

	pthread_mutex_init(&fragment_mutex, NULL);

	for(i = 0; i < processors; i++) {
		if(pthread_create(&inflator_thread[i], NULL, inflator, NULL) !=
				 0)
			EXIT_UNSQUASH("Failed to create thread\n");
	}

	if(pthread_sigmask(SIG_SETMASK, &old_mask, NULL) != 0)
		EXIT_UNSQUASH("Failed to set signal mask in initialise_threads"
			"\n");
}


void enable_progress_bar()
{
	pthread_mutex_lock(&screen_mutex);
	progress_enabled = progress;
	pthread_mutex_unlock(&screen_mutex);
}


void disable_progress_bar()
{
	pthread_mutex_lock(&screen_mutex);
	if(progress_enabled) {
		progress_bar(sym_count + dev_count + fifo_count + socket_count
			+ file_count + hardlnk_count + cur_blocks, total_inodes
			+ total_blocks, columns);
		printf("\n");
	}
	progress_enabled = FALSE;
	pthread_mutex_unlock(&screen_mutex);
}


void progressbar_error(char *fmt, ...)
{
	va_list ap;

	pthread_mutex_lock(&screen_mutex);

	if(progress_enabled)
		fprintf(stderr, "\n");

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	pthread_mutex_unlock(&screen_mutex);
}


void progressbar_info(char *fmt, ...)
{
	va_list ap;

	pthread_mutex_lock(&screen_mutex);

	if(progress_enabled)
		printf("\n");

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	pthread_mutex_unlock(&screen_mutex);
}


void progressbar(long long current, long long max, int columns)
{
	char rotate_list[] = { '|', '/', '-', '\\' };
	int max_digits, used, hashes, spaces;
	static int tty = -1;

	if(max == 0)
		return;

	max_digits = floor(log10(max)) + 1;
	used = max_digits * 2 + 11;
	hashes = (current * (columns - used)) / max;
	spaces = columns - used - hashes;

	if((current > max) || (columns - used < 0))
		return;

	if(tty == -1)
		tty = isatty(STDOUT_FILENO);
	if(!tty) {
		static long long previous = -1;

		/* Updating too frequently results in huge log files */
		if(current * 100 / max == previous && current != max)
			return;
		previous = current * 100 / max;
	}

	printf("\r[");

	while (hashes --)
		putchar('=');

	putchar(rotate_list[rotate]);

	while(spaces --)
		putchar(' ');

	printf("] %*lld/%*lld", max_digits, current, max_digits, max);
	printf(" %3lld%%", current * 100 / max);
	fflush(stdout);
}


void display_percentage(long long current, long long max)
{
	int percentage = max == 0 ? 100 : current * 100 / max;
	static int previous = -1;

	if(percentage != previous) {
		printf("%d\n", percentage);
		fflush(stdout);
		previous = percentage;
	}
}


void progress_bar(long long current, long long max, int columns)
{
	if(percent)
		display_percentage(current, max);
	else
		progressbar(current, max, columns);
}


int multiply_overflowll(long long a, int multiplier)
{
	return (LLONG_MAX / multiplier) < a;
}


int parse_numberll(char *start, long long *res, int size)
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

	if(size) {
		/*
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
				 * allow it to be "bytes" */
				if(strcmp(end + 1, "bytes"))
					return 0;

			break;
		case 'm':
		case 'M':
			if(multiply_overflowll(number, 1048576))
				return 0;
			number *= 1048576;

			if(end[1] != '\0')
				/* trailing junk after multiplier, but
				 * allow it to be "bytes" */
				if(strcmp(end + 1, "bytes"))
					return 0;

			break;
		case 'k':
		case 'K':
			if(multiply_overflowll(number, 1024))
				return 0;
			number *= 1024;

			if(end[1] != '\0')
				/* trailing junk after multiplier, but
				 * allow it to be "bytes" */
				if(strcmp(end + 1, "bytes"))
					return 0;

			break;
		case '\0':
			break;
		default:
			/* trailing junk after number */
			return 0;
		}
	} else if(end[0] != '\0')
		/* trailing junk after number */
		return 0;

	*res = number;
	return 1;
}


int parse_number(char *start, int *res)
{
	long long number;

	if(!parse_numberll(start, &number, 0))
		return 0;

	/* check if long result will overflow signed int */
	if(number > INT_MAX)
		return 0;

	*res = (int) number;
	return 1;
}


int parse_number_unsigned(char *start, unsigned int *res)
{
	long long number;

	if(!parse_numberll(start, &number, 0))
		return 0;

	/* check if long result will overflow unsigned int */
	if(number > UINT_MAX)
		return 0;

	*res = (unsigned int) number;
	return 1;
}


void resolve_symlinks(int argc, char *argv[])
{
	int n, found;
	struct directory_stack *stack;
	struct symlink *symlink;
	char *pathname;

	for(n = 0; n < argc; n++) {
		/*
		 * Try to follow the extract file pathname, and
		 * return the canonicalised pathname, and all
		 * symlinks necessary to resolve it.
		 */
		stack = create_stack();

		found = follow_path(argv[n], "",
			SQUASHFS_INODE_BLK(sBlk.s.root_inode),
			SQUASHFS_INODE_OFFSET(sBlk.s.root_inode),
			1, 0, stack);

		if(!found) {
			if(missing_symlinks)
				EXIT_UNSQUASH("Extract filename %s can't be "
							"resolved\n", argv[n]);
			else
				ERROR("Extract filename %s can't be resolved\n",
								argv[n]);

			add_extract(argv[n]);
			free_stack(stack);
			continue;
		}

		pathname = stack_pathname(stack, stack->name);
		add_extract(pathname);
		free(pathname);

		for(symlink = stack->symlink; symlink; symlink = symlink->next)
			add_extract(symlink->pathname);

		free_stack(stack);
	}
}


char *new_pathname(char *path, char *name)
{
	char *newpath;

	if(strcmp(path, "/") == 0) {
		newpath = malloc(strlen(name) + 2);
		if(newpath == NULL)
			MEM_ERROR();

		strcpy(newpath, "/");
		strcat(newpath, name);
	} else {
		newpath = malloc(strlen(path) + strlen(name) + 2);
		if(newpath == NULL)
			MEM_ERROR();

		strcpy(newpath, path);
		strcat(newpath, "/");
		strcat(newpath, name);
	}

	return newpath;
}


char *add_pathname(char *path, char *name)
{
	if(strcmp(path, "/") == 0) {
		path = realloc(path, strlen(name) + 2);
		if(path == NULL)
			MEM_ERROR();

		strcat(path, name);
	} else {
		path = realloc(path, strlen(path) + strlen(name) + 2);
		if(path == NULL)
			MEM_ERROR();

		strcat(path, "/");
		strcat(path, name);
	}

	return path;
}


int cat_scan(char *path, char *curpath, char *name, unsigned int start_block,
	unsigned int offset, int depth, struct directory_stack *stack)
{
	struct inode *i;
	struct dir *dir;
	char *target, *newpath, *addpath, *symlink;
	unsigned int type;
	int matched = FALSE, traversed = TRUE;
	int match, res;
	unsigned int entry_start, entry_offset;
	regex_t preg;
	struct directory_stack *new;

	newpath = new_pathname(curpath, name);

	while((path = get_component(path, &target))) {
		if(strcmp(target, ".") != 0)
			break;

		newpath = add_pathname(newpath, ".");
		free(target);
	}

	if(path == NULL) {
		ERROR("cat: %s is a directory\n", newpath);
		free(newpath);
		return FALSE;
	}

	add_stack(stack, start_block, offset, name, depth);

	if(strcmp(target, "..") == 0) {
		if(depth > 1) {
			free(target);
			start_block = stack->stack[depth - 2].start_block;
			offset = stack->stack[depth - 2].offset;

			new = clone_stack(stack);
			res = cat_scan(path, newpath, "..", start_block, offset,
					depth - 1, new);

			free_stack(new);
			return res;
		} else {
			newpath = add_pathname(newpath, "..");
			ERROR("cat: %s, cannot ascend beyond root directory\n", newpath);
			free(newpath);
			free(target);
			return FALSE;
		}
	}

	dir = s_ops->opendir(start_block, offset, &i);
	if(dir == NULL) {
		free(newpath);
		free(target);
		return FALSE;
	}

	if(use_regex) {
		res = regcomp(&preg, target, REG_EXTENDED|REG_NOSUB);
		if(res) {
			char str[1024]; /* overflow safe */

			regerror(res, &preg, str, 1024);
			ERROR("cat: invalid regex %s because %s\n", target, str);
			free(newpath);
			free(target);
			squashfs_closedir(dir);
			return FALSE;
		}
	}

	while(squashfs_readdir(dir, &name, &entry_start, &entry_offset, &type)) {
		if(no_wildcards)
			match = strcmp(name, target) == 0;
		else if(use_regex)
			match = regexec(&preg, name, (size_t) 0, NULL, 0) == 0;
		else
			match = fnmatch(target, name, FNM_PATHNAME|FNM_PERIOD| FNM_EXTMATCH) == 0;

		if(match) {
			matched = TRUE;

			switch(type) {
			case SQUASHFS_DIR_TYPE:
				/* if we're at leaf component then fail */
				if(path[0] == '\0')  {
					addpath = new_pathname(newpath, name);
					ERROR("cat: %s is a directory\n", addpath);
					free(addpath);
					traversed = FALSE;
					continue;
				}

				/* follow the path */
				res = cat_scan(path, newpath, name, entry_start, entry_offset,
								depth + 1, stack);
				if(res == FALSE)
					traversed = FALSE;
				pop_stack(stack);
				break;
			case SQUASHFS_FILE_TYPE:
				/* if there's path still to walk, fail */
				addpath = new_pathname(newpath, name);
				if(path[0] != '\0')  {
					ERROR("cat: %s is not a directory\n", addpath);
					free(addpath);
					traversed = FALSE;
					continue;
				}

				i = s_ops->read_inode(entry_start, entry_offset);
				res = cat_file(i, addpath);
				if(res == FALSE)
					traversed = FALSE;
				free(addpath);
				break;
			case SQUASHFS_SYMLINK_TYPE:
				i = s_ops->read_inode(entry_start, entry_offset);
				symlink = i->symlink;

				/* Symlink must be relative to current
				 * directory and not be absolute, otherwise
				 * we can't follow it, as it is probably
				 * outside the Squashfs filesystem */
				if(symlink[0] == '/') {
					addpath = new_pathname(newpath, name);
					ERROR("cat: %s failed to resolve symbolic link\n", addpath);
					free(addpath);
					traversed = FALSE;
					free(symlink);
					continue;
				}

				new = clone_stack(stack);

				/* follow the symlink */
				res= follow_path(symlink, name,
					start_block, offset, depth, 1, new);

				free(symlink);

				if(res == FALSE) {
					addpath = new_pathname(newpath, name);
					ERROR("cat: %s failed to resolve symbolic link\n", addpath);
					free(addpath);
					free_stack(new);
					traversed = FALSE;
					continue;
				}

				/* If we still have some path to
				 * walk, then walk it from where
				 * the symlink traversal left us
				 *
				 * Obviously symlink traversal must
				 * have left us at a directory to do
				 * this */
				if(path[0] != '\0') {
					if(new->type != SQUASHFS_DIR_TYPE) {
						addpath = new_pathname(newpath, name);
						ERROR("cat: %s symbolic link does not resolve to a directory\n", addpath);
						free(addpath);
						traversed = FALSE;
						free_stack(new);
						continue;
					}

					/* continue following path */
					res = cat_scan(path, newpath, name,
						new->start_block, new->offset,
						new->size + 1, new);
					if(res == FALSE)
						traversed = FALSE;
					free_stack(new);
					continue;
				}

				/* At leaf component, symlink must have
				 * resolved to a regular file */
				if(new->type != SQUASHFS_FILE_TYPE) {
					addpath = new_pathname(newpath, name);
					ERROR("cat: %s symbolic link does not resolve to a regular file\n", addpath);
					free(addpath);
					free_stack(new);
					traversed = FALSE;
					continue;
				}

				i = s_ops->read_inode(new->start_block, new->offset);
				addpath = new_pathname(newpath, name);
				res = cat_file(i, addpath);
				if(res == FALSE)
					traversed = FALSE;
				free_stack(new);
				free(addpath);
				break;
			default:
				/* not a directory, or a regular file, fail */
				addpath = new_pathname(newpath, name);
				if(path[0] == '\0')
					ERROR("cat: %s is not a regular file\n", addpath);
				else
					ERROR("cat: %s is not a directory\n", addpath);
				free(addpath);
				traversed = FALSE;
				continue;
			}
		}
	}

	if(matched == FALSE) {
		newpath = add_pathname(newpath, target);
		ERROR("cat: no matches for %s\n", newpath);
		traversed = FALSE;
	}

	free(newpath);
	free(target);
	squashfs_closedir(dir);

	return traversed;
}


int cat_path(int argc, char *argv[])
{
	int n, res, failed = FALSE;
	struct directory_stack *stack;

	for(n = 0; n < argc; n++) {
		stack = create_stack();

		res = cat_scan(argv[n], "/", "",
			SQUASHFS_INODE_BLK(sBlk.s.root_inode),
			SQUASHFS_INODE_OFFSET(sBlk.s.root_inode),
			1, stack);

		if(res == FALSE)
			failed = TRUE;

		free_stack(stack);
	}

	queue_put(to_writer, NULL);
	res = (long) queue_get(from_writer);

	return (failed == TRUE || res == TRUE) && set_exit_code ? 2 : 0;
}


char *process_filename(char *filename)
{
	static char *saved = NULL;
	char *ptr;
	int count = 0;

	for(ptr = filename; *ptr == '/'; ptr ++);

	if(*ptr == '\0')
		return "/";

	filename = ptr;

	while(*ptr != '\0') {
		if(*ptr == '\"' || *ptr == '\\' || isspace(*ptr))
			count ++;
		ptr ++;
	}

	if(count == 0)
		return filename;

	saved = realloc(saved, strlen(filename) + count + 1);
	if(saved == NULL)
		MEM_ERROR();

	for(ptr = saved; *filename != '\0'; ptr ++, filename ++) {
		if(*filename == '\"' || *filename == '\\' || isspace(*filename))
			*ptr ++ = '\\';

		*ptr = *filename;
	}

	*ptr = '\0';

	return saved;
}


void pseudo_print(char *pathname, struct inode *inode, char *link, long long offset)
{
	char userstr[12], groupstr[12]; /* overflow safe */
	char *type_string = "DRSBCIIDRSBCII";
	char *filename = process_filename(pathname);
	char type = type_string[inode->type - 1];
	int res;

	if(link) {
		char *name = strdup(filename);
		char *linkname = process_filename(link);
		res = dprintf(writer_fd, "%s L %s\n", name, linkname);
		if(res == -1)
			EXIT_UNSQUASH("Failed to write to pseudo output file\n");
		free(name);
		return;
	}

	res = snprintf(userstr, 12, "%d", inode->uid);
	if(res < 0)
		EXIT_UNSQUASH("snprintf failed in pseudo_print()\n");
	else if(res >= 12)
		EXIT_UNSQUASH("snprintf returned more than 11 digits in pseudo_print()\n");

	res = snprintf(groupstr, 12, "%d", inode->gid);
	if(res < 0)
		EXIT_UNSQUASH("snprintf failed in pseudo_print()\n");
	else if(res >= 12)
		EXIT_UNSQUASH("snprintf returned more than 11 digits in pseudo_print()\n");

	res = dprintf(writer_fd, "%s %c %ld %o %s %s", filename, type, inode->time, inode->mode & ~S_IFMT, userstr, groupstr);
	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	switch(inode->mode & S_IFMT) {
		case S_IFDIR:
			res = dprintf(writer_fd, "\n");
			break;
		case S_IFLNK:
			res = dprintf(writer_fd, " %s\n", inode->symlink);
			break;
		case S_IFSOCK:
		case S_IFIFO:
			if(inode->type == SQUASHFS_SOCKET_TYPE || inode->type == SQUASHFS_LSOCKET_TYPE)
				res = dprintf(writer_fd, " s\n");
			else
				res = dprintf(writer_fd, " f\n");
			break;
		case S_IFCHR:
		case S_IFBLK:
			res = dprintf(writer_fd, " %d %d\n", (int) inode->data >> 8, (int) inode->data & 0xff);
			break;
		case S_IFREG:
			res = dprintf(writer_fd, " %lld %lld %d\n", inode->data,
						offset, inode->sparse);
	}

	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	print_xattr(filename, inode->xattr, writer_fd);
}


int pseudo_scan1(char *parent_name, unsigned int start_block, unsigned int offset,
	struct pathnames *extracts, struct pathnames *excludes, int depth)
{
	unsigned int type;
	char *name;
	struct pathnames *newt, *newc = NULL;
	struct inode *i;
	struct dir *dir;
	static long long byte_offset = 0;

	if(max_depth != -1 && depth > max_depth)
		return TRUE;

	dir = s_ops->opendir(start_block, offset, &i);
	if(dir == NULL) {
		ERROR("pseudo_scan1: failed to read directory %s\n", parent_name);
		return FALSE;
	}

	if(inumber_lookup(i->inode_number))
		EXIT_UNSQUASH("File System corrupted: directory loop detected\n");

	pseudo_print(parent_name, i, NULL, 0);

	while(squashfs_readdir(dir, &name, &start_block, &offset, &type)) {
		struct inode *i;
		char *pathname;
		int res;

		TRACE("pseudo_scan1: name %s, start_block %d, offset %d, type %d\n",
			name, start_block, offset, type);

		if(!extract_matches(extracts, name, &newt))
			continue;

		if(exclude_matches(excludes, name, &newc)) {
			free_subdir(newt);
			continue;
		}

		res = asprintf(&pathname, "%s/%s", parent_name, name);
		if(res == -1)
			MEM_ERROR();

		if(type == SQUASHFS_DIR_TYPE) {
			res = pseudo_scan1(pathname, start_block, offset, newt,
							newc, depth + 1);
			if(res == FALSE) {
				free_subdir(newt);
				free_subdir(newc);
				free(pathname);
				return FALSE;
			}
		} else if(newt == NULL) {
			char *link;

			i = s_ops->read_inode(start_block, offset);
			link = lookup(i->inode_number);

			if(link == NULL) {
				pseudo_print(pathname, i, NULL, byte_offset);
				if(type == SQUASHFS_FILE_TYPE) {
					byte_offset += i->data;
					total_blocks += (i->data + (block_size - 1)) >> block_log;
				}
				insert_lookup(i->inode_number, strdup(pathname));
			} else
				pseudo_print(pathname, i, link, 0);

			if(i->type == SQUASHFS_SYMLINK_TYPE || i->type == SQUASHFS_LSYMLINK_TYPE)
				free(i->symlink);

		}

		free_subdir(newt);
		free_subdir(newc);
		free(pathname);
	}

	squashfs_closedir(dir);

	return TRUE;
}


int pseudo_scan2(char *parent_name, unsigned int start_block, unsigned int offset,
	struct pathnames *extracts, struct pathnames *excludes, int depth)
{
	unsigned int type;
	char *name;
	struct pathnames *newt, *newc = NULL;
	struct inode *i;
	struct dir *dir = s_ops->opendir(start_block, offset, &i);

	if(dir == NULL) {
		ERROR("pseudo_scan2: failed to read directory %s\n", parent_name);
		return FALSE;
	}

	if(inumber_lookup(i->inode_number))
		EXIT_UNSQUASH("File System corrupted: directory loop detected\n");

	if(max_depth == -1 || depth <= max_depth) {
		while(squashfs_readdir(dir, &name, &start_block, &offset, &type)) {
			char *pathname;
			int res;

			TRACE("pseudo_scan2: name %s, start_block %d, offset %d,"
				" type %d\n", name, start_block, offset, type);


			if(!extract_matches(extracts, name, &newt))
				continue;

			if(exclude_matches(excludes, name, &newc)) {
				free_subdir(newt);
				continue;
			}

			res = asprintf(&pathname, "%s/%s", parent_name, name);
			if(res == -1)
				MEM_ERROR();

			if(type == SQUASHFS_DIR_TYPE) {
				res = pseudo_scan2(pathname, start_block, offset,
							newt, newc, depth + 1);
				free(pathname);
				if(res == FALSE) {
					free_subdir(newt);
					free_subdir(newc);
					return FALSE;
				}
			} else if(newt == NULL && type == SQUASHFS_FILE_TYPE) {
				i = s_ops->read_inode(start_block, offset);

				if(lookup(i->inode_number) == NULL) {
					update_info(pathname);

					res = cat_file(i, pathname);
					if(res == FALSE) {
						free_subdir(newt);
						free_subdir(newc);
						return FALSE;
					}

					insert_lookup(i->inode_number, strdup(pathname));
				} else
					free(pathname);
			} else
				free(pathname);

			free_subdir(newt);
			free_subdir(newc);
		}
	}

	squashfs_closedir(dir);

	return TRUE;
}


int generate_pseudo(char *pseudo_file)
{
	int res;

	if(pseudo_stdout)
		writer_fd = STDOUT_FILENO;
	else {
		writer_fd = open_wait(pseudo_file, O_CREAT | O_TRUNC | O_WRONLY,
					S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
		if(writer_fd == -1)
			EXIT_UNSQUASH("generate_pseudo: failed to create "
				"pseudo file %s, because %s\n", pseudo_file,
				strerror(errno));
	}

	res = pseudo_scan1("/", SQUASHFS_INODE_BLK(sBlk.s.root_inode),
		SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), extracts, excludes, 1);
	if(res == FALSE)
		goto failed;

	free_inumber_table();
	inode_number = 1;
	free_lookup_table(TRUE);

	res = dprintf(writer_fd, "#\n# START OF DATA - DO NOT MODIFY\n#\n");
	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	enable_progress_bar();

	res = pseudo_scan2("/", SQUASHFS_INODE_BLK(sBlk.s.root_inode),
		SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), extracts, excludes, 1);
	if(res == FALSE)
		goto failed;

	queue_put(to_writer, NULL);
	res = (long) queue_get(from_writer);
	if(res == TRUE)
		goto failed;

	disable_progress_bar();

	if(pseudo_stdout == FALSE)
		close(writer_fd);

	return 0;

failed:
	disable_progress_bar();
	queue_put(to_writer, NULL);
	queue_get(from_writer);
	unlink(pseudo_file);
	return 1;
}


int parse_excludes(int argc, char *argv[])
{
	int i;

	for(i = 0; i < argc; i ++) {
		if(strcmp(argv[i], ";") == 0)
			break;
		add_exclude(argv[i]);
	}

	return (i == argc) ? 0 : i;
}


static void print_cat_options(FILE *stream, char *name)
{
	fprintf(stream, "SYNTAX: %s [OPTIONS] FILESYSTEM [list of files to cat to stdout]\n", name);
	fprintf(stream, "\t-v[ersion]\t\tprint version, licence and copyright ");
	fprintf(stream, "information\n");
	fprintf(stream, "\t-p[rocessors] <number>\tuse <number> processors.  ");
	fprintf(stream, "By default will use\n");
	fprintf(stream, "\t\t\t\tthe number of processors available\n");
	fprintf(stream, "\t-o[ffset] <bytes>\tskip <bytes> at start of FILESYSTEM.\n");
	fprintf(stream, "\t\t\t\tOptionally a suffix of K, M or G can be given to\n");
	fprintf(stream, "\t\t\t\tspecify Kbytes, Mbytes or Gbytes respectively\n");
	fprintf(stream, "\t\t\t\t(default 0 bytes).\n");
	fprintf(stream, "\t-ig[nore-errors]\ttreat errors writing files to stdout ");
	fprintf(stream, "as\n\t\t\t\tnon-fatal\n");
	fprintf(stream, "\t-st[rict-errors]\ttreat all errors as fatal\n");
	fprintf(stream, "\t-no-exit[-code]\t\tdon't set exit code (to nonzero) on ");
	fprintf(stream, "non-fatal\n\t\t\t\terrors\n");
	fprintf(stream, "\t-da[ta-queue] <size>\tset data queue to <size> Mbytes.  ");
	fprintf(stream, "Default %d\n\t\t\t\tMbytes\n", DATA_BUFFER_DEFAULT);
	fprintf(stream, "\t-fr[ag-queue] <size>\tset fragment queue to <size> Mbytes.  ");
	fprintf(stream, "Default\n\t\t\t\t%d Mbytes\n", FRAGMENT_BUFFER_DEFAULT);
	fprintf(stream, "\t-no-wild[cards]\t\tdo not use wildcard matching in filenames\n");
	fprintf(stream, "\t-r[egex]\t\ttreat filenames as POSIX regular ");
	fprintf(stream, "expressions\n");
	fprintf(stream, "\t\t\t\trather than use the default shell ");
	fprintf(stream, "wildcard\n\t\t\t\texpansion (globbing)\n");
	fprintf(stream, "\t-h[elp]\t\t\toutput options text to stdout\n");
	fprintf(stream, "\nDecompressors available:\n");
	display_compressors(stream, "", "");

	fprintf(stream, "\nExit status:\n");
	fprintf(stream, "  0\tThe file or files were output to stdout OK.\n");
	fprintf(stream, "  1\tFATAL errors occurred, e.g. filesystem ");
	fprintf(stream, "corruption, I/O errors.\n");
	fprintf(stream, "\tSqfscat did not continue and aborted.\n");
	fprintf(stream, "  2\tNon-fatal errors occurred, e.g. not a regular ");
	fprintf(stream, "file, or failed to resolve\n\tpathname.  Sqfscat ");
	fprintf(stream, "continued and did not abort.\n");
	fprintf(stream, "\nSee -ignore-errors, -strict-errors and ");
	fprintf(stream, "-no-exit-code options for how they affect\nthe exit ");
	fprintf(stream, "status.\n");
	fprintf(stream, "\nSee also:\n");
	fprintf(stream, "The README for the Squashfs-tools 4.6.1 release, ");
	fprintf(stream, "describing the new features can be\n");
	fprintf(stream, "read here https://github.com/plougher/squashfs-tools/blob/master/README-4.6.1\n");

	fprintf(stream, "\nThe Squashfs-tools USAGE guide can be read here\n");
	fprintf(stream, "https://github.com/plougher/squashfs-tools/blob/master/USAGE-4.6\n");
}


static void print_options(FILE *stream, char *name)
{
	fprintf(stream, "SYNTAX: %s [OPTIONS] FILESYSTEM [files ", name);
	fprintf(stream, "to extract or exclude (with -excludes) or cat (with -cat )]\n");
	fprintf(stream, "\nFilesystem extraction (filtering) options:\n");
	fprintf(stream, "\t-d[est] <pathname>\textract to <pathname>, ");
	fprintf(stream, "default \"squashfs-root\".\n\t\t\t\tThis option ");
	fprintf(stream, "also sets the prefix used when\n\t\t\t\tlisting the ");
	fprintf(stream, "filesystem\n");
	fprintf(stream, "\t-max[-depth] <levels>\tdescend at most <levels> of ");
	fprintf(stream, "directories when\n\t\t\t\textracting\n");
	fprintf(stream, "\t-excludes\t\ttreat files on command line as exclude files\n");
	fprintf(stream, "\t-ex[clude-list]\t\tlist of files to be excluded, terminated\n");
	fprintf(stream, "\t\t\t\twith ; e.g. file1 file2 ;\n");
	fprintf(stream, "\t-extract-file <file>\tlist of directories or files to ");
	fprintf(stream, "extract.\n\t\t\t\tOne per line\n");
	fprintf(stream, "\t-exclude-file <file>\tlist of directories or files to ");
	fprintf(stream, "exclude.\n\t\t\t\tOne per line\n");
	fprintf(stream, "\t-match\t\t\tabort if any extract file does not ");
	fprintf(stream, "match on\n\t\t\t\tanything, and can not be ");
	fprintf(stream, "resolved.  Implies\n\t\t\t\t-missing-symlinks and ");
	fprintf(stream, "-no-wildcards\n");
	fprintf(stream, "\t-follow[-symlinks]\tfollow symlinks in extract files, and ");
	fprintf(stream, "add all\n\t\t\t\tfiles/symlinks needed to resolve extract ");
	fprintf(stream, "file.\n\t\t\t\tImplies -no-wildcards\n");
	fprintf(stream, "\t-missing[-symlinks]\tUnsquashfs will abort if any symlink ");
	fprintf(stream, "can't be\n\t\t\t\tresolved in -follow-symlinks\n");
	fprintf(stream, "\t-no-wild[cards]\t\tdo not use wildcard matching in extract ");
	fprintf(stream, "and\n\t\t\t\texclude names\n");
	fprintf(stream, "\t-r[egex]\t\ttreat extract names as POSIX regular ");
	fprintf(stream, "expressions\n");
	fprintf(stream, "\t\t\t\trather than use the default shell ");
	fprintf(stream, "wildcard\n\t\t\t\texpansion (globbing)\n");
	fprintf(stream, "\t-all[-time] <time>\tset all file timestamps to ");
	fprintf(stream, "<time>, rather than\n\t\t\t\tthe time stored in the ");
	fprintf(stream, "filesystem inode.  <time>\n\t\t\t\tcan be an ");
	fprintf(stream, "unsigned 32-bit int indicating\n\t\t\t\tseconds ");
	fprintf(stream, "since the epoch (1970-01-01) or a string\n\t\t\t\t");
	fprintf(stream, "value which is passed to the \"date\" command to\n");
	fprintf(stream, "\t\t\t\tparse. Any string value which the date ");
	fprintf(stream, "command\n\t\t\t\trecognises can be used such as ");
	fprintf(stream, "\"now\", \"last\n\t\t\t\tweek\", or \"Wed Feb 15 ");
	fprintf(stream, "21:02:39 GMT 2023\"\n");
	fprintf(stream, "\t-cat\t\t\tcat the files on the command line to stdout\n");
	fprintf(stream, "\t-f[orce]\t\tif file already exists then overwrite\n");
	fprintf(stream, "\t-pf <file>\t\toutput a pseudo file equivalent ");
	fprintf(stream, "of the input\n\t\t\t\tSquashfs filesystem, use - for stdout\n");
	fprintf(stream, "\nFilesystem information and listing options:\n");
	fprintf(stream, "\t-s[tat]\t\t\tdisplay filesystem superblock information\n");
	fprintf(stream, "\t-max[-depth] <levels>\tdescend at most <levels> of ");
	fprintf(stream, "directories when\n\t\t\t\tlisting\n");
	fprintf(stream, "\t-i[nfo]\t\t\tprint files as they are extracted\n");
	fprintf(stream, "\t-li[nfo]\t\tprint files as they are extracted with file\n");
	fprintf(stream, "\t\t\t\tattributes (like ls -l output)\n");
	fprintf(stream, "\t-l[s]\t\t\tlist filesystem, but do not extract files\n");
	fprintf(stream, "\t-ll[s]\t\t\tlist filesystem with file attributes (like\n");
	fprintf(stream, "\t\t\t\tls -l output), but do not extract files\n");
	fprintf(stream, "\t-lln[umeric]\t\tsame as -lls but with numeric uids and gids\n");
	fprintf(stream, "\t-lc\t\t\tlist filesystem concisely, displaying only ");
	fprintf(stream, "files\n\t\t\t\tand empty directories.  Do not extract files\n");
	fprintf(stream, "\t-llc\t\t\tlist filesystem concisely with file ");
	fprintf(stream, "attributes,\n\t\t\t\tdisplaying only files and empty ");
	fprintf(stream, "directories.\n\t\t\t\tDo not extract files\n");
	fprintf(stream, "\t-full[-precision]\tuse full precision when ");
	fprintf(stream, "displaying times\n\t\t\t\tincluding seconds.  Use ");
	fprintf(stream, "with -linfo, -lls, -lln\n\t\t\t\tand -llc\n");
	fprintf(stream, "\t-UTC\t\t\tuse UTC rather than local time zone ");
	fprintf(stream, "when\n\t\t\t\tdisplaying time\n");
	fprintf(stream, "\t-mkfs-time\t\tdisplay filesystem superblock time, which is an\n");
	fprintf(stream, "\t\t\t\tunsigned 32-bit int representing the time in\n");
	fprintf(stream, "\t\t\t\tseconds since the epoch (1970-01-01)\n");
	fprintf(stream, "\nFilesystem extended attribute (xattrs) options:\n");
	fprintf(stream, "\t-no[-xattrs]\t\tdo not extract xattrs in file system");
	fprintf(stream, NOXOPT_STR"\n");
	fprintf(stream, "\t-x[attrs]\t\textract xattrs in file system" XOPT_STR "\n");
	fprintf(stream, "\t-xattrs-exclude <regex>\texclude any xattr names ");
	fprintf(stream, "matching <regex>.\n\t\t\t\t<regex> is a POSIX ");
	fprintf(stream, "regular expression, e.g.\n\t\t\t\t-xattrs-exclude ");
	fprintf(stream, "'^user.' excludes xattrs from\n\t\t\t\tthe user ");
	fprintf(stream, "namespace\n");
	fprintf(stream, "\t-xattrs-include <regex>\tinclude any xattr names ");
	fprintf(stream, "matching <regex>.\n\t\t\t\t<regex> is a POSIX ");
	fprintf(stream, "regular expression, e.g.\n\t\t\t\t-xattrs-include ");
	fprintf(stream, "'^user.' includes xattrs from\n\t\t\t\tthe user ");
	fprintf(stream, "namespace\n");
	fprintf(stream, "\nUnsquashfs runtime options:\n");
	fprintf(stream, "\t-v[ersion]\t\tprint version, licence and ");
	fprintf(stream, "copyright information\n");
	fprintf(stream, "\t-p[rocessors] <number>\tuse <number> processors.  ");
	fprintf(stream, "By default will use\n");
	fprintf(stream, "\t\t\t\tthe number of processors available\n");
	fprintf(stream, "\t-q[uiet]\t\tno verbose output\n");
	fprintf(stream, "\t-n[o-progress]\t\tdo not display the progress ");
	fprintf(stream, "bar\n");
	fprintf(stream, "\t-percentage\t\tdisplay a percentage rather than ");
	fprintf(stream, "the full\n\t\t\t\tprogress bar.  Can be used with ");
	fprintf(stream, "dialog --gauge\n\t\t\t\tetc.\n");
	fprintf(stream, "\t-ig[nore-errors]\ttreat errors writing files to ");
	fprintf(stream, "output as\n\t\t\t\tnon-fatal\n");
	fprintf(stream, "\t-st[rict-errors]\ttreat all errors as fatal\n");
	fprintf(stream, "\t-no-exit[-code]\t\tdo not set exit code (to ");
	fprintf(stream, "nonzero) on non-fatal\n\t\t\t\terrors\n");
	fprintf(stream, "\t-da[ta-queue] <size>\tset data queue to <size> ");
	fprintf(stream, "Mbytes.  Default ");
	fprintf(stream, "%d\n\t\t\t\tMbytes\n", DATA_BUFFER_DEFAULT);
	fprintf(stream, "\t-fr[ag-queue] <size>\tset fragment queue to ");
	fprintf(stream, "<size> Mbytes.  Default\n\t\t\t\t");
	fprintf(stream, "%d Mbytes\n", FRAGMENT_BUFFER_DEFAULT);
	fprintf(stream, "\nMiscellaneous options:\n");
	fprintf(stream, "\t-h[elp]\t\t\toutput this options text to stdout\n");
	fprintf(stream, "\t-o[ffset] <bytes>\tskip <bytes> at start of FILESYSTEM.  ");
	fprintf(stream, "Optionally\n\t\t\t\ta suffix of K, M or G can be given to ");
	fprintf(stream, "specify\n\t\t\t\tKbytes, Mbytes or Gbytes respectively ");
	fprintf(stream, "(default\n\t\t\t\t0 bytes).\n");
	fprintf(stream, "\t-fstime\t\t\tsynonym for -mkfs-time\n");
	fprintf(stream, "\t-e[f] <extract file>\tsynonym for -extract-file\n");
	fprintf(stream, "\t-exc[f] <exclude file>\tsynonym for -exclude-file\n");
	fprintf(stream, "\t-L\t\t\tsynonym for -follow-symlinks\n");
	fprintf(stream, "\t-pseudo-file <file>\talternative name for -pf\n");
	fprintf(stream, "\nDecompressors available:\n");
	display_compressors(stream, "", "");

	fprintf(stream, "\nExit status:\n");
	fprintf(stream, "  0\tThe filesystem listed or extracted OK.\n");
	fprintf(stream, "  1\tFATAL errors occurred, e.g. filesystem corruption, ");
	fprintf(stream, "I/O errors.\n");
	fprintf(stream, "\tUnsquashfs did not continue and aborted.\n");
	fprintf(stream, "  2\tNon-fatal errors occurred, e.g. no support for ");
	fprintf(stream, "XATTRs, Symbolic links\n\tin output filesystem or ");
	fprintf(stream, "couldn't write permissions to output filesystem.\n"); 
	fprintf(stream, "\tUnsquashfs continued and did not abort.\n");
	fprintf(stream, "\nSee -ignore-errors, -strict-errors and ");
	fprintf(stream, "-no-exit-code options for how they affect\nthe exit ");
	fprintf(stream, "status.\n");
	fprintf(stream, "\nSee also:\n");
	fprintf(stream, "The README for the Squashfs-tools 4.6.1 release, ");
	fprintf(stream, "describing the new features can be\n");
	fprintf(stream, "read here https://github.com/plougher/squashfs-tools/blob/master/README-4.6.1\n");

	fprintf(stream, "\nThe Squashfs-tools USAGE guide can be read here\n");
	fprintf(stream, "https://github.com/plougher/squashfs-tools/blob/master/USAGE-4.6\n");
}


void print_version(char *string)
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


int parse_cat_options(int argc, char *argv[])
{
	int i;

	cat_files = TRUE;

	for(i = 1; i < argc; i++) {
		if(*argv[i] != '-')
			break;
		if(strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "-h") == 0) {
			print_cat_options(stdout, argv[0]);
			exit(0);
		} else if(strcmp(argv[i], "-no-exit-code") == 0 ||
				strcmp(argv[i], "-no-exit") == 0)
			set_exit_code = FALSE;
		else if(strcmp(argv[i], "-no-wildcards") == 0 ||
				strcmp(argv[i], "-no-wild") == 0)
			no_wildcards = TRUE;
		else if(strcmp(argv[i], "-strict-errors") == 0 ||
				strcmp(argv[i], "-st") == 0)
			strict_errors = TRUE;
		else if(strcmp(argv[i], "-ignore-errors") == 0 ||
				strcmp(argv[i], "-ig") == 0)
			ignore_errors = TRUE;
		else if(strcmp(argv[i], "-version") == 0 ||
				strcmp(argv[i], "-v") == 0) {
			print_version("sqfscat");
			version = TRUE;
		} else if(strcmp(argv[i], "-processors") == 0 ||
				strcmp(argv[i], "-p") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&processors)) {
				ERROR("%s: -processors missing or invalid "
					"processor number\n", argv[0]);
				exit(1);
			}
			if(processors < 1) {
				ERROR("%s: -processors should be 1 or larger\n",
					argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-data-queue") == 0 ||
					 strcmp(argv[i], "-da") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&data_buffer_size)) {
				ERROR("%s: -data-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(data_buffer_size < 1) {
				ERROR("%s: -data-queue should be 1 Mbyte or "
					"larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-frag-queue") == 0 ||
					strcmp(argv[i], "-fr") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&fragment_buffer_size)) {
				ERROR("%s: -frag-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(fragment_buffer_size < 1) {
				ERROR("%s: -frag-queue should be 1 Mbyte or "
					"larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-regex") == 0 ||
				strcmp(argv[i], "-r") == 0)
			use_regex = TRUE;
		else if(strcmp(argv[i], "-offset") == 0 ||
				strcmp(argv[i], "-o") == 0) {
			if((++i == argc) ||
					!parse_numberll(argv[i], &start_offset,
									1)) {
				ERROR("%s: %s missing or invalid offset size\n",
							argv[0], argv[i - 1]);
				exit(1);
			}
		} else {
			print_cat_options(stderr, argv[0]);
			exit(1);
		}
	}

	if(strict_errors && ignore_errors)
		EXIT_UNSQUASH("Both -strict-errors and -ignore-errors should "
								"not be set\n");
	if(strict_errors && set_exit_code == FALSE)
		EXIT_UNSQUASH("Both -strict-errors and -no-exit-code should "
			"not be set.  All errors are fatal\n");

	if(no_wildcards && use_regex)
		EXIT_UNSQUASH("Both -no-wildcards and -regex should not be "
								"set\n");
	if(i == argc) {
		if(!version)
			print_cat_options(stderr, argv[0]);
		exit(1);
	}

	return i;
}


int parse_options(int argc, char *argv[])
{
	int i, res;

	for(i = 1; i < argc; i++) {
		if(*argv[i] != '-')
			break;
		if(strcmp(argv[i], "-help") == 0 || strcmp(argv[i], "-h") == 0) {
			print_options(stdout, argv[0]);
			exit(0);
		} else if(strcmp(argv[i], "-pseudo-file") == 0 ||
				strcmp(argv[i], "-pf") == 0) {
			if(++i == argc) {
				fprintf(stderr, "%s: -pf missing filename\n",
					argv[0]);
				exit(1);
			}
			pseudo_name = argv[i];
			pseudo_file = TRUE;
		} else if(strcmp(argv[i], "-cat") == 0)
			cat_files = TRUE;
		else if(strcmp(argv[i], "-excludes") == 0)
			treat_as_excludes = TRUE;
		else if(strcmp(argv[i], "-exclude-list") == 0 ||
				strcmp(argv[i], "-ex") == 0) {
			res = parse_excludes(argc - i - 1, argv + i + 1);
			if(res == 0) {
				fprintf(stderr, "%s: -exclude-list missing "
					"filenames or no ';' terminator\n", argv[0]);
				exit(1);
			}
			i += res + 1;
		} else if(strcmp(argv[i], "-no-exit-code") == 0 ||
				strcmp(argv[i], "-no-exit") == 0)
			set_exit_code = FALSE;
		else if(strcmp(argv[i], "-follow-symlinks") == 0 ||
				strcmp(argv[i], "-follow") == 0 ||
				strcmp(argv[i], "-L") == 0) {
			follow_symlinks = TRUE;
			no_wildcards = TRUE;
		} else if(strcmp(argv[i], "missing-symlinks") == 0 ||
				strcmp(argv[i], "-missing") == 0 ||
				strcmp(argv[i], "-match") == 0)
			missing_symlinks = TRUE;
		else if(strcmp(argv[i], "-no-wildcards") == 0 ||
				strcmp(argv[i], "-no-wild") == 0)
			no_wildcards = TRUE;
		else if(strcmp(argv[i], "-UTC") == 0)
			use_localtime = FALSE;
		else if(strcmp(argv[i], "-strict-errors") == 0 ||
				strcmp(argv[i], "-st") == 0)
			strict_errors = TRUE;
		else if(strcmp(argv[i], "-ignore-errors") == 0 ||
				strcmp(argv[i], "-ig") == 0)
			ignore_errors = TRUE;
		else if(strcmp(argv[i], "-quiet") == 0 ||
				strcmp(argv[i], "-q") == 0)
			quiet = TRUE;
		else if(strcmp(argv[i], "-version") == 0 ||
				strcmp(argv[i], "-v") == 0) {
			print_version("unsquashfs");
			version = TRUE;
		} else if(strcmp(argv[i], "-info") == 0 ||
				strcmp(argv[i], "-i") == 0)
			info = TRUE;
		else if(strcmp(argv[i], "-ls") == 0 ||
				strcmp(argv[i], "-l") == 0)
			lsonly = TRUE;
		else if(strcmp(argv[i], "-lc") == 0) {
			lsonly = TRUE;
			concise = TRUE;
		} else if(strcmp(argv[i], "-no-progress") == 0 ||
				strcmp(argv[i], "-n") == 0)
			progress = FALSE;
		else if(strcmp(argv[i], "-percentage") == 0)
			percent = progress = TRUE;
		else if(strcmp(argv[i], "-no-xattrs") == 0 ||
				strcmp(argv[i], "-no") == 0)
			no_xattrs = TRUE;
		else if(strcmp(argv[i], "-xattrs") == 0 ||
				strcmp(argv[i], "-x") == 0) {
			if(xattrs_supported())
				no_xattrs = FALSE;
			else {
				ERROR("%s: xattrs are unsupported in "
					"this build\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-user-xattrs") == 0 ||
				strcmp(argv[i], "-u") == 0) {
			if(!xattrs_supported()) {
				ERROR("%s: xattrs are unsupported in "
						"this build\n", argv[0]);
                                exit(1);
			} else {
				xattr_include_preg = xattr_regex("^user.", "include");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-xattrs-exclude") == 0) {
			if(!xattrs_supported()) {
				ERROR("%s: xattrs are unsupported in "
						"this build\n", argv[0]);
				exit(1);
			} else if(++i == argc) {
				ERROR("%s: -xattrs-exclude missing regex pattern\n", argv[0]);
				exit(1);
			} else {
				xattr_exclude_preg = xattr_regex(argv[i], "exclude");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-xattrs-include") == 0) {
			if(!xattrs_supported()) {
				ERROR("%s: xattrs are unsupported in "
						"this build\n", argv[0]);
				exit(1);
			} else if(++i == argc) {
				ERROR("%s: -xattrs-include missing regex pattern\n", argv[0]);
				exit(1);
			} else {
				xattr_include_preg = xattr_regex(argv[i], "include");
				no_xattrs = FALSE;
			}
		} else if(strcmp(argv[i], "-dest") == 0 ||
				strcmp(argv[i], "-d") == 0) {
			if(++i == argc) {
				fprintf(stderr, "%s: -dest missing filename\n",
					argv[0]);
				exit(1);
			}
			dest = argv[i];
		} else if(strcmp(argv[i], "-processors") == 0 ||
				strcmp(argv[i], "-p") == 0) {
			if((++i == argc) || 
					!parse_number(argv[i],
						&processors)) {
				ERROR("%s: -processors missing or invalid "
					"processor number\n", argv[0]);
				exit(1);
			}
			if(processors < 1) {
				ERROR("%s: -processors should be 1 or larger\n",
					argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-max-depth") == 0 ||
				strcmp(argv[i], "-max") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&max_depth)) {
				ERROR("%s: -max-depth missing or invalid "
					"levels\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-data-queue") == 0 ||
					 strcmp(argv[i], "-da") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&data_buffer_size)) {
				ERROR("%s: -data-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(data_buffer_size < 1) {
				ERROR("%s: -data-queue should be 1 Mbyte or "
					"larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-frag-queue") == 0 ||
					strcmp(argv[i], "-fr") == 0) {
			if((++i == argc) ||
					!parse_number(argv[i],
						&fragment_buffer_size)) {
				ERROR("%s: -frag-queue missing or invalid "
					"queue size\n", argv[0]);
				exit(1);
			}
			if(fragment_buffer_size < 1) {
				ERROR("%s: -frag-queue should be 1 Mbyte or "
					"larger\n", argv[0]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-force") == 0 ||
				strcmp(argv[i], "-f") == 0)
			force = TRUE;
		else if(strcmp(argv[i], "-stat") == 0 ||
				strcmp(argv[i], "-s") == 0)
			stat_sys = TRUE;
		else if(strcmp(argv[i], "-mkfs-time") == 0 ||
				strcmp(argv[i], "-fstime") == 0)
			mkfs_time_opt = TRUE;
		else if(strcmp(argv[i], "-lls") == 0 ||
				strcmp(argv[i], "-ll") == 0) {
			lsonly = TRUE;
			short_ls = FALSE;
		} else if(strcmp(argv[i], "-llnumeric") == 0 ||
				strcmp(argv[i], "-lln") == 0) {
			lsonly = TRUE;
			short_ls = FALSE;
			numeric = TRUE;
		} else if(strcmp(argv[i], "-llc") == 0) {
			lsonly = TRUE;
			short_ls = FALSE;
			concise = TRUE;
		} else if(strcmp(argv[i], "-linfo") == 0 ||
				strcmp(argv[i], "-li") == 0) {
			info = TRUE;
			short_ls = FALSE;
		} else if(strcmp(argv[i], "-extract-file") == 0 ||
				strcmp(argv[i], "-ef") == 0 ||
				strcmp(argv[i], "-e") == 0) {
			if(++i == argc) {
				fprintf(stderr, "%s: -extract-file missing filename\n",
					argv[0]);
				exit(1);
			}
			process_extract_files(argv[i]);
		} else if(strcmp(argv[i], "-exclude-file") == 0 ||
				strcmp(argv[i], "-excf") == 0 ||
				strcmp(argv[i], "-exc") == 0) {
			if(++i == argc) {
				fprintf(stderr, "%s: -exclude-file missing filename\n",
					argv[0]);
				exit(1);
			}
			process_exclude_files(argv[i]);
		} else if(strcmp(argv[i], "-regex") == 0 ||
				strcmp(argv[i], "-r") == 0)
			use_regex = TRUE;
		else if(strcmp(argv[i], "-offset") == 0 ||
				strcmp(argv[i], "-o") == 0) {
			if((++i == argc) ||
					!parse_numberll(argv[i], &start_offset,
									1)) {
				ERROR("%s: %s missing or invalid offset size\n",
							argv[0], argv[i - 1]);
				exit(1);
			}
		} else if(strcmp(argv[i], "-all-time") == 0 ||
				strcmp(argv[i], "-all") == 0) {
			if((++i == argc) ||
					(!parse_number_unsigned(argv[i], &timeval)
					&& !exec_date(argv[i], &timeval))) {
				ERROR("%s: %s missing or invalid time value\n",
							argv[0], argv[i - 1]);
				exit(1);
			}
			time_opt = TRUE;
		} else if(strcmp(argv[i], "-full-precision") == 0 ||
				strcmp(argv[i], "-full") == 0)
			full_precision = TRUE;
		else {
			print_options(stderr, argv[0]);
			exit(1);
		}
	}

	if(dest[0] == '\0' && !lsonly)
		EXIT_UNSQUASH("-dest: <pathname> is empty!  Use '.' to "
			"extract to current directory\n");

	if(lsonly || info)
		progress = FALSE;

	if(lsonly)
		quiet = TRUE;

	if(lsonly && pseudo_file)
		EXIT_UNSQUASH("File listing only (-ls, -lls etc.) and -pf "
							"should not be set\n");

	if(strict_errors && ignore_errors)
		EXIT_UNSQUASH("Both -strict-errors and -ignore-errors should "
								"not be set\n");
	if(strict_errors && set_exit_code == FALSE)
		EXIT_UNSQUASH("Both -strict-errors and -no-exit-code should "
			"not be set.  All errors are fatal\n");

	if(missing_symlinks && !follow_symlinks) {
		follow_symlinks = TRUE;
		no_wildcards = TRUE;
	}

	if(no_wildcards && use_regex)
		EXIT_UNSQUASH("Both -no-wildcards and -regex should not be "
								"set\n");

	if(pseudo_file && strcmp(pseudo_name, "-") == 0) {
		info = progress = FALSE;
		pseudo_stdout = quiet = TRUE;
	}

#ifdef SQUASHFS_TRACE
	/*
	 * Disable progress bar if full debug tracing is enabled.
	 * The progress bar in this case just gets in the way of the
	 * debug trace output
	 */
	progress = FALSE;
#endif

	if(i == argc) {
		if(!version)
			print_options(stderr, argv[0]);
		exit(1);
	}

	return i;
}


int main(int argc, char *argv[])
{
	int i, n;
	long res;
	int exit_code = 0;
	char *command;

	pthread_mutex_init(&screen_mutex, NULL);
	root_process = geteuid() == 0;
	if(root_process)
		umask(0);

	/* skip leading path components in invocation command */
	for(command = argv[0] + strlen(argv[0]) - 1; command >= argv[0] && command[0] != '/'; command--);

	if(command < argv[0])
		command = argv[0];
	else
		command++;

	if(strcmp(command, "sqfscat") == 0)
		i = parse_cat_options(argc, argv);
	else
		i = parse_options(argc, argv);

	if((fd = open(argv[i], O_RDONLY)) == -1) {
		ERROR("Could not open %s, because %s\n", argv[i],
			strerror(errno));
		exit(1);
	}

	if(read_super(argv[i]) == FALSE)
		EXIT_UNSQUASH("Can't find a valid SQUASHFS superblock on %s\n", argv[i]);

	if(mkfs_time_opt) {
		printf("%u\n", sBlk.s.mkfs_time);
		exit(0);
	}

	if(stat_sys) {
		s_ops->stat(argv[i]);
		exit(0);
	}

	if(!check_compression(comp))
		exit(1);

	block_size = sBlk.s.block_size;
	block_log = sBlk.s.block_log;

	/*
	 * Sanity check block size and block log.
	 *
	 * Check they're within correct limits
	 */
	if(block_size > SQUASHFS_FILE_MAX_SIZE ||
					block_log > SQUASHFS_FILE_MAX_LOG)
		EXIT_UNSQUASH("Block size or block_log too large."
			"  File system is corrupt.\n");

	if(block_size < 4096)
		EXIT_UNSQUASH("Block size too small."
			"  File system is corrupt.\n");

	/*
	 * Check block_size and block_log match
	 */
	if(block_size != (1 << block_log))
		EXIT_UNSQUASH("Block size and block_log do not match."
			"  File system is corrupt.\n");

	/*
	 * convert from queue size in Mbytes to queue size in
	 * blocks.
	 *
	 * In doing so, check that the user supplied values do not
	 * overflow a signed int
	 */
	if(shift_overflow(fragment_buffer_size, 20 - block_log))
		EXIT_UNSQUASH("Fragment queue size is too large\n");
	else
		fragment_buffer_size <<= 20 - block_log;

	if(shift_overflow(data_buffer_size, 20 - block_log))
		EXIT_UNSQUASH("Data queue size is too large\n");
	else
		data_buffer_size <<= 20 - block_log;

	if(!lsonly)
		initialise_threads(fragment_buffer_size, data_buffer_size, cat_files);

	res = s_ops->read_filesystem_tables();
	if(res == FALSE)
		EXIT_UNSQUASH("File system corruption detected\n");

	if(cat_files)
		return cat_path(argc - i - 1, argv + i + 1);
	else if(treat_as_excludes)
		for(n = i + 1; n < argc; n++)
			add_exclude(argv[n]);
	else if(follow_symlinks)
		resolve_symlinks(argc - i - 1, argv + i + 1);
	else
		for(n = i + 1; n < argc; n++)
			add_extract(argv[n]);

	if(extract) {
		extracts = init_subdir();
		extracts = add_subdir(extracts, extract);
	}

	if(exclude) {
		excludes = init_subdir();
		excludes = add_subdir(excludes, exclude);
	}

	if(pseudo_file)
		return generate_pseudo(pseudo_name);

	if(!quiet || progress) {
		res = pre_scan(dest, SQUASHFS_INODE_BLK(sBlk.s.root_inode),
			SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), extracts,
			excludes, 1);
		if(res == FALSE && set_exit_code)
			exit_code = 2;

		free_inumber_table();
		inode_number = 1;
		free_lookup_table(FALSE);

		if(!quiet)  {
			printf("Parallel unsquashfs: Using %d processor%s\n",
				processors, processors == 1 ? "" : "s");

			printf("%u inodes (%lld blocks) to write\n\n",
				total_inodes, total_blocks);
		}

		enable_progress_bar();
	}

	res = dir_scan(dest, SQUASHFS_INODE_BLK(sBlk.s.root_inode),
		SQUASHFS_INODE_OFFSET(sBlk.s.root_inode), extracts, excludes, 1);
	if(res == FALSE && set_exit_code)
		exit_code = 2;

	if(!lsonly) {
		queue_put(to_writer, NULL);
		res = (long) queue_get(from_writer);
		if(res == TRUE && set_exit_code)
			exit_code = 2;
	}

	disable_progress_bar();

	if(!quiet) {
		printf("\n");
		printf("created %d %s\n", file_count, file_count == 1 ? "file" : "files");
		printf("created %d %s\n", dir_count, dir_count == 1 ? "directory" : "directories");
		printf("created %d %s\n", sym_count, sym_count == 1 ? "symlink" : "symlinks");
		printf("created %d %s\n", dev_count, dev_count == 1 ? "device" : "devices");
		printf("created %d %s\n", fifo_count, fifo_count == 1 ? "fifo" : "fifos");
		printf("created %d %s\n", socket_count, socket_count == 1 ? "socket" : "sockets");
		printf("created %d %s\n", hardlnk_count, hardlnk_count == 1 ? "hardlink" : "hardlinks");
	}

	return exit_code;
}
