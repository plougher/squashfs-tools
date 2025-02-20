/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2021, 2022, 2024
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
 * reader.c
 */

#define TRUE 1
#define FALSE 0

#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <stddef.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "progressbar.h"
#include "mksquashfs_error.h"
#include "pseudo.h"
#include "sort.h"
#include "tar.h"
#include "reader.h"
#include "atomic_swap.h"
#include "caches-queues-lists.h"

#define READER_ALLOC 1024

static int reader_threads = 6, fragment_threads = 3, block_threads = 3;
static struct reader *reader = NULL;
static struct readahead **readahead_table = NULL;
static pthread_t *reader_thread = NULL;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int total_rblocks, total_rmbytes;
static int total_wblocks, total_wmbytes;
static int single_threaded = FALSE;

/* if throttling I/O, time to sleep between reads (in tenths of a second) */
static int sleep_time;

static struct read_entry **block_array = NULL;
static struct read_entry **fragment_array = NULL;

/* total number of files to be read, excluding hard links  */
static unsigned int file_count = 0;
static unsigned int block_count = 0;
static unsigned int fragment_count = 0;

extern struct queue_cache *bwriter_buffer;
extern int processors;

static void sigalrm_handler(int arg)
{
	struct timespec requested_time, remaining;

	requested_time.tv_sec = sleep_time / 10;
	requested_time.tv_nsec = (sleep_time % 10) * 100000000;

	nanosleep(&requested_time, &remaining);
}


static char *pathname(struct reader *reader, struct dir_ent *dir_ent)
{
	if (dir_ent->nonstandard_pathname)
		return dir_ent->nonstandard_pathname;

	if(reader->pathname == NULL) {
		reader->pathname = malloc(ALLOC_SIZE);
		if(reader->pathname == NULL)
			MEM_ERROR();
	}

	for(;;) {
		int res = snprintf(reader->pathname, reader->size, "%s/%s",
			dir_ent->our_dir->pathname,
			dir_ent->source_name ? : dir_ent->name);

		if(res < 0)
			BAD_ERROR("snprintf failed in pathname\n");
		else if(res >= reader->size) {
			/*
			 * pathname is too small to contain the result, so
			 * increase it and try again
			 */
			reader->size = (res + ALLOC_SIZE) & ~(ALLOC_SIZE - 1);
			reader->pathname = realloc(reader->pathname, reader->size);
			if(reader->pathname == NULL)
				MEM_ERROR();
		} else
			break;
	}

	return reader->pathname;
}


static inline int is_fragment(struct inode_info *inode)
{
	off_t file_size = inode->buf.st_size;

	/*
	 * If this block is to be compressed differently to the
	 * fragment compression then it cannot be a fragment
	 */
	if(inode->noF != noF)
		return FALSE;

	return !inode->no_fragments && file_size && (file_size < block_size ||
		(inode->always_use_fragments && file_size & (block_size - 1)));
}


static inline int is_large(struct inode_info *inode)
{
	return inode->buf.st_size >= block_size;
}


static void put_file_buffer(int id, struct file_buffer *file_buffer, int next_state)
{
	file_buffer->next_state = next_state;

	/*
	 * Decide where to send the file buffer:
	 * - compressible non-fragment blocks go to the deflate threads,
	 * - fragments go to the process fragment threads,
	 * - all others go directly to the main thread
	 */
	if(file_buffer->error) {
		file_buffer->fragment = 0;
		main_queue_put(to_main, file_buffer);
	} else if (file_buffer->file_size == 0)
		main_queue_put(to_main, file_buffer);
	else if(file_buffer->fragment)
		read_queue_put(to_process_frag, id, file_buffer);
	else
		queue_cache_put(to_deflate, id, file_buffer);
}


static struct file_buffer *get_buffer(struct reader *reader, struct read_entry *entry,
	long long file_size, long long block, int version)
{
	struct file_buffer *file_buffer = cache_get_nohash(reader->buffer);

	file_buffer->noD = entry->dir_ent->inode->noD;
	file_buffer->file_count = entry->file_count;
	file_buffer->file_size = file_size;
	file_buffer->version = version;
	file_buffer->block = block;
	file_buffer->error = FALSE;
	file_buffer->fragment = FALSE;
	file_buffer->next_state = FALSE;
	file_buffer->thread = reader->id;

	return file_buffer;
}


static void reader_read_process(struct reader *reader, struct read_entry *entry)
{
	long long bytes = 0, block = 0;
	struct inode_info *inode = entry->dir_ent->inode;
	struct file_buffer *prev_buffer = NULL, *file_buffer;
	int status, byte, res, child;
	int file;

	file = pseudo_exec_file(inode->pseudo, &child);
	if(!file) {
		file_buffer = get_buffer(reader, entry, 0, block, 0);
		goto read_err;
	}

	while(1) {
		file_buffer = get_buffer(reader, entry, -1, block ++, 0);

		byte = read_bytes(file, file_buffer->data, block_size);
		if(byte == -1)
			goto read_err2;

		file_buffer->size = byte;
		bytes += byte;

		if(byte == 0)
			break;

		/*
		 * Update progress bar size.  This is done
		 * on every block rather than waiting for all blocks to be
		 * read incase write_file_process() is running in parallel
		 * with this.  Otherwise the current progress bar position
		 * may get ahead of the progress bar size.
		 */
		progress_bar_size(1);

		if(prev_buffer)
			put_file_buffer(reader->id, prev_buffer, NEXT_BLOCK);
		prev_buffer = file_buffer;
	}

	/*
	 * Update inode file size now that the size of the dynamic pseudo file
	 * is known.  This is needed for the -info option.
	 */
	inode->buf.st_size = bytes;

	while(1) {
		res = waitpid(child, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR)
			BAD_ERROR("read process: waitpid returned %d\n", errno);
	}

	close(file);

	if(res == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
		goto read_err;

	if(prev_buffer == NULL)
		prev_buffer = file_buffer;
	else
		cache_block_put(file_buffer);

	prev_buffer->file_size = bytes;
	prev_buffer->fragment = is_fragment(inode);
	put_file_buffer(reader->id, prev_buffer, NEXT_FILE);

	return;

read_err2:
	close(file);
read_err:
	if(prev_buffer) {
		cache_block_put(file_buffer);
		file_buffer = prev_buffer;
	}
	file_buffer->error = TRUE;
	put_file_buffer(reader->id, file_buffer, NEXT_FILE);
}


static void reader_read_file(struct reader *reader, struct read_entry *entry, int reader_type)
{
	struct stat *buf = &entry->dir_ent->inode->buf, buf2;
	struct file_buffer *file_buffer;
	int blocks, file, res;
	long long bytes = 0, block = 0, read_size;
	struct inode_info *inode = entry->dir_ent->inode;
	unsigned short version = 0;

again:
	read_size = buf->st_size;
	blocks = (read_size + block_size - 1) >> block_log;

	while(1) {
		file = open(pathname(reader, entry->dir_ent), O_RDONLY);
		if(file != -1 || errno != EINTR)
			break;
	}

	if(file == -1) {
		file_buffer = get_buffer(reader, entry, 0, block, version);
		goto read_err2;
	}

	do {
		file_buffer = get_buffer(reader, entry, read_size, block ++, version);

		/*
		 * Always try to read block_size bytes from the file rather
		 * than expected bytes (which will be less than the block_size
		 * at the file tail) to check that the file hasn't grown
		 * since being stated.  If it is longer (or shorter) than
		 * expected, then restat, and try again.  Note the special
		 * case where the file is an exact multiple of the block_size
		 * is dealt with later.
		 */
		file_buffer->size = read_bytes(file, file_buffer->data,
			block_size);
		if(file_buffer->size == -1)
			goto read_err;

		bytes += file_buffer->size;

		if(blocks > 1) {
			/* non-tail block should be exactly block_size */
			if(file_buffer->size < block_size)
				goto restat;

			file_buffer->fragment = FALSE;
			put_file_buffer(reader->id, file_buffer, NEXT_BLOCK);
		}
	} while(-- blocks > 0);

	/* Overall size including tail should match */
	if(read_size != bytes)
		goto restat;

	if(read_size && read_size % block_size == 0) {
		/*
		 * Special case where we've not tried to read past the end of
		 * the file.  We expect to get EOF, i.e. the file isn't larger
		 * than we expect.
		 */
		char buffer;
		int res;

		res = read_bytes(file, &buffer, 1);
		if(res == -1)
			goto read_err;

		if(res != 0)
			goto restat;
	}

	file_buffer->fragment = is_fragment(inode);
	put_file_buffer(reader->id, file_buffer, NEXT_FILE);

	close(file);

	return;

restat:
	if(version == 1023)
		/* File has changed size too many times.  Treat this
		 * as an irretrievable error */
		goto read_err;

	res = fstat(file, &buf2);
	if(res == -1) {
		ERROR("Cannot stat dir/file %s because %s\n",
			pathname(reader, entry->dir_ent), strerror(errno));
		goto read_err;
	}

	if(read_size != buf2.st_size) {
		close(file);
		memcpy(buf, &buf2, sizeof(struct stat));
		file_buffer->error = 2;
		put_file_buffer(reader->id, file_buffer, NEXT_VERSION);
		bytes = block = 0;
		version ++;
		goto again;
	}
read_err:
	close(file);
read_err2:
	file_buffer->error = TRUE;
	put_file_buffer(reader->id, file_buffer, NEXT_FILE);
}


static void remove_readahead(int index, struct readahead *prev, struct readahead *new)
{
	if(prev)
		prev->next = new->next;
	else
		readahead_table[index] = new->next;
}


static void add_readahead(struct readahead *new)
{
	int index = READAHEAD_INDEX(new->start);

	new->next = readahead_table[index];
	readahead_table[index] = new;
}


static int get_bytes(char *data, int size)
{
	int res = fread(data, 1, size, stdin);

	if(res == size)
		return res;

	return feof(stdin) ? 0 : -1;
}


static int get_readahead(struct pseudo_file *file, long long current,
		struct file_buffer *file_buffer, int size)
{
	int count = size;
	char *dest = file_buffer->data;

	if(readahead_table == NULL)
		return -1;

	while(size) {
		int index = READAHEAD_INDEX(current);
		struct readahead *buffer = readahead_table[index], *prev = NULL;

		for(; buffer; prev = buffer, buffer = buffer->next) {
			if(buffer->start <= current && buffer->start + buffer->size > current) {
				int offset = READAHEAD_OFFSET(current);
				int buffer_offset = READAHEAD_OFFSET(buffer->start);

				/*
				 * Four posibilities:
				 * 1. Wanted data is whole of buffer
				 * 2. Wanted data is at start of buffer
				 * 3. Wanted data is at end of buffer
				 * 4. Wanted data is in middle of buffer
				 */
				if(offset == buffer_offset && size >= buffer->size) {
					memcpy(dest, buffer->src, buffer->size);
					dest += buffer->size;
					size -= buffer->size;
					current += buffer->size;

					remove_readahead(index, prev, buffer);
					free(buffer);
					break;
				} else if(offset == buffer_offset) {
					memcpy(dest, buffer->src, size);
					buffer->start += size;
					buffer->src += size;
					buffer->size -= size;

					remove_readahead(index, prev, buffer);
					add_readahead(buffer);

					goto finished;
				} else if(buffer_offset + buffer->size <= offset+ size) {
					int bytes = buffer_offset + buffer->size - offset;

					memcpy(dest, buffer->src + offset - buffer_offset, bytes);
					buffer->size -= bytes;
					dest += bytes;
					size -= bytes;
					current += bytes;
					break;
				} else {
					struct readahead *left, *right;
					int left_size = offset - buffer_offset;
					int right_size = buffer->size - (offset + size);

					memcpy(dest, buffer->src + offset - buffer_offset, size);

					/* Split buffer into two */
					left = malloc(sizeof(struct readahead) + left_size);
					right = malloc(sizeof(struct readahead) + right_size);

					if(left == NULL || right == NULL)
						MEM_ERROR();

					left->start = buffer->start;
					left->size = left_size;
					left->src = left->data;
					memcpy(left->data, buffer->src, left_size);

					right->start = current + size;
					right->size = right_size;
					right->src = right->data;
					memcpy(right->data, buffer->src + offset + size, right_size);

					remove_readahead(index, prev, buffer);
					free(buffer);

					add_readahead(left);
					add_readahead(right);
					goto finished;
				}
			}
		}

		if(buffer == NULL)
			return -1;
	}

finished:
	return count;
}


static int do_readahead(struct pseudo_file *file, long long current,
		struct file_buffer *file_buffer, int size)
{
	int res;
	long long readahead = current - file->current;

	if(readahead_table == NULL) {
		readahead_table = malloc(READAHEAD_ALLOC);
		if(readahead_table == NULL)
			MEM_ERROR();

		memset(readahead_table, 0, READAHEAD_ALLOC);
	}

	while(readahead) {
		int offset = READAHEAD_OFFSET(file->current);
		int bytes = READAHEAD_SIZE - offset < readahead ? READAHEAD_SIZE - offset : readahead;
		struct readahead *buffer = malloc(sizeof(struct readahead) + bytes);

		if(buffer == NULL)
			MEM_ERROR();

		res = get_bytes(buffer->data, bytes);

		if(res == -1) {
			free(buffer);
			return res;
		}

		buffer->start = file->current;
		buffer->size = bytes;
		buffer->src = buffer->data;
		add_readahead(buffer);

		file->current += bytes;
		readahead -= bytes;
	}

	res = get_bytes(file_buffer->data, size);

	if(res != -1)
		file->current += size;

	return res;
}


static int read_data(struct pseudo_file *file, long long current,
		struct file_buffer *file_buffer, int size)
{
	int res;

	if(file->fd != STDIN_FILENO) {
		if(current != file->current) {
			/*
			 * File data reading is not in the same order as stored
			 * in the pseudo file.  As this is not stdin, we can
			 * lseek() to the wanted data
			 */
			res = lseek(file->fd, current + file->start, SEEK_SET);
			if(res == -1)
				BAD_ERROR("Lseek on pseudo file %s failed because %s\n",
					file->filename, strerror(errno));

			file->current = current;
		}

		res = read_bytes(file->fd, file_buffer->data, size);

		if(res != -1)
			file->current += size;

		return res;
	}

	/*
	 * Reading from stdin.  Three possibilities
	 * 1. We are at the current place in stdin, so just read data
	 * 2. Data we want has already been read and buffered (readahead).
	 * 3. Data is later in the file, readahead and buffer data to that point
	 */

	if(current == file->current) {
		res = get_bytes(file_buffer->data, size);

		if(res != -1)
			file->current += size;

		return res;
	} else if(current < file->current)
		return get_readahead(file, current, file_buffer, size);
	else
		return do_readahead(file, current, file_buffer, size);
}


static void reader_read_data(struct reader *reader, struct read_entry *entry)
{
	struct file_buffer *file_buffer;
	int blocks;
	long long bytes, read_size, current, block = 0;
	struct inode_info *inode = entry->dir_ent->inode;
	static struct pseudo_file *file = NULL;

	bytes = 0;
	read_size = inode->pseudo->data->length;
	blocks = (read_size + block_size - 1) >> block_log;

	if(inode->pseudo->data->file != file) {
		/* Reading the first or a different pseudo file, if
		 * a different one, first close the previous pseudo
		 * file, unless it is stdin */
		if(file && file->fd > 0) {
			close(file->fd);
			file->fd = -1;
		}

		file = inode->pseudo->data->file;

		if(file->fd == -1) {
			while(1) {
				file->fd = open(file->filename, O_RDONLY);
				if(file->fd != -1 || errno != EINTR)
					break;
			}

			if(file->fd == -1)
				BAD_ERROR("Could not open pseudo file %s "
					"because %s\n", file->filename,
					strerror(errno));

			file->current = -file->start;
		}
	}

	current = inode->pseudo->data->offset;

	do {
		file_buffer = get_buffer(reader, entry, read_size, block ++, 0);

		if(blocks > 1) {
			/* non-tail block should be exactly block_size */
			file_buffer->size = read_data(file, current, file_buffer, block_size);
			if(file_buffer->size != block_size)
				BAD_ERROR("Failed to read pseudo file %s, it appears to be truncated or corrupted\n", file->filename);

			current += file_buffer->size;
			bytes += file_buffer->size;

			file_buffer->fragment = FALSE;
			put_file_buffer(reader->id, file_buffer, NEXT_BLOCK);
		} else {
			int expected = read_size - bytes;

			file_buffer->size = read_data(file, current, file_buffer, expected);
			if(file_buffer->size != expected)
				BAD_ERROR("Failed to read pseudo file %s, it appears to be truncated or corrupted\n", file->filename);

			current += file_buffer->size;
		}
	} while(-- blocks > 0);

	file_buffer->fragment = is_fragment(inode);
	put_file_buffer(reader->id, file_buffer, NEXT_FILE);
}


static void _add_entry(struct dir_ent *entry, struct read_entry ***array, unsigned int *count)
{
	if(*array == NULL || *count % READER_ALLOC == 0) {
		struct read_entry **tmp = realloc(*array, (*count + READER_ALLOC) * sizeof(struct read_entry *));

		if(tmp == NULL)
			MEM_ERROR();

		*array = tmp;
	}

	(*array)[*count] = malloc(sizeof(struct read_entry));
	if((*array)[*count] == NULL)
		MEM_ERROR();

	(*array)[*count]->dir_ent = entry;
	(*array)[(*count) ++]->file_count = file_count ++;
}


static void add_entry(struct dir_ent *dir_ent)
{
	if(IS_PSEUDO_PROCESS(dir_ent->inode) ||
			IS_PSEUDO_DATA(dir_ent->inode) ||
			is_large(dir_ent->inode))
		_add_entry(dir_ent, &block_array, &block_count);
	else
		_add_entry(dir_ent, &fragment_array, &fragment_count);
}


static void reader_scan(struct dir_info *dir)
{
	struct dir_ent *dir_ent = dir->list;

	for(; dir_ent; dir_ent = dir_ent->next) {
		if(dir_ent->inode->root_entry || IS_TARFILE(dir_ent->inode) || dir_ent->inode->scanned)
			continue;

		if(IS_PSEUDO_PROCESS(dir_ent->inode) ||
				IS_PSEUDO_DATA(dir_ent->inode) ||
				S_ISREG(dir_ent->inode->buf.st_mode)) {
			dir_ent->inode->scanned = TRUE;
			add_entry(dir_ent);
		} else if(S_ISDIR(dir_ent->inode->buf.st_mode))
			reader_scan(dir_ent->dir);
	}
}


static void create_resources()
{
	int i, per_rthread = total_rblocks / reader_threads;
	int total_fwthread = (processors + 1) * fragment_threads;
	int per_wthread = (total_wblocks - total_fwthread) / block_threads;

	queue_cache_set(bwriter_buffer, fragment_threads, processors + 1,
		block_threads, per_wthread, per_rthread);

	read_queue_set(to_process_frag, reader_threads, per_rthread);

	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	reader = malloc(reader_threads * sizeof(struct reader));
	if(reader == NULL)
		MEM_ERROR();

	for(i = 0; i < reader_threads; i++) {
		reader[i].id = i;
		reader[i].type = "";
		reader[i].buffer = cache_init(block_size, per_rthread, 0, 0);
		reader[i].size = ALLOC_SIZE;
		reader[i].pathname = NULL;
	}

	pthread_cleanup_pop(1);
}


static void *block_reader(void *arg)
{
	struct reader *reader = arg;

	for(int n = 0; n < block_count; n ++) {
		struct read_entry *entry = atomic_swap(&block_array[n], &mutex);

		if(entry == NULL)
			continue;

		if(IS_PSEUDO_PROCESS(entry->dir_ent->inode))
			reader_read_process(reader, entry);
		else if(S_ISREG(entry->dir_ent->inode->buf.st_mode))
			reader_read_file(reader, entry, BLOCK_READER);
		else
			BAD_ERROR("Unexpected file type when reading files!\n");
	}

	pthread_exit(NULL);
}


static void *fragment_reader(void *arg)
{
	struct reader *reader = arg;

	for(int n = 0; n < fragment_count; n ++) {
		struct read_entry *entry = atomic_swap(&fragment_array[n], &mutex);

		if(entry == NULL)
			continue;

		if(IS_PSEUDO_PROCESS(entry->dir_ent->inode))
			reader_read_process(reader, entry);
		else if(S_ISREG(entry->dir_ent->inode->buf.st_mode))
			reader_read_file(reader, entry, FRAGMENT_READER);
		else
			BAD_ERROR("Unexpected file type when reading files!\n");
	}

	pthread_exit(NULL);
}


static void multi_thread(struct dir_info *dir)
{
	pthread_t *thread;
	int i;

	if(!sorted)
		reader_scan(dir);
	else {
		struct priority_entry *entry;

		for(i = 65535; i >= 0; i--) {
			for(entry = priority_list[i]; entry; entry = entry->next) {
				if(!entry->dir->inode->scanned) {
					entry->dir->inode->scanned = TRUE;
					add_entry(entry->dir);
				}
			}
		}
	}

	if(fragment_threads > fragment_count)
		fragment_threads = fragment_count;

	if(block_threads > block_count)
		block_threads = block_count;

	reader_threads = fragment_threads + block_threads;
	create_resources();

	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	thread = malloc(reader_threads * sizeof(pthread_t));
	if(thread == NULL)
		MEM_ERROR();

	for(i = 0; i < fragment_threads; i++) {
		reader[i].type = "small";
		pthread_create(&thread[i], NULL, fragment_reader, &reader[i]);
	}

	for(i = 0; i < block_threads; i++) {
		reader[i + fragment_threads].type = "block";
		pthread_create(&thread[i + fragment_threads], NULL, block_reader, &reader[i + fragment_threads]);
	}

	reader_thread = thread;

	pthread_cleanup_pop(1);
}


static void single_reader_scan(struct dir_info *dir)
{
	struct dir_ent *dir_ent = dir->list;
	struct read_entry entry;

	for(; dir_ent; dir_ent = dir_ent->next) {
		if(dir_ent->inode->root_entry || IS_TARFILE(dir_ent->inode) || dir_ent->inode->scanned)
			continue;

		if(IS_PSEUDO_PROCESS(dir_ent->inode) ||
				IS_PSEUDO_DATA(dir_ent->inode) ||
				S_ISREG(dir_ent->inode->buf.st_mode)) {
			dir_ent->inode->scanned = TRUE;
			entry.dir_ent = dir_ent;
			entry.file_count = file_count ++;
		}

		if(IS_PSEUDO_PROCESS(dir_ent->inode))
			reader_read_process(&reader[0], &entry);
		else if(IS_PSEUDO_DATA(dir_ent->inode))
			reader_read_data(&reader[0], &entry);
		else if(S_ISREG(dir_ent->inode->buf.st_mode))
			reader_read_file(&reader[0], &entry, COMBINED_READER);
		else if(S_ISDIR(dir_ent->inode->buf.st_mode))
			single_reader_scan(dir_ent->dir);
	}
}


static void single_thread(struct dir_info *dir)
{
	if(!sorted)
		single_reader_scan(dir);
	else {
		int i;
		struct priority_entry *entry;
		struct read_entry ent;

		for(i = 65535; i >= 0; i--) {
			for(entry = priority_list[i]; entry; entry = entry->next) {
				if(!entry->dir->inode->scanned) {
					entry->dir->inode->scanned = TRUE;
					ent.dir_ent = entry->dir;
					ent.file_count = file_count ++;
					reader_read_file(&reader[0], &ent, COMBINED_READER);
				}
			}
		}
	}
}


void *initial_reader(void *arg)
{
	struct itimerval itimerval;
	struct dir_info *dir = queue_get(to_reader);

	if(sleep_time) {
		signal(SIGALRM, sigalrm_handler);

		itimerval.it_value.tv_sec = 0;
		itimerval.it_value.tv_usec = 100000;
		itimerval.it_interval.tv_sec = 10;
		itimerval.it_interval.tv_usec = 0;
		setitimer(ITIMER_REAL, &itimerval, NULL);
	}

	if(tarfile) {
		create_resources();
		reader[0].type = "combined";
		file_count = read_tar_file();
		single_thread(queue_get(to_reader));
	} else if(!sleep_time && reader_threads > 1)
		multi_thread(dir);
	else {
		create_resources();
		reader[0].type = "combined";

		single_thread(dir);
	}

	pthread_exit(NULL);
}


struct reader *get_readers(int *num)
{
	struct reader *readers;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	readers = reader;
	*num = reader ? reader_threads : 0;

	pthread_cleanup_pop(1);

	return readers;
}


pthread_t *get_reader_threads(int *num)
{
	pthread_t *threads;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	threads = reader_thread;
	*num = reader_thread ? reader_threads : 0;

	pthread_cleanup_pop(1);

	return threads;
}


int set_read_frag_threads(int fragments)
{
	if(fragments <= 0 || fragments > 8192)
		return FALSE;

	fragment_threads = fragments;
	reader_threads = fragment_threads + block_threads;

	return TRUE;
}


int set_read_block_threads(int blocks)
{
	if(blocks <= 0 || blocks > 8192)
		return FALSE;

	block_threads = blocks;
	reader_threads = fragment_threads + block_threads;

	return TRUE;
}


void set_single_threaded()
{
	single_threaded = TRUE;
	reader_threads = 1;
	block_threads = 1;
	fragment_threads = 0;
}


int get_reader_num()
{
	return reader_threads;
}


void set_sleep_time(int time)
{
	sleep_time = time;
}


void check_min_memory(int rmbytes, int wmbytes, int block_log)
{
	int rblocks = rmbytes << (20 - block_log);
	int wblocks = wmbytes << (20 - block_log);
	int per_rthread = rblocks / reader_threads;
	int total_fwthread = (processors + 1) * fragment_threads;
	int per_wthread = (wblocks - total_fwthread) / block_threads;

	if(per_wthread < (processors + 1) || per_rthread < BLOCKS_MIN) {
		int twblocks = total_fwthread + (processors + 1) * block_threads;
		int twmbytes = twblocks >> (20 - block_log) ? : 1;
		int twmin_mem = twmbytes * SQUASHFS_BWRITEQ_MEM;
		int trblocks = BLOCKS_MIN * reader_threads;
		int trmbytes = trblocks >> (20 - block_log) ? : 1;
		int trmin_mem = trmbytes * SQUASHFS_READQ_MEM;
		int reader_only = twmin_mem <= trmin_mem;
		int min_mem = reader_only ? trmin_mem : twmin_mem;

		ERROR("\nERROR: Insufficient memory for specified options!  "
			"Please increase memory\nto %d Mbytes (-mem option)\n"
			"\n", min_mem);

		if(reader_only && !single_threaded) {
			ERROR("Alternatively, you could try reducing the "
				"number of reader threads\n"
				"(-single-reader-thread option, and "
				"-small-reader-threads/-block-reader-threads\n"
				"options)\n\n");
			ERROR("Current options:\n");
			ERROR("\t-small-reader-threads is set to %d\n", fragment_threads);
			ERROR("\t-block-reader-threads is set to %d\n\n", block_threads);
		} else if(!reader_only && !single_threaded && processors > 1) {
			ERROR("Alternatively, you could try reducing the "
				"number of reader threads\n"
				"(-single-reader-thread option, and "
				"-small-reader-threads/-block-reader-threads\n"
				"options)\n\n");
			ERROR("Or you could reduce the number of processors "
				"used (-processors option)\n\n");
			ERROR("Current options:\n");
			ERROR("\t-small-reader-threads is set to %d\n", fragment_threads);
			ERROR("\t-block-reader-threads is set to %d\n", block_threads);
			ERROR("\t-processors is set to %d\n\n", processors);
		} else if(!reader_only && !single_threaded && processors == 1) {
			ERROR("Alternatively, you could try reducing the "
				"number of reader threads\n"
				"(-single-reader-thread option, and "
				"-small-reader-threads/-block-reader-threads\n"
				"options)\n\n");
			ERROR("Current options:\n");
			ERROR("\t-small-reader-threads is set to %d\n", fragment_threads);
			ERROR("\t-block-reader-threads is set to %d\n", block_threads);
		} else if(!reader_only && single_threaded && processors > 1) {
			ERROR("Alternatively, you could reduce the number of "
				"processors used (-processors option)\n\n");
			ERROR("-processors set to %d\n\n", processors);
		}

		BAD_ERROR("Insufficient memory\n");

	}

	total_rblocks = rblocks;
	total_rmbytes = rmbytes;
	total_wblocks = wblocks;
	total_wmbytes = wmbytes;
}
