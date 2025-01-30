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

/* if throttling I/O, time to sleep between reads (in tenths of a second) */
int sleep_time;

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
#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "caches-queues-lists.h"
#include "progressbar.h"
#include "mksquashfs_error.h"
#include "pseudo.h"
#include "sort.h"
#include "tar.h"
#include "reader.h"

static struct readahead **readahead_table = NULL;

static void sigalrm_handler(int arg)
{
	struct timespec requested_time, remaining;

	requested_time.tv_sec = sleep_time / 10;
	requested_time.tv_nsec = (sleep_time % 10) * 100000000;

	nanosleep(&requested_time, &remaining);
}


static char *pathname(struct dir_ent *dir_ent)
{
	static char *pathname = NULL;
	static int size = ALLOC_SIZE;

	if (dir_ent->nonstandard_pathname)
		return dir_ent->nonstandard_pathname;

	if(pathname == NULL) {
		pathname = malloc(ALLOC_SIZE);
		if(pathname == NULL)
			MEM_ERROR();
	}

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
			pathname = realloc(pathname, size);
			if(pathname == NULL)
				MEM_ERROR();
		} else
			break;
	}

	return pathname;
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


static void put_file_buffer(struct file_buffer *file_buffer)
{
	/*
	 * Decide where to send the file buffer:
	 * - compressible non-fragment blocks go to the deflate threads,
	 * - fragments go to the process fragment threads,
	 * - all others go directly to the main thread
	 */
	if(file_buffer->error) {
		file_buffer->fragment = 0;
		seq_queue_put(to_main, file_buffer);
	} else if (file_buffer->file_size == 0)
		seq_queue_put(to_main, file_buffer);
	else if(file_buffer->fragment)
		queue_put(to_process_frag, file_buffer);
	else
		queue_put(to_deflate, file_buffer);
}


static void reader_read_process(struct dir_ent *dir_ent)
{
	long long bytes = 0;
	struct inode_info *inode = dir_ent->inode;
	struct file_buffer *prev_buffer = NULL, *file_buffer;
	int status, byte, res, child;
	int file;

	if(inode->read)
		return;

	inode->read = TRUE;

	file = pseudo_exec_file(inode->pseudo, &child);
	if(!file) {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->sequence = sequence_count ++;
		goto read_err;
	}

	while(1) {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->sequence = sequence_count ++;
		file_buffer->noD = inode->noD;

		byte = read_bytes(file, file_buffer->data, block_size);
		if(byte == -1)
			goto read_err2;

		file_buffer->size = byte;
		file_buffer->file_size = -1;
		file_buffer->error = FALSE;
		file_buffer->fragment = FALSE;
		bytes += byte;

		if(byte == 0)
			break;

		/*
		 * Update progress bar size.  This is done
		 * on every block rather than waiting for all blocks to be
		 * read in case write_file_process() is running in parallel
		 * with this.  Otherwise the current progress bar position
		 * may get ahead of the progress bar size.
		 */
		progress_bar_size(1);

		if(prev_buffer)
			put_file_buffer(prev_buffer);
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
	else {
		cache_block_put(file_buffer);
		sequence_count --;
	}
	prev_buffer->file_size = bytes;
	prev_buffer->fragment = is_fragment(inode);
	put_file_buffer(prev_buffer);

	return;

read_err2:
	close(file);
read_err:
	if(prev_buffer) {
		cache_block_put(file_buffer);
		sequence_count --;
		file_buffer = prev_buffer;
	}
	file_buffer->error = TRUE;
	put_file_buffer(file_buffer);
}


static void reader_read_file(struct dir_ent *dir_ent)
{
	struct stat *buf = &dir_ent->inode->buf, buf2;
	struct file_buffer *file_buffer;
	int blocks, file, res;
	long long bytes, read_size;
	struct inode_info *inode = dir_ent->inode;

	if(inode->read)
		return;

	inode->read = TRUE;
again:
	bytes = 0;
	read_size = buf->st_size;
	blocks = (read_size + block_size - 1) >> block_log;

	while(1) {
		file = open(pathname(dir_ent), O_RDONLY);
		if(file != -1 || errno != EINTR)
			break;
	}

	if(file == -1) {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->sequence = sequence_count ++;
		goto read_err2;
	}

	do {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->file_size = read_size;
		file_buffer->sequence = sequence_count ++;
		file_buffer->noD = inode->noD;
		file_buffer->error = FALSE;

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
			put_file_buffer(file_buffer);
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
	put_file_buffer(file_buffer);

	close(file);

	return;

restat:
	res = fstat(file, &buf2);
	if(res == -1) {
		ERROR("Cannot stat dir/file %s because %s\n",
			pathname(dir_ent), strerror(errno));
		goto read_err;
	}

	if(read_size != buf2.st_size) {
		close(file);
		memcpy(buf, &buf2, sizeof(struct stat));
		file_buffer->error = 2;
		put_file_buffer(file_buffer);
		goto again;
	}
read_err:
	close(file);
read_err2:
	file_buffer->error = TRUE;
	put_file_buffer(file_buffer);
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
				 * Four possibilities:
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


static void reader_read_data(struct dir_ent *dir_ent)
{
	struct file_buffer *file_buffer;
	int blocks;
	long long bytes, read_size, current;
	struct inode_info *inode = dir_ent->inode;
	static struct pseudo_file *file = NULL;

	if(inode->read)
		return;

	inode->read = TRUE;
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
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->file_size = read_size;
		file_buffer->sequence = sequence_count ++;
		file_buffer->noD = inode->noD;
		file_buffer->error = FALSE;

		if(blocks > 1) {
			/* non-tail block should be exactly block_size */
			file_buffer->size = read_data(file, current, file_buffer, block_size);
			if(file_buffer->size != block_size)
				BAD_ERROR("Failed to read pseudo file %s, it appears to be truncated or corrupted\n", file->filename);

			current += file_buffer->size;
			bytes += file_buffer->size;

			file_buffer->fragment = FALSE;
			put_file_buffer(file_buffer);
		} else {
			int expected = read_size - bytes;

			file_buffer->size = read_data(file, current, file_buffer, expected);
			if(file_buffer->size != expected)
				BAD_ERROR("Failed to read pseudo file %s, it appears to be truncated or corrupted\n", file->filename);

			current += file_buffer->size;
		}
	} while(-- blocks > 0);

	file_buffer->fragment = is_fragment(inode);
	put_file_buffer(file_buffer);
}


static void reader_scan(struct dir_info *dir)
{
	struct dir_ent *dir_ent = dir->list;

	for(; dir_ent; dir_ent = dir_ent->next) {
		struct stat *buf = &dir_ent->inode->buf;

		if(dir_ent->inode->root_entry || IS_TARFILE(dir_ent->inode))
			continue;

		if(IS_PSEUDO_PROCESS(dir_ent->inode)) {
			reader_read_process(dir_ent);
			continue;
		}

		if(IS_PSEUDO_DATA(dir_ent->inode)) {
			reader_read_data(dir_ent);
			continue;
		}

		switch(buf->st_mode & S_IFMT) {
			case S_IFREG:
				reader_read_file(dir_ent);
				break;
			case S_IFDIR:
				reader_scan(dir_ent->dir);
				break;
		}
	}
}


void *reader(void *arg)
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
		read_tar_file();
		dir = queue_get(to_reader);
	}

	if(!sorted)
		reader_scan(dir);
	else{
		int i;
		struct priority_entry *entry;

		for(i = 65535; i >= 0; i--)
			for(entry = priority_list[i]; entry;
							entry = entry->next)
				reader_read_file(entry->dir);
	}

	pthread_exit(NULL);
}
