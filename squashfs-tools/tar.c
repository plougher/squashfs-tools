/*
 * Squashfs
 *
 * Copyright (c) 2021, 2022
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
 * tar.c
 */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <regex.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "caches-queues-lists.h"
#include "mksquashfs_error.h"
#include "xattr.h"
#include "tar.h"
#include "progressbar.h"
#include "info.h"

#define TRUE 1
#define FALSE 0

extern int silent;
int ignore_zeros = FALSE;
extern int ignore_zeros;
int default_uid_opt = FALSE;
unsigned int default_uid;
int default_gid_opt = FALSE;
unsigned int default_gid;
int default_mode_opt = FALSE;
mode_t default_mode;

static long long read_octal(char *s, int size)
{
	long long res = 0;

	for(; size && *s == ' '; s++, size--);

	if(size == 0)
		return -1;

	for(; size && *s >= '0' && *s < '8'; s++, size--)
		res = (res << 3) + *s - '0';

	if(size && (*s != ' ' && *s != '\0'))
		return -1;

	return res;
}


static long long read_binary(char *src, int size)
{
	unsigned char *s = (unsigned char *) src;
	long long res = 0;

	for(; size; s++, size --)
		res = (res << 8) + *s;

	return res;
}


static long long read_number(char *s, int size)
{
	if(*((signed char *) s) == -128)
		return read_binary(s + 1, size - 1);
	else
		return read_octal(s, size);
}


static long long read_decimal(char *s, int maxsize, int *bytes)
{
	long long res = 0;
	int size = maxsize;

	for(; size && *s >= '0' && *s <= '9'; s++, size--)
		res = (res * 10) + *s - '0';

	/* size should be > 0, and we should be at the terminator */
	if(size > 0 && *s == '\n') {
		*bytes = maxsize - size + 1;
		return res;
	}

	/* Bad value or out of bytes? */
	if(size)
		return -1;
	else
		return -2;
}


static char *read_long_string(int size, int skip)
{
	char buffer[512];
	char *name = malloc(size + 1);
	int i, res, length = size;

	if(name == NULL)
		MEM_ERROR();

	for(i = 0; size > 0; i++) {
		int expected = size > 512 ? 512 : size;

		res = read_bytes(STDIN_FILENO, buffer, 512);
		if(res < 512) {
			if(res != -1)
				ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
			free(name);
			return NULL;
		}
		memcpy(name + i * 512, buffer, expected);
		size -= 512;
	}

	name[length] = '\0';

	if(skip) {
		char *filename = name;

		while(1) {
			if(length >= 3 && strncmp(filename, "../", 3) == 0) {
				filename += 3;
				length -= 3;
			} else if(length >= 2 && strncmp(filename, "./", 2) == 0) {
				filename += 2;
				length -= 2;
			} else if(length >= 1 && *filename == '/') {
				filename++;
				length--;
			} else
				break;
		}

		if(filename != name) {
			if(length == 0) {
				ERROR("Empty tar filename after skipping leading /, ./, or ../\n");
				free(name);
				return NULL;
			}

			memmove(name, filename, length + 1);
			name = realloc(name, length + 1);
			if(name == NULL)
				MEM_ERROR();
		}
	}

	return name;
}


static int all_zero(struct tar_header *header)
{
	int i;

	for(i = 0; i < 512; i++)
		if(header->udata[i])
			return FALSE;

	return TRUE;
}


static int checksum_matches(struct tar_header *header, int silent)
{
	int checksum = read_number(header->checksum, 8);
	int computed = 0;
	int i;

	if(checksum == -1) {
		if(!silent)
			ERROR("Failed to read checksum in tar header\n");
		return FALSE;
	}

	/* The checksum is computed with the checksum field
	 * filled with spaces */
	memcpy(header->checksum, "        ", 8);

	/* Header bytes should be treated as unsigned */
	for(i = 0; i < 512; i++)
		computed += header->udata[i];

	if(computed == checksum)
		return TRUE;

	/* Some historical implementations treated header bytes as signed */
	for(computed = 0, i = 0; i < 512; i++)
		computed += header->sdata[i];

	return computed == checksum;
}


static char *get_component(char *target, char **targname)
{
	char *start;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = strndup(start, target - start);

	while(*target == '/')
		target ++;

	return target;
}


static struct inode_info *new_inode(struct tar_file *tar_file)
{
	struct inode_info *inode;
	int bytes = tar_file->link ? strlen(tar_file->link) + 1 : 0;

	inode = malloc(sizeof(struct inode_info) + bytes);
	if(inode == NULL)
		MEM_ERROR();

	if(bytes)
		memcpy(&inode->symlink, tar_file->link, bytes);
	memcpy(&inode->buf, &tar_file->buf, sizeof(struct stat));
	inode->read = FALSE;
	inode->root_entry = FALSE;
	inode->tar_file = tar_file;
	inode->inode = SQUASHFS_INVALID_BLK;
	inode->nlink = 1;
	inode->inode_number = 0;
	inode->pseudo = NULL;
	inode->dummy_root_dir = FALSE;
	inode->xattr = NULL;
	inode->tarfile = TRUE;

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

	inode->next = inode_info[0];
	inode_info[0] = inode;

	return inode;
}


static struct inode_info *copy_inode(struct inode_info *source)
{
	struct inode_info *inode;
	int bytes = S_ISLNK(source->buf.st_mode) ? strlen(source->symlink) + 1 : 0;

	inode = malloc(sizeof(struct inode_info) + bytes);
	if(inode == NULL)
		MEM_ERROR();

	memcpy(inode, source, sizeof(struct inode_info) + bytes);

	return inode;
}


static void fixup_tree(struct dir_info *dir)
{
	struct dir_ent *entry;

	for(entry = dir->list; entry; entry = entry->next) {
		if(entry->dir && entry->inode == NULL) {
			/* Tar file didn't create this directory, and so it lacks
			 * an inode with metadata.  Create a default definition ... */
			struct stat buf;

			memset(&buf, 0, sizeof(buf));
			if(default_mode_opt)
				buf.st_mode = default_mode | S_IFDIR;
			else
				buf.st_mode = S_IRWXU | S_IRGRP | S_IXGRP |
					S_IROTH | S_IXOTH | S_IFDIR;
			if(default_uid_opt)
				buf.st_uid = default_uid;
			else
				buf.st_uid = getuid();
			if(default_gid_opt)
				buf.st_gid = default_gid;
			else
				buf.st_gid = getgid();
			buf.st_mtime = time(NULL);
			buf.st_dev = 0;
			buf.st_ino = 0;
			entry->inode = lookup_inode(&buf);
			entry->inode->tar_file = NULL;
			entry->inode->tarfile = TRUE;
		}
		
		if(entry->dir == NULL && S_ISDIR(entry->inode->buf.st_mode)) {
			/* Tar file created this directory, but, never created
			 * anything in it.  This will leave a NULL sub-directory,
			 * where the scanning code expects to find an empty
			 * directory.  Create an empty directory in this case ... */
			char *subpath = subpathname(entry);

			entry->dir = create_dir("", subpath, dir->depth + 1);
			entry->dir->dir_ent = entry;
		} 

		if(entry->dir)
			fixup_tree(entry->dir);
	}
}


/*
 * Add source to the tardir directory hierachy.
 * Tarfile describes the tar file to be added.
 */
static struct dir_info *add_tarfile(struct dir_info *sdir, char *source,
		char *subpath, struct tar_file *tarfile, struct pathnames *paths,
		int depth, struct dir_ent **dir_ent, struct inode_info *link)
{
	struct dir_info *sub;
	struct dir_ent *entry;
	struct pathnames *new = NULL;
	struct dir_info *dir = sdir;
	char *name;

	if(dir == NULL)
		dir = create_dir("", subpath, depth);

	source = get_component(source, &name);

	if((strcmp(name, ".") == 0) || strcmp(name, "..") == 0)
		BAD_ERROR("Error: Tar pathname can't have '.' or '..' in it\n");

	entry = lookup_name(dir, name);

	if(entry) {
		/* existing matching entry */
		if(entry->dir == NULL) {
			/* No sub-directory which means this is the leaf
			 * component of a pre-existing tarfile */
			if(source[0] != '\0') {
				/* existing entry must be a directory */
				subpath = subpathname(entry);
				if(S_ISDIR(entry->inode->buf.st_mode)) {
					/* recurse adding child components */
					excluded(name, paths, &new);
					entry->dir = add_tarfile(NULL, source, subpath, tarfile, new, depth + 1, dir_ent, link);
					if(entry->dir == NULL)
						goto failed_early;
					entry->dir->dir_ent = entry;
				} else 
					BAD_ERROR("%s exists in the tar file as"
						" a non-directory, cannot add"
						" tar pathname %s!\n",
						subpath, tarfile->pathname);
			} else {
				ERROR("%s already exists in the tar file, ignoring\n", tarfile->pathname);
				goto failed_early;
			}
		} else {
			if(source[0] == '\0') {
				/* sub-directory exists, we must be adding a
				 * directory, and we must not already have a
				 * definition for this directory */
				if(S_ISDIR(tarfile->buf.st_mode)) {
					if(entry->inode == NULL)
						entry->inode = new_inode(tarfile);
					else {
						ERROR("%s already exists in the tar file, ignoring!\n", tarfile->pathname);
						goto failed_early;
					}
				} else
					BAD_ERROR("%s exists in the tar file as"
						" both a directory and"
						" non-directory!\n",
						tarfile->pathname);
			} else {
				/* recurse adding child components */
				excluded(name, paths, &new);
				subpath = subpathname(entry);
				sub = add_tarfile(entry->dir, source, subpath, tarfile, new, depth + 1, dir_ent, link);
				if(sub == NULL)
					goto failed_early;
			}
		}

		free(name);
	} else {
		/*
		 * No matching name found.
		 *
		 * - If we're at the leaf of the source, then add it.
		 *
		 * - If we're not at the leaf of the source, we will add it,
		 *   and recurse walking the source
		 */
		if(old_exclude == FALSE && excluded(name, paths, &new))
			goto failed_early;

		entry = create_dir_entry(name, NULL, NULL, dir);

		if(source[0] == '\0') {
			if(S_ISDIR(tarfile->buf.st_mode)) {
				add_dir_entry(entry, NULL, new_inode(tarfile));
				dir->directory_count ++;
			} else if (link == FALSE) {
				add_dir_entry(entry, NULL, new_inode(tarfile));
				if(S_ISREG(tarfile->buf.st_mode))
					*dir_ent = entry;
			} else if(no_hardlinks)
				add_dir_entry(entry, NULL, copy_inode(link));
			else
				add_dir_entry(entry, NULL, link);
		} else {
			subpath = subpathname(entry);
			sub = add_tarfile(NULL, source, subpath, tarfile, new, depth + 1, dir_ent, link);
			if(sub == NULL)
				goto failed_entry;
			add_dir_entry(entry, sub, NULL);
			dir->directory_count ++;
		}
	}

	free(new);
	return dir;

failed_early:
	free(new);
	free(name);
	if(sdir == NULL)
		free_dir(dir);
	return NULL;

failed_entry:
	free(new);
	free_dir_entry(entry);
	if(sdir == NULL)
		free_dir(dir);
	return NULL;
}


struct dir_ent *lookup_pathname(struct dir_info *dir, char *pathname)
{
	char *name;
	struct dir_ent *entry;

	pathname = get_component(pathname, &name);

	if((strcmp(name, ".") == 0) || strcmp(name, "..") == 0) {
		ERROR("Error: Tar hardlink pathname can't have '.' or '..' in it\n");
		return NULL;
	}

	entry = lookup_name(dir, name);
	free(name);

	if(entry == NULL)
		return NULL;

	if(pathname[0] == '\0')
		return entry;

	if(entry->dir == NULL)
		return NULL;

	return lookup_pathname(entry->dir, pathname);
}


static inline int is_fragment(long long file_size)
{
	return !no_fragments && file_size && (file_size < block_size ||
		(always_use_fragments && file_size & (block_size - 1)));
}


static void put_file_buffer(struct file_buffer *file_buffer)
{
	/*
	 * Decide where to send the file buffer:
	 * - compressible non-fragment blocks go to the deflate threads,
	 * - fragments go to the process fragment threads,
	 */
	if(file_buffer->fragment)
		queue_put(to_process_frag, file_buffer);
	else
		queue_put(to_deflate, file_buffer);
}


int sparse_reader(struct tar_file *file, long long cur_offset, char *dest, int bytes, long long *off)
{
	static int cur;
	static long long offset;
	static long long number;
	int avail, res;

	if(bytes == 0) {
		cur = 0;
		offset = file->map[0].offset;
		number = file->map[0].number;
		*off = offset;
		return 0;
	}

	if(cur_offset != offset)
		return -1;

	avail = bytes > number ? number : bytes;
	res = read_bytes(STDIN_FILENO, dest, avail);
	if(res != avail)
		BAD_ERROR("Failed to read tar file %s, the tarfile appears to be truncated or corrupted\n", file->pathname);

	offset += avail;
	number -= avail;

	if(number == 0) {
		cur ++;
		offset = file->map[cur].offset;
		number = (file->map[cur].number + 511) & ~511;
	}

	*off = offset;
	return avail;
}


static int read_sparse_block(struct tar_file *file, int fd, char *dest, int bytes, int block)
{
	static long long offset;
	long long cur_offset = (long long) block * block_size;
	int avail, copied = bytes;

	if(block == 0)
		sparse_reader(file, cur_offset, dest, 0, &offset);

	if(offset - cur_offset >= block_size && bytes == block_size) {
		memset(dest, 0, block_size);
		return block_size;
	}

	while(bytes) {
		if(offset - cur_offset > 0) {
			avail = offset - cur_offset < bytes ? offset - cur_offset : bytes;

			memset(dest, 0, avail);
			dest += avail;
			cur_offset += avail;
			bytes -= avail;
		} else if(cur_offset == offset) {
			avail = sparse_reader(file, cur_offset, dest, bytes, &offset);

			dest += avail;
			cur_offset += avail;
			bytes -= avail;
		} else
			return -1;
	}

	return copied;
}


static int read_block(struct tar_file *file, int fd, char *data, int bytes, int block)
{
	if(file->map)
		return read_sparse_block(file, fd, data, bytes, block);
	else
		return read_bytes(fd, data, bytes);
}


static void skip_file(struct tar_file *tar_file)
{
	int blocks = (tar_file->buf.st_size + block_size - 1) >> block_log, i;

	for(i = 0; i < blocks; i++)
		cache_block_put(seq_queue_get(to_main));

	progress_bar_size(-blocks);
}

static void read_tar_data(struct tar_file *tar_file)
{
	struct stat *buf = &tar_file->buf;
	struct file_buffer *file_buffer;
	int blocks, block = 0;
	long long bytes, read_size;

	bytes = 0;
	read_size = buf->st_size;
	blocks = (read_size + block_size - 1) >> block_log;

	do {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->file_size = read_size;
		file_buffer->tar_file = tar_file;
		file_buffer->sequence = sequence_count ++;
		file_buffer->noD = noD;
		file_buffer->error = FALSE;

		if((block + 1) < blocks) {
			/* non-tail block should be exactly block_size */
			file_buffer->size = read_block(tar_file, STDIN_FILENO, file_buffer->data, block_size, block);
			if(file_buffer->size != block_size)
				BAD_ERROR("Failed to read tar file %s, the tarfile appears to be truncated or corrupted\n", tar_file->pathname);

			bytes += file_buffer->size;

			file_buffer->fragment = FALSE;
			put_file_buffer(file_buffer);
		} else {
			/* The remaining bytes will be rounded up to 512 bytes */
			int expected = (read_size + 511 - bytes) & ~511;
			int size = read_block(tar_file, STDIN_FILENO, file_buffer->data, expected, block);

			if(size != expected)
				BAD_ERROR("Failed to read tar file %s, the tarfile appears to be truncated or corrupted\n", tar_file->pathname);

			file_buffer->size = read_size - bytes;
		}
	} while(++ block < blocks);

	file_buffer->fragment = is_fragment(read_size);
	put_file_buffer(file_buffer);

	return;
}


static char *skip_components(char *filename, int size, int *sizep)
{
	while(1) {
		if(size >= 3 && strncmp(filename, "../", 3) == 0) {
			filename += 3;
			size -= 3;
		} else if(size >= 2 && strncmp(filename, "./", 2) == 0) {
			filename += 2;
			size -= 2;
		} else if(size >= 1 && *filename == '/') {
			filename++;
			size--;
		} else
			break;
	}

	if(sizep)
		*sizep = size;

	return filename;
}


static int read_sparse_value(struct tar_file *file, char *value, int map_entries)
{
	int bytes, res, i = 0;
	long long number;

	while(1) {
		res = sscanf(value, "%lld %n", &number, &bytes);
		if(res < 1 || value[bytes] != ',')
			goto failed;

		file->map[i].offset = number;

		value += bytes + 1;

		res = sscanf(value, "%lld %n", &number, &bytes);
		if(res < 1 || (value[bytes] != ',' && value[bytes] != '\0'))
			goto failed;

		file->map[i++].number = number;

		if(value[bytes] == '\0' || i >= map_entries)
			break;

		value += bytes + 1;
	}

	return TRUE;

failed:
	return FALSE;
}


static int read_pax_header(struct tar_file *file, long long st_size)
{
	long long size = (st_size + 511) & ~511;
	char *data, *ptr, *end, *keyword, *value;
	int res, length, bytes, vsize;
	long long number;
	long long major = -1, minor = -1, realsize = -1;
	int old_gnu_pax = FALSE, old_gnu_ver = -1;
	int map_entries = 0, cur_entry = 0;
	char *name = NULL;

	data = malloc(size);
	if(data == NULL)
		MEM_ERROR();

	res = read_bytes(STDIN_FILENO, data, size);
	if(res < size) {
		if(res != -1)
			ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
		free(data);
		return FALSE;
	}

	for(ptr = data, end = data + st_size; ptr < end;) {
		/*
		 * What follows should be <length> <keyword>=<value>,
		 * where <length> is the full length, including the
		 * <length> field and newline
		 */
		res = sscanf(ptr, "%d%n", &length, &bytes);
		if(res < 1 || length <= bytes || length > st_size)
			goto failed;

		length -= bytes;
		ptr += bytes;

		/* Skip whitespace */
		for(; length && *ptr == ' '; length--, ptr++);

		/* Store and parse keyword */
		for(keyword = ptr; length && *ptr != '='; length--, ptr++);

		/* length should be 2 or more, given it includes the = and newline */
		if(length < 2)
			goto failed;

		/* Terminate the keyword string */
		*ptr++ = '\0';
		length --;

		/* Store value */
		value = ptr;

		/* Check the string is terminated by '\n' */
		if(value[length - 1] != '\n')
			goto failed;

		/* Replace the '\n' with a nul terminator.
		 * In some tars the value may be binary, and include nul
		 * characters, and so we have to not treat it as a
		 * null terminated string then, and so also store
		 * the length of the string */
		value[length - 1] = '\0';
		vsize = length - 1;

		/* Evaluate keyword */
		if(strcmp(keyword, "size") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			file->buf.st_size = number;
			file->have_size = TRUE;
		} else if(strcmp(keyword, "uid") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			file->buf.st_uid = number;
			file->have_uid = TRUE;
		} else if(strcmp(keyword, "gid") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			file->buf.st_gid = number;
			file->have_gid = TRUE;
		} else if(strcmp(keyword, "mtime") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '.')
				goto failed;
			file->buf.st_mtime = number;
			file->have_mtime = TRUE;
		} else if(strcmp(keyword, "uname") == 0)
			file->uname = strdup(value);
		else if(strcmp(keyword, "gname") == 0)
			file->gname = strdup(value);
		else if(strcmp(keyword, "path") == 0)
			file->pathname = strdup(skip_components(value, vsize, NULL));
		else if(strcmp(keyword, "linkpath") == 0)
			file->link = strdup(value);
		else if(strcmp(keyword, "GNU.sparse.major") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			major = number;
		} else if(strcmp(keyword, "GNU.sparse.minor") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			minor = number;
		} else if(strcmp(keyword, "GNU.sparse.realsize") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			realsize = number;
		} else if(strcmp(keyword, "GNU.sparse.name") == 0)
			name = strdup(value);
		else if(strcmp(keyword, "GNU.sparse.size") == 0) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			realsize = number;
			old_gnu_pax = 1;
		} else if(strcmp(keyword, "GNU.sparse.numblocks") == 0 && old_gnu_pax == 1) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			file->map = malloc(number * sizeof(struct file_map));
			if(file->map == NULL)
				MEM_ERROR();
			map_entries = number;
			cur_entry = 0;
			old_gnu_pax = 2;
		} else if(strcmp(keyword, "GNU.sparse.offset") == 0 && old_gnu_pax == 2 && old_gnu_ver != 1) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			if(cur_entry < map_entries)
				file->map[cur_entry].offset = number;
			old_gnu_ver = 0;
		} else if(strcmp(keyword, "GNU.sparse.numbytes") == 0 && old_gnu_pax == 2 && old_gnu_ver != 1) {
			res = sscanf(value, "%lld %n", &number, &bytes);
			if(res < 1 || value[bytes] != '\0')
				goto failed;
			if(cur_entry < map_entries)
				file->map[cur_entry++].number = number;
			old_gnu_ver = 0;
		} else if(strcmp(keyword, "GNU.sparse.map") == 0 && old_gnu_pax == 2 && old_gnu_ver != 0) {
			res = read_sparse_value(file, value, map_entries);
			if(res == FALSE)
				goto failed;
			old_gnu_ver = 1;
		} else if(strncmp(keyword, "LIBARCHIVE.xattr.", strlen("LIBARCHIVE.xattr.")) == 0)
			read_tar_xattr(keyword + strlen("LIBARCHIVE.xattr."), value, strlen(value), ENCODING_BASE64, file);
		else if(strncmp(keyword, "SCHILY.xattr.", strlen("SCHILY.xattr.")) == 0)
			read_tar_xattr(keyword + strlen("SCHILY.xattr."), value, vsize, ENCODING_BINARY, file);
		else if(strcmp(keyword, "GNU.sparse.numblocks") != 0 &&
				strcmp(keyword, "GNU.sparse.offset") != 0 &&
				strcmp(keyword, "GNU.sparse.numbytes") != 0 &&
				strcmp(keyword, "GNU.sparse.map") != 0 &&
				strcmp(keyword, "atime") != 0 &&
				strcmp(keyword, "ctime") != 0 &&
				strcmp(keyword, "comment") != 0)
			ERROR("Unrecognised keyword \"%s\" in pax header, ignoring\n", keyword);

		ptr += length;
	}

	/* Is this a sparse file, and version (1.0)?
	 * If it is flag it, and the sparse map will be read
	 * later */
	if(!old_gnu_pax && major != -1 && minor != -1 && realsize != -1 && name) {
		if(major == 1 && minor == 0) {
			file->realsize = realsize;
			file->sparse_pax = 2;
			file->pathname = name;
		} else {
			ERROR("Pax sparse file not Major 1, Minor 0!\n");
			free(name);
		}
	}

	/* Is this an older sparse format? */
	if(old_gnu_pax == 2 && (old_gnu_ver == 0 || (old_gnu_ver == 1 && name))) {
		file->realsize = realsize;
		file->map_entries = map_entries;
		file->sparse_pax = 1;
		if(old_gnu_ver == 1)
			file->pathname = name;
	}

	free(data);
	return TRUE;

failed:
	ERROR("Failed to parse pax header\n");
	free(data);
	return FALSE;
}


static int check_sparse_map(struct file_map *map, int map_entries, long long size, long long realsize)
{
	long long total_data = 0;
	long long total_sparse = map[0].offset;
	int i;

	for(i = 0; i < map_entries; i++) {
		if(i > 0)
			total_sparse += (map[i].offset - (map[i - 1].offset + map[i - 1].number));
		total_data += map[i].number;
	}

	return total_data == size && total_data + total_sparse == realsize;
}


static struct file_map *read_sparse_headers(struct tar_file *file, struct short_sparse_header *short_header, int *entries)
{
	struct long_sparse_header long_header;
	int res, i, map_entries, isextended;
	struct file_map *map = NULL;
	long long realsize;

	realsize = read_number(short_header->realsize, 12);
	if(realsize == -1) {
		ERROR("Failed to read offset from sparse header\n");
		goto failed;
	}

	map = malloc(4 * sizeof(struct file_map));
	if(map == NULL)
		MEM_ERROR();

	/* There should always be at least one sparse entry */
	map[0].offset = read_number(short_header->sparse[0].offset, 12);
	if(map[0].offset == -1) {
		ERROR("Failed to read offset from sparse header\n");
		goto failed;
	}

	map[0].number = read_number(short_header->sparse[0].number, 12);
	if(map[0].number == -1) {
		ERROR("Failed to read number from sparse header\n");
		goto failed;
	}

	/* There may be three more sparse entries in this short header.
	 * An offset of 0 means unused */
	for(i = 1; i < 4; i++) {
		map[i].offset = read_number(short_header->sparse[i].offset, 12);
		if(map[i].offset == -1) {
			ERROR("Failed to read offset from sparse header\n");
			goto failed;
		}

		if(map[i].offset == 0)
			break;

		map[i].number = read_number(short_header->sparse[i].number, 12);
		if(map[i].number == -1) {
			ERROR("Failed to read number from sparse header\n");
			goto failed;
		}
	}

	/* If we've read two or less entries, then we expect the isextended
	 * entry to be FALSE */
	isextended = read_number(&short_header->isextended, 1);
	if(i < 3 && isextended) {
		ERROR("Invalid sparse header\n");
		goto failed;
	}

	map_entries = i;

	while(isextended) {
		res = read_bytes(STDIN_FILENO, &long_header, 512);
		if(res < 512) {
			if(res != -1)
				ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
			goto failed;
		}

		map = realloc(map, (map_entries + 21) * sizeof(struct file_map));
		if(map == NULL)
			MEM_ERROR();

		/* There may be up to 21 sparse entries in this long header.
		 * An offset of 0 means unused */
		for(i = map_entries; i < (map_entries + 21); i++) {
			map[i].offset = read_number(long_header.sparse[i - map_entries].offset, 12);
			if(map[i].offset == -1) {
				ERROR("Failed to read offset from sparse header\n");
				goto failed;
			}

			if(map[i].offset == 0)
				break;

			map[i].number = read_number(long_header.sparse[i - map_entries].number, 12);
			if(map[i].number == -1) {
				ERROR("Failed to read number from sparse header\n");
				goto failed;
			}
		}

		/* If we've read less than 21 entries, then we expect the isextended
		 * entry to be FALSE */
		isextended = read_number(&long_header.isextended, 1);
		if(i < (map_entries + 21) && isextended) {
			ERROR("Invalid sparse header\n");
			goto failed;
		}

		map_entries = i;
	}

	res = check_sparse_map(map, map_entries, file->buf.st_size, realsize);
	if(res == FALSE) {
		ERROR("Sparse file map inconsistent\n");
		goto failed;
	}

	*entries = map_entries;
	file->buf.st_size = realsize;

	return map;

failed:
	free(map);
	return NULL;
}


static struct file_map *read_sparse_map(struct tar_file *file, int *entries)
{
	int map_entries, bytes, size;
	struct file_map *map = NULL;
	char buffer[529], *src = buffer;
	long long offset = 0, number, res;
	int atoffset = TRUE, i = 0;

	res = read_bytes(STDIN_FILENO, buffer, 512);
	if(res < 512) {
		if(res != -1)
			ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
		goto failed;
	}

	/* First number is the number of map entries */
	map_entries = read_decimal(src, 512, &bytes);
	if(map_entries < 0) {
		ERROR("Could not parse Pax sparse map data\n");
		goto failed;
	}

	src += bytes;
	size = 512 - bytes;
	file->buf.st_size -= 512;

	while(i < map_entries) {
		res = read_decimal(src, size, &bytes);
		if(res == -1) {
			ERROR("Could not parse Pax sparse map data\n");
			goto failed;
		}

		if(res == -2) {
			/* Out of data */
			if(size >= 18) {
				/* Too large block of '0' .. '9' without a '\n' */
				ERROR("Could not parse Pax sparse map data\n");
				goto failed;
			}

			memmove(buffer, src, size);
			res = read_bytes(STDIN_FILENO, buffer + size, 512);
			if(res < 512) {
				if(res != -1)
					ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
				goto failed;
			}

			src = buffer;
			size += 512;
			file->buf.st_size -= 512;
			continue;
		}

		src += bytes;
		size -= bytes;

		if(atoffset)
			offset = res;
		else {
			number = res;

			if(i % 50 == 0) {
				map = realloc(map, (i + 50) * sizeof(struct file_map));
				if(map == NULL)
					MEM_ERROR();
			}

			map[i].offset = offset;
			map[i++].number = number;
		}

		atoffset = !atoffset;
	}

	*entries = map_entries;
	return map;

failed:
	free(map);
	return NULL;
}


static void copy_tar_header(struct tar_file *dest, struct tar_file *source)
{
	memcpy(dest, source, sizeof(struct tar_file));
	if(source->pathname)
		dest->pathname = strdup(source->pathname);
	if(source->link)
		dest->link = strdup(source->link);
	if(source->uname)
		dest->uname = strdup(source->uname);
	if(source->gname)
		dest->gname = strdup(source->gname);
}


static int skip_to_valid_header(struct tar_header *header)
{
	int res, first = TRUE;

	while(1) {
		res = read_bytes(STDIN_FILENO, header, 512);

		if(res < 512) {
			if(res == 0)
				return 0;
			if(res != -1)
				ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
			return -1;
		}

		if(all_zero(header))
			continue;

		if(checksum_matches(header, TRUE))
			return 1;

		if(first) {
			ERROR("sqfstar: Skipping to next header\n");
			first = FALSE;
		}
	}
}


static struct tar_file *read_tar_header(int *status)
{
	struct tar_header header;
	struct tar_file *file;
	long long res;
	int size, type;
	char *filename, *user, *group;
	static struct tar_file *global = NULL;

	file = malloc(sizeof(struct tar_file));
	if(file == NULL)
		MEM_ERROR();

	if(global)
		copy_tar_header(file, global);
	else
		memset(file, 0, sizeof(struct tar_file));

again:
	res = read_bytes(STDIN_FILENO, &header, 512);
	if(res < 512) {
		if(res == 0)
			goto eof;
		if(res != -1)
			ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
		goto failed;
	}

	if(all_zero(&header)) {
		if(ignore_zeros) {
			res = skip_to_valid_header(&header);
			if(res == 0)
				goto eof;
			if(res == -1)
				goto failed;
		} else
			goto eof;
	} else if(checksum_matches(&header, FALSE) == FALSE) {
		ERROR("Tar header checksum does not match!\n");
		goto failed;
	}

	/* Read filesize */
	if(file->have_size == FALSE) {
		res = read_number(header.size, 12);
		if(res == -1) {
			ERROR("Failed to read file size from tar header\n");
			goto failed;
		}
		file->buf.st_size = res;
	}

	switch(header.type) {
		case GNUTAR_SPARSE:
			file->map = read_sparse_headers(file, (struct short_sparse_header *) &header, &file->map_entries);
			if(file->map == NULL)
				goto failed;
			/* fall through */
		case TAR_NORMAL1:
		case TAR_NORMAL2:
		case TAR_NORMAL3:
			type = S_IFREG;
			break;
		case TAR_DIR:
			type = S_IFDIR;
			break;
		case TAR_SYM:
			type = S_IFLNK;
			break;
		case TAR_HARD:
			type = S_IFHRD;
			break;
		case TAR_CHAR:
			type = S_IFCHR;
			break;
		case TAR_BLOCK:
			type = S_IFBLK;
			break;
		case TAR_FIFO:
			type = S_IFIFO;
			break;
		case TAR_XHDR:
		case SOLARIS_XHDR:
			res = read_pax_header(file, file->buf.st_size);
			if(res == FALSE) {
				ERROR("Failed to read pax header\n");
				goto failed;
			}
			goto again;
		case TAR_GXHDR:
			if(global == NULL) {
				global = malloc(sizeof(struct tar_file));
				if(global == NULL)
					MEM_ERROR();
				memset(global, 0, sizeof(struct tar_file));
			}
			res = read_pax_header(global, file->buf.st_size);
			if(res == FALSE) {
				ERROR("Failed to read pax header\n");
				goto failed;
			}
			/* file is now out of date, and needs to be
			 * (re-)synced with the global header */
			free(file->pathname);
			free(file->link);
			free(file->uname);
			free(file->gname);
			copy_tar_header(file, global);
			goto again;
		case GNUTAR_LONG_NAME:
			file->pathname = read_long_string(file->buf.st_size, TRUE);
			if(file->pathname == NULL) {
				ERROR("Failed to read GNU Long Name\n");
				goto failed;
			}
			goto again;
		case GNUTAR_LONG_LINK:
			file->link = read_long_string(file->buf.st_size, FALSE);
			if(file->link == NULL) {
				ERROR("Failed to read GNU Long Name\n");
				goto failed;
			}
			goto again;
		default:
			ERROR("Unhandled tar type in header 0x%x - ignoring\n", header.type);
			goto ignored;
	}

	/* Process filename - skip any leading slashes or ./ or ../ */
	if(file->pathname == NULL && header.prefix[0] != '\0') {
		int length1, length2;

		filename = skip_components(header.prefix, 155, &size);
		length1 = strnlen(filename, size);
		length2 = strnlen(header.name, 100);
		file->pathname = malloc(length1 + length2 + 2);
		if(file->pathname == NULL)
			MEM_ERROR();

		memcpy(file->pathname, filename, length1);
		file->pathname[length1] = '/';
		memcpy(file->pathname + length1 + 1, header.name, length2);
		file->pathname[length1 + length2 + 1] = '\0';
	} else if (file->pathname == NULL) {
		filename = skip_components(header.name, 100, &size);
		file->pathname = strndup(filename, size);
	}

	/* Ignore empty filenames */
	if(strlen(file->pathname) == 0) {
		ERROR("Empty tar filename after skipping leading /, ./, or ../, ignoring\n");
		goto ignored;
	}

	/* Read mtime */
	if(file->have_mtime == FALSE) {
		res = read_number(header.mtime, 12);
		if(res == -1) {
			ERROR("Failed to read file mtime from tar header\n");
			goto failed;
		}
		file->buf.st_mtime = res;
	}

	/* Read mode and file type */
	res = read_number(header.mode, 8);
	if(res == -1) {
		ERROR("Failed to read file mode from tar header\n");
		goto failed;
	}
	file->buf.st_mode = res;

	/* V7 and others used to append a trailing '/' to indicate a
	 * directory */
	if(file->pathname[strlen(file->pathname) - 1] == '/') {
		file->pathname[strlen(file->pathname) - 1] = '\0';
		type = S_IFDIR;
	}
	
	file->buf.st_mode |= type;

	/* Get user information - if file->uname non NULL (from PAX header),
	 * use that if recognised by the system, otherwise if header.user
	 * filled, and it is recognised by the system use that, otherwise
	 * fallback to using uid, either from PAX header (if have_uid TRUE),
	 * or header.uid */
	res = -1;
	if(file->uname)
		user = file->uname;
	else
		user = strndup(header.user, 32);

	if(strlen(user)) {
		struct passwd *pwuid = getpwnam(user);
		if(pwuid)
			res = pwuid->pw_uid;
	}
		
	if(res == -1) {
		if(file->have_uid == FALSE) {
			res = read_number(header.uid, 8);
			if(res == -1) {
				ERROR("Failed to read file uid from tar header\n");
				goto failed;
			}
			file->buf.st_uid = res;
		}
	} else
		file->buf.st_uid = res;

	free(user);

	/* Get group information - if file->gname non NULL (from PAX header),
	 * use that if recognised by the system, otherwise if header.group
	 * filled, and it is recognised by the system use that, otherwise
	 * fallback to using gid, either from PAX header (if have_gid TRUE),
	 * or header.gid */
	res = -1;
	if(file->gname)
		group = file->gname;
	else
		group = strndup(header.group, 32);

	if(strlen(group)) {
		struct group *grgid = getgrnam(group);
		if(grgid)
			res = grgid->gr_gid;
	}
		
	if(res == -1) {
		if(file->have_gid == FALSE) {
			res = read_number(header.gid, 8);
			if(res == -1) {
				ERROR("Failed to read file gid from tar header\n");
				goto failed;
			}
			file->buf.st_gid = res;
		}
	} else
		file->buf.st_gid = res;

	free(group);

	/* Read major and minor for device files */
	if(type == S_IFCHR || type == S_IFBLK) {
		int major, minor;

		major = read_number(header.major, 8);
		if(major == -1) {
			ERROR("Failed to read device major tar header\n");
			goto failed;
		}

		minor = read_number(header.minor, 8);
		if(minor == -1) {
			ERROR("Failed to read device minor from tar header\n");
			goto failed;
		}
		file->buf.st_rdev = (major << 8) | (minor & 0xff) | ((minor & ~0xff) << 12);
	}

	/* Handle symbolic links */
	if(type == S_IFLNK) {
		/* Permissions on symbolic links are always rwxrwxrwx */
		file->buf.st_mode = 0777 | S_IFLNK;

		if(file->link == FALSE)
			file->link = strndup(header.link, 100);
	}

	/* Handle hard links */
	if(type == S_IFHRD) {
		if(file->link) {
			char *link = skip_components(file->link, strlen(file->link), NULL);

			if(link != file->link) {
				char *old = file->link;

				file->link = strdup(link);
				free(old);
			}
		} else {
			filename = skip_components(header.link, 100, &size);
			file->link = strndup(filename, size);
		}
	}

	*status = TAR_OK;
	return file;

failed:
	free_tar_xattrs(file);
	free(file->pathname);
	free(file->link);
	free(file);
	*status = TAR_ERROR;
	return NULL;

ignored:
	if(file->buf.st_size) {
		/* Skip any data blocks */
		long long size = file->buf.st_size;

		while(size > 0) {
			res = read_bytes(STDIN_FILENO, &header, 512);
			if(res < 512) {
				if(res != -1)
					ERROR("Unexpected EOF (end of file), the tarfile appears to be truncated or corrupted\n");
				goto failed;
			}
			size -= 512;
		}
	}

	free(file->pathname);
	free(file->link);
	free(file);
	*status = TAR_IGNORED;
	return NULL;

eof:
	*status = TAR_EOF;
	free(file);
	return NULL;
}


void read_tar_file()
{
	struct tar_file *tar_file;
	int status, res;
       
	while(1) {
		struct file_buffer *file_buffer;

		file_buffer = malloc(sizeof(struct file_buffer));
		if(file_buffer == NULL)
			MEM_ERROR();

		while(1) {
			tar_file = read_tar_header(&status);
			if(status != TAR_IGNORED)
				break;
		}

		if(status == TAR_ERROR)
			BAD_ERROR("Error occurred reading tar file.  Aborting\n");

		/* If Pax 1.0 sparse file, read the map data now */
		if(tar_file && tar_file->sparse_pax == 2) {
			tar_file->map = read_sparse_map(tar_file, &tar_file->map_entries);
			if(tar_file->map == NULL)
				BAD_ERROR("Error occurred reading tar file.  Aborting\n");
		}

		/* Check Pax sparse map for consistency */
		if(tar_file && tar_file->sparse_pax) {
			res = check_sparse_map(tar_file->map, tar_file->map_entries, tar_file->buf.st_size, tar_file->realsize);
			if(res == FALSE)
				BAD_ERROR("Sparse file map inconsistent.  Aborting\n");
			tar_file->buf.st_size = tar_file->realsize;
		}

		if(tar_file && (tar_file->buf.st_mode & S_IFMT) == S_IFREG)
			progress_bar_size((tar_file->buf.st_size + block_size - 1)
								 >> block_log);

		file_buffer->cache = NULL;
		file_buffer->fragment = FALSE;
		file_buffer->tar_file = tar_file;
		file_buffer->sequence = sequence_count ++;
		seq_queue_put(to_main, file_buffer);

		if(status == TAR_EOF)
			break;

		if(S_ISREG(tar_file->buf.st_mode))
			read_tar_data(tar_file);
	}
}


squashfs_inode process_tar_file(int progress)
{
	struct stat buf;
	struct dir_info *new;
	struct dir_ent *dir_ent;
	struct tar_file *tar_file;
	struct file_buffer *file_buffer;

	queue_put(to_reader, NULL);
	set_progressbar_state(progress);

	while(1) {
		struct inode_info *link = NULL;

		file_buffer = seq_queue_get(to_main);
		if(file_buffer->tar_file == NULL)
			break;

		tar_file = file_buffer->tar_file;

		if(S_ISHRD(tar_file->buf.st_mode)) {
			/* Hard link, need to resolve where it points to, and
			 * replace with a reference to that inode */
			struct dir_ent *entry = lookup_pathname(root_dir, tar_file->link);
			if(entry== NULL) {
				ERROR("Could not resolve hardlink %s, file %s doesn't exist\n", tar_file->pathname, tar_file->link);
				free(file_buffer);
				free(tar_file->pathname);
				free(tar_file->link);
				free(tar_file);
				continue;
			}

			if(entry->inode == NULL || S_ISDIR(entry->inode->buf.st_mode)) {
				ERROR("Could not resolve hardlink %s, because %s is a directory\n", tar_file->pathname, tar_file->link);
				free(file_buffer);
				free(tar_file->pathname);
				free(tar_file->link);
				free(tar_file);
				continue;
			}

			link = entry->inode;
			free(tar_file->link);
			tar_file->link = NULL;
		}

		new = add_tarfile(root_dir, tar_file->pathname, "",
			tar_file, paths, 1, &dir_ent, link);

		if(new) {
			int duplicate_file;
			root_dir = new;

			if(S_ISREG(tar_file->buf.st_mode) && dir_ent->inode->read == FALSE) {
				update_info(dir_ent);
				tar_file->file = write_file(dir_ent, &duplicate_file);
				dir_ent->inode->read = TRUE;
				INFO("file %s, uncompressed size %lld bytes %s\n", tar_file->pathname,
					(long long) tar_file->buf.st_size, duplicate_file ?  "DUPLICATE" : "");
			}

			if(link) {
				if(no_hardlinks)
					INFO("file %s, uncompressed size %lld bytes DUPLICATE\n", tar_file->pathname,
						(long long) link->buf.st_size);
				else
					link->nlink ++;
				free(tar_file->pathname);
				free(tar_file);
			}
		} else if(S_ISREG(tar_file->buf.st_mode))
			skip_file(file_buffer->tar_file);

		free(file_buffer);
	}

	free(file_buffer);

	if(root_dir)
		fixup_tree(root_dir);
	else
		root_dir = scan1_opendir("", "", 0);

	/* Create root directory dir_ent and associated inode, and connect
	 * it to the root directory dir_info structure */
	dir_ent = create_dir_entry("", NULL, "", scan1_opendir("", "", 0));

	memset(&buf, 0, sizeof(buf));
	if(root_mode_opt)
		buf.st_mode = root_mode | S_IFDIR;
	else
		buf.st_mode = S_IRWXU | S_IRWXG | S_IRWXO | S_IFDIR;
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
