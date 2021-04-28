/*
 * Squashfs
 *
 * Copyright (c) 2021
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

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "caches-queues-lists.h"
#include "mksquashfs_error.h"
#include "tar.h"
#include "progressbar.h"

#define TRUE 1
#define FALSE 0

int read_octal(char *s, int size)
{
	int res = 0;

	for(; size-- && *s == ' '; s++);

	if(size == 0)
		return -1;

	for(; size-- && *s >= '0' && *s < '8'; s++)
		res = (res << 3) + *s - '0';

	if(size && (*s != ' ' && *s != '\0'))
		return -1;

	return res;
}


char *print_octal(int number)
{
	static char buff[128];

	sprintf(buff, "%s%o", number < 0 ? "-" : "", abs(number));

	return buff;
}


int checksum_matches(struct tar_header *header)
{
	int checksum = read_octal(header->checksum, 8);
	int computed = 0;
	int i;

	if(checksum == -1) {
		ERROR("Bad checksum in tar header\n");
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
	int bytes = tar_file->symlink ? strlen(tar_file->symlink) + 1 : 0;

	inode = malloc(sizeof(struct inode_info) + bytes);
	if(inode == NULL)
		MEM_ERROR();

	if(bytes)
		memcpy(&inode->symlink, tar_file->symlink, bytes);
	memcpy(&inode->buf, &tar_file->buf, sizeof(struct stat));
	inode->read = FALSE;
	inode->root_entry = FALSE;
	inode->tar_file = tar_file;
	inode->inode = SQUASHFS_INVALID_BLK;
	inode->nlink = 1;
	inode->inode_number = 0;
	inode->dummy_root_dir = FALSE;
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
			buf.st_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IFDIR;
			buf.st_uid = getuid();
			buf.st_gid = getgid();
			buf.st_mtime = time(NULL);
			buf.st_dev = 0;
			buf.st_ino = 0;
			entry->inode = lookup_inode(&buf);
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
		int depth, struct dir_ent **dir_ent)
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
					entry->dir = add_tarfile(NULL, source, subpath, tarfile, new, depth + 1, dir_ent);
					if(entry->dir == NULL)
						goto failed_early;
					entry->dir->dir_ent = entry;
				} else 
					BAD_ERROR("%s exists in the tar file as"
						" a non-directory, cannot add"
						" tar pathname %s!\n",
						subpath, tarfile->pathname);
			} else
					BAD_ERROR("%s exists in the tar file as"
						" two different files!\n",
						tarfile->pathname);
		} else {
			if(source[0] == '\0') {
				/* sub-directory exists, we must be adding a
				 * directory, and we must not already have a
				 * definition for this directory */
				if(S_ISDIR(tarfile->buf.st_mode)) {
					if(entry->inode == NULL)
						entry->inode = new_inode(tarfile);
					else
						BAD_ERROR("%s exists in the tar file as"
							" two different directories!\n",
							tarfile->pathname);
				} else
					BAD_ERROR("%s exists in the tar file as"
						" both a directory and"
						" non-directory!\n",
						tarfile->pathname);
			} else {
				/* recurse adding child components */
				subpath = subpathname(entry);
				sub = add_tarfile(entry->dir, source, subpath, tarfile, new, depth + 1, dir_ent);
				if(sub == NULL)
					goto failed_early;
			}
		}
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

#if 0
		if(exclude_actions()) {
			if(eval_exclude_actions(name, file, subpath, &buf,
							depth, entry)) {
				ERROR("Error: Source %s is excluded\n", file);
				goto failed_entry;
			}
		}
#endif

		if(source[0] == '\0') {
			add_dir_entry(entry, NULL, new_inode(tarfile));
			if(S_ISDIR(tarfile->buf.st_mode))
				dir->directory_count ++;
			else if(S_ISREG(tarfile->buf.st_mode))
				*dir_ent = entry;
		} else {
			subpath = subpathname(entry);
			sub = add_tarfile(NULL, source, subpath, tarfile, new, depth + 1, dir_ent);
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


static int seq = 0;
static void read_tar_data(struct tar_file *tar_file)
{
	struct stat *buf = &tar_file->buf;
	struct file_buffer *file_buffer;
	int blocks;
	long long bytes, read_size;

	bytes = 0;
	read_size = buf->st_size;
	blocks = (read_size + block_size - 1) >> block_log;

	do {
		file_buffer = cache_get_nohash(reader_buffer);
		file_buffer->file_size = read_size;
		file_buffer->tar_file = tar_file;
		file_buffer->sequence = seq ++;
		file_buffer->noD = noD;
		file_buffer->error = FALSE;

		if(blocks > 1) {
			/* non-tail block should be exactly block_size */
			file_buffer->size = read_bytes(STDIN_FILENO, file_buffer->data, block_size);
			if(file_buffer->size != block_size)
				BAD_ERROR("Failed to read tar file %s, the tarfile appears to be truncated or corrupted\n", tar_file->pathname);

			bytes += file_buffer->size;

			file_buffer->fragment = FALSE;
			put_file_buffer(file_buffer);
		} else {
			/* The remaining bytes will be rounded up to 512 bytes */
			int expected = (read_size + 511 - bytes) & ~511;
			int size = read_bytes(STDIN_FILENO, file_buffer->data, expected);

			if(size != expected)
				BAD_ERROR("Failed to read tar file %s, the tarfile appears to be truncated or corrupted\n", tar_file->pathname);

			file_buffer->size = read_size - bytes;
		}
	} while(-- blocks > 0);

	file_buffer->fragment = is_fragment(read_size);
	put_file_buffer(file_buffer);

	return;
}


static struct tar_file *read_tar_header() {
	struct tar_header header;
	struct tar_file *file;
	int res, size, type;
	char *filename, *user, *group;

	file = malloc(sizeof(struct tar_file));
	if(file == NULL)
		MEM_ERROR();

	res = read_bytes(STDIN_FILENO, &header, 512);

	if(res == FALSE)
		goto failed1;

	if(checksum_matches(&header) == FALSE) {
		ERROR("Tar header checksum does not match!\n");
		goto failed1;
	}

	memset(file, 0, sizeof(struct tar_file));

	/* Process filename - skip any leading slashes or ./ or ../ */
	if(header.prefix[0] != '\0') {
		int length1, length2;

		size = 155;
		filename = header.prefix;
		while(1) {
			if(size >= 3 && strncmp(filename, "../", 3) == 0) {
				filename += 3;
				size -= 3;
			} else if(size >= 2 && strncmp(filename, "./", 2) == 0) {
				filename += 2;
				size -= 2;
			} else if(size > 1 && *filename == '/') {
				filename++;
				size--;
			} else
				break;
		}

		length1 = strnlen(filename, size);
		length2 = strnlen(header.name, 100);
		file->pathname = malloc(length1 + length2 + 2);
		if(file->pathname == NULL)
			MEM_ERROR();

		memcpy(file->pathname, filename, length1);
		file->pathname[length1] = '/';
		memcpy(file->pathname + length1 + 1, header.name, length2);
		file->pathname[length1 + length2 + 1] = '\0';
	} else {
		size = 100;
		filename = header.name;
		while(1) {
			if(size >= 3 && strncmp(filename, "../", 3) == 0) {
				filename += 3;
				size -= 3;
			} else if(size >= 2 && strncmp(filename, "./", 2) == 0) {
				filename += 2;
				size -= 2;
			} else if(size > 1 && *filename == '/') {
				filename++;
				size--;
			} else
				break;
		}

		file->pathname = strndup(filename, size);
	}

	/* Reject empty filenames */
	if(strlen(file->pathname) == 0) {
		ERROR("Empty tar filename after skipping leading /, ./, or ../\n");
		goto failed2;
	}

	/* Read mtime */
	res = read_octal(header.mtime, 12);
	if(res == -1) {
		ERROR("Failed to read tar header\n");
		goto failed2;
	}
	file->buf.st_mtime = res;

	/* Read mode and file type */
	res = read_octal(header.mode, 8);
	if(res == -1) {
		ERROR("Failed to read tar header\n");
		goto failed2;
	}
	file->buf.st_mode = res;

	switch(header.type) {
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
		case TAR_CHAR:
			type = S_IFCHR;
			break;
		case TAR_BLOCK:
			type = S_IFBLK;
			break;
		case TAR_FIFO:
			type = S_IFIFO;
			break;
		default:
			ERROR("Unhandled tar type in header %d\n", header.type);
			goto failed2;
	}

	/* V7 and others used to append a trailing '/' to indicate a
	 * directory */
	if(file->pathname[strlen(file->pathname) - 1] == '/') {
		file->pathname[strlen(file->pathname) - 1] = '\0';
		type = S_IFDIR;
	}
	
	file->buf.st_mode |= type;

	/* Read filesize if regular file */
	if(type == S_IFREG) {
		res = read_octal(header.size, 12);
		if(res == -1) {
			ERROR("Failed to read tar header\n");
			goto failed2;
		}
		file->buf.st_size = res;
	}

	/* Get user information - if header.user filled, and it is
	 * recognised by the system use that, otherwise fallback to
	 * using header.uid */
	res = -1;
	user = strndup(header.user, 32);
	if(strlen(user)) {
		struct passwd *pwuid = getpwnam(user);
		if(pwuid)
			res = pwuid->pw_uid;
	}
		
	if(res == -1) {
		res = read_octal(header.uid, 8);
		if(res == -1) {
			ERROR("Failed to read tar header\n");
			goto failed2;
		}
	}
	file->buf.st_uid = res;
	free(user);

	/* Get group information - if header.group filled, and it is
	 * recognised by the system use that, otherwise fallback to
	 * using header.gid */
	res = -1;
	group = strndup(header.group, 32);
	if(strlen(group)) {
		struct group *grgid = getgrnam(group);
		if(grgid)
			res = grgid->gr_gid;
	}
		
	if(res == -1) {
		res = read_octal(header.gid, 8);
		if(res == -1) {
			ERROR("Failed to read tar header\n");
			goto failed2;
		}
	}
	file->buf.st_gid = res;
	free(group);

	/* Read major and minor for device files */
	if(type == S_IFCHR || type == S_IFBLK) {
		int major, minor;

		major = read_octal(header.major, 8);
		if(major == -1) {
			ERROR("Failed to read tar header\n");
			goto failed2;
		}

		minor = read_octal(header.minor, 8);
		if(minor == -1) {
			ERROR("Failed to read tar header\n");
			goto failed2;
		}
		file->buf.st_rdev = (major << 8) | (minor & 0xff) | ((minor & ~0xff) << 12);
	}

	/* Handle symbolic links */
	if(type == S_IFLNK) {
		/* Permissions on symbolic links are always rwxrwxrwx */
		file->buf.st_mode = 0777 | S_IFLNK;

		file->symlink = strndup(header.link, 100);
	}

	return file;

failed2:
	free(file->pathname);
failed1:
	free(file);
	return NULL;
}


void read_tar_file()
{
	struct tar_file *tar_file;
       
	while(1) {
		struct file_buffer *file_buffer;

		file_buffer = malloc(sizeof(struct file_buffer));
		if(file_buffer == NULL)
			MEM_ERROR();

		tar_file = read_tar_header();

		if(tar_file && (tar_file->buf.st_mode & S_IFMT) == S_IFREG)
			progress_bar_size((tar_file->buf.st_size + block_size - 1)
								 >> block_log);

		file_buffer->cache = NULL;
		file_buffer->tar_file = tar_file;
		file_buffer->sequence = seq ++;
		seq_queue_put(to_main, file_buffer);

		if(tar_file == NULL)
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

	queue_put(to_reader, NULL);
	set_progressbar_state(progress);

	while(1) {
		struct file_buffer *file_buffer = seq_queue_get(to_main);
		if(file_buffer->tar_file == NULL)
			break;

		tar_file = file_buffer->tar_file;

		new = add_tarfile(root_dir, tar_file->pathname, "",
			tar_file, paths, 1, &dir_ent);

		if(new) {
			root_dir = new;

			if(S_ISREG(tar_file->buf.st_mode) && dir_ent->inode->read == FALSE) {
				tar_file->file = write_file(dir_ent, &tar_file->duplicate);
				dir_ent->inode->read = TRUE;
			}
		}

		free(file_buffer);
	}

	fixup_tree(root_dir);

	/* Create root directory dir_ent and associated inode, and connect
	 * it to the root directory dir_info structure */
	dir_ent = create_dir_entry("", NULL, "", scan1_opendir("", "", 0));

	memset(&buf, 0, sizeof(buf));
	if(root_mode_opt)
		buf.st_mode = root_mode | S_IFDIR;
	else
		buf.st_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IFDIR;
	buf.st_uid = getuid();
	buf.st_gid = getgid();
	buf.st_mtime = time(NULL);
	buf.st_dev = 0;
	buf.st_ino = 0;
	dir_ent->inode = lookup_inode(&buf);
	dir_ent->inode->dummy_root_dir = TRUE;
	dir_ent->dir = root_dir;
	root_dir->dir_ent = dir_ent;

	return do_directory_scans(dir_ent, progress);
}
