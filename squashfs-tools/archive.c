/*
 * Squashfs
 *
 * Copyright (c) 2026
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
 * archive.c
 */

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "tar.h"
#include "symbolic_mode.h"
#include "caches-queues-lists.h"
#include "alloc.h"

char *get_component(char *target, char **targname)
{
	char *start;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = STRNDUP(start, target - start);

	while(*target == '/')
		target ++;

	return target;
}


struct inode_info *new_inode(struct tar_file *tar_file)
{
	static int warned = FALSE;
	struct inode_info *inode;
	int bytes = tar_file->link ? strlen(tar_file->link) + 1 : 0;

	inode = MALLOC(sizeof(struct inode_info));

	if(bytes) {
		inode->symlink = MALLOC(bytes);
		memcpy(inode->symlink, tar_file->link, bytes);
	} else
		inode->symlink = NULL;

	if(tar_file->buf.st_mtime < 0) {
		/* Squashfs cannot store timestamps before the epoch
		 * (1970-01-01), and so round up to zero.  But warn
		 * the first time this happens
		 */
		if(!warned) {
			ERROR("\nWARNING: File has timestamp before the epoch of "
				"1970-01-01, this cannot be\nstored in "
				"Squashfs.  Rounding to 1970-01-01.\nFurther "
				"messages are supressed.\n\n");
			warned = TRUE;
		}

		tar_file->buf.st_mtime = 0;
	}

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


void fixup_tree(struct dir_info *dir)
{
	struct dir_ent *entry;

	for(entry = dir->list; entry; entry = entry->next) {
		if(entry->dir && entry->inode == NULL) {
			/* Tar file didn't create this directory, and so it lacks
			 * an inode with metadata.  Create a default definition ... */
			struct stat buf;

			memset(&buf, 0, sizeof(buf));
			buf.st_mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH | S_IFDIR;
			if(default_mode_opt)
				buf.st_mode = mode_execute(default_mode, buf.st_mode);
			if(default_uid_opt)
				buf.st_uid = default_uid;
			else
				buf.st_uid = getuid();
			if(default_gid_opt)
				buf.st_gid = default_gid;
			else
				buf.st_gid = getgid();
			buf.st_dev = 0;
			buf.st_ino = 0;
			entry->inode = lookup_inode_flag(&buf, FALSE);
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


static struct inode_info *copy_inode(struct inode_info *source)
{
	struct inode_info *inode;
	int bytes = S_ISLNK(source->buf.st_mode) ? strlen(source->symlink) + 1 : 0;

	inode = MALLOC(sizeof(struct inode_info) + bytes);
	memcpy(inode, source, sizeof(struct inode_info) + bytes);

	return inode;
}


struct dir_info *add_tarfile(struct dir_info *sdir, char *source,
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


int is_fragment(long long file_size)
{
	return !no_fragments && file_size && (file_size < block_size ||
		(always_use_fragments && file_size & (block_size - 1)));
}


void put_file_buffer(struct file_buffer *file_buffer)
{
	/*
	 * Decide where to send the file buffer:
	 * - compressible non-fragment blocks go to the deflate threads,
	 * - fragments go to the process fragment threads,
	 */
	if(file_buffer->fragment)
		read_queue_put(to_process_frag, 0, file_buffer);
	else
		queue_cache_put(to_deflate, 0, file_buffer);
}
