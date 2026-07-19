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
 * archive.h
 */

#define TARFILE	1
#define ZIPFILE 2

static inline int tar_archive(int type)
{
	return type == TARFILE;
}


static inline int zip_archive(int type)
{
	return type == ZIPFILE;
}

static inline char *archive(int type)
{
	return tar_archive(type) ? "tarfile" : "zipfile";
}

extern char *get_component(char *target, char **targname);
extern struct inode_info *new_inode(struct tar_file *tar_file, int type);
extern struct dir_info *add_archive_file(struct dir_info *sdir, char *source,
		char *subpath, struct tar_file *tarfile, struct pathnames *paths,
		int depth, struct dir_ent **dir_ent, struct inode_info *link,
		int type);
extern void put_file_buff(struct file_buffer *file_buffer, int id);
extern squashfs_inode create_root_scan(int progress, int type);

static inline int is_frag(long long file_size)
{
	return !no_fragments && file_size && (file_size < block_size ||
		(always_use_fragments && file_size & (block_size - 1)));
}


