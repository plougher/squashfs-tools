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
extern char *get_component(char *target, char **targname);
extern struct inode_info *new_inode(struct tar_file *tar_file);
extern void fixup_tree(struct dir_info *dir);
extern struct dir_info *add_archive_file(struct dir_info *sdir, char *source,
		char *subpath, struct tar_file *tarfile, struct pathnames *paths,
		int depth, struct dir_ent **dir_ent, struct inode_info *link,
		char *type);
extern void put_file_buffer(struct file_buffer *file_buffer);

static inline int is_fragment(long long file_size)
{
	return !no_fragments && file_size && (file_size < block_size ||
		(always_use_fragments && file_size & (block_size - 1)));
}


