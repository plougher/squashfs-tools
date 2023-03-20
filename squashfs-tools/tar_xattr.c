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
 * tar_xattr.c
 */

#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <regex.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "mksquashfs_error.h"
#include "tar.h"
#include "xattr.h"

#define TRUE 1
#define FALSE 0

extern regex_t *xattr_exclude_preg;
extern regex_t *xattr_include_preg;


void read_tar_xattr(char *name, char *value, int size, int encoding, struct tar_file *file)
{
	char *data;
	struct xattr_list *xattr;
	int i;

	/* Some tars output both LIBARCHIVE and SCHILY xattrs, which
	 * will lead to multiple definitions of the same xattr.
	 * So check that this xattr hasn't already been defined */
	for(i = 0; i < file->xattrs; i++)
		if(strcmp(name, file->xattr_list[i].full_name) == 0)
			return;

	if(xattr_exclude_preg) {
		int res = regexec(xattr_exclude_preg, name, (size_t) 0, NULL, 0);

		if(res == 0)
			return;
	}

	if(xattr_include_preg) {
		int res = regexec(xattr_include_preg, name, (size_t) 0, NULL, 0);

		if(res)
			return;
	}

	if(encoding == ENCODING_BASE64) {
		data = base64_decode(value, size, &size);
		if(data == NULL) {
			ERROR("Invalid LIBARCHIVE xattr base64 value, ignoring\n");
			return;
		}
	} else {
		data = malloc(size);
		if(data == NULL)
			MEM_ERROR();
		memcpy(data, value, size);
	}

	file->xattr_list = realloc(file->xattr_list, (file->xattrs + 1) *
						sizeof(struct xattr_list));
	if(file->xattr_list == NULL)
		MEM_ERROR();

	xattr = &file->xattr_list[file->xattrs];

	xattr->type = xattr_get_prefix(xattr, name);
	if(xattr->type == -1) {
		ERROR("Unrecognised tar xattr prefix %s, ignoring\n", name);
		free(data);
		return;
	}

	xattr->value = data;
	xattr->vsize = size;
	file->xattrs ++;
}


int read_xattrs_from_tarfile(struct inode_info *inode, struct xattr_list **xattr_list)
{
	if(inode->tar_file) {
		*xattr_list = inode->tar_file->xattr_list;
		return inode->tar_file->xattrs;
	} else
		return 0;
}


void free_tar_xattrs(struct tar_file *file)
{
	int i;

	for(i = 0; i < file->xattrs; i++)
		free(file->xattr_list[i].full_name);

	free(file->xattr_list);
}
