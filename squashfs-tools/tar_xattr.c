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
 * tar_xattr.c
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
#include "mksquashfs_error.h"
#include "tar.h"
#include "xattr.h"

#define TRUE 1
#define FALSE 0


static char *base64_decode(char *source, int size, int *bytes)
{
	char *dest;
	unsigned char *dest_ptr, *source_ptr = (unsigned char *) source;
	int bit_pos = 0;
	int output = 0;
	int count;

	/* Calculate number of bytes the base64 encoding represents */
	count = size * 3 / 4;

	dest = malloc(count);

	for(dest_ptr = (unsigned char *) dest; size; size --, source_ptr ++) {
		int value = *source_ptr;

		if(value >= 'A' && value <= 'Z')
			value -= 'A';
		else if(value >= 'a' && value <= 'z')
			value -= 'a' - 26;
		else if(value >= '0' && value <= '9')
			value -= '0' - 52;
		else if(value == '+')
			value = 62;
		else if(value == '/')
			value = 63;
		else {
			ERROR("Invalid character in LIBARCHIVE xattr base64 value, ignoring\n");
			free(dest);
			return NULL;
		}

		if(bit_pos == 24) {
			dest_ptr[0] = output >> 16;
			dest_ptr[1] = (output >> 8) & 0xff;
			dest_ptr[2] = output & 0xff;
			bit_pos = 0;
			output = 0;
			dest_ptr += 3;
		}

		output = (output << 6) | value;
		bit_pos += 6;
	}

	output = output << (24 - bit_pos);

	if(bit_pos == 6) {
		ERROR("Invalid length in LIBARCHIVE xattr base64 value, ignoring\n");
		free(dest);
		return NULL;
	}

	if(bit_pos >= 12)
		dest_ptr[0] = output >> 16;

	if(bit_pos >= 18)
		dest_ptr[1] = (output >> 8) & 0xff;

	if(bit_pos == 24)
		dest_ptr[2] = output & 0xff;

	*bytes = (dest_ptr - (unsigned char *) dest) + (bit_pos / 8);
	return dest;
}


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

	if(encoding == ENCODING_BASE64) {
		data = base64_decode(value, size, &size);
		if(data == NULL)
			return;
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
		free(xattr->full_name);
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
