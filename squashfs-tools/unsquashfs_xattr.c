/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2010, 2012, 2019, 2021, 2022, 2023, 2025
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
 * unsquashfs_xattr.c
 */

#include "unsquashfs.h"
#include "xattr.h"
#include "alloc.h"

extern int strict_errors;
extern regex_t *xattr_exclude_preg;
extern regex_t *xattr_include_preg;

int has_xattrs(unsigned int xattr)
{
	if(xattr == SQUASHFS_INVALID_XATTR ||
			sBlk.s.xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return FALSE;
	else
		return TRUE;
}


static void print_xattr_name_value(struct xattr_list *xattr, int writer_fd)
{
	unsigned char *value = xattr->value;
	int i, count = 0, printable = TRUE, res;

	for(i = 0; i < xattr->vsize; i++) {
		if(value[i] < 32 || value[i] > 126) {
			printable = FALSE;
			count += 4;
		} else if(value[i] == '\\')
			count += 4;
		else
			count ++;
	}

	if(!printable) {
		unsigned char *new = MALLOC(count + 2), *dest;

		memcpy(new, "0t", 2);
		count += 2;

		for(dest = new + 2, i = 0; i < xattr->vsize; i++) {
			if(value[i] < 32 || value[i] > 126 || value[i] == '\\') {
				sprintf((char *) dest, "\\%03o", value[i]);
				dest += 4;
			} else
				*dest ++ = value[i];
		}

		value = new;
	} else
		count = xattr->vsize;
	
	res = dprintf(writer_fd, "%s=", xattr->full_name);
	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	res = write_bytes(writer_fd, (char *) value, count);
	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	res = dprintf(writer_fd, "\n");
	if(res == -1)
		EXIT_UNSQUASH("Failed to write to pseudo output file\n");

	if(!printable)
		free(value);
}


void print_xattr(char *pathname, unsigned int xattr, int writer_fd)
{
	unsigned int count;
	struct xattr_list *xattr_list;
	int i, failed, res;

	if(!has_xattrs(xattr))
		return;

	if(xattr >= sBlk.xattr_ids)
		EXIT_UNSQUASH("File system corrupted - xattr index in inode too large (xattr: %u)\n", xattr);

	xattr_list = get_xattr(xattr, &count, &failed);
	if(xattr_list == NULL && failed == FALSE)
		exit(1);

	if(failed)
		EXIT_UNSQUASH_STRICT("write_xattr: Failed to read one or more xattrs for %s\n", pathname);

	for(i = 0; i < count; i++) {
		if(xattr_exclude_preg) {
			int res = regexec(xattr_exclude_preg,
				xattr_list[i].full_name, (size_t) 0, NULL, 0);

			if(res == 0)
				continue;
		}

		if(xattr_include_preg) {
			int res = regexec(xattr_include_preg,
				xattr_list[i].full_name, (size_t) 0, NULL, 0);

			if(res)
				continue;
		}

		res = dprintf(writer_fd, "%s x ", pathname);
		if(res == -1)
			EXIT_UNSQUASH("Failed to write to pseudo output file\n");

		print_xattr_name_value(&xattr_list[i], writer_fd);
	}

	free_xattr(xattr_list, count);
}


regex_t *xattr_regex(char *pattern, char *option)
{
	int error;
	regex_t *preg = MALLOC(sizeof(regex_t));

	error = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);

	if(error) {
		char str[1024]; /* overflow safe */

		regerror(error, preg, str, 1024);
		BAD_ERROR("invalid regex %s in xattrs-%s option, because %s\n",
				pattern, option, str);
	}

	return preg;
}
