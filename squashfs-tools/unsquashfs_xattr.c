/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2010, 2012, 2019, 2021, 2022
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

#include <sys/xattr.h>

#ifdef XATTR_NOFOLLOW /* Apple's xattrs */
	#define lsetxattr(path_, name_, val_, sz_, flags_) \
		setxattr(path_, name_, val_, sz_, 0, flags_ | XATTR_NOFOLLOW)
#endif

#define NOSPACE_MAX 10

extern int root_process;
extern int ignore_errors;
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
		unsigned char *new = malloc(count + 2), *dest;
		if(new == NULL)
			MEM_ERROR();

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


int write_xattr(char *pathname, unsigned int xattr)
{
	unsigned int count;
	struct xattr_list *xattr_list;
	int i;
	static int nonsuper_error = FALSE;
	static int ignore_xattrs = FALSE;
	static int nospace_error = 0;
	int failed;

	if(ignore_xattrs || !has_xattrs(xattr))
		return TRUE;

	if(xattr >= sBlk.xattr_ids)
		EXIT_UNSQUASH("File system corrupted - xattr index in inode too large (xattr: %u)\n", xattr);

	xattr_list = get_xattr(xattr, &count, &failed);
	if(xattr_list == NULL && failed == FALSE)
		exit(1);

	if(failed)
		EXIT_UNSQUASH_STRICT("write_xattr: Failed to read one or more xattrs for %s\n", pathname);

	for(i = 0; i < count; i++) {
		int prefix = xattr_list[i].type & SQUASHFS_XATTR_PREFIX_MASK;

		if(ignore_xattrs)
			continue;

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

		if(root_process || prefix == SQUASHFS_XATTR_USER) {
			int res = lsetxattr(pathname, xattr_list[i].full_name,
				xattr_list[i].value, xattr_list[i].vsize, 0);

			if(res == -1) {
				if(errno == ENOTSUP) {
					/*
					 * If the destination filesystem cannot
					 * suppport xattrs, print error, and
					 * disable xattr output as this error is
					 * unlikely to go away, and printing
					 * screenfulls of the same error message
					 * is rather annoying
					 */
					ERROR("write_xattr: failed to write "
						"xattr %s for file %s because " 
						"extended attributes are not "
						"supported by the destination "
						"filesystem\n",
						xattr_list[i].full_name,
						pathname);
					ERROR("Ignoring xattrs in "
								"filesystem\n");
					EXIT_UNSQUASH_STRICT("To avoid this error message, "
						"specify -no-xattrs\n");
					ignore_xattrs = TRUE;
				} else if((errno == ENOSPC || errno == EDQUOT)
						&& nospace_error < NOSPACE_MAX) {
					/*
					 * Many filesystems like ext2/3/4 have
					 * limits on the amount of xattr
					 * data that can be stored per file
					 * (typically one block or 4K), so
					 * we shouldn't disable xattr ouput,
					 * as the error may be restriced to one
					 * file only.  If we get a lot of these
					 * then suppress the error messsage
					 */
					EXIT_UNSQUASH_IGNORE("write_xattr: failed to write "
						"xattr %s for file %s because " 
						"no extended attribute space "
						"remaining (per file or "
						"filesystem limit)\n",
						xattr_list[i].full_name,
						pathname);
					if(++ nospace_error == NOSPACE_MAX)
						ERROR("%d of these errors "
							"printed, further error "
							"messages of this type "
							"are suppressed!\n",
							NOSPACE_MAX);
				} else
					EXIT_UNSQUASH_IGNORE("write_xattr: failed to write "
						"xattr %s for file %s because "
						"%s\n", xattr_list[i].full_name,
						pathname, strerror(errno));
				failed = TRUE;
			}
		} else if(nonsuper_error == FALSE) {
			/*
			 * if extract user xattrs only then
			 * error message is suppressed, if not
			 * print error, and then suppress further error
			 * messages to avoid possible screenfulls of the
			 * same error message!
			 */
			ERROR("write_xattr: could not write xattr %s "
					"for file %s because you're not "
					"superuser!\n",
					xattr_list[i].full_name, pathname);
			EXIT_UNSQUASH_STRICT("write_xattr: to avoid this error message, either"
				" specify -xattrs-include '^user.', -no-xattrs, or run as "
				"superuser!\n");
			ERROR("Further error messages of this type are "
				"suppressed!\n");
			nonsuper_error = TRUE;
			failed = TRUE;
		}
	}

	free_xattr(xattr_list, count);

	return !failed;
}


regex_t *xattr_regex(char *pattern, char *option)
{
	int error;
	regex_t *preg = malloc(sizeof(regex_t));

	if(preg == NULL)
		MEM_ERROR();

	error = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);

	if(error) {
		char str[1024]; /* overflow safe */

		regerror(error, preg, str, 1024);
		BAD_ERROR("invalid regex %s in xattrs-%s option, because %s\n",
				pattern, option, str);
	}

	return preg;
}
