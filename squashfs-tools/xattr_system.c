/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (C) 2023, 2024, 2025
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
 * xattr_system.c
 */

#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/xattr.h>
#include <regex.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "xattr.h"
#include "mksquashfs_error.h"
#include "progressbar.h"
#include "pseudo.h"
#include "tar.h"
#include "action.h"
#include "xattr_compat.h"
#include "alloc.h"

extern regex_t *xattr_exclude_preg;
extern regex_t *xattr_include_preg;

int read_xattrs_from_system(struct dir_ent *dir_ent, char *filename,
						struct xattr_list **xattrs)
{
	ssize_t size, vsize;
	char *xattr_names, *p;
	int i = 0;
	struct xattr_list *xattr_list = NULL;
	struct xattr_data *xattr_exc_list;
	struct xattr_data *xattr_inc_list;

	while(1) {
		size = llistxattr(filename, NULL, 0);
		if(size <= 0) {
			if(size < 0 && errno != ENOTSUP) {
				ERROR_START("llistxattr for %s failed in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
			}
			return 0;
		}

		xattr_names = MALLOC(size);
		size = llistxattr(filename, xattr_names, size);
		if(size < 0) {
			free(xattr_names);
			if(errno == ERANGE)
				/* xattr list grew?  Try again */
				continue;
			else {
				ERROR_START("llistxattr for %s failed in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
				return 0;
			}
		}

		break;
	}

	xattr_exc_list = eval_xattr_exc_actions(root_dir, dir_ent);
	xattr_inc_list = eval_xattr_inc_actions(root_dir, dir_ent);

	for(p = xattr_names; p < xattr_names + size;) {
		int res;

		res = match_xattr_exc_actions(xattr_exc_list, p);
		if(res) {
			p += strlen(p) + 1;
			continue;
		}

		if(xattr_exclude_preg) {
			res = regexec(xattr_exclude_preg, p, (size_t) 0, NULL, 0);
			if(res == 0) {
				p += strlen(p) + 1;
				continue;
			}
		}

		res = match_xattr_inc_actions(xattr_inc_list, p);
		if(res) {
			p += strlen(p) + 1;
			continue;
		}

		if(xattr_include_preg) {
			res = regexec(xattr_include_preg, p, (size_t) 0, NULL, 0);
			if(res) {
				p += strlen(p) + 1;
				continue;
			}
		}

		xattr_list = REALLOC(xattr_list, (i + 1) * sizeof(struct xattr_list));
		xattr_list[i].type = xattr_get_prefix(&xattr_list[i], p);

		if(xattr_list[i].type == -1) {
			ERROR("Unrecognised xattr prefix %s\n", p);
			p += strlen(p) + 1;
			continue;
		}

		p += strlen(p) + 1;

		while(1) {
			vsize = lgetxattr(filename, xattr_list[i].full_name,
								NULL, 0);
			if(vsize < 0) {
				ERROR_START("lgetxattr failed for %s in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
				free(xattr_list[i].full_name);
				goto failed;
			}

			xattr_list[i].value = MALLOC(vsize);
			vsize = lgetxattr(filename, xattr_list[i].full_name,
						xattr_list[i].value, vsize);
			if(vsize < 0) {
				free(xattr_list[i].value);
				if(errno == ERANGE)
					/* xattr grew?  Try again */
					continue;
				else {
					ERROR_START("lgetxattr failed for %s "
						"in read_attrs, because %s",
						filename, strerror(errno));
					ERROR_EXIT(".  Ignoring\n");
					free(xattr_list[i].full_name);
					goto failed;
				}
			}

			break;
		}

		xattr_list[i].vsize = vsize;

		TRACE("read_xattrs_from_system: filename %s, xattr name %s,"
			" vsize %d\n", filename, xattr_list[i].full_name,
			xattr_list[i].vsize);
		i++;
	}

	free(xattr_names);

	if(i > 0)
		*xattrs = xattr_list;
	else
		free(xattr_list);
	return i;

failed:
	while(--i >= 0) {
		free(xattr_list[i].full_name);
		free(xattr_list[i].value);
	}
	free(xattr_list);
	free(xattr_names);
	return 0;
}
