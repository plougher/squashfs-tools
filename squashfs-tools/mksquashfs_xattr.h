#ifndef MKSQUASHFS_XATTR_H
#define MKSQUASHFS_XATTR_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2023
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
 * unsquashfs_xattr.h
 */

#ifdef XATTR_SUPPORT
#ifdef XATTR_OS_SUPPORT
extern int read_xattrs_from_system(struct dir_ent *dir_ent, char *filename,
						struct xattr_list **xattrs);
#else
static inline int read_xattrs_from_system(struct dir_ent *dir_ent, char *filename,
						struct xattr_list **xattrs)
{
	return 0;
}
#endif
#endif
#endif
