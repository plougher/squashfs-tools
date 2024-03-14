#ifndef XATTR_COMPAT_H
#define XATTR_COMPAT_H
/*
 * Squashfs
 *
 * Copyright (c) 2024
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
 * xattr_compat.h
 */

#ifdef XATTR_NOFOLLOW /* Apple's xattrs */
#define lsetxattr(path_, name_, val_, sz_, flags_) \
	setxattr(path_, name_, val_, sz_, 0, flags_ | XATTR_NOFOLLOW)

#define llistxattr(path_, buf_, sz_) \
	listxattr(path_, buf_, sz_, XATTR_NOFOLLOW)

#define lgetxattr(path_, name_, val_, sz_) \
	getxattr(path_, name_, val_, sz_, 0, XATTR_NOFOLLOW)
#endif
#endif
