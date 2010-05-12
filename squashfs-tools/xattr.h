/*
 * Create a squashfs filesystem.  This is a highly compressed read only filesystem.
 *
 * Copyright (c) 2010
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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
 * xattr.h
 */

#define XATTR_VALUE_OOL		SQUASHFS_XATTR_VALUE_OOL
#define XATTR_PREFIX_MASK	SQUASHFS_XATTR_PREFIX_MASK

#define XATTR_VALUE_OOL_SIZE	sizeof(long long)
#define XATTR_NAME_OOL_SIZE 	0 /* XXX dummy value */

#define XATTR_INLINE_MAX 	128
#define XATTR_NAME_INLINE_MAX	65536

#define XATTR_TARGET_MAX	65536

#define IS_XATTR(a)		(a != SQUASHFS_INVALID_XATTR)

struct xattr_list {
	char			*name;
	char			*full_name;
	int			size;
	int			vsize;
	void			*value;
	int			type;
	long long		ool_value;
	unsigned short		vchecksum;
	struct xattr_list	*vnext;
};

struct dupl_id {
	struct xattr_list	*xattr_list;
	int			xattrs;
	int			xattr_id;
	struct dupl_id		*next;
};

struct prefix {
	char			*prefix;
	int			type;
};

extern int read_xattrs(struct dir_ent *);
