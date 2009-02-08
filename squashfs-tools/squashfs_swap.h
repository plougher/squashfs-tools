#ifndef SQUASHFS_SWAP_H
#define SQUASHFS_SWAP_H
/*
 * Squashfs
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
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
 * squashfs_swap.h
 */

/*
 * macros to convert each stucture from big endian to little endian
 */

extern void swap_le16(unsigned short *, unsigned short *);
extern void swap_le32(unsigned int *, unsigned int *);
extern void swap_le64(long long *, long long *);
extern void swap_le16_num(unsigned short *, unsigned short *, int);
extern void swap_le32_num(unsigned int *, unsigned int *, int);
extern void swap_le64_num(long long *, long long *, int);

#define SQUASHFS_SWAP_SUPER_BLOCK(s, d) {\
	SWAP_LE32(s, d, s_magic);\
	SWAP_LE32(s, d, inodes);\
	SWAP_LE32(s, d, mkfs_time);\
	SWAP_LE32(s, d, block_size);\
	SWAP_LE32(s, d, fragments);\
	SWAP_LE16(s, d, compression);\
	SWAP_LE16(s, d, block_log);\
	SWAP_LE16(s, d, flags);\
	SWAP_LE16(s, d, no_ids);\
	SWAP_LE16(s, d, s_major);\
	SWAP_LE16(s, d, s_minor);\
	SWAP_LE64(s, d, root_inode);\
	SWAP_LE64(s, d, bytes_used);\
	SWAP_LE64(s, d, id_table_start);\
	SWAP_LE64(s, d, xattr_table_start);\
	SWAP_LE64(s, d, inode_table_start);\
	SWAP_LE64(s, d, directory_table_start);\
	SWAP_LE64(s, d, fragment_table_start);\
	SWAP_LE64(s, d, lookup_table_start);\
}

#define SQUASHFS_SWAP_DIR_INDEX(s, d) {\
	SWAP_LE32(s, d, index);\
	SWAP_LE32(s, d, start_block);\
	SWAP_LE32(s, d, size);\
}

#define SQUASHFS_SWAP_BASE_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
}

#define SQUASHFS_SWAP_IPC_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, nlink);\
}

#define SQUASHFS_SWAP_DEV_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, nlink);\
	SWAP_LE32(s, d, rdev);\
}

#define SQUASHFS_SWAP_SYMLINK_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, nlink);\
	SWAP_LE32(s, d, symlink_size);\
}

#define SQUASHFS_SWAP_REG_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, start_block);\
	SWAP_LE32(s, d, fragment);\
	SWAP_LE32(s, d, offset);\
	SWAP_LE32(s, d, file_size);\
}

#define SQUASHFS_SWAP_LREG_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE64(s, d, start_block);\
	SWAP_LE64(s, d, file_size);\
	SWAP_LE64(s, d, sparse);\
	SWAP_LE32(s, d, nlink);\
	SWAP_LE32(s, d, fragment);\
	SWAP_LE32(s, d, offset);\
	SWAP_LE32(s, d, xattr);\
}

#define SQUASHFS_SWAP_DIR_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, start_block);\
	SWAP_LE32(s, d, nlink);\
	SWAP_LE16(s, d, file_size);\
	SWAP_LE16(s, d, offset);\
	SWAP_LE32(s, d, parent_inode);\
}

#define SQUASHFS_SWAP_LDIR_INODE_HEADER(s, d) {\
	SWAP_LE16(s, d, inode_type);\
	SWAP_LE16(s, d, mode);\
	SWAP_LE16(s, d, uid);\
	SWAP_LE16(s, d, guid);\
	SWAP_LE32(s, d, mtime);\
	SWAP_LE32(s, d, inode_number);\
	SWAP_LE32(s, d, nlink);\
	SWAP_LE32(s, d, file_size);\
	SWAP_LE32(s, d, start_block);\
	SWAP_LE32(s, d, parent_inode);\
	SWAP_LE16(s, d, i_count);\
	SWAP_LE16(s, d, offset);\
	SWAP_LE32(s, d, xattr);\
}


#define SQUASHFS_SWAP_DIR_ENTRY(s, d) {\
	SWAP_LE16(s, d, offset);\
	SWAP_ULE16(s, d, inode_number);\
	SWAP_LE16(s, d, type);\
	SWAP_LE16(s, d, size);\
}

#define SQUASHFS_SWAP_DIR_HEADER(s, d) {\
	SWAP_LE32(s, d, count);\
	SWAP_LE32(s, d, start_block);\
	SWAP_LE32(s, d, inode_number);\
}

#define SQUASHFS_SWAP_FRAGMENT_ENTRY(s, d) {\
	SWAP_LE64(s, d, start_block);\
	SWAP_LE32(s, d, size);\
}

#define SQUASHFS_SWAP_INODE_T(s, d) SQUASHFS_SWAP_LONG_LONGS(s, d, 1)
#define SQUASHFS_SWAP_FRAGMENT_INDEXES(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)
#define SQUASHFS_SWAP_LOOKUP_BLOCKS(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)
#define SQUASHFS_SWAP_ID_BLOCKS(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)
#endif
