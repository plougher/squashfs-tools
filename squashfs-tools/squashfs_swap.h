#ifndef SQUASHFS_SWAP_H
#define SQUASHFS_SWAP_H
/*
 * Squashfs
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
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
 * macros to convert each packed bitfield structure from little endian to big
 * endian and vice versa.  These are needed when creating or using a filesystem
 * on a machine with different byte ordering to the target architecture.
 *
 */

#define SQUASHFS_SWAP_START \
	int bits;\
	int b_pos;\
	unsigned long long val;\
	unsigned char *s;\
	unsigned char *d;

#define SQUASHFS_SWAP_SUPER_BLOCK(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, sizeof(struct squashfs_super_block));\
	SQUASHFS_SWAP((s)->s_magic, d, 0, 32);\
	SQUASHFS_SWAP((s)->inodes, d, 32, 32);\
	SQUASHFS_SWAP((s)->bytes_used_2, d, 64, 32);\
	SQUASHFS_SWAP((s)->uid_start_2, d, 96, 32);\
	SQUASHFS_SWAP((s)->guid_start_2, d, 128, 32);\
	SQUASHFS_SWAP((s)->inode_table_start_2, d, 160, 32);\
	SQUASHFS_SWAP((s)->directory_table_start_2, d, 192, 32);\
	SQUASHFS_SWAP((s)->s_major, d, 224, 16);\
	SQUASHFS_SWAP((s)->s_minor, d, 240, 16);\
	SQUASHFS_SWAP((s)->block_size_1, d, 256, 16);\
	SQUASHFS_SWAP((s)->block_log, d, 272, 16);\
	SQUASHFS_SWAP((s)->flags, d, 288, 8);\
	SQUASHFS_SWAP((s)->no_uids, d, 296, 8);\
	SQUASHFS_SWAP((s)->no_guids, d, 304, 8);\
	SQUASHFS_SWAP((s)->mkfs_time, d, 312, 32);\
	SQUASHFS_SWAP((s)->root_inode, d, 344, 64);\
	SQUASHFS_SWAP((s)->block_size, d, 408, 32);\
	SQUASHFS_SWAP((s)->fragments, d, 440, 32);\
	SQUASHFS_SWAP((s)->fragment_table_start_2, d, 472, 32);\
	SQUASHFS_SWAP((s)->bytes_used, d, 504, 64);\
	SQUASHFS_SWAP((s)->uid_start, d, 568, 64);\
	SQUASHFS_SWAP((s)->guid_start, d, 632, 64);\
	SQUASHFS_SWAP((s)->inode_table_start, d, 696, 64);\
	SQUASHFS_SWAP((s)->directory_table_start, d, 760, 64);\
	SQUASHFS_SWAP((s)->fragment_table_start, d, 824, 64);\
	SQUASHFS_SWAP((s)->lookup_table_start, d, 888, 64);\
}

#define SQUASHFS_SWAP_BASE_INODE_CORE(s, d, n)\
	SQUASHFS_MEMSET(s, d, n);\
	SQUASHFS_SWAP((s)->inode_type, d, 0, 4);\
	SQUASHFS_SWAP((s)->mode, d, 4, 12);\
	SQUASHFS_SWAP((s)->uid, d, 16, 8);\
	SQUASHFS_SWAP((s)->guid, d, 24, 8);\
	SQUASHFS_SWAP((s)->mtime, d, 32, 32);\
	SQUASHFS_SWAP((s)->inode_number, d, 64, 32);

#define SQUASHFS_SWAP_BASE_INODE_HEADER(s, d, n) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, n)\
}

#define SQUASHFS_SWAP_IPC_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_ipc_inode_header))\
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
}

#define SQUASHFS_SWAP_DEV_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_dev_inode_header)); \
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
	SQUASHFS_SWAP((s)->rdev, d, 128, 16);\
}

#define SQUASHFS_SWAP_SYMLINK_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_symlink_inode_header));\
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
	SQUASHFS_SWAP((s)->symlink_size, d, 128, 16);\
}

#define SQUASHFS_SWAP_REG_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_reg_inode_header));\
	SQUASHFS_SWAP((s)->start_block, d, 96, 64);\
	SQUASHFS_SWAP((s)->fragment, d, 160, 32);\
	SQUASHFS_SWAP((s)->offset, d, 192, 32);\
	SQUASHFS_SWAP((s)->file_size, d, 224, 32);\
}

#define SQUASHFS_SWAP_LREG_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_lreg_inode_header));\
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
	SQUASHFS_SWAP((s)->start_block, d, 128, 64);\
	SQUASHFS_SWAP((s)->fragment, d, 192, 32);\
	SQUASHFS_SWAP((s)->offset, d, 224, 32);\
	SQUASHFS_SWAP((s)->file_size, d, 256, 64);\
}

#define SQUASHFS_SWAP_DIR_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_dir_inode_header));\
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
	SQUASHFS_SWAP((s)->file_size, d, 128, 19);\
	SQUASHFS_SWAP((s)->offset, d, 147, 13);\
	SQUASHFS_SWAP((s)->start_block, d, 160, 32);\
	SQUASHFS_SWAP((s)->parent_inode, d, 192, 32);\
}

#define SQUASHFS_SWAP_LDIR_INODE_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_SWAP_BASE_INODE_CORE(s, d, \
			sizeof(struct squashfs_ldir_inode_header));\
	SQUASHFS_SWAP((s)->nlink, d, 96, 32);\
	SQUASHFS_SWAP((s)->file_size, d, 128, 27);\
	SQUASHFS_SWAP((s)->offset, d, 155, 13);\
	SQUASHFS_SWAP((s)->start_block, d, 168, 32);\
	SQUASHFS_SWAP((s)->i_count, d, 200, 16);\
	SQUASHFS_SWAP((s)->parent_inode, d, 216, 32);\
}

#define SQUASHFS_SWAP_DIR_INDEX(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, sizeof(struct squashfs_dir_index));\
	SQUASHFS_SWAP((s)->index, d, 0, 32);\
	SQUASHFS_SWAP((s)->start_block, d, 32, 32);\
	SQUASHFS_SWAP((s)->size, d, 64, 8);\
}

#define SQUASHFS_SWAP_DIR_HEADER(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, sizeof(struct squashfs_dir_header));\
	SQUASHFS_SWAP((s)->count, d, 0, 8);\
	SQUASHFS_SWAP((s)->start_block, d, 8, 32);\
	SQUASHFS_SWAP((s)->inode_number, d, 40, 32);\
}

#define SQUASHFS_SWAP_DIR_ENTRY(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, sizeof(struct squashfs_dir_entry));\
	SQUASHFS_SWAP((s)->offset, d, 0, 13);\
	SQUASHFS_SWAP((s)->type, d, 13, 3);\
	SQUASHFS_SWAP((s)->size, d, 16, 8);\
	SQUASHFS_SWAP((s)->inode_number, d, 24, 16);\
}

#define SQUASHFS_SWAP_FRAGMENT_ENTRY(s, d) {\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, sizeof(struct squashfs_fragment_entry));\
	SQUASHFS_SWAP((s)->start_block, d, 0, 64);\
	SQUASHFS_SWAP((s)->size, d, 64, 32);\
}

#define SQUASHFS_SWAP_INODE_T(s, d) SQUASHFS_SWAP_LONG_LONGS(s, d, 1)

#define SQUASHFS_SWAP_SHORTS(s, d, n) {\
	int entry;\
	int bit_position;\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, n * 2);\
	for(entry = 0, bit_position = 0; entry < n; entry++, bit_position += \
			16)\
		SQUASHFS_SWAP(s[entry], d, bit_position, 16);\
}

#define SQUASHFS_SWAP_INTS(s, d, n) {\
	int entry;\
	int bit_position;\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, n * 4);\
	for(entry = 0, bit_position = 0; entry < n; entry++, bit_position += \
			32)\
		SQUASHFS_SWAP(s[entry], d, bit_position, 32);\
}

#define SQUASHFS_SWAP_LONG_LONGS(s, d, n) {\
	int entry;\
	int bit_position;\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, n * 8);\
	for(entry = 0, bit_position = 0; entry < n; entry++, bit_position += \
			64)\
		SQUASHFS_SWAP(s[entry], d, bit_position, 64);\
}

#define SQUASHFS_SWAP_DATA(s, d, n, bits) {\
	int entry;\
	int bit_position;\
	SQUASHFS_SWAP_START\
	SQUASHFS_MEMSET(s, d, n * bits / 8);\
	for(entry = 0, bit_position = 0; entry < n; entry++, bit_position += \
			bits)\
		SQUASHFS_SWAP(s[entry], d, bit_position, bits);\
}

#define SQUASHFS_SWAP_FRAGMENT_INDEXES(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)
#define SQUASHFS_SWAP_LOOKUP_BLOCKS(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)
#define SQUASHFS_SWAP_ID_BLOCKS(s, d, n) SQUASHFS_SWAP_LONG_LONGS(s, d, n)

#endif
