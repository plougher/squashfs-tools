#ifndef LZ4_WRAPPER_H
#define LZ4_WRAPPER_H
/*
 * Squashfs
 *
 * Copyright (c) 2013, 2021, 2026
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
 * lz4_wrapper.h
 *
 */

#include "endian_compat.h"

#if __BYTE_ORDER == __BIG_ENDIAN
extern unsigned int inswap_le32(unsigned int);

#define SQUASHFS_INSWAP_COMP_OPTS_V1(s) { \
	(s)->version = inswap_le32((s)->version); \
	(s)->flags = inswap_le32((s)->flags); \
}

#define SQUASHFS_INSWAP_COMP_OPTS_V2(s) { \
	(s)->version = inswap_le32((s)->version); \
	(s)->flags = inswap_le32((s)->flags); \
	(s)->data = inswap_le32((s)->data); \
}
#else
#define SQUASHFS_INSWAP_COMP_OPTS_V1(s)
#define SQUASHFS_INSWAP_COMP_OPTS_V2(s)
#endif

/*
 * Define the various stream formats recognised.
 * Currently omly legacy stream format is supported by the
 * kernel
 */
#define LZ4_LEGACY		1

/* Define the compression flags recognised. */
#define LZ4_HC			1
#define LZ4_NON_DEFAULT		2
#define LZ4_FLAGS_MASK		3

/* Default acceleration */
#define LZ4_ACC_DEFAULT		1

struct lz4_comp_opts_v1 {
	int version;
	int flags;
};

struct lz4_comp_opts_v2 {
	int version;
	int flags;
	int data;
};

#if LZ4_VERSION_NUMBER >= 10700
#define OLD_LIBRARY_OPTION
#define OLD_LIBRARY_EXTRACT
#define COMPRESS(src, dest, size, max)		LZ4_compress_fast(src, dest, size, max, acceleration)
#define COMPRESS_HC(src, dest, size, max)	LZ4_compress_HC(src, dest, size, max, compression)
#define LZ4_COMP_DEFAULT			12
#else
#define OLD_LIBRARY_OPTION			{ \
							if(acceleration_opt && acceleration != LZ4_ACC_DEFAULT) { \
								fprintf(stderr, "lz4: lz4 library is too old (pre r129) " \
									"to support acceleration!\n"); \
								return -1; \
							} \
						}
#define OLD_LIBRARY_EXTRACT			{ \
							if(acceleration != LZ4_ACC_DEFAULT) { \
								fprintf(stderr, "lz4: append filesystem uses " \
									"non-default acceleration and the lz4 library " \
									"is too old (pre r129) to support " \
									"acceleration!\n"); \
								return -1; \
							} \
						}
#define COMPRESS(src, dest, size, max)		LZ4_compress_limitedOutput(src, dest, size, max)
#define COMPRESS_HC(src, dest, size, max)	LZ4_compressHC2_limitedOutput(src, dest, size, max, compression)
#define LZ4_COMP_DEFAULT			9
#endif
#endif
