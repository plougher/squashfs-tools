#ifndef ZSTD_WRAPPER_H
#define ZSTD_WRAPPER_H
/*
 * Squashfs
 *
 * Copyright (c) 2017, 2021
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
 * zstd_wrapper.h
 *
 */

#include "endian_compat.h"

#if __BYTE_ORDER == __BIG_ENDIAN
extern unsigned int inswap_le16(unsigned short);
extern unsigned int inswap_le32(unsigned int);

#define SQUASHFS_INSWAP_COMP_OPTS(s) { \
	(s)->compression_level = inswap_le32((s)->compression_level); \
	(s)->rsyncable = inswap_le32((s)->rsyncable); \
}
#else
#define SQUASHFS_INSWAP_COMP_OPTS(s)
#endif

/* Default compression */
#define ZSTD_DEFAULT_COMPRESSION_LEVEL 15

struct zstd_comp_opts {
	int compression_level;
	int rsyncable;
};
#endif
