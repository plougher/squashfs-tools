/*
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
 * xz_wrapper.c
 *
 * Support for XZ (LZMA2) compression using XZ Utils liblzma http://tukaani.org/xz/
 */

#include <stdio.h>
#include <string.h>
#include <lzma.h>

#include "squashfs_fs.h"
#include "compressor.h"

#define MEMLIMIT (32 * 1024 * 1024)

static lzma_options_lzma opt;
static lzma_filter filters[2] = {
	{ LZMA_FILTER_LZMA2, &opt },
	{ LZMA_VLI_UNKNOWN, NULL }
};


static int xz_compress(void *dummy, void *dest, void *src,  int size,
	int block_size, int *error)
{
	size_t out_size = 0;
        lzma_ret res = 0;

        if(lzma_lzma_preset(&opt, LZMA_PRESET_DEFAULT))
                goto failed;

	res = lzma_stream_buffer_encode(filters, LZMA_CHECK_CRC32, NULL,
				src, size, dest, &out_size, block_size);

	if(res == LZMA_OK)
		return (int) out_size;

	if(res == LZMA_BUF_ERROR)
		/*
	 	 * Output buffer overflow.  Return out of buffer space
	 	 */
		return 0;

failed:
	/*
	 * All other errors return failure, with the compressor
	 * specific error code in *error
	 */
	*error = res;
	return -1;
}


static int xz_uncompress(void *dest, void *src, int size, int block_size,
	int *error)
{
	size_t src_pos = 0;
	size_t dest_pos = 0;
	uint64_t memlimit = MEMLIMIT;
	lzma_ret res = lzma_stream_buffer_decode(&memlimit, 0, NULL,
			src, &src_pos, size, dest, &dest_pos, block_size);

	*error = res;
	return res == LZMA_OK && size == (int) src_pos ? (int) dest_pos : -1;
}


struct compressor xz_comp_ops = {
	.init = NULL,
	.compress = xz_compress,
	.uncompress = xz_uncompress,
	.options = NULL,
	.id = XZ_COMPRESSION,
	.name = "xz",
	.supported = 1
};

