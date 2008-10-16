/*
 * Squashfs - a compressed read only filesystem for Linux
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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * block.c
 */

/*
 * This file implements the low-level routines to read and decompress
 * datablocks and metadata blocks.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/buffer_head.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

/*
 * Read the metadata block length, this is stored in the first two
 * bytes of the metadata block.
 */
static struct buffer_head *get_block_length(struct super_block *s,
			int *cur_index, int *offset, unsigned int *length)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct buffer_head *bh;

	bh = sb_bread(s, *cur_index);
	if (bh == NULL)
		goto out;

	if (msblk->devblksize - *offset == 1) {
		*length = (unsigned char) bh->b_data[*offset];
		brelse(bh);
		bh = sb_bread(s, ++(*cur_index));
		if (bh == NULL)
			goto out;
		*length |= (unsigned char) bh->b_data[0] << 8;
		*offset = 1;
	} else {
		*length = (unsigned char) bh->b_data[*offset] |
			(unsigned char) bh->b_data[*offset + 1] << 8;
		*offset += 2;
	}

out:
	return bh;
}


/*
 * Read and decompress a metadata block or datablock.  Length is non-zero
 * if a datablock is being read (the size is stored elsewhere in the
 * filesystem), otherwise the length is obtained from the first two bytes of
 * the metadata block.  A bit in the length field indicates if the block
 * is stored uncompressed in the filesystem (usually because compression
 * generated a larger block - this does occasionally happen with zlib).
 */
unsigned int squashfs_read_data(struct super_block *s, void *buffer,
			long long index, unsigned int length,
			long long *next_index, int srclength)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	struct buffer_head **bh;
	unsigned int offset = index & ((1 << msblk->devblksize_log2) - 1);
	unsigned int cur_index = index >> msblk->devblksize_log2;
	int bytes, avail, b = 0, k = 0;
	unsigned int compressed;
	unsigned int c_byte = length;

	bh = kcalloc((msblk->block_size >> msblk->devblksize_log2) + 1,
				sizeof(*bh), GFP_KERNEL);
	if (bh == NULL)
		goto read_failure;

	if (c_byte) {
		/*
 		 * Datablock.
 		 */
		bytes = -offset;
		compressed = SQUASHFS_COMPRESSED_BLOCK(c_byte);
		c_byte = SQUASHFS_COMPRESSED_SIZE_BLOCK(c_byte);

		TRACE("Block @ 0x%llx, %scompressed size %d, src size %d\n",
			index, compressed ? "" : "un", c_byte, srclength);

		if (c_byte > srclength || index < 0 ||
				(index + c_byte) > msblk->bytes_used)
			goto read_failure;

		for (b = 0; bytes < (int) c_byte; b++, cur_index++) {
			bh[b] = sb_getblk(s, cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b, bh);
	} else {
		/*
		 * Metadata block.
		 */
		if (index < 0 || (index + 2) > msblk->bytes_used)
			goto read_failure;

		bh[0] = get_block_length(s, &cur_index, &offset, &c_byte);
		if (bh[0] == NULL)
			goto read_failure;
		b = 1;

		bytes = msblk->devblksize - offset;
		compressed = SQUASHFS_COMPRESSED(c_byte);
		c_byte = SQUASHFS_COMPRESSED_SIZE(c_byte);

		TRACE("Block @ 0x%llx, %scompressed size %d\n", index,
				compressed ? "" : "un", c_byte);

		if (c_byte > srclength || (index + c_byte) > msblk->bytes_used)
			goto block_release;

		for (; bytes < c_byte; b++) {
			bh[b] = sb_getblk(s, ++cur_index);
			if (bh[b] == NULL)
				goto block_release;
			bytes += msblk->devblksize;
		}
		ll_rw_block(READ, b - 1, bh + 1);
	}

	if (compressed) {
		int zlib_err = 0;

		/*
		 * Uncompress block.
		 */

		mutex_lock(&msblk->read_data_mutex);

		msblk->stream.next_out = buffer;
		msblk->stream.avail_out = srclength;

		for (bytes = 0; k < b; k++) {
			avail = min(c_byte - bytes, msblk->devblksize - offset);

			wait_on_buffer(bh[k]);
			if (!buffer_uptodate(bh[k]))
				goto release_mutex;

			msblk->stream.next_in = bh[k]->b_data + offset;
			msblk->stream.avail_in = avail;

			if (k == 0) {
				zlib_err = zlib_inflateInit(&msblk->stream);
				if (zlib_err != Z_OK) {
					ERROR("zlib_inflateInit returned"
						" unexpected result 0x%x,"
						" srclength %d\n", zlib_err,
						srclength);
					goto release_mutex;
				}

				if (avail == 0) {
					offset = 0;
					brelse(bh[k]);
					continue;
				}
			}

			zlib_err = zlib_inflate(&msblk->stream, Z_NO_FLUSH);
			if (zlib_err != Z_OK && zlib_err != Z_STREAM_END) {
				ERROR("zlib_inflate returned unexpected result"
					" 0x%x, srclength %d, avail_in %d,"
					" avail_out %d\n", zlib_err, srclength,
					msblk->stream.avail_in,
					msblk->stream.avail_out);
				goto release_mutex;
			}

			bytes += avail;
			offset = 0;
			brelse(bh[k]);
		}

		if (zlib_err != Z_STREAM_END)
			goto release_mutex;

		zlib_err = zlib_inflateEnd(&msblk->stream);
		if (zlib_err != Z_OK) {
			ERROR("zlib_inflateEnd returned unexpected result 0x%x,"
				" srclength %d\n", zlib_err, srclength);
			goto release_mutex;
		}
		bytes = msblk->stream.total_out;
		mutex_unlock(&msblk->read_data_mutex);
	} else {
		/*
		 * Block is uncompressed.
		 */
		int i;

		for (i = 0; i < b; i++) {
			wait_on_buffer(bh[i]);
			if (!buffer_uptodate(bh[i]))
				goto block_release;
		}

		for (bytes = 0; k < b; k++) {
			avail = min(c_byte - bytes, msblk->devblksize - offset);

			memcpy(buffer + bytes, bh[k]->b_data + offset, avail);
			bytes += avail;
			offset = 0;
			brelse(bh[k]);
		}
	}

	if (next_index)
		*next_index = index + c_byte + (length ? 0 : 2);

	kfree(bh);
	return bytes;

release_mutex:
	mutex_unlock(&msblk->read_data_mutex);

block_release:
	for (; k < b; k++)
		brelse(bh[k]);

read_failure:
	ERROR("sb_bread failed reading block 0x%x\n", cur_index);
	kfree(bh);
	return 0;
}
