/*
 * Copyright (c) 2013
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
 * lz4_wrapper.c
 *
 * Support for LZ4 compression http://xxx
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lz4.h>

#include "squashfs_fs.h"
#include "lz4_wrapper.h"
#include "compressor.h"

static struct lz4_comp_opts comp_opts;

/*
 * This function is called by the options parsing code in mksquashfs.c
 * to parse any -X compressor option.
 *
 * This function returns 1 on successful parsing of an option
 *			-1 if the option was unrecognised, or
 *			-2 if the option was recognised, but otherwise bad in
 *			   some way (e.g. invalid parameter) 
 *
 * Note: this function sets internal compressor state, but does not
 * pass back the results of the parsing other than success/failure.
 * The lz4_dump_options() function is called later to get the options in
 * a format suitable for writing to the filesystem.
 */
static int lz4_options(char *argv[], int argc)
{
	return -1;
	
failed:
	return -2;
}


/*
 * This function is called after all options have been parsed.
 * It is used to do post-processing on the compressor options using
 * values that were not expected to be known at option parse time.
 *
 * XXX needed?
 *
 * This function returns 0 on successful post processing, or
 *			-1 on error
 */
static int lz4_options_post(int block_size)
{
	return 0;

failed:
	return -1;
}


/*
 * This function is called by mksquashfs to dump the parsed
 * compressor options in a format suitable for writing to the
 * compressor options field in the filesystem (stored immediately
 * after the superblock).
 *
 * This function returns a pointer to the compression options structure
 * to be stored (and the size), or NULL if there are no compression
 * options
 *
 * Currently LZ4 always returns a comp_opts structure, with
 * the version indicating LZ4_LEGACY stream fomat.  This is to
 * easily accomodate changes in the kernel code to different
 * stream formats 
 */
static void *lz4_dump_options(int block_size, int *size)
{
	comp_opts.version = LZ4_LEGACY;
	comp_opts.flags = 0;
	SQUASHFS_INSWAP_COMP_OPTS(&comp_opts);

	*size = sizeof(comp_opts);
	return &comp_opts;
}


/*
 * This function is a helper specifically for the append mode of
 * mksquashfs.  Its purpose is to set the internal compressor state
 * to the stored compressor options in the passed compressor options
 * structure.
 *
 * In effect this function sets up the compressor options
 * to the same state they were when the filesystem was originally
 * generated, this is to ensure on appending, the compressor uses
 * the same compression options that were used to generate the
 * original filesystem.
 *
 * Note, even if there are no compressor options, this function is still
 * called with an empty compressor structure (size == 0), to explicitly
 * set the default options, this is to ensure any user supplied
 * -X options on the appending mksquashfs command line are over-ridden
 *
 * This function returns 0 on sucessful extraction of options, and
 *			-1 on error
 */
static int lz4_extract_options(int block_size, void *buffer, int size)
{
	struct lz4_comp_opts *comp_opts = buffer;

	/* we expect a comp_opts structure to be present */
	if(size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	/* we expect the stream format to be LZ4_LEGACY */
	if(comp_opts->version != LZ4_LEGACY)
		goto failed;

	/*
	 * we currently don't know about any flags, so if the flags field is not
	 * zero we don't know how that affects compression or decompression,
	 * which is a comp_opts read failure
	 */
	if(comp_opts->flags != 0)
		goto failed;

	return 0;

failed:
	fprintf(stderr, "lz4: error reading stored compressor options from "
		"filesystem!\n");

	return -1;
}


void lz4_display_options(void *buffer, int size)
{
	struct lz4_comp_opts *comp_opts = buffer;

	/* check passed comp opts struct is of the correct length */
	if(size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	/* we expect the stream format to be LZ4_LEGACY */
	if(comp_opts->version != LZ4_LEGACY)
		goto failed;

	/*
	 * we currently don't know about any flags, so if the flags field is not
	 * zero we don't know how to display that, which is a failure
	 */
	if(comp_opts->flags != 0)
		goto failed;

	return;

failed:
	fprintf(stderr, "lz4: error reading stored compressor options from "
		"filesystem!\n");
}	


/*
 * This function is called by mksquashfs to initialise the
 * compressor, before compress() is called.
 *
 * This function returns 0 on success, and
 *			-1 on error
 */
static int lz4_init(void **strm, int block_size, int datablock)
{
#if 0
	struct lz4_stream *stream;

	stream = *strm = malloc(sizeof(struct xz_stream));
	if(stream == NULL)
		goto failed;
#endif

	return 0;

failed:
	return -1;
}


static int lz4_compress(void *strm, void *dest, void *src,  int size,
	int block_size, int *error)
{
	//struct lz4_stream *stream = strm;
	int res = LZ4_compress_limitedOutput(src, dest, size, block_size);
	if(res == 0) {
		/*
	 	 * Output buffer overflow.  Return out of buffer space
	 	 */
		return 0;
	} else if(res < 0) {
		/*
	 	 * All other errors return failure, with the compressor
	 	 * specific error code in *error
	 	 */
		*error = res;
		return -1;
	}

	return res;
}


static int lz4_uncompress(void *dest, void *src, int size, int outsize,
	int *error)
{
	int res = LZ4_decompress_safe(src, dest, size, outsize);
	if(res < 0) {
		*error = res;
		return -1;
	}

	return res;
}


void lz4_usage()
{
}


struct compressor lz4_comp_ops = {
	.init = lz4_init,
	.compress = lz4_compress,
	.uncompress = lz4_uncompress,
	.options = lz4_options,
	.options_post = lz4_options_post,
	.dump_options = lz4_dump_options,
	.extract_options = lz4_extract_options,
	.display_options = lz4_display_options,
	.usage = lz4_usage,
	.id = LZ4_COMPRESSION,
	.name = "lz4",
	.supported = 1
};
