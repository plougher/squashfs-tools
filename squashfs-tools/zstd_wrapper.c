/*
 * Copyright (c) 2017
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
 * zstd_wrapper.c
 *
 * Support for ZSTD compression http://zstd.net
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zstd.h>
#include <zstd_errors.h>

#include "squashfs_fs.h"
#include "zstd_wrapper.h"
#include "compressor.h"

static int compression_level = ZSTD_DEFAULT_COMPRESSION_LEVEL;

/*
 * This function is called by the options parsing code in mksquashfs.c
 * to parse any -X compressor option.
 *
 * This function returns:
 *	>=0 (number of additional args parsed) on success
 *	-1 if the option was unrecognised, or
 *	-2 if the option was recognised, but otherwise bad in
 *	   some way (e.g. invalid parameter)
 *
 * Note: this function sets internal compressor state, but does not
 * pass back the results of the parsing other than success/failure.
 * The zstd_dump_options() function is called later to get the options in
 * a format suitable for writing to the filesystem.
 */
static int zstd_options(char *argv[], int argc)
{
	if (strcmp(argv[0], "-Xcompression-level") == 0) {
		if (argc < 2) {
			fprintf(stderr, "zstd: -Xcompression-level missing "
				"compression level\n");
			fprintf(stderr, "zstd: -Xcompression-level it should "
				"be 1 <= n <= %d\n", ZSTD_maxCLevel());
			goto failed;
		}

		compression_level = atoi(argv[1]);
		if (compression_level < 1 ||
		    compression_level > ZSTD_maxCLevel()) {
			fprintf(stderr, "zstd: -Xcompression-level invalid, it "
				"should be 1 <= n <= %d\n", ZSTD_maxCLevel());
			goto failed;
		}

		return 1;
	}

	return -1;
failed:
	return -2;
}

/*
 * This function is called by mksquashfs to dump the parsed
 * compressor options in a format suitable for writing to the
 * compressor options field in the filesystem (stored immediately
 * after the superblock).
 *
 * This function returns a pointer to the compression options structure
 * to be stored (and the size), or NULL if there are no compression
 * options.
 */
static void *zstd_dump_options(int block_size, int *size)
{
	static struct zstd_comp_opts comp_opts;

	/* don't return anything if the options are all default */
	if (compression_level == ZSTD_DEFAULT_COMPRESSION_LEVEL)
		return NULL;

	comp_opts.compression_level = compression_level;

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
 * -X options on the appending mksquashfs command line are over-ridden.
 *
 * This function returns 0 on sucessful extraction of options, and -1 on error.
 */
static int zstd_extract_options(int block_size, void *buffer, int size)
{
	struct zstd_comp_opts *comp_opts = buffer;

	if (size == 0) {
		/* Set default values */
		compression_level = ZSTD_DEFAULT_COMPRESSION_LEVEL;
		return 0;
	}

	/* we expect a comp_opts structure of sufficient size to be present */
	if (size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	if (comp_opts->compression_level < 1 ||
	    comp_opts->compression_level > ZSTD_maxCLevel()) {
		fprintf(stderr, "zstd: bad compression level in compression "
			"options structure\n");
		goto failed;
	}

	compression_level = comp_opts->compression_level;

	return 0;

failed:
	fprintf(stderr, "zstd: error reading stored compressor options from "
		"filesystem!\n");

	return -1;
}

static void zstd_display_options(void *buffer, int size)
{
	struct zstd_comp_opts *comp_opts = buffer;

	/* we expect a comp_opts structure of sufficient size to be present */
	if (size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	if (comp_opts->compression_level < 1 ||
	    comp_opts->compression_level > ZSTD_maxCLevel()) {
		fprintf(stderr, "zstd: bad compression level in compression "
			"options structure\n");
		goto failed;
	}

	printf("\tcompression-level %d\n", comp_opts->compression_level);

	return;

failed:
	fprintf(stderr, "zstd: error reading stored compressor options from "
		"filesystem!\n");
}

/*
 * This function is called by mksquashfs to initialise the
 * compressor, before compress() is called.
 *
 * This function returns 0 on success, and -1 on error.
 */
static int zstd_init(void **strm, int block_size, int datablock)
{
	ZSTD_CCtx *cctx = ZSTD_createCCtx();

	if (!cctx) {
		fprintf(stderr, "zstd: failed to allocate compression "
			"context!\n");
		return -1;
	}

	*strm = cctx;
	return 0;
}

static int zstd_compress(void *strm, void *dest, void *src, int size,
			 int block_size, int *error)
{
	const size_t res = ZSTD_compressCCtx((ZSTD_CCtx*)strm, dest, block_size,
					     src, size, compression_level);

	if (ZSTD_isError(res)) {
		/* FIXME:
		 * zstd does not expose stable error codes. The error enum may
		 * change between versions. Until upstream zstd stablizes the
		 * error codes, we have no way of knowing why the error occurs.
		 * zstd shouldn't fail to compress any input unless there isn't
		 * enough output space. We assume that is the cause and return
		 * the special error code for not enough output space.
		 */
		return 0;
	}

	return (int)res;
}

static int zstd_uncompress(void *dest, void *src, int size, int outsize,
			   int *error)
{
	const size_t res = ZSTD_decompress(dest, outsize, src, size);

	if (ZSTD_isError(res)) {
		fprintf(stderr, "\t%d %d\n", outsize, size);

		*error = (int)ZSTD_getErrorCode(res);
		return -1;
	}

	return (int)res;
}

static void zstd_usage(void)
{
	fprintf(stderr, "\t  -Xcompression-level <compression-level>\n");
	fprintf(stderr, "\t\t<compression-level> should be 1 .. %d (default "
		"%d)\n", ZSTD_maxCLevel(), ZSTD_DEFAULT_COMPRESSION_LEVEL);
}

struct compressor zstd_comp_ops = {
	.init = zstd_init,
	.compress = zstd_compress,
	.uncompress = zstd_uncompress,
	.options = zstd_options,
	.dump_options = zstd_dump_options,
	.extract_options = zstd_extract_options,
	.display_options = zstd_display_options,
	.usage = zstd_usage,
	.id = ZSTD_COMPRESSION,
	.name = "zstd",
	.supported = 1
};
