/*
 * Copyright (c) 2009, 2010, 2013, 2014
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
 * gzip_wrapper.c
 *
 * Support for ZLIB compression http://xxx
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "squashfs_fs.h"
#include "gzip_wrapper.h"
#include "compressor.h"

/* default compression level */
static int compression_level = GZIP_DEFAULT_COMPRESSION_LEVEL;

/* default window size */
static int window_size = GZIP_DEFAULT_WINDOW_SIZE;

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
 * The gzip_dump_options() function is called later to get the options in
 * a format suitable for writing to the filesystem.
 */
static int gzip_options(char *argv[], int argc)
{
	if(strcmp(argv[0], "-Xcompression-level") == 0) {
		if(argc < 2) {
			fprintf(stderr, "gzip: -Xcompression-level missing "
				"compression level\n");
			fprintf(stderr, "gzip: -Xcompression-level it "
				"should be 1 >= n <= 9\n");
			goto failed;
		}

		compression_level = atoi(argv[1]);
		if(compression_level < 1 || compression_level > 9) {
			fprintf(stderr, "gzip: -Xcompression-level invalid, it "
				"should be 1 >= n <= 9\n");
			goto failed;
		}

		return 1;
	} else if(strcmp(argv[0], "-Xwindow-size") == 0) {
		if(argc < 2) {
			fprintf(stderr, "gzip: -Xwindow-size missing window "
				"	size\n");
			fprintf(stderr, "gzip: -Xwindow-size <window-size>\n");
			goto failed;
		}

		window_size = atoi(argv[1]);
		if(window_size < 8 || window_size > 15) {
			fprintf(stderr, "gzip: -Xwindow-size invalid, it "
				"should be 8 >= n <= 15\n");
			goto failed;
		}
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
 * options
 *
 */
static void *gzip_dump_options(int block_size, int *size)
{
	static struct gzip_comp_opts comp_opts;

	/*
	 * If default compression options of:
	 * compression-level: 8 and
	 * window-size: 15 then
	 * don't store a compression options structure (this is compatible
	 * with the legacy implementation of GZIP for Squashfs)
	 */
	if(compression_level == GZIP_DEFAULT_COMPRESSION_LEVEL &&
					window_size == GZIP_DEFAULT_WINDOW_SIZE)
		return NULL;

	comp_opts.compression_level = compression_level;
	comp_opts.window_size = window_size;

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
static int gzip_extract_options(int block_size, void *buffer, int size)
{
	struct gzip_comp_opts *comp_opts = buffer;

	if(size == 0) {
		/* Set default values */
		compression_level = GZIP_DEFAULT_COMPRESSION_LEVEL;
		window_size = GZIP_DEFAULT_WINDOW_SIZE;
		return 0;
	}

	/* we expect a comp_opts structure of sufficient size to be present */
	if(size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	/* Check comp_opts structure for correctness */
	if(comp_opts->compression_level < 1 ||
			comp_opts->compression_level > 9) {
		fprintf(stderr, "gzip: bad compression level in "
			"compression options structure\n");
		goto failed;
	}
	compression_level = comp_opts->compression_level;

	if(comp_opts->window_size < 8 ||
			comp_opts->window_size > 15) {
		fprintf(stderr, "gzip: bad window size in "
			"compression options structure\n");
		goto failed;
	}
	window_size = comp_opts->window_size;
	return 0;

failed:
	fprintf(stderr, "gzip: error reading stored compressor options from "
		"filesystem!\n");

	return -1;
}


void gzip_display_options(void *buffer, int size)
{
	struct gzip_comp_opts *comp_opts = buffer;

	/* we expect a comp_opts structure of sufficient size to be present */
	if(size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS(comp_opts);

	/* Check comp_opts structure for correctness */
	if(comp_opts->compression_level < 1 ||
			comp_opts->compression_level > 9) {
		fprintf(stderr, "gzip: bad compression level in "
			"compression options structure\n");
		goto failed;
	}
	printf("\tcompression-level %d\n", comp_opts->compression_level);

	if(comp_opts->window_size < 8 ||
			comp_opts->window_size > 15) {
		fprintf(stderr, "gzip: bad window size in "
			"compression options structure\n");
		goto failed;
	}
	printf("\twindow-size %d\n", comp_opts->window_size);

	return;

failed:
	fprintf(stderr, "gzip: error reading stored compressor options from "
		"filesystem!\n");
}	


/*
 * This function is called by mksquashfs to initialise the
 * compressor, before compress() is called.
 *
 * This function returns 0 on success, and
 *			-1 on error
 */
static int gzip_init(void **strm, int block_size, int flags)
{
	int res;
	z_stream *stream;

	stream = *strm = malloc(sizeof(z_stream));
	if(stream == NULL)
		goto failed;

	stream->zalloc = Z_NULL;
	stream->zfree = Z_NULL;
	stream->opaque = 0;

	res = deflateInit2(stream, compression_level, Z_DEFLATED,
			window_size, 9, Z_DEFAULT_STRATEGY);
	if(res != Z_OK)
		goto failed2;

	return 0;

failed2:
	free(stream);
failed:
	return -1;
}


static int gzip_compress(void *strm, void *d, void *s, int size, int block_size,
		int *error)
{
	int res;
	z_stream *stream = strm;

	res = deflateReset(stream);
	if(res != Z_OK)
		goto failed;

	stream->next_in = s;
	stream->avail_in = size;
	stream->next_out = d;
	stream->avail_out = block_size;

	res = deflate(stream, Z_FINISH);
	if(res == Z_STREAM_END)
		/*
		 * Success, return the compressed size.
		 */
		return (int) stream->total_out;
	if(res == Z_OK)
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


static int gzip_uncompress(void *d, void *s, int size, int outsize, int *error)
{
	int res;
	unsigned long bytes = outsize;

	res = uncompress(d, &bytes, s, size);

	if(res == Z_OK)
		return (int) bytes;
	else {
		*error = res;
		return -1;
	}
}


void gzip_usage()
{
	fprintf(stderr, "\t  -Xcompression-level <compression-level>\n");
	fprintf(stderr, "\t\t<compression-level> should be 1 .. 9 (default "
		"%d)\n", GZIP_DEFAULT_COMPRESSION_LEVEL);
	fprintf(stderr, "\t  -Xwindow-size <window-size>\n");
	fprintf(stderr, "\t\t<window-size> should be 8 .. 15 (default "
		"%d)\n", GZIP_DEFAULT_WINDOW_SIZE);
}


struct compressor gzip_comp_ops = {
	.init = gzip_init,
	.compress = gzip_compress,
	.uncompress = gzip_uncompress,
	.options = gzip_options,
	.dump_options = gzip_dump_options,
	.extract_options = gzip_extract_options,
	.display_options = gzip_display_options,
	.usage = gzip_usage,
	.id = ZLIB_COMPRESSION,
	.name = "gzip",
	.supported = 1
};
