/*
 * Copyright (c) 2013, 2019, 2021, 2024, 2026
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
 * Support for LZ4 compression http://fastcompression.blogspot.com/p/lz4.html
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <lz4.h>
#include <lz4hc.h>

#include "squashfs_fs.h"
#include "lz4_wrapper.h"
#include "compressor.h"
#include "print_pager.h"

static int hc = 0;
static int acceleration = LZ4_ACC_DEFAULT; /* LZ4_compress_default */
static int compression = LZ4_COMP_DEFAULT; /* LZ4_compress_HC_default */
static int acceleration_opt = FALSE;
static int compression_opt = FALSE;

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
 * The lz4_dump_options() function is called later to get the options in
 * a format suitable for writing to the filesystem.
 */
static int lz4_options(char *argv[], int argc)
{
	if(strcmp(argv[0], "-Xhc") == 0) {
		hc = 1;
		return 0;
	} else if(strcmp( argv[0], "-Xacceleration") == 0) {
		if(argc < 2) {
			fprintf(stderr, "lz4: -Xacceleration missing "
				"acceleration value\n");
			fprintf(stderr, "lz4: it should be 1 >= n <= 65537\n");
			goto failed;
		}

		acceleration = atoi(argv[1]);
		if(acceleration < 1 || acceleration > 65537) {
			fprintf(stderr, "lz4: -Xacceleration value invalid, it "
				"should be 1 >= n <= 65537\n");
			goto failed;
		}

		acceleration_opt = TRUE;

		return 1;
	} else if(strcmp( argv[0], "-Xcompression-level") == 0) {
		if(argc < 2) {
			fprintf(stderr, "lz4: -Xcompression-level missing "
				"compression value\n");
			fprintf(stderr, "lz4: it should be between 1 >= n <= "
				"12\n");
			goto failed;
		}

		compression = atoi(argv[1]);
		if(compression < 1 || compression > 12) {
			fprintf(stderr, "lz4: -Xcompression-level invalid, it "
				"should be 1 >= n <= 12\n");
			goto failed;
		}

		compression_opt = TRUE;
		return 1;
	}

	return -1;

failed:
	return -2;
}


/*
 * This function is called after all options have been parsed.
 * It is used to do post-processing on the compressor options using
 * values that were not expected to be known at option parse time.
 *
 * This function returns 0 on successful post processing, or
 *			-1 on error
 */
static int lz4_options_post(int block_size)
{
	if(acceleration_opt && hc) {
		fprintf(stderr, "lz4: -Xacceleration can't be used with "
			"-Xhc\n");
		return -1;
	} else if(compression_opt && !hc) {
		fprintf(stderr, "lz4: -Xcompression-level can't be used "
			"without -Xhc option\n");
		return -1;
	}

	OLD_LIBRARY_OPTION;

	return 0;
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
	if(acceleration != LZ4_ACC_DEFAULT || compression != LZ4_COMP_DEFAULT) {
		static struct lz4_comp_opts_v2 comp_opts;

		comp_opts.version = LZ4_LEGACY;
		if(hc) {
			comp_opts.flags = LZ4_HC | LZ4_NON_DEFAULT;
			comp_opts.data = compression;
		} else {
			comp_opts.flags = LZ4_NON_DEFAULT;
			comp_opts.data = acceleration;
		}
		SQUASHFS_INSWAP_COMP_OPTS_V2(&comp_opts);
		*size = sizeof(comp_opts);
		return &comp_opts;
	} else {
		static struct lz4_comp_opts_v1 comp_opts;

		comp_opts.version = LZ4_LEGACY;
		comp_opts.flags = hc ? LZ4_HC : 0;
		SQUASHFS_INSWAP_COMP_OPTS_V1(&comp_opts);
		*size = sizeof(comp_opts);
		return &comp_opts;
	}
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
	/* we expect a comp_opts structure to be present */
	if(size == sizeof(struct lz4_comp_opts_v1)) {
		struct lz4_comp_opts_v1 *comp_opts = buffer;

		SQUASHFS_INSWAP_COMP_OPTS_V1(comp_opts);

		/* we expect the stream format to be LZ4_LEGACY */
		if(comp_opts->version != LZ4_LEGACY) {
			fprintf(stderr, "lz4: unknown LZ4 version\n");
			goto failed;
		}

		/*
		 * Check compression flags, only LZ4_HC ("high compression")
		 * can be set.
		 */
		if(comp_opts->flags & ~LZ4_HC) {
			fprintf(stderr, "lz4: unknown LZ4 flags\n");
			goto failed;
		} else if(comp_opts->flags == LZ4_HC)
			hc = 1;

		acceleration = LZ4_ACC_DEFAULT; /* LZ4_compress_default */
		compression = LZ4_COMP_DEFAULT; /* LZ4_compress_HC_default */
		return 0;
	} else if(size == sizeof(struct lz4_comp_opts_v2)) {
		struct lz4_comp_opts_v2 *comp_opts = buffer;

		SQUASHFS_INSWAP_COMP_OPTS_V2(comp_opts);

		/* we expect the stream format to be LZ4_LEGACY */
		if(comp_opts->version != LZ4_LEGACY) {
			fprintf(stderr, "lz4: unknown LZ4 version\n");
			goto failed;
		}

		/* LZ4_NON_DEFAULT should be set */
		if((comp_opts->flags & LZ4_NON_DEFAULT) == 0) {
			fprintf(stderr, "lz4: corrupt flags field in compression options structure\n");
			goto failed;
		}

		if(comp_opts->flags & ~LZ4_FLAGS_MASK) {
			fprintf(stderr, "lz4: unknown LZ4 flags\n");
			goto failed;
		}

		if(comp_opts->flags & LZ4_HC) {
			compression = comp_opts->data;
			hc = TRUE;
		} else
			acceleration = comp_opts->data;

		OLD_LIBRARY_EXTRACT;

		return 0;
	}

failed:
	fprintf(stderr, "lz4: error reading stored compressor options from "
		"filesystem!\n");

	return -1;
}


/*
 * This function is a helper specifically for unsquashfs.
 * Its purpose is to check that the compression options are
 * understood by this version of LZ4.
 *
 * This is important for LZ4 because the format understood by the
 * Linux kernel may change from the already obsolete legacy format
 * currently supported.
 *
 * If this does happen, then this version of LZ4 will not be able to decode
 * the newer format.  So we need to check for this.
 *
 * This function returns 0 on sucessful checking of options, and
 *			-1 on error
 */
static int lz4_check_options(int block_size, void *buffer, int size)
{
	struct lz4_comp_opts_v1 *comp_opts = buffer;

	/* we expect a comp_opts structure to be present */
	if(size < sizeof(*comp_opts))
		goto failed;

	SQUASHFS_INSWAP_COMP_OPTS_V1(comp_opts);

	/* we expect the stream format to be LZ4_LEGACY */
	if(comp_opts->version != LZ4_LEGACY) {
		fprintf(stderr, "lz4: unknown LZ4 version\n");
		goto failed;
	}

	return 0;

failed:
	fprintf(stderr, "lz4: error reading stored compressor options from "
		"filesystem!\n");
	return -1;
}


static void lz4_display_options(void *buffer, int size)
{
	int display_hc = FALSE;
	int display_acceleration;
	int display_compression;

	/* we expect a comp_opts structure to be present */
	if(size == sizeof(struct lz4_comp_opts_v1)) {
		struct lz4_comp_opts_v1 *comp_opts = buffer;

		SQUASHFS_INSWAP_COMP_OPTS_V1(comp_opts);

		/* we expect the stream format to be LZ4_LEGACY */
		if(comp_opts->version != LZ4_LEGACY) {
			fprintf(stderr, "lz4: unknown LZ4 version\n");
			goto failed;
		}

		/*
		 * Check compression flags, only LZ4_HC ("high compression")
		 * can be set.
		 */
		if(comp_opts->flags & ~LZ4_HC) {
			fprintf(stderr, "lz4: unknown LZ4 flags\n");
			goto failed;
		} else if(comp_opts->flags == LZ4_HC) {
			display_hc = TRUE;
			display_compression = LZ4_COMP_DEFAULT; /* LZ4_compress_HC_default */
		} else
			display_acceleration = LZ4_ACC_DEFAULT; /* LZ4_compress_default */
	} else if(size == sizeof(struct lz4_comp_opts_v2)) {
		struct lz4_comp_opts_v2 *comp_opts = buffer;

		SQUASHFS_INSWAP_COMP_OPTS_V2(comp_opts);

		/* we expect the stream format to be LZ4_LEGACY */
		if(comp_opts->version != LZ4_LEGACY) {
			fprintf(stderr, "lz4: unknown LZ4 version\n");
			goto failed;
		}

		/* LZ4_NON_DEFAULT should be set */
		if((comp_opts->flags & LZ4_NON_DEFAULT) == 0) {
			fprintf(stderr, "lz4: corrupt flags field in compression options structure\n");
			goto failed;
		}

		if(comp_opts->flags & ~LZ4_FLAGS_MASK) {
			fprintf(stderr, "lz4: unknown LZ4 flags\n");
			goto failed;
		}

		if(comp_opts->flags & LZ4_HC) {
			display_compression = comp_opts->data;
			display_hc = TRUE;
		} else
			display_acceleration = comp_opts->data;
	} else
		goto failed;


	if(display_hc) {
		printf("\tHigh Compression option specified (-Xhc)\n");
		printf("\tCompression-level %d%s\n", display_compression, display_compression == LZ4_COMP_DEFAULT ? " (default)" : "");
	} else
		printf("\tAcceleration %d%s\n", display_acceleration, display_acceleration == LZ4_ACC_DEFAULT ? " (default)" : "");

	return;

failed:
	fprintf(stderr, "lz4: error reading stored compressor options from "
		"filesystem!\n");
}	


static int lz4_compress(void *strm, void *dest, void *src,  int size,
	int block_size, int *error)
{
	int res;

	if(hc)
		res = COMPRESS_HC(src, dest, size, block_size);
	else
		res = COMPRESS(src, dest, size, block_size);

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


static void lz4_usage(FILE *stream, int cols)
{
	autowrap_print(stream, "\t  -Xhc\n", cols);
	autowrap_print(stream, "\t\tCompress using LZ4 High Compression\n", cols);
	autowrap_print(stream, "\t  -Xacceleration <acceleration>\n\tAccelerate "
		"compresssion by <acceleration>.  <acceleration> should be "
		"between 1 .. 65537 (default 1).  Option doesn't apply to LZ4 "
		"High Compression\n", cols);
	autowrap_print(stream, "\t  -Xcompression-level <compression-level>\n"
		"\t<compression-level> should be 1 .. 12 (default 12).  Option "
		"only applies to LZ4 High Compression\n", cols);
}


struct compressor lz4_comp_ops = {
	.compress = lz4_compress,
	.uncompress = lz4_uncompress,
	.options = lz4_options,
	.options_post = lz4_options_post,
	.dump_options = lz4_dump_options,
	.extract_options = lz4_extract_options,
	.check_options = lz4_check_options,
	.display_options = lz4_display_options,
	.usage = lz4_usage,
	.id = LZ4_COMPRESSION,
	.name = "lz4",
	.supported = 1
};
