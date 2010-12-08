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
#include <stdlib.h>
#include <lzma.h>

#include "squashfs_fs.h"
#include "compressor.h"

#define MEMLIMIT (32 * 1024 * 1024)

static struct bcj {
	char	 	*name;
	lzma_vli	id;
	int		selected;
} bcj[] = {
	{ "x86", LZMA_FILTER_X86, 0 },
	{ "powerpc", LZMA_FILTER_POWERPC, 0 },
	{ "ia64", LZMA_FILTER_IA64, 0 },
	{ "arm", LZMA_FILTER_ARM, 0 },
	{ "armthumb", LZMA_FILTER_ARMTHUMB, 0 },
	{ "sparc", LZMA_FILTER_SPARC, 0 },
	{ NULL, LZMA_VLI_UNKNOWN, 0 }
};

struct filter {
	void		*buffer;
	lzma_filter	filter[3];
	size_t		length;
};

struct xz_stream {
	struct filter	*filter;
	int		filters;
	lzma_options_lzma opt;
};

static int filter_count = 1;


static int xz_options(char *argv[], int argc)
{
	int i;
	char *name;

	if(strcmp(argv[0], "-Xbcj") == 0) {
		if(argc < 2) {
			fprintf(stderr, "xz: -Xbcj missing filter\n");
			goto failed;
		}

		name = argv[1];
		while(name[0] != '\0') {
			for(i = 0; bcj[i].name; i++) {
				int n = strlen(bcj[i].name);
				if((strncmp(name, bcj[i].name, n) == 0) &&
						(name[n] == '\0' ||
						 name[n] == ',')) {
					if(bcj[i].selected == 0) {
				 		bcj[i].selected = 1;
						filter_count++;
					}
					name += name[n] == ',' ? n + 1 : n;
					break;
				}
			}
			if(bcj[i].name == NULL) {
				fprintf(stderr, "xz: -Xbcj unrecognised filter\n");
				goto failed;
			}
		}
	
		return 1;
	}

	return -1;
	
failed:
	return -2;
}
		

void xz_usage()
{
	fprintf(stderr, "\t  -Xbcj filter1,filter2,...,filterN\n");
	fprintf(stderr, "\t\tCompress using filter1,filter2,...,filterN in");
	fprintf(stderr, " turn\n\t\t(in addition to no filter), and choose");
	fprintf(stderr, " the best compression.\n");
	fprintf(stderr, "\t\tAvailable filters: x86, arm, armthumb,");
	fprintf(stderr, " powerpc, sparc, ia64\n");
}


static int xz_init(void **strm, int block_size, int flags)
{
	int i, j, filters = flags ? filter_count : 1;
	struct filter *filter = malloc(filters * sizeof(struct filter));
	struct xz_stream *stream;

	if(filter == NULL)
		goto failed;

	stream = *strm = malloc(sizeof(struct xz_stream));
	if(stream == NULL)
		goto failed2;

	stream->filter = filter;
	stream->filters = filters;

	memset(filter, 0, filters * sizeof(struct filter));

	filter[0].filter[0].id = LZMA_FILTER_LZMA2;
	filter[0].filter[0].options = &stream->opt;
	filter[0].filter[1].id = LZMA_VLI_UNKNOWN;

	for(i = 0, j = 1; flags && bcj[i].name; i++) {
		if(bcj[i].selected) {
			filter[j].buffer = malloc(block_size);
			if(filter[j].buffer == NULL)
				goto failed3;
			filter[j].filter[0].id = bcj[i].id;
			filter[j].filter[1].id = LZMA_FILTER_LZMA2;
			filter[j].filter[1].options = &stream->opt;
			filter[j].filter[2].id = LZMA_VLI_UNKNOWN;
			j++;
		}
	}

	return 0;

failed3:
	for(i = 1; i < filters; i++)
		free(filter[i].buffer);
	free(stream);

failed2:
	free(filter);

failed:
	return -1;
}


static int xz_compress(void *strm, void *dest, void *src,  int size,
	int block_size, int *error)
{
	int i;
        lzma_ret res = 0;
	struct xz_stream *stream = strm;
	struct filter *selected = NULL;

	stream->filter[0].buffer = dest;

	for(i = 0; i < stream->filters; i++) {
		struct filter *filter = &stream->filter[i];

        	if(lzma_lzma_preset(&stream->opt, LZMA_PRESET_DEFAULT))
                	goto failed;

		stream->opt.dict_size = block_size;
		filter->length = 0;
		res = lzma_stream_buffer_encode(filter->filter,
			LZMA_CHECK_CRC32, NULL, src, size, filter->buffer,
			&filter->length, block_size);
	
		if(res == LZMA_OK) {
			if(!selected || selected->length > filter->length)
				selected = filter;
		} else if(res != LZMA_BUF_ERROR)
			goto failed;
	}

	if(!selected)
		/*
	 	 * Output buffer overflow.  Return out of buffer space
	 	 */
		return 0;

	if(selected->buffer != dest)
		memcpy(dest, selected->buffer, selected->length);

	return (int) selected->length;

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
	.init = xz_init,
	.compress = xz_compress,
	.uncompress = xz_uncompress,
	.options = xz_options,
	.usage = xz_usage,
	.id = XZ_COMPRESSION,
	.name = "xz",
	.supported = 1
};

