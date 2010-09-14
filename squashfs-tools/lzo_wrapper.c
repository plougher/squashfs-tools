/*
 * Copyright (c) 2010 LG Electronics
 * Chan Jeong <chan.jeong@lge.com>
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
 * lzo_wrapper.c
 */

#include <stdlib.h>
#include <string.h>

#include <lzo/lzoconf.h>
#include <lzo/lzo1x.h>

/* worst-case expansion calculation during compression,
   see LZO FAQ for more information */
#define LZO_OUTPUT_BUFFER_SIZE(size)	(size + (size/16) + 64 + 3)

struct lzo_stream {
	lzo_voidp wrkmem;
	lzo_bytep out;
};

int lzo_compress(void **strm, char *d, char *s, int size, int block_size,
		int *error)
{
	int res = 0;
	lzo_uint outlen;
	struct lzo_stream *stream = *strm;

	if(stream == NULL) {
		if((stream = *strm = malloc(sizeof(struct lzo_stream))) == NULL)
			goto failed;
		/* work memory for compression */
		if((stream->wrkmem = malloc(LZO1X_999_MEM_COMPRESS)) == NULL)
			goto failed;
		/* temporal output buffer */
		if((stream->out = malloc(LZO_OUTPUT_BUFFER_SIZE(block_size))) == NULL)
			goto failed;
	}

	res = lzo1x_999_compress((lzo_bytep)s, size, stream->out, &outlen, stream->wrkmem);
	if(res != LZO_E_OK)
		goto failed;
	if(outlen >= size)
		/*
		 * Output buffer overflow. Return out of buffer space
		 */
		return 0;

	/*
	 * Success, return the compressed size.
	 */
	memcpy(d, stream->out, outlen);
	return outlen;

failed:
	/*
	 * All other errors return failure, with the compressor
	 * specific error code in *error
	 */
	*error = res;
	return -1;
}


int lzo_uncompress(char *d, char *s, int size, int block_size, int *error)
{
	int res;
	lzo_uint bytes = block_size;

	res = lzo1x_decompress_safe((lzo_bytep)s, size, (lzo_bytep)d, &bytes, NULL);

	*error = res;
	return res == LZO_E_OK ? bytes : -1;
}
