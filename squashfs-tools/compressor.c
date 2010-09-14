/*
 *
 * Copyright (c) 2009, 2010
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
 * compressor.c
 */

#include <stdio.h>
#include <string.h>
#include "compressor.h"
#include "squashfs_fs.h"

extern int gzip_compress(void **, char *, char *, int, int, int *);
extern int gzip_uncompress(char *, char *, int, int, int *);
extern int lzma_compress(void **, char *, char *, int, int, int *);
extern int lzma_uncompress(char *, char *, int, int, int *);
extern int lzo_compress(void **, char *, char *, int, int, int *);
extern int lzo_uncompress(char *, char *, int, int, int *);

struct compressor compressor[] = {
#ifdef GZIP_SUPPORT
	{ gzip_compress, gzip_uncompress, ZLIB_COMPRESSION, "gzip", 1 },
#else
	{ NULL, NULL, ZLIB_COMPRESSION, "gzip", 0 },
#endif
#ifdef LZMA_SUPPORT
	{ lzma_compress, lzma_uncompress, LZMA_COMPRESSION, "lzma", 1 },
#else
	{ NULL, NULL, LZMA_COMPRESSION, "lzma", 0 },
#endif
#ifdef LZO_SUPPORT
	{ lzo_compress, lzo_uncompress, LZO_COMPRESSION, "lzo", 1 },
#else
	{ NULL, NULL, LZO_COMPRESSION, "lzo", 0 },
#endif

	{ NULL, NULL , 0, "unknown", 0}
};


struct compressor *lookup_compressor(char *name)
{
	int i;

	for(i = 0; compressor[i].id; i++)
		if(strcmp(compressor[i].name, name) == 0)
			break;

	return &compressor[i];
}


struct compressor *lookup_compressor_id(int id)
{
	int i;

	for(i = 0; compressor[i].id; i++)
		if(id == compressor[i].id)
			break;

	return &compressor[i];
}


void display_compressors(char *indent, char *def_comp)
{
	int i;

	for(i = 0; compressor[i].id; i++)
		if(compressor[i].supported)
			fprintf(stderr, "%s\t%s%s\n", indent,
				compressor[i].name,
				strcmp(compressor[i].name, def_comp) == 0 ?
				" (default)" : "");
}
