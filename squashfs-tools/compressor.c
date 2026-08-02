/*
 *
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2021, 2022, 2024, 2026
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
 * compressor.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "compressor.h"
#include "squashfs_fs.h"
#include "print_pager.h"

#define COMPRESSOR_DEF(NAME, TYPE) \
	static struct compressor NAME##_comp_ops = { \
		TYPE, #NAME \
	};

#ifndef GZIP_SUPPORT
COMPRESSOR_DEF(gzip, ZLIB_COMPRESSION);
#else
extern struct compressor gzip_comp_ops;
#endif

#ifndef LZMA_SUPPORT
COMPRESSOR_DEF(lzma, LZMA_COMPRESSION);
#else
extern struct compressor lzma_comp_ops;
#endif

#ifndef LZO_SUPPORT
COMPRESSOR_DEF(lzo, LZO_COMPRESSION);
#else
extern struct compressor lzo_comp_ops;
#endif

#ifndef LZ4_SUPPORT
COMPRESSOR_DEF(lz4, LZ4_COMPRESSION);
#else
extern struct compressor lz4_comp_ops;
#endif

#ifndef XZ_SUPPORT
COMPRESSOR_DEF(XZ_COMPRESSION, xz);
#else
extern struct compressor xz_comp_ops;
#endif

#ifndef ZSTD_SUPPORT
COMPRESSOR_DEF(zstd, ZSTD_COMPRESSION);
#else
extern struct compressor zstd_comp_ops;
#endif

COMPRESSOR_DEF(unknown, 0);

struct compressor *compressor[] = {
	&gzip_comp_ops,
	&lzo_comp_ops,
	&lz4_comp_ops,
	&xz_comp_ops,
	&zstd_comp_ops,
	&lzma_comp_ops,
	&unknown_comp_ops
};


struct compressor *lookup_compressor(char *name)
{
	int i;

	for(i = 0; compressor[i]->id; i++)
		if(strcmp(compressor[i]->name, name) == 0)
			break;

	return compressor[i];
}


struct compressor *lookup_compressor_id(int id)
{
	int i;

	for(i = 0; compressor[i]->id; i++)
		if(id == compressor[i]->id)
			break;

	return compressor[i];
}


int valid_compressor(char *name)
{
	return lookup_compressor(name)->supported;
}


void display_compressor_usage(FILE *stream, char *def_comp, int cols)
{
	int i;

	autowrap_print(stream, "\nCompressors available and compressor specific options:\n", cols);

	for(i = 0; compressor[i]->id; i++)
		if(compressor[i]->supported) {
			char *str = strcmp(compressor[i]->name, def_comp) == 0 ?
				" (default)" : "";
			if(compressor[i]->usage) {
				autowrap_printf(stream, cols, "\t%s%s\n",
					compressor[i]->name, str);
				compressor[i]->usage(stream, cols);
			} else
				autowrap_printf(stream, cols, "\t%s (no "
					"options)%s\n", compressor[i]->name,
					str);
		}
}


void print_selected_comp_options(FILE *stream, struct compressor *comp, char *prog_name)
{
	int cols = get_column_width();

	autowrap_printf(stream, cols, "%s: selected compressor \"%s\".  "
		"Options supported: %s\n", prog_name, comp->name, comp->usage ?
		"" : "none");
	if(comp->usage)
		comp->usage(stream, cols);
}


void print_comp_options(FILE *stream, int cols, char *comp_name, char *prog_name)
{
	int i;

	if(strcmp(comp_name, "all") == 0) {
		display_compressor_usage(stream, COMP_DEFAULT, cols);
		return;
	}

	for(i = 0; compressor[i]->id; i++)
		if(compressor[i]->supported && strcmp(compressor[i]->name, comp_name) == 0) {
			struct compressor *comp = compressor[i];

			autowrap_printf(stream, cols, "%s: compressor \"%s\".  "
				"Options supported: %s\n", prog_name,
				comp->name, comp->usage ? "" : "none");
			if(comp->usage)
				comp->usage(stream, cols);

			return;
		}
}
