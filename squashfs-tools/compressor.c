/*
 *
 * Copyright (c) 2009, 2010, 2011, 2022, 2024
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

#ifndef GZIP_SUPPORT
static struct compressor gzip_comp_ops =  {
	ZLIB_COMPRESSION, "gzip"
};
#else
extern struct compressor gzip_comp_ops;
#endif

#ifndef LZMA_SUPPORT
static struct compressor lzma_comp_ops = {
	LZMA_COMPRESSION, "lzma"
};
#else
extern struct compressor lzma_comp_ops;
#endif

#ifndef LZO_SUPPORT
static struct compressor lzo_comp_ops = {
	LZO_COMPRESSION, "lzo"
};
#else
extern struct compressor lzo_comp_ops;
#endif

#ifndef LZ4_SUPPORT
static struct compressor lz4_comp_ops = {
	LZ4_COMPRESSION, "lz4"
};
#else
extern struct compressor lz4_comp_ops;
#endif

#ifndef XZ_SUPPORT
static struct compressor xz_comp_ops = {
	XZ_COMPRESSION, "xz"
};
#else
extern struct compressor xz_comp_ops;
#endif

#ifndef ZSTD_SUPPORT
static struct compressor zstd_comp_ops = {
	ZSTD_COMPRESSION, "zstd"
};
#else
extern struct compressor zstd_comp_ops;
#endif

static struct compressor unknown_comp_ops = {
	0, "unknown"
};


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
