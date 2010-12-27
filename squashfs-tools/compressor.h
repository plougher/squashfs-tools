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
 * compressor.h
 */

struct compressor {
	int (*init)(void **, int, int);
	int (*compress)(void *, void *, void *, int, int, int *);
	int (*uncompress)(void *, void *, int, int, int *);
	int (*options)(char **, int);
	int (*options_post)(int);
	void *(*dump_options)(int *);
	void (*usage)();
	int id;
	char *name;
	int supported;
};

extern struct compressor *lookup_compressor(char *);
extern struct compressor *lookup_compressor_id(int);
extern void display_compressors(char *, char *);
extern void display_compressor_usage(char *);

static inline int compressor_options(struct compressor *comp, char *argv[],
	int argc)
{
	if(comp->options == NULL)
		return -1;

	return comp->options(argv, argc);
}


static inline int compressor_init(struct compressor *comp, void **stream,
	int block_size, int datablock)
{
	if(comp->init == NULL)
		return 0;
	return comp->init(stream, block_size, datablock);
}


static inline void *compressor_dump_options(struct compressor *comp, int *size)
{
	if(comp->dump_options == NULL)
		return NULL;
	return comp->dump_options(size);
}


static inline int compressor_options_post(struct compressor *comp, int block_size)
{
	if(comp->options_post == NULL)
		return 0;
	return comp->options_post(block_size);
}
