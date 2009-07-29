/*
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009
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

extern int gzip_compress(void **, char *, char *, int, int, int *);

struct compressor compressor[] = {
	{ gzip_compress, "gzip" },
	{ NULL, NULL }
};


struct compressor *lookup_compressor(char *name)
{
	int i;

	for(i = 0; compressor[i].name; i++)
		if(strcmp(compressor[i].name, name) == 0)
			return &compressor[i];

	return NULL;
}


struct compressor *enumerate_compressor(struct compressor *comp)
{
	if(comp == NULL)
		return &compressor[0];
	return (comp + 1)->name ? comp + 1 : NULL;
}
