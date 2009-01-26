/*
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
 * swap.c
 */
void swap_le16(unsigned short *src, unsigned short *dest)
{
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	d[0] = s[1];
	d[1] = s[0];
}


void swap_le32(unsigned int *src, unsigned int *dest)
{
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	d[0] = s[3];
	d[1] = s[2];
	d[2] = s[1];
	d[3] = s[0];
}


void swap_le64(long long *src, long long *dest)
{
	unsigned char *s = (unsigned char *) src;
	unsigned char *d = (unsigned char *) dest;

	d[0] = s[7];
	d[1] = s[6];
	d[2] = s[5];
	d[3] = s[4];
	d[4] = s[3];
	d[5] = s[2];
	d[6] = s[1];
	d[7] = s[0];
}


#define SWAP_LE_NUM(BITS, TYPE) \
void swap_le##BITS##_num(TYPE *s, TYPE *d, int n) \
{\
	int i;\
	for(i = 0; i < n; i++, s++, d++)\
		swap_le##BITS(s, d);\
}

SWAP_LE_NUM(16, unsigned short)
SWAP_LE_NUM(32, unsigned int)
SWAP_LE_NUM(64, long long)
