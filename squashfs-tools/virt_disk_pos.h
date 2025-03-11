#ifndef VIRT_DISK_POS_H
#define VIRT_DISK_POS_H
/*
 * Squashfs
 *
 * Copyright (c) 2025
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
 * virt_disk_pos.h
 */

/*
 * These functions keep track of the current write position within
 * the output filesytem.   They allow the current write position to be
 * saved or marked, and later have the write position reset to that
 * value if for instance the file is discovered to be unreadable or
 * to be a duplicate.
 */
extern long long pos, marked_pos;

static inline void set_pos(long long value)
{
	pos = value;
}


static inline long long get_pos(void)
{
	return pos;
}


long long get_and_inc_pos(long long value)
{
	long long tmp = pos;

	pos += value;
	return tmp;
}


static inline int reset_pos(void)
{
	if(marked_pos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else if(marked_pos == 1)
		return FALSE;
	else {
		set_pos(marked_pos);
		return TRUE;
	}
}


static inline void unmark_pos()
{
	if(marked_pos == 0)
		BAD_ERROR("BUG: Saved write position should not be empty!\n");

	marked_pos = 0;
}


static inline void mark_pos()
{
	if(marked_pos != 0)
		BAD_ERROR("BUG: Saved write position should be empty!\n");

	marked_pos = 1;
}


static inline long long get_marked_pos(void)
{
	if(marked_pos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else if(marked_pos == 1)
		return get_pos();
	else
		return marked_pos;
}
#endif
