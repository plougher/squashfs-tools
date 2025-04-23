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
 * These functions keep track of the current write position within the output
 * filesystem.
 */
extern long long dpos;

static inline void set_dpos(long long value)
{
	dpos = value;
}


static inline long long get_dpos(void)
{
	return dpos;
}


static inline long long get_and_inc_dpos(long long value)
{
	long long tmp = dpos;

	dpos += value;
	return tmp;
}


/*
 * These functions keep track of the current VIRTUAL write position within the
 * output filesystem.   They allow the current write position to be saved or
 * marked, and later have the write position reset to that value if for instance
 * the file is discovered to be unreadable or to be a duplicate.
 *
 * Currently the real and virtual write positions are the same.
 */
extern long long vpos, marked_vpos;

static inline void set_vpos(long long value)
{
	vpos = value;
}


static inline long long get_vpos(void)
{
	return vpos;
}


static inline long long get_and_inc_vpos(long long value)
{
	long long tmp = vpos;

	if(marked_vpos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else if(marked_vpos == 1)
		marked_vpos = vpos;

	vpos += value;
	return tmp;
}


static inline int reset_vpos(void)
{
	if(marked_vpos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else if(marked_vpos == 1)
		return FALSE;
	else {
		set_vpos(marked_vpos);
		return TRUE;
	}
}


static inline void unmark_vpos()
{
	if(marked_vpos == 0)
		BAD_ERROR("BUG: Saved write position should not be empty!\n");

	marked_vpos = 0;
}


static inline void mark_vpos()
{
	if(marked_vpos != 0)
		BAD_ERROR("BUG: Saved write position should be empty!\n");

	marked_vpos = 1;
}


static inline long long get_marked_vpos(void)
{
	if(marked_vpos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else if(marked_vpos == 1)
		return get_vpos();
	else
		return marked_vpos;
}


static inline void set_pos(long long value)
{
	set_vpos(value);
	set_dpos(value);
}


static inline int is_vpos_marked(void)
{
	if(marked_vpos == 0)
		BAD_ERROR("BUG: Saved write position is empty!\n");
	else
		return marked_vpos != 1;
}


#define VIRT_DISK_HASH_SIZE 1048576
#define VIRT_DISK_HASH(hash) (hash & 1048575)

struct virt_disk {
	long long		virt;
	long long		disk;
	struct virt_disk	*next;
};

extern void add_virt_disk(long long virt, long long disk);
extern long long get_virt_disk(long long virt);
#endif
