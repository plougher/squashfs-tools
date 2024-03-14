#ifndef TIME_COMPAT_H
#define TIME_COMPAT_H
/*
 * Squashfs
 *
 * Copyright (c) 2024
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
 * time_compat.h
 */

#ifdef __OpenBSD__
static inline int set_timestamp(char *pathname, struct inode *i)
{
	struct timespec times[2] = {
		{ i->time, 0 },
		{ i->time, 0 }
	};

	return utimensat(AT_FDCWD, pathname, times, AT_SYMLINK_NOFOLLOW);
}
#else
static inline int set_timestamp(char *pathname, struct inode *i)
{
	struct timeval times[2] = {
		{ i->time, 0 },
		{ i->time, 0 }
	};

	return lutimes(pathname, times);
}
#endif
#endif
