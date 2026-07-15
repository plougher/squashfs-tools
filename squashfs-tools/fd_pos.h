#ifndef FD_POS_H
#define FD_POS_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2026
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
 * fd_pos.h
 */

#ifdef TEST_STREAM_SEEK
static long long fd_pos = 0;

static pthread_mutex_t mutex;

static inline void check_fd_pos(long long offset)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	if(fd_pos != offset)
		ERROR("BUG: trying to seek on stdout when streaming!\n");

	pthread_cleanup_pop(1);
}


static inline void update_fd_pos(long long offset)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	fd_pos = offset;

	pthread_cleanup_pop(1);
}
#else
static inline void check_fd_pos(long long offset)
{
}


static inline void update_fd_pos(long long offset)
{
}
#endif
#endif
