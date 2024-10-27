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
 * thread.c
 */

#include <pthread.h>
#include <stdlib.h>

#include "nprocessors_compat.h"
#include "mksquashfs_error.h"
#include "thread.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static struct thread *threads = NULL;
static int total = 0;
static int cur = 0;
static int active_frags = 0;
static int active_blocks = 0;

int get_thread_id(int type)
{
	int id;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &mutex);
	pthread_mutex_lock(&mutex);

	if(threads == NULL) {
		total = get_nprocessors();

		threads = malloc(total * sizeof(struct thread));
		if(threads == NULL)
			MEM_ERROR();
	}

	threads[cur].type = type;
	threads[cur].state = THREAD_ACTIVE;

	if(type == THREAD_FRAGMENT)
		active_frags ++;
	else
		active_blocks ++;

	id = cur ++;
	pthread_cleanup_pop(1);

	return id;
}
