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
 * virt_disk_pos.c
 */

#define FALSE 0
#define TRUE 1

#include <pthread.h>
#include <stdlib.h>

#include "mksquashfs_error.h"
#include "virt_disk_pos.h"
#include "alloc.h"

static pthread_mutex_t virt_disk_mutex = PTHREAD_MUTEX_INITIALIZER;

static struct virt_disk *vd_hashtable[VIRT_DISK_HASH_SIZE];

long long vpos = 0, dpos = 0, marked_vpos = 0;

void add_virt_disk(long long virt, long long disk)
{
	int hash = VIRT_DISK_HASH(virt);
	struct virt_disk *new = MALLOC(sizeof(struct virt_disk));

	new->virt = virt;
	new->disk = disk;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &virt_disk_mutex);
	pthread_mutex_lock(&virt_disk_mutex);

	new->next = vd_hashtable[hash];
	vd_hashtable[hash] = new;

	pthread_cleanup_pop(1);
}


long long get_virt_disk(long long virt)
{
	int hash = VIRT_DISK_HASH(virt);
	struct virt_disk *head;

	if(virt == 0)
		return 0;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &virt_disk_mutex);
	pthread_mutex_lock(&virt_disk_mutex);

	head = vd_hashtable[hash];

	pthread_cleanup_pop(1);

	for(; head; head = head->next) {
		if(head->virt == virt)
			return head->disk;
	}

	BAD_ERROR("BUG in get_virt_disk, %lld not found\n", virt);
}
