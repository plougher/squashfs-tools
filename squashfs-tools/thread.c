/*
 * Squashfs
 *
 * Copyright (c) 2024, 2025
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
#include <stdio.h>

#include "mksquashfs_error.h"
#include "thread.h"
#include "alloc.h"

extern int processors;
pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t idle = PTHREAD_COND_INITIALIZER;

static struct thread *threads = NULL;
static int cur = 0;
static int active_frags = 0;
static int active_blocks = 0;
static int waiting_threads = 0;

int get_thread_id(int type)
{
	int id;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &thread_mutex);
	pthread_mutex_lock(&thread_mutex);

	if(threads == NULL)
		threads = MALLOC(processors * 2 * sizeof(struct thread));

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


/*
 * Called with the thread mutex held.
 */
void set_thread_idle(int tid)
{
	if(threads[tid].type == THREAD_FRAGMENT) {
		active_frags --;
		if(waiting_threads)
			pthread_cond_signal(&idle);
	} else
		active_blocks --;

	threads[tid].state = THREAD_IDLE;
}


/*
 * Called with the thread mutex held.
 */
void wait_thread_idle(int tid, pthread_mutex_t *queue_mutex)
{
	if(threads[tid].type == THREAD_FRAGMENT && threads[tid].state == THREAD_IDLE)
		active_frags ++;
	else if(threads[tid].type == THREAD_BLOCK) {
		if(threads[tid].state == THREAD_IDLE)
			active_blocks ++;

		while((active_frags + active_blocks) > (processors + processors / 4)) {
			active_blocks --;
			threads[tid].state = THREAD_IDLE;
			waiting_threads ++;
			pthread_cond_wait(&idle, queue_mutex);
			waiting_threads --;
			active_blocks ++;
		}
	}

	threads[tid].state = THREAD_ACTIVE;
}


void dump_threads()
{
	int i, j;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &thread_mutex);
	pthread_mutex_lock(&thread_mutex);

	printf("Total fragment deflator threads %d, active %d:", processors, active_frags);

	for(i = 0, j = 1; i < (processors * 2); i++) {
		if(threads[i].type == THREAD_FRAGMENT) {
			if(threads[i].state == THREAD_ACTIVE)
				printf(" %d", j);
			j ++;
		}
	}

	printf("\nTotal block deflator threads %d, active %d:", processors, active_blocks);

	for(i = 0, j = 1; i < (processors * 2); i++) {
		if(threads[i].type == THREAD_BLOCK) {
			if(threads[i].state == THREAD_ACTIVE)
				printf(" %d", j);
			j ++;
		}
	}

	printf("\n");
	pthread_cleanup_pop(1);
}
