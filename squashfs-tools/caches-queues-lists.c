/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2013
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
 * caches-queues-lists.c
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "error.h"
#include "caches-queues-lists.h"

extern int add_overflow(int, int);
extern int multiply_overflow(int, int);

#define TRUE 1
#define FALSE 0

struct queue *queue_init(int size)
{
	struct queue *queue = malloc(sizeof(struct queue));

	if(queue == NULL)
		MEM_ERROR();

	if(add_overflow(size, 1) ||
				multiply_overflow(size + 1, sizeof(void *)))
		BAD_ERROR("Size too large in queue_init\n");

	queue->data = malloc(sizeof(void *) * (size + 1));
	if(queue->data == NULL)
		MEM_ERROR();

	queue->size = size + 1;
	queue->readp = queue->writep = 0;
	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->empty, NULL);
	pthread_cond_init(&queue->full, NULL);

	return queue;
}


void queue_put(struct queue *queue, void *data)
{
	int nextp;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	while((nextp = (queue->writep + 1) % queue->size) == queue->readp)
		pthread_cond_wait(&queue->full, &queue->mutex);

	queue->data[queue->writep] = data;
	queue->writep = nextp;
	pthread_cond_signal(&queue->empty);
	pthread_cleanup_pop(1);
}


void *queue_get(struct queue *queue)
{
	void *data;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	while(queue->readp == queue->writep)
		pthread_cond_wait(&queue->empty, &queue->mutex);

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_cleanup_pop(1);

	return data;
}


void dump_queue(struct queue *queue)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	printf("Max size %d, readp %d, writep %d, size %d%s\n",
		queue->size - 1, queue->readp, queue->writep,  
		queue->readp <= queue->writep ? queue->writep - queue->readp :
			queue->size - queue->readp + queue->writep,
		queue->readp == queue->writep ? " (EMPTY)" :
			((queue->writep + 1) % queue->size) == queue->readp ?
			" (FULL)" : "");

	pthread_cleanup_pop(1);
}


#define CALCULATE_HASH(start)	(start & 0xffff) \


/* Called with the cache mutex held */
void insert_hash_table(struct cache *cache, struct file_buffer *entry)
{
	int hash = CALCULATE_HASH(entry->index);

	entry->hash_next = cache->hash_table[hash];
	cache->hash_table[hash] = entry;
	entry->hash_prev = NULL;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry;
}


/* Called with the cache mutex held */
void remove_hash_table(struct cache *cache, struct file_buffer *entry)
{
	if(entry->hash_prev)
		entry->hash_prev->hash_next = entry->hash_next;
	else
		cache->hash_table[CALCULATE_HASH(entry->index)] =
			entry->hash_next;
	if(entry->hash_next)
		entry->hash_next->hash_prev = entry->hash_prev;

	entry->hash_prev = entry->hash_next = NULL;
}


/* Called with the cache mutex held */
INSERT_LIST(free, struct file_buffer)

/* Called with the cache mutex held */
REMOVE_LIST(free, struct file_buffer)

INSERT_LIST(fragment, struct frag_locked)
REMOVE_LIST(fragment, struct frag_locked)


struct cache *cache_init(int buffer_size, int max_buffers, int first_freelist)
{
	struct cache *cache = malloc(sizeof(struct cache));

	if(cache == NULL)
		MEM_ERROR();

	cache->max_buffers = max_buffers;
	cache->buffer_size = buffer_size;
	cache->count = 0;
	cache->free_list = NULL;

	/*
	 * The default use freelist before growing cache policy behaves
	 * poorly with appending - with many deplicates the caches
	 * do not grow due to the fact that large queues of outstanding
	 * fragments/writer blocks do not occur, leading to small caches
	 * and un-uncessary performance loss to frequent cache
	 * replacement in the small caches.  Therefore with appending
	 * change the policy to grow the caches before reusing blocks
	 * from the freelist
	 */
	cache->first_freelist = first_freelist;

	memset(cache->hash_table, 0, sizeof(struct file_buffer *) * 65536);
	pthread_mutex_init(&cache->mutex, NULL);
	pthread_cond_init(&cache->wait_for_free, NULL);

	return cache;
}


struct file_buffer *cache_lookup(struct cache *cache, long long index)
{
	/* Lookup block in the cache, if found return with usage count
 	 * incremented, if not found return NULL */
	int hash = CALCULATE_HASH(index);
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	for(entry = cache->hash_table[hash]; entry; entry = entry->hash_next)
		if(entry->index == index)
			break;

	if(entry) {
		/* found the block in the cache, increment used count and
 		 * if necessary remove from free list so it won't disappear
 		 */
		entry->used ++;
		remove_free_list(&cache->free_list, entry);
	}

	pthread_cleanup_pop(1);

	return entry;
}


struct file_buffer *cache_get(struct cache *cache, long long index, int keep)
{
	/* Get a free block out of the cache indexed on index. */
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	while(1) {
		/* first try to get a block from the free list */
		if(cache->first_freelist && cache->free_list) {
			/* a block on the free_list is a "keep" block */
			entry = cache->free_list;
			remove_free_list(&cache->free_list, entry);
			remove_hash_table(cache, entry);
			break;
		} else if(cache->count < cache->max_buffers) {
			/* next try to allocate new block */
			entry = malloc(sizeof(struct file_buffer) +
				cache->buffer_size);
			if(entry == NULL)
				MEM_ERROR();
			entry->cache = cache;
			entry->free_prev = entry->free_next = NULL;
			cache->count ++;
			break;
		} else if(!cache->first_freelist && cache->free_list) {
			/* a block on the free_list is a "keep" block */
			entry = cache->free_list;
			remove_free_list(&cache->free_list, entry);
			remove_hash_table(cache, entry);
			break;
		} else
			/* wait for a block */
			pthread_cond_wait(&cache->wait_for_free, &cache->mutex);
	}

	/* initialise block and if a keep block insert into the hash table */
	entry->used = 1;
	entry->error = FALSE;
	entry->keep = keep;
	if(keep) {
		entry->index = index;
		insert_hash_table(cache, entry);
	}

	pthread_cleanup_pop(1);

	return entry;
}


void cache_rehash(struct file_buffer *entry, long long index)
{
	struct cache *cache = entry->cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);
	if(entry->keep)
		remove_hash_table(cache, entry);
	entry->keep = TRUE;
	entry->index = index;
	insert_hash_table(cache, entry);
	pthread_cleanup_pop(1);
}


void cache_block_put(struct file_buffer *entry)
{
	struct cache *cache;

	/* finished with this cache entry, once the usage count reaches zero it
 	 * can be reused and if a keep block put onto the free list.  As keep
 	 * blocks remain accessible via the hash table they can be found
 	 * getting a new lease of life before they are reused. */

	if(entry == NULL)
		return;

	cache = entry->cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	entry->used --;
	if(entry->used == 0) {
		if(entry->keep)
			insert_free_list(&cache->free_list, entry);
		else {
			free(entry);
			cache->count --;
		}

		/* One or more threads may be waiting on this block */
		pthread_cond_signal(&cache->wait_for_free);
	}

	pthread_cleanup_pop(1);
}


void dump_cache(struct cache *cache)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	printf("Max buffers %d, Current count %d, %s\n", cache->max_buffers,
		cache->count, cache->free_list ? "Free buffers" :
		"No free buffers");

	pthread_cleanup_pop(1);
}

