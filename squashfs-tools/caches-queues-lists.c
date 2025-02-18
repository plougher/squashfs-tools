/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2013, 2014, 2019, 2021, 2024
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

#include "mksquashfs_error.h"
#include "caches-queues-lists.h"
#include "thread.h"

extern int add_overflow(int, int);
extern int multiply_overflow(int, int);

#define TRUE 1
#define FALSE 0

struct queue *queue_init(int size, pthread_mutex_t *mutex)
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

	if(mutex)
		queue->mutex = mutex;
	else {
		queue->mutex = malloc(sizeof(pthread_mutex_t));
		if(queue->mutex == NULL)
			MEM_ERROR();

		pthread_mutex_init(queue->mutex, NULL);
	}

	pthread_cond_init(&queue->empty, NULL);
	pthread_cond_init(&queue->full, NULL);

	return queue;
}


void queue_put(struct queue *queue, void *data)
{
	int nextp;

	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	while((nextp = (queue->writep + 1) % queue->size) == queue->readp)
		pthread_cond_wait(&queue->full, queue->mutex);

	queue->data[queue->writep] = data;
	queue->writep = nextp;
	pthread_cond_signal(&queue->empty);
	pthread_cleanup_pop(1);
}


void *queue_get(struct queue *queue)
{
	void *data;

	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	while(queue->readp == queue->writep)
		pthread_cond_wait(&queue->empty, queue->mutex);

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_cleanup_pop(1);

	return data;
}


int queue_empty(struct queue *queue)
{
	int empty;

	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	empty = queue->readp == queue->writep;

	pthread_cleanup_pop(1);

	return empty;
}


void queue_flush(struct queue *queue)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	queue->readp = queue->writep;

	pthread_cleanup_pop(1);
}


void *queue_get_tid(int tid, struct queue *queue)
{
	void *data;

	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	while(1) {
		wait_thread_idle(tid, queue->mutex);

		if(queue->readp == queue->writep) {
			set_thread_idle(tid);
			pthread_cond_wait(&queue->empty, queue->mutex);
		} else
			break;
	}

	data = queue->data[queue->readp];
	queue->readp = (queue->readp + 1) % queue->size;
	pthread_cond_signal(&queue->full);
	pthread_cleanup_pop(1);

	return data;
}


void dump_queue(struct queue *queue)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, queue->mutex);
	pthread_mutex_lock(queue->mutex);

	printf("\tMax size %d, size %d%s\n", queue->size - 1,  
		queue->readp <= queue->writep ? queue->writep - queue->readp :
			queue->size - queue->readp + queue->writep,
		queue->readp == queue->writep ? " (EMPTY)" :
			((queue->writep + 1) % queue->size) == queue->readp ?
			" (FULL)" : "");

	pthread_cleanup_pop(1);
}


/* Called with the seq queue mutex held */
INSERT_HASH_TABLE(seq, struct seq_queue, seq)

/* Called with the cache mutex held */
REMOVE_HASH_TABLE(seq, struct seq_queue, seq);


struct seq_queue *seq_queue_init()
{
	struct seq_queue *queue = malloc(sizeof(struct seq_queue));
	if(queue == NULL)
		MEM_ERROR();

	memset(queue, 0, sizeof(struct seq_queue));

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->wait, NULL);

	return queue;
}


void seq_queue_flush(struct seq_queue *queue)
{
	int i;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	for(i = 0; i < HASH_SIZE; i++)
		queue->hash_table[i] = NULL;

	queue->fragment_count = queue->block_count = 0;

	pthread_cleanup_pop(1);
}


void dump_seq_queue(struct seq_queue *queue, int fragment_queue)
{
	int size;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	size = fragment_queue ? queue->fragment_count : queue->block_count;

	printf("\tMax size unlimited, size %d%s\n", size,
						size == 0 ? " (EMPTY)" : "");

	pthread_cleanup_pop(1);
}


/* define main seq queue hash function */
#define CALCULATE_READER_HASH(C,N) (((C << 8) & 0xff00) | (N & 0xff))

void main_queue_put(struct seq_queue *queue, struct file_buffer *entry)
{
	int hash = CALCULATE_READER_HASH(entry->file_count, entry->block);
	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	insert_seq_hash_table(queue, entry, hash);

	if(entry->fragment)
		queue->fragment_count ++;
	else
		queue->block_count ++;

	if(entry->file_count == queue->file_count &&
						entry->block == queue->block &&
						entry->version == queue->version)
		pthread_cond_signal(&queue->wait);

	pthread_cleanup_pop(1);
}


struct file_buffer *main_queue_get(struct seq_queue *queue)
{
	/*
	 * Return next buffer from queue in sequence order (queue->file_count
	 * and queue->block).  If found return it, otherwise wait for it to
	 * arrive.
	 */
	int hash = CALCULATE_READER_HASH(queue->file_count, queue->block);
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	while(1) {
		for(entry = queue->hash_table[hash]; entry;
						entry = entry->seq_next)
			if(entry->file_count == queue->file_count &&
						entry->block == queue->block &&
						entry->version == queue->version)
				break;

		if(entry) {
			/*
			 * found the buffer in the queue, decrement the
			 * appropriate count, and remove from hash list
			 */
			if(entry->fragment)
				queue->fragment_count --;
			else
				queue->block_count --;

			remove_seq_hash_table(queue, entry, hash);

			switch(entry->next_state) {
				case NEXT_VERSION:
					queue->version ++;
					queue->block = 0;
					break;
				case NEXT_BLOCK:
					queue->block ++;
					break;
				case NEXT_FILE:
					queue->version = 0;
					queue->block = 0;
					queue->file_count ++;
					break;
				default:
					BAD_ERROR("Unknown file_buffer state!\n");
			}

			break;
		}

		/* entry not found, wait for it to arrive */
		pthread_cond_wait(&queue->wait, &queue->mutex);
	}

	pthread_cleanup_pop(1);

	return entry;
}


/* define fragment seq queue hash function */
#define CALCULATE_FRAG_HASH(N) CALCULATE_HASH(N)

void fragment_queue_put(struct seq_queue *queue, struct file_buffer *entry)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	insert_seq_hash_table(queue, entry, CALCULATE_FRAG_HASH(entry->sequence));

	if(entry->fragment)
		queue->fragment_count ++;
	else
		queue->block_count ++;

	if(entry->sequence == queue->sequence)
		pthread_cond_signal(&queue->wait);

	pthread_cleanup_pop(1);
}


struct file_buffer *fragment_queue_get(struct seq_queue *queue)
{
	/*
	 * Return next buffer from queue in sequence order (queue->sequence).  If
	 * found return it, otherwise wait for it to arrive.
	 */
	int hash = CALCULATE_FRAG_HASH(queue->sequence);
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	while(1) {
		for(entry = queue->hash_table[hash]; entry;
						entry = entry->seq_next)
			if(entry->sequence == queue->sequence)
				break;

		if(entry) {
			/*
			 * found the buffer in the queue, decrement the
			 * appropriate count, and remove from hash list
			 */
			if(entry->fragment)
				queue->fragment_count --;
			else
				queue->block_count --;

			remove_seq_hash_table(queue, entry, hash);

			queue->sequence ++;

			break;
		}

		/* entry not found, wait for it to arrive */
		pthread_cond_wait(&queue->wait, &queue->mutex);
	}

	pthread_cleanup_pop(1);

	return entry;
}


int earlier_buffer(struct file_buffer *new, struct file_buffer *old) {
	if(old->file_count == new->file_count) {
		if(old->version == new->version)
			return new->block < old->block;
		else
			return new->version < old->version;
	} else
		return new->file_count < old->file_count;
}


struct read_queue *read_queue_init()
{
	struct read_queue *queue = malloc(sizeof(struct read_queue));

	if(queue == NULL)
		MEM_ERROR();

	queue->threads = queue->count = 0;

	pthread_mutex_init(&queue->mutex, NULL);
	pthread_cond_init(&queue->empty, NULL);

	return queue;
}


void read_queue_set(struct read_queue *queue, int threads, int size)
{
	int i;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	if(add_overflow(size, 1) ||
				multiply_overflow(size + 1, sizeof(struct file_buffer *)))
		BAD_ERROR("Size too large in read_queue_init\n");

	queue->threads = threads;

	queue->thread = malloc(threads * sizeof(struct readq_thrd));
	if(queue->thread == NULL)
		MEM_ERROR();

	for(i = 0; i < threads; i++) {
		queue->thread[i].buffer = malloc(sizeof(struct file_buffer *) * (size + 1));
		if(queue->thread[i].buffer == NULL)
			MEM_ERROR();
		queue->thread[i].size = size + 1;
		queue->thread[i].readp = queue->thread[i].writep = 0;
		pthread_cond_init(&queue->thread[i].full, NULL);
	}

	pthread_cleanup_pop(1);
}


void read_queue_put(struct read_queue *queue, int id, struct file_buffer *buffer)
{
	struct readq_thrd *thread;
	int nextp;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	thread = &queue->thread[id];

	while((nextp = (thread->writep + 1) % thread->size) == thread->readp)
		pthread_cond_wait(&thread->full, &queue->mutex);

	thread->buffer[thread->writep] = buffer;
	thread->writep = nextp;
	queue->count ++;
	pthread_cond_signal(&queue->empty);
	pthread_cleanup_pop(1);
}


struct file_buffer *read_queue_get(struct read_queue *queue)
{
	struct file_buffer *buffer = NULL;
	int i, id, empty = TRUE;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	while(1) {
		for(i = 0; i < queue->threads; i++) {
			struct readq_thrd *thread = &queue->thread[i];

			if(thread->readp == thread->writep)
				continue;

			if(buffer == NULL || earlier_buffer(thread->buffer[thread->readp], buffer)) {
				buffer = thread->buffer[thread->readp];
				id = i;
				empty = FALSE;
			}
		}

		if(empty)
			pthread_cond_wait(&queue->empty, &queue->mutex);
		else
			break;
	}

	queue->thread[id].readp = (queue->thread[id].readp + 1) % queue->thread[id].size;
	queue->count --;
	pthread_cond_signal(&queue->thread[id].full);
	pthread_cleanup_pop(1);

	return buffer;
}


void read_queue_flush(struct read_queue *queue)
{
	int i;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	for(i = 0; i < queue->threads; i++)
		queue->thread[i].readp = queue->thread[i].writep;

	pthread_cleanup_pop(1);
}


void dump_read_queue(struct read_queue *queue)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &queue->mutex);
	pthread_mutex_lock(&queue->mutex);

	printf("\tSize %d%s\n", queue->count, queue->count == 0 ? " (EMPTY)" : "");

	pthread_cleanup_pop(1);
}


/* define cache hash tables */
#define CALCULATE_CACHE_HASH(N) CALCULATE_HASH(llabs(N))

/* Called with the cache mutex held */
INSERT_HASH_TABLE(cache, struct cache, hash)

/* Called with the cache mutex held */
REMOVE_HASH_TABLE(cache, struct cache, hash);

/* define cache free list */

/* Called with the cache mutex held */
INSERT_LIST(free, struct file_buffer)

/* Called with the cache mutex held */
REMOVE_LIST(free, struct file_buffer)


struct cache *cache_init(int buffer_size, int max_buffers, int noshrink_lookup,
	int first_freelist)
{
	struct cache *cache = malloc(sizeof(struct cache));

	if(cache == NULL)
		MEM_ERROR();

	cache->max_buffers = max_buffers;
	cache->buffer_size = buffer_size;
	cache->count = 0;
	cache->used = 0;
	cache->free_list = NULL;

	/*
	 * The cache will grow up to max_buffers in size in response to
	 * an increase in readhead/number of buffers in flight.  But
	 * once the outstanding buffers gets returned, we can either elect
	 * to shrink the cache, or to put the freed blocks onto a free list.
	 *
	 * For the caches where we want to do lookup (fragment/writer),
	 * a don't shrink policy is best, for the reader cache it
	 * makes no sense to keep buffers around longer than necessary as
	 * we don't do any lookup on those blocks.
	 */
	cache->noshrink_lookup = noshrink_lookup;

	/*
	 * The default use freelist before growing cache policy behaves
	 * poorly with appending - with many duplicates the caches
	 * do not grow due to the fact that large queues of outstanding
	 * fragments/writer blocks do not occur, leading to small caches
	 * and un-uncessary performance loss to frequent cache
	 * replacement in the small caches.  Therefore with appending
	 * change the policy to grow the caches before reusing blocks
	 * from the freelist
	 */
	cache->first_freelist = first_freelist;

	memset(cache->hash_table, 0, sizeof(struct file_buffer *) * HASH_SIZE);
	pthread_mutex_init(&cache->mutex, NULL);
	pthread_cond_init(&cache->wait_for_free, NULL);
	pthread_cond_init(&cache->wait_for_unlock, NULL);

	return cache;
}


struct file_buffer *cache_lookup(struct cache *cache, long long index)
{
	/* Lookup block in the cache, if found return with usage count
 	 * incremented, if not found return NULL */
	int hash = CALCULATE_CACHE_HASH(index);
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
		if(entry->used == 0) {
			remove_free_list(&cache->free_list, entry);
			cache->used ++;
		}
		entry->used ++;
	}

	pthread_cleanup_pop(1);

	return entry;
}


static struct file_buffer *cache_freelist(struct cache *cache)
{
	struct file_buffer *entry = cache->free_list;

	remove_free_list(&cache->free_list, entry);

	/* a block on the free_list is hashed */
	remove_cache_hash_table(cache, entry, CALCULATE_CACHE_HASH(entry->index));

	cache->used ++;
	return entry;
}


static struct file_buffer *cache_alloc(struct cache *cache)
{
	struct file_buffer *entry = malloc(sizeof(struct file_buffer) +
							cache->buffer_size);
	if(entry == NULL)
			MEM_ERROR();

	entry->cache = cache;
	entry->free_prev = entry->free_next = NULL;
	entry->cache_type = GEN_CACHE;
	cache->count ++;
	return entry;
}


static struct file_buffer *_cache_get(struct cache *cache, long long index,
	int hash)
{
	/* Get a free block out of the cache indexed on index. */
	struct file_buffer *entry = NULL;
 
	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	while(1) {
		if(cache->noshrink_lookup) {	
			/* first try to get a block from the free list */
			if(cache->first_freelist && cache->free_list)
				entry = cache_freelist(cache);
			else if(cache->count < cache->max_buffers) {
				entry = cache_alloc(cache);
				cache->used ++;
			} else if(!cache->first_freelist && cache->free_list)
				entry = cache_freelist(cache);
		} else { /* shrinking non-lookup cache */
			if(cache->count < cache->max_buffers) {
				entry = cache_alloc(cache);
				if(cache->count > cache->max_count)
					cache->max_count = cache->count;
			}
		}

		if(entry)
			break;

		/* wait for a block */
		pthread_cond_wait(&cache->wait_for_free, &cache->mutex);
	}

	/* initialise block and if hash is set insert into the hash table */
	entry->used = 1;
	entry->locked = FALSE;
	entry->wait_on_unlock = FALSE;
	entry->error = FALSE;
	if(hash) {
		entry->index = index;
		insert_cache_hash_table(cache, entry, CALCULATE_CACHE_HASH(entry->index));
	}

	pthread_cleanup_pop(1);

	return entry;
}


struct file_buffer *cache_get(struct cache *cache, long long index)
{
	return _cache_get(cache, index, 1);
}


struct file_buffer *cache_get_nohash(struct cache *cache)
{
	return _cache_get(cache, 0, 0);
}


void cache_hash(struct file_buffer *entry, long long index)
{
	struct cache *cache = entry->cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	entry->index = index;
	insert_cache_hash_table(cache, entry, CALCULATE_CACHE_HASH(entry->index));

	pthread_cleanup_pop(1);
}


void cache_block_put(struct file_buffer *entry)
{
	struct cache *cache;

	/*
	 * Finished with this cache entry, once the usage count reaches zero it
 	 * can be reused.
	 *
	 * If noshrink_lookup is set, put the block onto the free list.
 	 * As blocks remain accessible via the hash table they can be found
 	 * getting a new lease of life before they are reused.
	 *
	 * if noshrink_lookup is not set then shrink the cache.
	 */

	if(entry == NULL)
		return;

	if(entry->cache == NULL) {
		free(entry);
		return;
	}

	cache = entry->cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	entry->used --;
	if(entry->used == 0) {
		if(cache->noshrink_lookup) {
			insert_free_list(&cache->free_list, entry);
			cache->used --;
		} else {
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

	if(cache->noshrink_lookup)
		printf("\tMax buffers %d, Current size %d, Used %d,  %s\n",
			cache->max_buffers, cache->count, cache->used,
			cache->free_list ?  "Free buffers" : "No free buffers");
	else
		printf("\tMax buffers %d, Current size %d, Maximum historical "
			"size %d\n", cache->max_buffers, cache->count,
			cache->max_count);

	pthread_cleanup_pop(1);
}


struct file_buffer *cache_get_nowait(struct cache *cache, long long index)
{
	struct file_buffer *entry = NULL;
	/*
	 * block doesn't exist, create it, but return it with the
	 * locked flag set, so nothing tries to use it while it doesn't
	 * contain data.
	 *
	 * If there's no space in the cache then return NULL.
	 */

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	/* first try to get a block from the free list */
	if(cache->first_freelist && cache->free_list)
		entry = cache_freelist(cache);
	else if(cache->count < cache->max_buffers) {
		entry = cache_alloc(cache);
		cache->used ++;
	} else if(!cache->first_freelist && cache->free_list)
		entry = cache_freelist(cache);

	if(entry) {
		/* initialise block and insert into the hash table */
		entry->used = 1;
		entry->locked = TRUE;
		entry->wait_on_unlock = FALSE;
		entry->error = FALSE;
		entry->index = index;
		insert_cache_hash_table(cache, entry, CALCULATE_CACHE_HASH(entry->index));
	}

	pthread_cleanup_pop(1);

	return entry;
}


struct file_buffer *cache_lookup_nowait(struct cache *cache, long long index,
	char *locked)
{
	/*
	 * Lookup block in the cache, if found return it with the locked flag
	 * indicating whether it is currently locked.  In both cases increment
	 * the used count.
	 *
	 * If it doesn't exist in the cache return NULL;
	 */
	int hash = CALCULATE_CACHE_HASH(index);
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	/* first check if the entry already exists */
	for(entry = cache->hash_table[hash]; entry; entry = entry->hash_next)
		if(entry->index == index)
			break;

	if(entry) {
		if(entry->used == 0) {
			remove_free_list(&cache->free_list, entry);
			cache->used ++;
		}
		entry->used ++;
		*locked = entry->locked;
	}

	pthread_cleanup_pop(1);

	return entry;
}


void cache_wait_unlock(struct file_buffer *buffer)
{
	struct cache *cache = buffer->cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	while(buffer->locked) {
		/*
		 * another thread is filling this in, wait until it
		 * becomes unlocked.  Used has been incremented to ensure it
		 * doesn't get reused.  By definition a block can't be
		 * locked and unused, and so we don't need to worry
		 * about it being on the freelist now, but, it may
		 * become unused when unlocked unless used is
		 * incremented
		 */
		buffer->wait_on_unlock = TRUE;
		pthread_cond_wait(&cache->wait_for_unlock, &cache->mutex);
	}

	pthread_cleanup_pop(1);
}


void cache_unlock(struct file_buffer *entry)
{
	struct cache *cache = entry->cache;

	/*
	 * Unlock this locked cache entry.  If anything is waiting for this
	 * to become unlocked, wake it up.
	 */
	pthread_cleanup_push((void *) pthread_mutex_unlock, &cache->mutex);
	pthread_mutex_lock(&cache->mutex);

	entry->locked = FALSE;

	if(entry->wait_on_unlock) {
		entry->wait_on_unlock = FALSE;
		pthread_cond_broadcast(&cache->wait_for_unlock);
	}

	pthread_cleanup_pop(1);
}


/* Called with the cache mutex held */
INSERT_HASH_TABLE(queue_cache, struct queue_cache, hash)

/* Called with the cache mutex held */
REMOVE_HASH_TABLE(queue_cache, struct queue_cache, hash);


struct queue_cache *queue_cache_init(pthread_mutex_t *mutex, int buffer_size,
	int first_freelist)
{
	struct queue_cache *qc = malloc(sizeof(struct queue_cache));

	if(qc == NULL)
		MEM_ERROR();

	qc->buffer_size = buffer_size;
	qc->first_freelist = first_freelist;
	qc->mutex = mutex;
	pthread_cond_init(&qc->wait_for_buffer, NULL);
	qc->waiting = qc->threads = qc->count = 0;
	qc->rthread = NULL;
	qc->wthread = NULL;
	memset(qc->hash_table, 0, sizeof(struct file_buffer *) * HASH_SIZE);

	return qc;
}


void queue_cache_set(struct queue_cache *qc, int fthreads, int fbuffers,
	int bthreads, int bbuffers, int size)
{
	int i, threads = fthreads + bthreads;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	if(add_overflow(size, 1) ||
				multiply_overflow(size + 1, sizeof(struct file_buffer *)))
		BAD_ERROR("Size too large in queue_cache_set\n");

	qc->rthread = malloc(threads * sizeof(struct readq_thrd));
	if(qc->rthread == NULL)
		MEM_ERROR();

	qc->wthread = malloc(sizeof(struct writeq_thrd) * threads);
	if(qc->wthread == NULL)
		MEM_ERROR();

	for(i = 0; i < threads; i++) {
		qc->rthread[i].buffer = malloc(sizeof(struct file_buffer *) * (size + 1));
		if(qc->rthread[i].buffer == NULL)
			MEM_ERROR();
		qc->rthread[i].size = size + 1;
		qc->rthread[i].readp = qc->rthread[i].writep = 0;
		pthread_cond_init(&qc->rthread[i].full, NULL);

		qc->wthread[i].max_buffers = i < fthreads ? fbuffers : bbuffers;
		qc->wthread[i].count = 0;
		qc->wthread[i].used = 0;
		qc->wthread[i].free_list = NULL;
	}

	qc->threads = threads;

	pthread_cleanup_pop(1);
}


struct file_buffer *queue_cache_lookup(struct queue_cache *qc, long long index)
{
	/* Lookup block in the cache, if found return with usage count
	 * incremented, if not found return NULL */
	int hash = CALCULATE_CACHE_HASH(index);
	struct file_buffer *entry;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	for(entry = qc->hash_table[hash]; entry; entry = entry->hash_next)
		if(entry->index == index)
			break;

	if(entry) {
		/* found the block in the cache, increment used count and
		 * if necessary remove from free list so it won't disappear
		 */
		if(entry->used == 0) {
			remove_free_list(&qc->wthread[entry->thread].free_list, entry);
			qc->wthread[entry->thread].used ++;
		}
		entry->used ++;
	}

	pthread_cleanup_pop(1);

	return entry;
}


static struct file_buffer *queue_cache_freelist(struct queue_cache *qc,
	struct writeq_thrd *thread)
{
	struct file_buffer *entry = thread->free_list;

	remove_free_list(&thread->free_list, entry);

	/* a block on the free_list is hashed */
	if(entry->hashed)
		remove_queue_cache_hash_table(qc, entry, CALCULATE_CACHE_HASH(entry->index));

	thread->used ++;
	return entry;
}


static struct file_buffer *queue_cache_alloc(struct queue_cache *qc,
	struct writeq_thrd *thread, int i)
{
	struct file_buffer *entry = malloc(sizeof(struct file_buffer) +
							qc->buffer_size);
	if(entry == NULL)
		MEM_ERROR();

	entry->queue_cache = qc;
	entry->thread = i;
	entry->free_prev = entry->free_next = NULL;
	entry->cache_type = QUEUE_CACHE;
	thread->count ++;
	thread->used ++;
	return entry;
}


void queue_cache_hash(struct file_buffer *entry, long long index)
{
	struct queue_cache *qc = entry->queue_cache;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	entry->index = index;
	entry->hashed = TRUE;
	insert_queue_cache_hash_table(qc, entry, CALCULATE_CACHE_HASH(entry->index));

	pthread_cleanup_pop(1);
}


void queue_cache_block_put(struct file_buffer *entry)
{
	struct queue_cache *qc;
	struct writeq_thrd *thread;

	/*
	 * Finished with this cache entry, once the usage count reaches zero it
	 * can be reused.
	 *
	 * Put the block onto the free list.  As blocks remain accessible via
	 * the hash table they can be found getting a new lease of life before
	 * they are reused.
	 */

	if(entry == NULL)
		return;

	qc = entry->queue_cache;
	thread = &qc->wthread[entry->thread];

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	entry->used --;
	if(entry->used == 0) {
		insert_free_list(&thread->free_list, entry);
		thread->used --;
		if(qc->waiting)
			pthread_cond_signal(&qc->wait_for_buffer);
	}

	pthread_cleanup_pop(1);
}


void dump_write_cache(struct queue_cache *qc)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	int i;

	for(i = 0; i < qc->threads; i++) {
		printf("block write cache %d (compressed blocks waiting for the writer thread)\n", i + 1);
		printf("\tMax buffers %d, Current size %d, Used %d,  %s\n",
			qc->wthread[i].max_buffers, qc->wthread[i].count,
			qc->wthread[i].used, qc->wthread[i].free_list ?
			"Free buffers" : "No free buffers");
	}

	pthread_cleanup_pop(1);
}


void queue_cache_put(struct queue_cache *qc, int id, struct file_buffer *buffer)
{
	struct readq_thrd *thread;
	int nextp;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	thread = &qc->rthread[id];

	while((nextp = (thread->writep + 1) % thread->size) == thread->readp)
		pthread_cond_wait(&thread->full, qc->mutex);

	thread->buffer[thread->writep] = buffer;
	thread->writep = nextp;
	qc->count ++;
	if(qc->waiting)
		pthread_cond_signal(&qc->wait_for_buffer);
	pthread_cleanup_pop(1);
}


struct file_buffer *queue_cache_get_tid(int tid, struct queue_cache *qc, struct file_buffer **wbuffer)
{
	struct file_buffer *rbuffer = NULL;
	struct readq_thrd *rthread;
	struct writeq_thrd *wthread;
	int i;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	while(1) {
		wait_thread_idle(tid, qc->mutex);

		for(i = 0; i < qc->threads; i++) {
			struct readq_thrd *rthrd = &qc->rthread[i];
			struct writeq_thrd *wthrd = &qc->wthread[i];

			/* Skip if thread read queue is empty */
			if(rthrd->readp == rthrd->writep)
				continue;

			/* Skip if no thread cache buffers are available */
			if(!wthrd->free_list && wthrd->count == wthrd->max_buffers)
				continue;

			if(rbuffer == NULL || earlier_buffer(rthrd->buffer[rthrd->readp], rbuffer)) {
				rbuffer = rthrd->buffer[rthrd->readp];
				rthread = rthrd;
				wthread = wthrd;
			}
		}

		if(rbuffer == NULL) {
			set_thread_idle(tid);
			qc->waiting ++;
			pthread_cond_wait(&qc->wait_for_buffer, qc->mutex);
			qc->waiting --;
		} else
			break;
	}

	/* Remove rbuffer from queue */
	rthread->readp = (rthread->readp + 1) % rthread->size;
	qc->count --;
	pthread_cond_signal(&rthread->full);

	/* Get wbuffer from cache */
	if(qc->first_freelist && wthread->free_list)
		*wbuffer = queue_cache_freelist(qc, wthread);
	else if(wthread->count < wthread->max_buffers)
		*wbuffer = queue_cache_alloc(qc, wthread, wthread - &qc->wthread[0]);
	else if(!qc->first_freelist && wthread->free_list)
		*wbuffer = queue_cache_freelist(qc, wthread);
	else
		BAD_ERROR("Bug in queue_cache_get_tid()");

	/* initialise block */
	(*wbuffer)->used = 1;
	(*wbuffer)->locked = FALSE;
	(*wbuffer)->wait_on_unlock = FALSE;
	(*wbuffer)->error = FALSE;
	(*wbuffer)->hashed = FALSE;

	pthread_cleanup_pop(1);

	return rbuffer;
}


void queue_cache_flush(struct queue_cache *qc)
{
	int i;

	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	for(i = 0; i < qc->threads; i++)
		qc->rthread[i].readp = qc->rthread[i].writep;

	pthread_cleanup_pop(1);
}


void dump_block_read_queue(struct queue_cache *qc)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, qc->mutex);
	pthread_mutex_lock(qc->mutex);

	printf("\tSize %d%s\n", qc->count, qc->count == 0 ? " (EMPTY)" : "");

	pthread_cleanup_pop(1);
}
