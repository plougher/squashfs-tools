#ifndef CACHES_QUEUES_LISTS_H
#define CACHES_QUEUES_LISTS_H
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
 * caches-queues-lists.h
 */

#define INSERT_LIST(NAME, TYPE) \
void insert_##NAME##_list(TYPE **list, TYPE *entry) { \
	if(*list) { \
		entry->NAME##_next = *list; \
		entry->NAME##_prev = (*list)->NAME##_prev; \
		(*list)->NAME##_prev->NAME##_next = entry; \
		(*list)->NAME##_prev = entry; \
	} else { \
		*list = entry; \
		entry->NAME##_prev = entry->NAME##_next = entry; \
	} \
}


#define REMOVE_LIST(NAME, TYPE) \
void remove_##NAME##_list(TYPE **list, TYPE *entry) { \
	if(entry->NAME##_prev == entry && entry->NAME##_next == entry) { \
		/* only this entry in the list */ \
		*list = NULL; \
	} else if(entry->NAME##_prev != NULL && entry->NAME##_next != NULL) { \
		/* more than one entry in the list */ \
		entry->NAME##_next->NAME##_prev = entry->NAME##_prev; \
		entry->NAME##_prev->NAME##_next = entry->NAME##_next; \
		if(*list == entry) \
			*list = entry->NAME##_next; \
	} \
	entry->NAME##_prev = entry->NAME##_next = NULL; \
}


#define INSERT_HASH_TABLE(NAME, TYPE, LINK) \
void insert_##NAME##_hash_table(TYPE *container, struct file_buffer *entry, int hash) \
{ \
	entry->LINK##_next = container->hash_table[hash]; \
	container->hash_table[hash] = entry; \
	entry->LINK##_prev = NULL; \
	if(entry->LINK##_next) \
		entry->LINK##_next->LINK##_prev = entry; \
}


#define REMOVE_HASH_TABLE(NAME, TYPE, LINK) \
void remove_##NAME##_hash_table(TYPE *container, struct file_buffer *entry, int hash) \
{ \
	if(entry->LINK##_prev) \
		entry->LINK##_prev->LINK##_next = entry->LINK##_next; \
	else \
		container->hash_table[hash] = entry->LINK##_next; \
	if(entry->LINK##_next) \
		entry->LINK##_next->LINK##_prev = entry->LINK##_prev; \
\
	entry->LINK##_prev = entry->LINK##_next = NULL; \
}

#define HASH_SIZE 65536
#define CALCULATE_HASH(n) ((n) & 0xffff)


#define NEXT_BLOCK	1
#define NEXT_FILE	2
#define NEXT_VERSION	3

#define QUEUE_CACHE	1
#define GEN_CACHE	2

/* struct describing a cache entry passed between threads */
struct file_buffer {
	long long index;
	union {
		long long sequence;
		long long file_count;
	};
	long long file_size;
	long long block;
	union {
		struct cache		*cache;
		struct queue_cache	*queue_cache;
	};
	union {
		struct file_info *dupl_start;
		struct file_buffer *hash_next;
	};
	union {
		struct tar_file *tar_file;
		struct file_buffer *hash_prev;
	};
	union {
		struct {
			struct file_buffer *free_next;
			struct file_buffer *free_prev;
		};
		struct {
			struct file_buffer *seq_next;
			struct file_buffer *seq_prev;
		};
	};
	int size;
	int c_byte;
	unsigned short checksum;
	unsigned short version;
	unsigned short thread;
	char used;
	char fragment;
	char error;
	char locked;
	char wait_on_unlock;
	char noD;
	char duplicate;
	char next_state;
	char cache_type;
	char hashed;
	char data[0] __attribute__((aligned));
};


/* struct describing queues used to pass data between threads */
struct queue {
	int			size;
	int			readp;
	int			writep;
	pthread_mutex_t		*mutex;
	pthread_cond_t		empty;
	pthread_cond_t		full;
	void			**data;
};


/*
 * struct describing seq_queues used to pass data between the deflate
 * threads/process fragment threads and the main thread
 */
struct seq_queue {
	unsigned short		version;
	int			fragment_count;
	int			block_count;
	long long		sequence;
	long long		file_count;
	long long		block;
	struct file_buffer	*hash_table[HASH_SIZE];
	pthread_mutex_t		mutex;
	pthread_cond_t		wait;
};


/*
 * struct describing seq_queues used to pass data between the reader
 * threads and the deflate threads/process fragment threads
 */
struct readq_thrd {
	int			size;
	struct file_buffer	**buffer;
	int			readp;
	int			writep;
	pthread_cond_t		full;
};


struct read_queue {
	int			threads;
	int			count;
	pthread_mutex_t		mutex;
	pthread_cond_t		empty;
	struct readq_thrd	*thread;
};


/* Cache status struct.  Caches are used to keep
  track of memory buffers passed between different threads */
struct cache {
	int	max_buffers;
	int	count;
	int	buffer_size;
	int	noshrink_lookup;
	int	first_freelist;
	union {
		int	used;
		int	max_count;
	};
	pthread_mutex_t	mutex;
	pthread_cond_t wait_for_free;
	pthread_cond_t wait_for_unlock;
	struct file_buffer *free_list;
	struct file_buffer *hash_table[HASH_SIZE];
};


/*
 * Specialised combined queue and cache for managing buffers
 * sent from the reader threads to the block deflator threads,
 * and which also creates writer buffers, so that reader
 * buffers and write buffers are returned in one atomic operation.
 */
struct writeq_thrd {
	int			max_buffers;
	int			count;
	int			used;
	struct file_buffer	*free_list;
};


struct queue_cache {
	int			buffer_size;
	int			first_freelist;
	int			threads;
	int			count;
	int			waiting;
	pthread_cond_t		wait_for_buffer;
	pthread_mutex_t		*mutex;
	struct file_buffer	*hash_table[HASH_SIZE];
	struct readq_thrd	*rthread;
	struct writeq_thrd	*wthread;
};


extern struct queue *queue_init(int, pthread_mutex_t *mutex);
extern void queue_put(struct queue *, void *);
extern void *queue_get(struct queue *);
extern int queue_empty(struct queue *);
extern void queue_flush(struct queue *);
extern void *queue_get_tid(int tid, struct queue *);
extern void dump_queue(struct queue *);
extern struct seq_queue *seq_queue_init();
extern void dump_seq_queue(struct seq_queue *, int);
extern void seq_queue_flush(struct seq_queue *);
extern void main_queue_put(struct seq_queue *, struct file_buffer *);
extern void fragment_queue_put(struct seq_queue *, struct file_buffer *);
extern struct file_buffer *main_queue_get(struct seq_queue *);
extern struct file_buffer *fragment_queue_get(struct seq_queue *);
extern struct read_queue *read_queue_init();
extern void read_queue_set(struct read_queue *, int, int);
extern void read_queue_put(struct read_queue *, int, struct file_buffer *);
extern struct file_buffer *read_queue_get(struct read_queue *);
extern void read_queue_flush(struct read_queue *);
extern void dump_read_queue(struct read_queue *);
extern struct cache *cache_init(int, int, int, int);
extern struct file_buffer *cache_lookup(struct cache *, long long);
extern struct file_buffer *cache_get(struct cache *, long long);
extern struct file_buffer *cache_get_nohash(struct cache *);
extern void cache_hash(struct file_buffer *, long long);
extern void cache_block_put(struct file_buffer *);
extern void dump_cache(struct cache *);
extern struct file_buffer *cache_get_nowait(struct cache *, long long);
extern struct file_buffer *cache_lookup_nowait(struct cache *, long long,
	char *);
extern void cache_wait_unlock(struct file_buffer *);
extern void cache_unlock(struct file_buffer *);
extern struct queue_cache *queue_cache_init(pthread_mutex_t *, int, int);
void queue_cache_set(struct queue_cache *, int, int, int, int, int);
extern struct file_buffer *queue_cache_lookup(struct queue_cache *, long long);
extern void queue_cache_hash(struct file_buffer *, long long);
extern void queue_cache_block_put(struct file_buffer *);
extern void dump_write_cache(struct queue_cache *);
extern void queue_cache_put(struct queue_cache *, int, struct file_buffer *);
extern struct file_buffer *queue_cache_get_tid(int, struct queue_cache *, struct file_buffer **);
extern void queue_cache_flush(struct queue_cache *);
extern void dump_block_read_queue(struct queue_cache *);

static inline void gen_cache_block_put(struct file_buffer *entry)
{
	if(entry == NULL)
		return;
	else if(entry->cache_type == GEN_CACHE)
		cache_block_put(entry);
	else if(entry->cache_type == QUEUE_CACHE)
		queue_cache_block_put(entry);
	else
		BAD_ERROR("Bug in gen_cache_block_put\n");
}


static inline int cache_maxsize(struct file_buffer *entry)
{
	if(entry == NULL)
		BAD_ERROR("Bug in cache_maxsize\n");
	else if(entry->cache_type == GEN_CACHE)
		return entry->cache->max_buffers;
	else if(entry->cache_type == QUEUE_CACHE)
		return entry->queue_cache->wthread[entry->thread].max_buffers;
	else
		BAD_ERROR("Bug in block handling\n");
}


#endif
