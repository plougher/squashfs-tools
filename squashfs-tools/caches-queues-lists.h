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
 * caches-queues-lists.h
 */

/* struct describing a cache entry passed between threads */
struct file_buffer {
	struct cache *cache;
	struct file_buffer *hash_next;
	struct file_buffer *hash_prev;
	struct file_buffer *free_next;
	struct file_buffer *free_prev;
	struct file_buffer *next;
	long long file_size;
	long long index;
	long long block;
	long long sequence;
	int size;
	int c_byte;
	char keep;
	char used;
	char fragment;
	char error;
	char noD;
	char data[0];
};


/* struct describing queues used to pass data between threads */
struct queue {
	int			size;
	int			readp;
	int			writep;
	pthread_mutex_t		mutex;
	pthread_cond_t		empty;
	pthread_cond_t		full;
	void			**data;
};


/* Cache status struct.  Caches are used to keep
  track of memory buffers passed between different threads */
struct cache {
	int	max_buffers;
	int	count;
	int	buffer_size;
	int	first_freelist;
	pthread_mutex_t	mutex;
	pthread_cond_t wait_for_free;
	struct file_buffer *free_list;
	struct file_buffer *hash_table[65536];
};


struct frag_locked {
	struct file_buffer *buffer;
	int c_byte;
	int fragment;
	struct frag_locked *fragment_prev;
	struct frag_locked *fragment_next;
};


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

extern struct queue *queue_init(int);
extern void queue_put(struct queue *, void *);
extern void *queue_get(struct queue *);
extern void dump_queue(struct queue *);
extern struct cache *cache_init(int, int, int);
extern struct file_buffer *cache_lookup(struct cache *, long long);
extern struct file_buffer *cache_get(struct cache *, long long, int);
extern void cache_rehash(struct file_buffer *, long long);
extern void cache_block_put(struct file_buffer *);
extern void insert_fragment_list(struct frag_locked **, struct frag_locked *);
extern void remove_fragment_list(struct frag_locked **, struct frag_locked *);

extern int first_freelist;

