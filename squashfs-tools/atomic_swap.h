#ifndef ATOMIC_SWAP_H
#define ATOMIC_SWAP_H

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
 * atomic_swap.h
 */

#ifdef DONT_USE_ATOMIC_EXCHANGE_N
static inline struct read_entry *atomic_swap(struct read_entry **entry,
					pthread_mutex_t *mutex)
{
	struct read_entry *value;

	pthread_cleanup_push((void *) pthread_mutex_unlock, mutex);
	pthread_mutex_lock(mutex);

	value = *entry;
	*entry = NULL;

	pthread_cleanup_pop(1);

	return value;
}
#else
static inline struct read_entry *atomic_swap(struct read_entry **entry,
					pthread_mutex_t *mutex)
{
	return __atomic_exchange_n(entry, NULL, __ATOMIC_SEQ_CST);
}
#endif
#endif
