/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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
 * cache.c
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

struct squashfs_cache_entry *squashfs_cache_get(struct super_block *s,
	struct squashfs_cache *cache, long long block, int length)
{
	int i, n;
	struct squashfs_cache_entry *entry;

	spin_lock(&cache->lock);

	while (1) {
		for (i = 0; i < cache->entries && cache->entry[i].block != block; i++);

		if (i == cache->entries) {
			if (cache->unused_blks == 0) {
				cache->waiting ++;
				spin_unlock(&cache->lock);
				wait_event(cache->wait_queue, cache->unused_blks);
				spin_lock(&cache->lock);
				cache->waiting --;
				continue;
			}

			i = cache->next_blk;
			for (n = 0; n < cache->entries; n++) {
				if (cache->entry[i].locked == 0)
					break;
				i = (i + 1) % cache->entries;
			}

			cache->next_blk = (i + 1) % cache->entries;
			entry = &cache->entry[i];

			cache->unused_blks --;
			entry->block = block;
			entry->locked = 1;
			entry->pending = 1;
			entry->waiting = 0;
			entry->error = 0;
			spin_unlock(&cache->lock);

			entry->length = squashfs_read_data(s, entry->data,
				block, length, &entry->next_index, cache->block_size);

			spin_lock(&cache->lock);

			if (entry->length == 0)
				entry->error = 1;

			entry->pending = 0;
			spin_unlock(&cache->lock);
			if (entry->waiting)
				wake_up_all(&entry->wait_queue);
			goto out;
		}

		entry = &cache->entry[i];
		if (entry->locked == 0)
			cache->unused_blks --;
		entry->locked++;

		if (entry->pending) {
			entry->waiting ++;
			spin_unlock(&cache->lock);
			wait_event(entry->wait_queue, !entry->pending);
			goto out;
		}

		spin_unlock(&cache->lock);
		goto out;
	}

out:
	TRACE("Got %s %d, start block %lld, locked %d, error %d\n", cache->name,
		i, entry->block, entry->locked, entry->error);
	if (entry->error)
		ERROR("Unable to read %s cache entry [%llx]\n", cache->name, block);
	return entry;
}


void squashfs_cache_put(struct squashfs_cache *cache,
				struct squashfs_cache_entry *entry)
{
	spin_lock(&cache->lock);
	entry->locked --;
	if (entry->locked == 0) {
		cache->unused_blks ++;
		spin_unlock(&cache->lock);
		if (cache->waiting)
			wake_up(&cache->wait_queue);
	} else
		spin_unlock(&cache->lock);
}


void squashfs_cache_delete(struct squashfs_cache *cache)
{
	int i;

	if (cache == NULL)
		return;

	for (i = 0; i < cache->entries; i++)
		if (cache->entry[i].data) {
			if (cache->use_vmalloc)
				vfree(cache->entry[i].data);
			else
				kfree(cache->entry[i].data);
		}

	kfree(cache);
}


struct squashfs_cache *squashfs_cache_init(char *name, int entries,
	int block_size, int use_vmalloc)
{
	int i;
	struct squashfs_cache *cache = kzalloc(sizeof(struct squashfs_cache) +
			entries * sizeof(struct squashfs_cache_entry), GFP_KERNEL);
	if (cache == NULL) {
		ERROR("Failed to allocate %s cache\n", name);
		goto failed;
	}

	cache->next_blk = 0;
	cache->unused_blks = entries;
	cache->entries = entries;
	cache->block_size = block_size;
	cache->use_vmalloc = use_vmalloc;
	cache->name = name;
	cache->waiting = 0;
	spin_lock_init(&cache->lock);
	init_waitqueue_head(&cache->wait_queue);

	for (i = 0; i < entries; i++) {
		init_waitqueue_head(&cache->entry[i].wait_queue);
		cache->entry[i].block = SQUASHFS_INVALID_BLK;
		cache->entry[i].data = use_vmalloc ? vmalloc(block_size) :
				kmalloc(block_size, GFP_KERNEL);
		if (cache->entry[i].data == NULL) {
			ERROR("Failed to allocate %s cache entry\n", name);
			goto cleanup;
		}
	}

	return cache;

cleanup:
	squashfs_cache_delete(cache);
failed:
	return NULL;
}
