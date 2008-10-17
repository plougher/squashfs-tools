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
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * cache.c
 */

/*
 * Blocks in Squashfs are compressed.  To avoid repeatedly decompressing
 * recently accessed data Squashfs uses two small metadata and fragment caches.
 *
 * This file implements a generic cache implementation used for both caches,
 * plus functions layered ontop of the generic cache implementation to
 * access the metadata and fragment caches.
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

/*
 * Look-up block in cache, and increment usage count.  If not in cache, read
 * and decompress it from disk.
 */
struct squashfs_cache_entry *squashfs_cache_get(struct super_block *s,
	struct squashfs_cache *cache, long long block, int length)
{
	int i, n;
	struct squashfs_cache_entry *entry;

	spin_lock(&cache->lock);

	while (1) {
		for (i = 0; i < cache->entries; i++)
			if (cache->entry[i].block == block)
				break;

		if (i == cache->entries) {
			/*
			 * Block not in cache, if all cache entries are locked
			 * go to sleep waiting for one to become available.
			 */
			if (cache->unused == 0) {
				cache->waiting++;
				spin_unlock(&cache->lock);
				wait_event(cache->wait_queue, cache->unused);
				spin_lock(&cache->lock);
				cache->waiting--;
				continue;
			}

			/*
			 * At least one unlocked cache entry.  A simple
			 * round-robin strategy is used to choose the entry to
			 * be evicted from the cache.
			 */
			i = cache->next_blk;
			for (n = 0; n < cache->entries; n++) {
				if (cache->entry[i].locked == 0)
					break;
				i = (i + 1) % cache->entries;
			}

			cache->next_blk = (i + 1) % cache->entries;
			entry = &cache->entry[i];

			/*
			 * Initialise choosen cache entry, and fill it in from
			 * disk.
			 */
			cache->unused--;
			entry->block = block;
			entry->locked = 1;
			entry->pending = 1;
			entry->waiting = 0;
			entry->error = 0;
			spin_unlock(&cache->lock);

			entry->length = squashfs_read_data(s, entry->data,
				block, length, &entry->next_index,
				cache->block_size);

			spin_lock(&cache->lock);

			if (entry->length == 0)
				entry->error = 1;

			entry->pending = 0;
			spin_unlock(&cache->lock);

			/*
			 * While filling this entry one or more other processes
			 * have looked it up in the cache, and have slept
			 * waiting for it to become available.
			 */
			if (entry->waiting)
				wake_up_all(&entry->wait_queue);
			goto out;
		}

		/*
		 * Block already in cache.  Increment lock so it doesn't
		 * get reused until we're finished with it, if it was
		 * previously unlocked there's one less cache entry available
		 * for reuse.
		 */
		entry = &cache->entry[i];
		if (entry->locked == 0)
			cache->unused--;
		entry->locked++;

		/*
		 * If the entry is currently being filled in by another process
		 * go to sleep waiting for it to become available.
		 */
		if (entry->pending) {
			entry->waiting++;
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
		ERROR("Unable to read %s cache entry [%llx]\n", cache->name,
							block);
	return entry;
}


/*
 * Release block, once usage count is zero it can be reused.
 */
void squashfs_cache_put(struct squashfs_cache *cache,
				struct squashfs_cache_entry *entry)
{
	spin_lock(&cache->lock);
	entry->locked--;
	if (entry->locked == 0) {
		cache->unused++;
		spin_unlock(&cache->lock);
		/*
		 * If there's any processes waiting for a block to become
		 * available, wake one up.
		 */
		if (cache->waiting)
			wake_up(&cache->wait_queue);
	} else {
		spin_unlock(&cache->lock);
	}
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
	struct squashfs_cache *cache = kzalloc(sizeof(*cache) + entries *
			sizeof(*(cache->entry)), GFP_KERNEL);

	if (cache == NULL) {
		ERROR("Failed to allocate %s cache\n", name);
		goto failed;
	}

	cache->next_blk = 0;
	cache->unused = entries;
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


/*
 * Read length bytes from metadata position <block, offset> (block is the
 * start of the compressed block on disk, and offset is the offset into
 * the block once decompressed).  Data is packed into consecutive blocks,
 * and length bytes may require reading more than one block.
 */
int squashfs_read_metadata(struct super_block *s, void *buffer,
				long long block, unsigned int offset,
				int length, long long *next_block,
				unsigned int *next_offset)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;
	int bytes, return_length = length;
	struct squashfs_cache_entry *entry;

	TRACE("Entered squashfs_read_metadata [%llx:%x]\n", block, offset);

	while (1) {
		entry = squashfs_cache_get(s, msblk->block_cache, block, 0);
		bytes = entry->length - offset;

		if (entry->error || bytes < 1) {
			return_length = 0;
			goto finish;
		} else if (bytes >= length) {
			if (buffer)
				memcpy(buffer, entry->data + offset, length);
			if (entry->length - offset == length) {
				*next_block = entry->next_index;
				*next_offset = 0;
			} else {
				*next_block = block;
				*next_offset = offset + length;
			}
			goto finish;
		} else {
			if (buffer) {
				memcpy(buffer, entry->data + offset, bytes);
				buffer += bytes;
			}
			block = entry->next_index;
			squashfs_cache_put(msblk->block_cache, entry);
			length -= bytes;
			offset = 0;
		}
	}

finish:
	squashfs_cache_put(msblk->block_cache, entry);
	return return_length;
}


struct squashfs_cache_entry *get_cached_fragment(struct super_block *s,
				long long start_block, int length)
{
	struct squashfs_sb_info *msblk = s->s_fs_info;

	return squashfs_cache_get(s, msblk->fragment_cache, start_block,
		length);
}


void release_cached_fragment(struct squashfs_sb_info *msblk,
				struct squashfs_cache_entry *fragment)
{
	squashfs_cache_put(msblk->fragment_cache, fragment);
}

