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
 * file.c
 */

/*
 * This file contains code for handling regular files.  A regular file
 * consists of a sequence of contiguous compressed blocks, and/or a
 * compressed fragment block (tail-end packed block).   The compressed size
 * of each datablock is stored in a blocklist contained within the 
 * file inode (itself stored in one or more compressed metadata blocks).
 *
 * To speed up access to datablocks when reading 'large' files (256 Mbytes or
 * larger), the code implements an index cache that caches the mapping from
 * block index to datablock location on disk.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/mutex.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static struct meta_index *locate_meta_index(struct inode *inode, int index,
				int offset)
{
	struct meta_index *meta = NULL;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int i;

	mutex_lock(&msblk->meta_index_mutex);

	TRACE("locate_meta_index: index %d, offset %d\n", index, offset);

	if (msblk->meta_index == NULL)
		goto not_allocated;

	for (i = 0; i < SQUASHFS_META_NUMBER; i++) {
		if (msblk->meta_index[i].inode_number == inode->i_ino &&
				msblk->meta_index[i].offset >= offset &&
				msblk->meta_index[i].offset <= index &&
				msblk->meta_index[i].locked == 0) {
			TRACE("locate_meta_index: entry %d, offset %d\n", i,
					msblk->meta_index[i].offset);
			meta = &msblk->meta_index[i];
			offset = meta->offset;
		}
	}

	if (meta)
		meta->locked = 1;

not_allocated:
	mutex_unlock(&msblk->meta_index_mutex);

	return meta;
}


static struct meta_index *empty_meta_index(struct inode *inode, int offset,
				int skip)
{
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	struct meta_index *meta = NULL;
	int i;

	mutex_lock(&msblk->meta_index_mutex);

	TRACE("empty_meta_index: offset %d, skip %d\n", offset, skip);

	if (msblk->meta_index == NULL) {
		msblk->meta_index = kmalloc(sizeof(struct meta_index) *
					SQUASHFS_META_NUMBER, GFP_KERNEL);
		if (msblk->meta_index == NULL) {
			ERROR("Failed to allocate meta_index\n");
			goto failed;
		}
		for (i = 0; i < SQUASHFS_META_NUMBER; i++) {
			msblk->meta_index[i].inode_number = 0;
			msblk->meta_index[i].locked = 0;
		}
		msblk->next_meta_index = 0;
	}

	for (i = SQUASHFS_META_NUMBER; i &&
			msblk->meta_index[msblk->next_meta_index].locked; i--)
		msblk->next_meta_index = (msblk->next_meta_index + 1) %
			SQUASHFS_META_NUMBER;

	if (i == 0) {
		TRACE("empty_meta_index: failed!\n");
		goto failed;
	}

	TRACE("empty_meta_index: returned meta entry %d, %p\n",
			msblk->next_meta_index,
			&msblk->meta_index[msblk->next_meta_index]);

	meta = &msblk->meta_index[msblk->next_meta_index];
	msblk->next_meta_index = (msblk->next_meta_index + 1) %
			SQUASHFS_META_NUMBER;

	meta->inode_number = inode->i_ino;
	meta->offset = offset;
	meta->skip = skip;
	meta->entries = 0;
	meta->locked = 1;

failed:
	mutex_unlock(&msblk->meta_index_mutex);
	return meta;
}


static void release_meta_index(struct inode *inode, struct meta_index *meta)
{
	meta->locked = 0;
	smp_mb();
}


static int read_block_index(struct super_block *s, int blocks, void *block_list,
				long long *start_block, int *offset)
{
	__le32 *blist = block_list;
	int i, block = 0;

	if (!squashfs_get_cached_block(s, block_list, *start_block,
			*offset, blocks << 2, start_block, offset)) {
		ERROR("Fail reading block list [%llx:%x]\n", *start_block,
			*offset);
		goto failure;
	}

	for (i = 0; i < blocks; i++)
		block += SQUASHFS_COMPRESSED_SIZE_BLOCK(le32_to_cpu(blist[i]));

	return block;

failure:
	return -1;
}


static inline int calculate_skip(int blocks)
{
	int skip = (blocks - 1) / ((SQUASHFS_SLOTS * SQUASHFS_META_ENTRIES + 1)
		 * SQUASHFS_META_INDEXES);
	return skip >= 7 ? 7 : skip + 1;
}


static int get_meta_index(struct inode *inode, int index,
		long long *index_block, int *index_offset,
		long long *data_block, void *block_list)
{
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	int skip = calculate_skip(i_size_read(inode) >> msblk->block_log);
	int offset = 0;
	struct meta_index *meta;
	struct meta_entry *meta_entry;
	long long cur_index_block = SQUASHFS_I(inode)->block_list_start;
	int cur_offset = SQUASHFS_I(inode)->offset;
	long long cur_data_block = SQUASHFS_I(inode)->start_block;
	int i;

	index /= SQUASHFS_META_INDEXES * skip;

	while (offset < index) {
		meta = locate_meta_index(inode, index, offset + 1);

		if (meta == NULL) {
			meta = empty_meta_index(inode, offset + 1, skip);
			if (meta == NULL)
				goto all_done;
		} else {
			if (meta->entries == 0)
				goto failed;
			offset = index < meta->offset + meta->entries ? index :
				meta->offset + meta->entries - 1;
			meta_entry = &meta->meta_entry[offset - meta->offset];
			cur_index_block = meta_entry->index_block +
				msblk->inode_table_start;
			cur_offset = meta_entry->offset;
			cur_data_block = meta_entry->data_block;
			TRACE("get_meta_index: offset %d, meta->offset %d, "
				"meta->entries %d\n", offset, meta->offset,
				meta->entries);
			TRACE("get_meta_index: index_block 0x%llx, offset 0x%x"
				" data_block 0x%llx\n", cur_index_block,
				cur_offset, cur_data_block);
		}

		for (i = meta->offset + meta->entries; i <= index &&
				i < meta->offset + SQUASHFS_META_ENTRIES; i++) {
			int blocks = skip * SQUASHFS_META_INDEXES;

			while (blocks) {
				int block = min(PAGE_CACHE_SIZE >> 2, blocks);
				int res = read_block_index(inode->i_sb, block,
					block_list, &cur_index_block,
					&cur_offset);

				if (res == -1)
					goto failed;

				cur_data_block += res;
				blocks -= block;
			}

			meta_entry = &meta->meta_entry[i - meta->offset];
			meta_entry->index_block = cur_index_block -
				msblk->inode_table_start;
			meta_entry->offset = cur_offset;
			meta_entry->data_block = cur_data_block;
			meta->entries++;
			offset++;
		}

		TRACE("get_meta_index: meta->offset %d, meta->entries %d\n",
				meta->offset, meta->entries);

		release_meta_index(inode, meta);
	}

all_done:
	*index_block = cur_index_block;
	*index_offset = cur_offset;
	*data_block = cur_data_block;

	return offset * SQUASHFS_META_INDEXES * skip;

failed:
	release_meta_index(inode, meta);
	return -1;
}


long long read_blocklist(struct inode *inode, int index, void *block_list,
				unsigned int *bsize)
{
	long long block_ptr;
	int offset;
	long long block;
	__le32 *blist = block_list;
	int res = get_meta_index(inode, index, &block_ptr, &offset, &block,
		block_list);

	TRACE("read_blocklist: res %d, index %d, block_ptr 0x%llx, offset"
		       " 0x%x, block 0x%llx\n", res, index, block_ptr, offset,
			block);

	if (res == -1)
		goto failure;

	index -= res;

	while (index) {
		int blocks = min(index, PAGE_CACHE_SIZE >> 2);
		int res = read_block_index(inode->i_sb, blocks, block_list,
			&block_ptr, &offset);
		if (res == -1)
			goto failure;
		block += res;
		index -= blocks;
	}

	if (read_block_index(inode->i_sb, 1, block_list, &block_ptr, &offset)
			== -1)
		goto failure;
	*bsize = le32_to_cpu(blist[0]);

	return block;

failure:
	return 0;
}


static int squashfs_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	struct squashfs_sb_info *msblk = inode->i_sb->s_fs_info;
	void *block_list = NULL;
	long long block;
	unsigned int bsize, i;
	int bytes;
	int index = page->index >> (msblk->block_log - PAGE_CACHE_SHIFT);
	void *pageaddr;
	struct squashfs_cache_entry *fragment = NULL;
	char *data_ptr = msblk->read_page;

	int mask = (1 << (msblk->block_log - PAGE_CACHE_SHIFT)) - 1;
	int start_index = page->index & ~mask;
	int end_index = start_index | mask;
	int file_end = i_size_read(inode) >> msblk->block_log;
	int sparse = 0;

	TRACE("Entered squashfs_readpage, page index %lx, start block %llx\n",
				page->index, SQUASHFS_I(inode)->start_block);

	if (page->index >= ((i_size_read(inode) + PAGE_CACHE_SIZE - 1) >>
					PAGE_CACHE_SHIFT))
		goto out;

	if (SQUASHFS_I(inode)->fragment_block == SQUASHFS_INVALID_BLK
					|| index < file_end) {
		block_list = kmalloc(PAGE_CACHE_SIZE, GFP_KERNEL);
		if (block_list == NULL) {
			ERROR("Failed to allocate block_list\n");
			goto error_out;
		}

		block = read_blocklist(inode, index, block_list, &bsize);
		if (block == 0)
			goto error_out;

		if (bsize == 0) { /* hole */
			bytes = index == file_end ?
				(i_size_read(inode) & (msblk->block_size - 1)) :
				 msblk->block_size;
			sparse = 1;
		} else {
			mutex_lock(&msblk->read_page_mutex);

			bytes = squashfs_read_data(inode->i_sb,
				msblk->read_page, block, bsize, NULL,
				msblk->block_size);

			if (bytes == 0) {
				ERROR("Unable to read page, block %llx, size %x"
					"\n", block, bsize);
				mutex_unlock(&msblk->read_page_mutex);
				goto error_out;
			}
		}
	} else {
		fragment = get_cached_fragment(inode->i_sb,
				SQUASHFS_I(inode)->fragment_block,
				SQUASHFS_I(inode)->fragment_size);

		if (fragment->error) {
			ERROR("Unable to read page, block %llx, size %x\n",
				SQUASHFS_I(inode)->fragment_block,
				SQUASHFS_I(inode)->fragment_size);
			release_cached_fragment(msblk, fragment);
			goto error_out;
		}
		bytes = i_size_read(inode) & (msblk->block_size - 1);
		data_ptr = fragment->data + SQUASHFS_I(inode)->fragment_offset;
	}

	for (i = start_index; i <= end_index && bytes > 0; i++,
			bytes -= PAGE_CACHE_SIZE, data_ptr += PAGE_CACHE_SIZE) {
		struct page *push_page;
		int avail = sparse ? 0 : min_t(unsigned int, bytes,
			PAGE_CACHE_SIZE);

		TRACE("bytes %d, i %d, available_bytes %d\n", bytes, i, avail);

		push_page = (i == page->index) ? page :
			grab_cache_page_nowait(page->mapping, i);

		if (!push_page)
			continue;

		if (PageUptodate(push_page))
			goto skip_page;

		pageaddr = kmap_atomic(push_page, KM_USER0);
		memcpy(pageaddr, data_ptr, avail);
		memset(pageaddr + avail, 0, PAGE_CACHE_SIZE - avail);
		kunmap_atomic(pageaddr, KM_USER0);
		flush_dcache_page(push_page);
		SetPageUptodate(push_page);
skip_page:
		unlock_page(push_page);
		if (i != page->index)
			page_cache_release(push_page);
	}

	if (SQUASHFS_I(inode)->fragment_block == SQUASHFS_INVALID_BLK
					|| index < file_end) {
		if (!sparse)
			mutex_unlock(&msblk->read_page_mutex);
		kfree(block_list);
	} else
		release_cached_fragment(msblk, fragment);

	return 0;

error_out:
	SetPageError(page);
out:
	pageaddr = kmap_atomic(page, KM_USER0);
	memset(pageaddr, 0, PAGE_CACHE_SIZE);
	kunmap_atomic(pageaddr, KM_USER0);
	flush_dcache_page(page);
	if (!PageError(page))
		SetPageUptodate(page);
	unlock_page(page);

	kfree(block_list);
	return 0;
}


const struct address_space_operations squashfs_aops = {
	.readpage = squashfs_readpage
};
