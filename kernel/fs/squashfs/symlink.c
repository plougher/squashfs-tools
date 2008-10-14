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
 * symlink.c
 */

/*
 * This file implements code to handle symbolic links.
 *
 * The data contents of symbolic links are stored inside the symbolic
 * link inode within the inode table.  This allows the normally small symbolic
 * link to be compressed as part of the inode table, achieving much greater
 * compression than if the symbolic link was compressed individually.
 */

#include <linux/fs.h>
#include <linux/vfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/pagemap.h>
#include <linux/zlib.h>
#include <linux/squashfs_fs.h>
#include <linux/squashfs_fs_sb.h>
#include <linux/squashfs_fs_i.h>

#include "squashfs.h"

static int squashfs_symlink_readpage(struct file *file, struct page *page)
{
	struct inode *inode = page->mapping->host;
	int index = page->index << PAGE_CACHE_SHIFT;
	long long block = SQUASHFS_I(inode)->start_block;
	int offset = SQUASHFS_I(inode)->offset;
	void *pageaddr = kmap(page);
	int length, bytes, avail_bytes;

	TRACE("Entered squashfs_symlink_readpage, page index %ld, start block "
				"%llx, offset %x\n", page->index,
				SQUASHFS_I(inode)->start_block,
				SQUASHFS_I(inode)->offset);

	for (length = 0; length < index; length += bytes) {
		bytes = squashfs_read_metadata(inode->i_sb, NULL, block,
				offset, PAGE_CACHE_SIZE, &block, &offset);
		if (bytes == 0) {
			ERROR("Unable to read symbolic link [%llx:%x]\n",
				block, offset);
			goto skip_read;
		}
	}

	if (length != index) {
		ERROR("(squashfs_symlink_readpage) length != index\n");
		bytes = 0;
		goto skip_read;
	}

	avail_bytes = min_t(int, i_size_read(inode) - length, PAGE_CACHE_SIZE);

	bytes = squashfs_read_metadata(inode->i_sb, pageaddr, block, offset,
				avail_bytes, &block, &offset);
	if (bytes == 0)
		ERROR("Unable to read symbolic link [%llx:%x]\n", block,
				offset);

skip_read:
	memset(pageaddr + bytes, 0, PAGE_CACHE_SIZE - bytes);
	kunmap(page);
	flush_dcache_page(page);
	SetPageUptodate(page);
	unlock_page(page);

	return 0;
}


const struct address_space_operations squashfs_symlink_aops = {
	.readpage = squashfs_symlink_readpage
};
