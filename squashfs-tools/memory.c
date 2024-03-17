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
 * memory.c
 */

#include <unistd.h>

#include "error.h"
#include "memory_compat.h"
#include "memory.h"

int check_usable_phys_mem(int total_mem, char *name)
{
	/*
	 * We want to allow users to use as much of their physical
	 * memory as they wish.  However, for practical reasons there are
	 * limits which need to be imposed, to protect users from themselves
	 * and to prevent people from using Mksquashfs as a DOS attack by using
	 * all physical memory.   Mksquashfs uses memory to cache data from disk
	 * to optimise performance.  It is pointless to ask it to use more
	 * than 75% of physical memory, as this causes thrashing and it is thus
	 * self-defeating.
	 */
	int mem = get_physical_memory();

	if(mem == 0) {
		ERROR("FATAL_ERROR: get_physical_memory() failed to get available system memory\n");
		return FALSE;
	}

	mem = (mem >> 1) + (mem >> 2); /* 75% */

	if(total_mem > mem) {
		ERROR("Total memory requested is more than 75%% of physical "
						"memory.\n");
		ERROR("%s uses memory to cache data from disk to "
					"optimise performance.\n", name);
		ERROR("It is pointless to ask it to use more than this amount "
						"of memory, as this\n");
		ERROR("causes thrashing and it is thus self-defeating.\n");
		ERROR("FATAL ERROR: Requested memory size too large\n");
		return FALSE;
	}

	if(sizeof(void *) == 4 && total_mem > 2048) {
		/*
		 * If we're running on a kernel with PAE or on a 64-bit kernel,
		 * then the 75% physical memory limit can still easily exceed
		 * the addressable memory by this process.
		 *
		 * Due to the typical kernel/user-space split (1GB/3GB, or
		 * 2GB/2GB), we have to conservatively assume the 32-bit
		 * processes can only address 2-3GB.  So refuse if the user
		 * tries to allocate more than 2GB.
		 */
		ERROR("Total memory requested may exceed maximum "
				"addressable memory by this process\n");
		ERROR("FATAL ERROR: Requested memory size too large\n");
		return FALSE;
	}

	return TRUE;
}
