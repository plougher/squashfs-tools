#ifndef MEMORY_COMPAT_H
#define MEMORY_COMPAT_H
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
 * memory_compat.h
 */

#ifdef __linux__
#include <sys/sysinfo.h>

static inline int get_physical_memory()
{
	/*
	 * Long longs are used here because with PAE, a 32-bit
	 * machine can have more than 4GB of physical memory
	 *
	 * sysconf(_SC_PHYS_PAGES) relies on /proc being mounted.
	 * If it fails use sysinfo, if that fails return 0
	 */
	long long num_pages = sysconf(_SC_PHYS_PAGES);
	long long page_size = sysconf(_SC_PAGESIZE);
	int phys_mem;

	if(num_pages == -1 || page_size == -1) {
		struct sysinfo sys;
		int res = sysinfo(&sys);

		if(res == -1)
			return 0;

		num_pages = sys.totalram;
		page_size = sys.mem_unit;
	}

	phys_mem = num_pages * page_size >> 20;

	if(phys_mem < SQUASHFS_LOWMEM)
		BAD_ERROR("Mksquashfs requires more physical memory than is "
			"available!\n");

	return phys_mem;
}
#else
static inline int get_physical_memory()
{
	/*
	 * Long longs are used here because with PAE, a 32-bit
	 * machine can have more than 4GB of physical memory
	 */
	long long num_pages = sysconf(_SC_PHYS_PAGES);
	long long page_size = sysconf(_SC_PAGESIZE);
	int phys_mem;

	if(num_pages == -1 || page_size == -1)
		return 0;

	phys_mem = num_pages * page_size >> 20;

	if(phys_mem < SQUASHFS_LOWMEM)
		BAD_ERROR("Mksquashfs requires more physical memory than is "
			"available!\n");

	return phys_mem;
}
#endif
#endif
