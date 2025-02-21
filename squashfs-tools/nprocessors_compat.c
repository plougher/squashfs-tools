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
 * nprocessors_compat.c
 */

static int processors = -1;

#ifdef __linux__
#include <sched.h>
#include <unistd.h>

int get_nprocessors(void)
{
	cpu_set_t cpu_set;

	if(processors != -1)
		return processors;

	CPU_ZERO(&cpu_set);

	if(sched_getaffinity(0, sizeof cpu_set, &cpu_set) == 0)
		return processors = CPU_COUNT(&cpu_set);
	else
		return processors = sysconf(_SC_NPROCESSORS_ONLN);
}
#else
#include <sys/sysctl.h>
#include "error.h"

int get_nprocessors(void)
{
	int mib[2];
	size_t len = sizeof(processors);

	if(processors != -1)
		return processors;

	mib[0] = CTL_HW;
#ifdef HW_AVAILCPU
	mib[1] = HW_AVAILCPU;
#else
	mib[1] = HW_NCPU;
#endif

	if(sysctl(mib, 2, &processors, &len, NULL, 0) == -1) {
		ERROR("Failed to get number of available processors.  Defaulting to 1\n");
		processors = 1;
	}

	return processors;
}
#endif
