/*
 * Squashfs
 *
 * Copyright (c) 2025
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
 * limit.c
 */

#include <sys/resource.h>

#include "error.h"
#include "limit.h"

int file_limit()
{
	static int max_files = -2;
	struct rlimit rlim;
	int res;

	if(max_files == -2) {
		res = getrlimit(RLIMIT_NOFILE, &rlim);
		if (res == -1) {
			ERROR("failed to get open file limit!  Defaulting to 1\n");
			max_files = 1;
		} else if (rlim.rlim_cur != RLIM_INFINITY) {
			/*
			 * leave OPEN_FILE_MARGIN free (rlim_cur includes fds used by
			 * stdin, stdout, stderr and filesystem fd
			 */
			if (rlim.rlim_cur <= OPEN_FILE_MARGIN)
				/* no margin, use minimum possible */
				max_files = 1;
			else
				max_files = rlim.rlim_cur - OPEN_FILE_MARGIN;
		} else
			max_files = -1;
	}

	return max_files;
}
