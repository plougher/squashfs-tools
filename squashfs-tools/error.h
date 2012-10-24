/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2012
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
 * error.h
 */

extern void prep_exit_mksquashfs();

#include "progressbar.h"

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			printf("mksquashfs: "s, ## args); \
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define INFO(s, args...) \
		do {\
			 if(!silent)\
				progressbar_info("mksquashfs: "s, ## args);\
		} while(0)

#define ERROR(s, args...) \
		do {\
			progressbar_error(s, ## args); \
		} while(0)

#define EXIT_MKSQUASHFS() \
		do {\
			prep_exit_mksquashfs();\
			exit(1);\
		} while(0)

#define BAD_ERROR(s, args...) \
		do {\
			progressbar_error("FATAL ERROR:" s, ##args); \
			EXIT_MKSQUASHFS();\
		} while(0)
