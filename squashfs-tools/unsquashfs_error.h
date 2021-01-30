#ifndef UNSQUASHFS_ERROR_H
#define UNSQUASHFS_ERROR_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2021
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
 * unsquashfs_error.h
 */

#include "error.h"

#define INFO(s, args...) \
		do {\
			progressbar_info(s, ## args);\
		} while(0)

#define BAD_ERROR(s, args...) \
		do {\
			progressbar_error("FATAL ERROR: " s, ##args); \
			exit(1); \
		} while(0)

#define EXIT_UNSQUASH(s, args...) BAD_ERROR(s, ##args)

#define EXIT_UNSQUASH_IGNORE(s, args...) \
	do {\
		if(ignore_errors) \
			ERROR(s, ##args); \
		else \
			BAD_ERROR(s, ##args); \
	} while(0)

#define EXIT_UNSQUASH_STRICT(s, args...) \
	do {\
		if(!strict_errors) \
			ERROR(s, ##args); \
		else \
			BAD_ERROR(s, ##args); \
	} while(0)

#define MEM_ERROR() \
	do {\
		progressbar_error("FATAL ERROR: Out of memory (%s)\n", \
								__func__); \
		exit(1); \
	} while(0)
#endif
