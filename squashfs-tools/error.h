#ifndef ERROR_H
#define ERROR_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2012, 2013, 2014, 2019, 2021
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
 * error.h
 */

extern void progressbar_error(char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void progressbar_info(char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void exit_squashfs();

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...) \
		do { \
			progressbar_info("squashfs: "s, ## args);\
		} while(0)
#else
#define TRACE(s, args...)
#endif

#define ERROR(s, args...) \
		do {\
			progressbar_error(s, ## args); \
		} while(0)
#endif

#define MEM_ERROR(func) \
	do {\
		progressbar_error("FATAL ERROR: Out of memory (%s)\n", \
								func); \
		exit_squashfs();\
	} while(0)
