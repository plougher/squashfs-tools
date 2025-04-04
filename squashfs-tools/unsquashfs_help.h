#ifndef UNSQUASHFS_HELP_H
#define UNSQUASHFS_HELP_H
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
 * unsquashfs_help.h
 */

#ifdef XATTR_SUPPORT
#ifdef XATTR_OS_SUPPORT
#ifdef XATTR_DEFAULT
#define NOXOPT_STR
#define XOPT_STR " (default)"
#else
#define NOXOPT_STR " (default)"
#define XOPT_STR
#endif
#else
#ifdef XATTR_DEFAULT
#define NOXOPT_STR
#define XOPT_STR " (default - no OS support)"
#else
#define NOXOPT_STR " (default)"
#define XOPT_STR " (no OS support)"
#endif
#endif
#else
#define NOXOPT_STR " (default)"
#define XOPT_STR " (unsupported)"
#endif

extern void unsquashfs_help_all(void);
extern void unsquashfs_section(char *opt_name, char *sec_name);
extern void unsquashfs_option(char *opt_name, char *pattern);
extern void unsquashfs_help(char *message);
extern void unsquashfs_invalid_option(char *opt_name);
extern void unsquashfs_option_help(char *option, const char *restrict fmt, ...);
extern void sqfscat_help_all(void);
extern void sqfscat_option(char *opt_name, char *pattern);
extern void sqfscat_section(char *opt_name, char *sec_name);
extern void sqfscat_help(char *message);
extern void sqfscat_invalid_option(char *opt_name);
extern void sqfscat_option_help(char *option, const char *restrict fmt, ...);
extern void display_compressors(void);
#endif
