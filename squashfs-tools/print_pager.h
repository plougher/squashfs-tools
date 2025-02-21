#ifndef PRINT_PAGER_H
#define PRINT_PAGER_H
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
 * print_pager.h
 */

#define TRUE 1
#define FALSE 0

#define LESS_PAGER 1
#define MORE_PAGER 2
#define UNKNOWN_PAGER 3

extern void wait_to_die(pid_t process);
extern FILE *exec_pager(pid_t *process);
extern int get_column_width();
extern void autowrap_print(FILE *stream, char *text, int maxl);
extern void autowrap_printf(FILE *stream, int maxl, char *fmt, ...)
	__attribute__ ((format (printf, 3, 4)));
extern int check_and_set_pager(char *pager);
#endif
