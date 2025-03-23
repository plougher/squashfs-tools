#ifndef SYMBOLIC_MODE_H
#define SYMBOLIC_MODE_H
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
 * symbolic_mode.h
 */

#include "alloc.h"

#define SYNTAX_ERR(S, ARGS...) { \
	if(source) { \
		char *src = STRDUP(source); \
		src[cur_ptr - source] = '\0'; \
		fprintf(stderr, "Failed to parse action \"%s\"\n", source); \
		fprintf(stderr, "Syntax error: "S, ##ARGS); \
		fprintf(stderr, "Got here \"%s\"\n", src); \
		free(src); \
	} else \
		fprintf(stderr, "Syntax error: "S, ##ARGS); \
}

/*
 * Mode action specific definitions
 */
#define SYMBOLIC_MODE_SET 0
#define SYMBOLIC_MODE_ADD 1
#define SYMBOLIC_MODE_REM 2
#define SYMBOLIC_MODE_OCT 3

struct mode_data {
	struct mode_data *next;
	int operation;
	int mode;
	unsigned int mask;
	char X;
};


extern int parse_octal_mode_args(char *source, char *cur_ptr, int args, char **argv, void **data);
extern int parse_sym_mode_arg(char *source, char *cur_ptr, char *arg, struct mode_data **head, struct mode_data **cur);
extern int parse_mode_args(char *source, char *cur_ptr, int args, char **argv, void **data);
extern int mode_execute(struct mode_data *mode_data, int st_mode);
extern int parse_mode(char *source, struct mode_data **data);
#endif
