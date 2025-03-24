/*
 * Squashfs
 *
 * Copyright (c) 2024, 2025
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
 * symbolic_mode.c
 */

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

#include "mksquashfs_error.h"
#include "symbolic_mode.h"
#include "alloc.h"

int parse_octal_mode_args(char *source, char *cur_ptr, int args, char **argv,
								void **data)
{
	int n, bytes;
	unsigned int mode;
	struct mode_data *mode_data;

	/* octal mode number? */
	n = sscanf(argv[0], "%o%n", &mode, &bytes);
	if (n == 0)
		return -1; /* not an octal number arg */


	/* check there's no trailing junk */
	if (argv[0][bytes] != '\0') {
		SYNTAX_ERR("Unexpected trailing bytes after octal "
			"mode number\n");
		return 0; /* bad octal number arg */
	}

	/* check there's only one argument */
	if (args > 1) {
		SYNTAX_ERR("Octal mode number is first argument, "
			"expected one argument, got %d\n", args);
		return 0; /* bad octal number arg */
	}

	/*  check mode is within range */
	if (mode > 07777) {
		SYNTAX_ERR("Octal mode %o is out of range\n", mode);
		return 0; /* bad octal number arg */
	}

	mode_data = MALLOC(sizeof(struct mode_data));
	mode_data->operation = SYMBOLIC_MODE_OCT;
	mode_data->mode = mode;
	mode_data->next = NULL;
	*data = mode_data;

	return 1;
}


/*
 * Parse symbolic mode of format [ugoa]*[[+-=]PERMS]+
 * PERMS = [rwxXst]+ or [ugo]
 */
int parse_sym_mode_arg(char *source, char *cur_ptr, char *arg,
	struct mode_data **head, struct mode_data **cur)
{
	struct mode_data *mode_data;
	int mode;
	int mask = 0;
	int op;
	char X;

	if (arg[0] != 'u' && arg[0] != 'g' && arg[0] != 'o' && arg[0] != 'a') {
		/* no ownership specifiers, default to a */
		mask = 0777;
		goto parse_operation;
	}

	/* parse ownership specifiers */
	while(1) {
		switch(*arg) {
		case 'u':
			mask |= 04700;
			break;
		case 'g':
			mask |= 02070;
			break;
		case 'o':
			mask |= 01007;
			break;
		case 'a':
			mask = 07777;
			break;
		default:
			goto parse_operation;
		}
		arg ++;
	}

parse_operation:
	/* trap a symbolic mode with just an ownership specification */
	if(*arg != '+' && *arg != '-' && *arg != '=') {
		if(*arg == '\0') {
			SYNTAX_ERR("Expected ownership specification (ugoa) "
				"or operator (+-=), but got end of string\n");
		} else {
			SYNTAX_ERR("Expected ownership specification (ugoa) "
				"or operator (+-=), but got '%c'\n", *arg);
		}
		goto failed;
	}

	while(*arg != '\0') {
		mode = 0;
		X = 0;

		switch(*arg) {
		case '+':
			op = SYMBOLIC_MODE_ADD;
			break;
		case '-':
			op = SYMBOLIC_MODE_REM;
			break;
		case '=':
			op = SYMBOLIC_MODE_SET;
			break;
		default:
			SYNTAX_ERR("Expected one of '+', '-' or '=', got "
				"'%c'\n", *arg);
			goto failed;
		}
	
		arg ++;
	
		/* Parse PERMS */
		if (*arg == 'u' || *arg == 'g' || *arg == 'o') {
	 		/* PERMS = [ugo] */
			mode = - *arg;
			arg ++;
		} else {
	 		/* PERMS = [rwxXst]* */
			while(1) {
				switch(*arg) {
				case 'r':
					mode |= 0444;
					break;
				case 'w':
					mode |= 0222;
					break;
				case 'x':
					mode |= 0111;
					break;
				case 's':
					mode |= 06000;
					break;
				case 't':
					mode |= 01000;
					break;
				case 'X':
					X = 1;
					break;
				case '+':
				case '-':
				case '=':
				case '\0':
					mode &= mask;
					goto perms_parsed;
				default:
					SYNTAX_ERR("Expected permission "
						"specification (rwxstX), but "
						"got '%c'\n", *arg);
					goto failed;
				}
	
				arg ++;
			}
		}
	
perms_parsed:
		mode_data = MALLOC(sizeof(*mode_data));
		mode_data->operation = op;
		mode_data->mode = mode;
		mode_data->mask = mask;
		mode_data->X = X;
		mode_data->next = NULL;

		if (*cur) {
			(*cur)->next = mode_data;
			*cur = mode_data;
		} else
			*head = *cur = mode_data;
	}

	return 1;

failed:
	return 0;
}


static int parse_sym_mode_args(char *source, char *cur_ptr, int args,
				char **argv, void **data)
{
	int i, res = 1;
	struct mode_data *head = NULL, *cur = NULL;

	for (i = 0; i < args && res; i++)
		res = parse_sym_mode_arg(source, cur_ptr, argv[i], &head, &cur);

	*data = head;

	return res;
}


int parse_mode_args(char *source, char *cur_ptr, int args, char **argv,
							void **data)
{
	int res = parse_octal_mode_args(source, cur_ptr, args, argv, data);

	if(res >= 0)
		/* Got an octal mode argument */
		return res;
	else  /* not an octal mode argument */
		return parse_sym_mode_args(source, cur_ptr, args, argv, data);
}


int parse_mode(char *source, struct mode_data **data)
{
	int args = 0, res = 0;
	char **argv = NULL, *cur_ptr = source, *first = source;

	while(*cur_ptr != '\0') {
		while(*cur_ptr != ',' && *cur_ptr != '\0')
			cur_ptr ++;

		if(cur_ptr != first) {
			argv = REALLOC(argv, (args + 1) * sizeof(char *));
			argv[args ++] = STRNDUP(first, cur_ptr - first);
		}

		if(*cur_ptr == ',')
			first = ++ cur_ptr;
	}

	if(args) {
		res = parse_mode_args(NULL, NULL, args, argv, (void **) data);

		free(argv);
	} else {
		source = NULL;
		SYNTAX_ERR("After skipping commas, no arguments found!\n");
	}

	return res;
}


int mode_execute(struct mode_data *mode_data, int st_mode)
{
	int mode = 0;

	for (;mode_data; mode_data = mode_data->next) {
		if (mode_data->mode < 0) {
			/* 'u', 'g' or 'o' */
			switch(-mode_data->mode) {
			case 'u':
				mode = (st_mode >> 6) & 07;
				break;
			case 'g':
				mode = (st_mode >> 3) & 07;
				break;
			case 'o':
				mode = st_mode & 07;
				break;
			}
			mode = ((mode << 6) | (mode << 3) | mode) &
				mode_data->mask;
		} else if (mode_data->X &&
				((st_mode & S_IFMT) == S_IFDIR ||
				(st_mode & 0111)))
			/* X permission, only takes effect if inode is a
			 * directory or x is set for some owner */
			mode = mode_data->mode | (0111 & mode_data->mask);
		else
			mode = mode_data->mode;

		switch(mode_data->operation) {
		case SYMBOLIC_MODE_OCT:
			st_mode = (st_mode & S_IFMT) | mode;
			break;
		case SYMBOLIC_MODE_SET:
			st_mode = (st_mode & ~mode_data->mask) | mode;
			break;
		case SYMBOLIC_MODE_ADD:
			st_mode |= mode;
			break;
		case SYMBOLIC_MODE_REM:
			st_mode &= ~mode;
		}
	}

	return st_mode;
}
