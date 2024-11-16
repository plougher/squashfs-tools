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
 * symbolic_mode.c
 */

#include <string.h>
#include <stdlib.h>

#include "mksquashfs_error.h"
#include "symbolic_mode.h"

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
	if(*arg == '\0') {
		SYNTAX_ERROR("Expected one of '+', '-' or '=', got EOF\n");
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
			SYNTAX_ERROR("Expected one of '+', '-' or '=', got "
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
					SYNTAX_ERROR("Unrecognised permission "
								"'%c'\n", *arg);
					goto failed;
				}
	
				arg ++;
			}
		}
	
perms_parsed:
		mode_data = malloc(sizeof(*mode_data));
		if (mode_data == NULL)
			MEM_ERROR();

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
