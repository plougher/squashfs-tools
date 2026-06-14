/*
 * Squashfs
 *
 * Copyright (c) 2026
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
 * uid_gid.c
 */

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

int get_uid_from_arg(char *arg, unsigned int *uid)
{
	char *last;
	long long res;

	res = strtoll(arg, &last, 10);
	if(*last == '\0') {
		if(res < 0 || res > (((long long) 1 << 32) - 1))
			return -2;

		*uid = res;
		return 0;
	} else {
		struct passwd *id;

		for(;;) {
			errno = 0;
			id = getpwnam(arg);
			if(id) {
				*uid = id->pw_uid;
				return 0;
			} else if(errno != EINTR)
				break;
		}
	}

	return -1;
}


int get_gid_from_arg(char *arg, unsigned int *gid)
{
	char *last;
	long long res;

	res = strtoll(arg, &last, 10);
	if(*last == '\0') {
		if(res < 0 || res > (((long long) 1 << 32) - 1))
			return -2;

		*gid = res;
		return 0;
	} else {
		struct group *id;

		for(;;) {
			errno = 0;
			id = getgrnam(arg);
			if(id) {
				*gid = id->gr_gid;
				return 0;
			} else if(errno != EINTR)
				break;
		}
	}

	return -1;
}
