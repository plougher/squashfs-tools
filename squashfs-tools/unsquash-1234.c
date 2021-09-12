/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
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
 * unsquash-1234.c
 *
 * Helper functions used by unsquash-1, unsquash-2, unsquash-3 and
 * unsquash-4.
 */

#include "unsquashfs.h"

/*
 * Check name for validity, name should not
 *  - be ".", "./", or
 *  - be "..", "../" or
 *  - have a "/" anywhere in the name, or
 *  - be shorter than the expected size
 */
int check_name(char *name, int size)
{
	char *start = name;

	if(name[0] == '.') {
		if(name[1] == '.')
			name++;
		if(name[1] == '/' || name[1] == '\0')
			return FALSE;
	}

	while(name[0] != '/' && name[0] != '\0')
		name ++;

	if(name[0] == '/')
		return FALSE;

	if((name - start) != size)
		return FALSE;

	return TRUE;
}


void squashfs_closedir(struct dir *dir)
{
	struct dir_ent *ent = dir->dirs;

	while(ent) {
		struct dir_ent *tmp = ent;

		ent = ent->next;
		free(tmp->name);
		free(tmp);
	}

	free(dir);
}


/*
 * Check directory for duplicate names.  As the directory should be sorted,
 * duplicates will be consecutive.  Obviously we also need to check if the
 * directory has been deliberately unsorted, to evade this check.
 */
int check_directory(struct dir *dir)
{
	int i;
	struct dir_ent *ent;

	if(dir->dir_count < 2)
		return TRUE;

	for(ent = dir->dirs, i = 0; i < dir->dir_count - 1; ent = ent->next, i++)
		if(strcmp(ent->name, ent->next->name) >= 0)
			return FALSE;

	return TRUE;
}
