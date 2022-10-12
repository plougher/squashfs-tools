/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2022
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
 * pseudo_xattr.c
 */

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <regex.h>
#include <dirent.h>

#include "pseudo.h"
#include "mksquashfs_error.h"
#include "squashfs_fs.h"
#include "xattr.h"

#define TRUE 1
#define FALSE 0

static void add_xattr(struct pseudo_xattr **xattr, struct xattr_add *entry)
{
	if(*xattr == NULL) {
		*xattr = malloc(sizeof(struct pseudo_xattr));
		if(*xattr == NULL)
			MEM_ERROR();

		(*xattr)->xattr = entry;
		entry->next = NULL;
		(*xattr)->count = 1;
	} else {
		entry->next = (*xattr)->xattr;
		(*xattr)->xattr = entry;
		(*xattr)->count ++;
	}
}


/*
 * Add pseudo xattr to the set of pseudo definitions.
 */
static struct pseudo *add_pseudo_xattr(struct pseudo *pseudo, struct xattr_add *xattr,
	char *target, char *alltarget)
{
	char *targname;
	int i;

	target = get_element(target, &targname);

	if(pseudo == NULL) {
		pseudo = malloc(sizeof(struct pseudo));
		if(pseudo == NULL)
			MEM_ERROR();

		pseudo->names = 0;
		pseudo->count = 0;
		pseudo->name = NULL;
	}

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(pseudo->name[i].name, targname) == 0)
			break;

	if(i == pseudo->names) {
		/* allocate new name entry */
		pseudo->names ++;
		pseudo->name = realloc(pseudo->name, (i + 1) *
			sizeof(struct pseudo_entry));
		if(pseudo->name == NULL)
			MEM_ERROR();
		pseudo->name[i].name = targname;
		pseudo->name[i].pathname = NULL;
		pseudo->name[i].dev = NULL;
		pseudo->name[i].xattr = NULL;

		if(target[0] == '\0') {
			/* at leaf pathname component */
			pseudo->name[i].pathname = strdup(alltarget);
			pseudo->name[i].pseudo = NULL;
			add_xattr(&pseudo->name[i].xattr, xattr);
		} else {
			/* recurse adding child components */
			pseudo->name[i].pseudo = add_pseudo_xattr(NULL, xattr,
				target, alltarget);
		}
	} else {
		/* existing matching entry */

		free(targname);

		if(target[0] == '\0') {
			/* Add xattr to this entry */
			pseudo->name[i].pathname = strdup(alltarget);
			add_xattr(&pseudo->name[i].xattr, xattr);
		} else {
			/* recurse adding child components */
			pseudo->name[i].pseudo = add_pseudo_xattr(pseudo->name[i].pseudo, xattr, target, alltarget);
		}
	}

	return pseudo;
}


static struct pseudo *add_pseudo_xattr_definition(struct pseudo *pseudo,
	struct xattr_add *xattr, char *target, char *alltarget)
{
	/* special case if a root pseudo definition is being added */
	if(strcmp(target, "/") == 0) {
		/* if already have a root pseudo just add xattr */
		if(pseudo && pseudo->names == 1 && strcmp(pseudo->name[0].name, "/") == 0) {
			add_xattr(&pseudo->name[0].xattr, xattr);
			return pseudo;
		} else {
			struct pseudo *new = malloc(sizeof(struct pseudo));
			if(new == NULL)
				MEM_ERROR();

			new->names = 1;
			new->count = 0;
			new->name = malloc(sizeof(struct pseudo_entry));
			if(new->name == NULL)
				MEM_ERROR();

			new->name[0].name = "/";
			new->name[0].pseudo = pseudo;
			new->name[0].pathname = "/";
			new->name[0].dev = NULL;
			new->name[0].xattr = NULL;
			add_xattr(&new->name[0].xattr, xattr);
			return new;
		}
	}

	/* if there's a root pseudo definition, skip it before walking target */
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->name[0].name, "/") == 0) {
		pseudo->name[0].pseudo = add_pseudo_xattr(pseudo->name[0].pseudo, xattr, target, alltarget);
		return pseudo;
	} else
		return add_pseudo_xattr(pseudo, xattr, target, alltarget);
}


int read_pseudo_xattr(char *orig_def, char *filename, char *name, char *def)
{
	struct xattr_add *xattr = xattr_parse(def, "", "pseudo xattr");

	if(xattr == NULL) {
		print_definitions();
		free(filename);
		return FALSE;
	}

	pseudo = add_pseudo_xattr_definition(pseudo, xattr, name, name);

	free(filename);
	return TRUE;
}
