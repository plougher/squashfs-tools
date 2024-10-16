/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2022, 2023, 2024
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
	char *targname, *subpathend;
	int new;
	struct pseudo_entry *ent;

	target = get_element(target, &targname, &subpathend);

	if(pseudo == NULL) {
		pseudo = malloc(sizeof(struct pseudo));
		if(pseudo == NULL)
			MEM_ERROR();

		pseudo->names = 0;
		pseudo->current = NULL;
		pseudo->head = NULL;
	}

	ent = pseudo_search(pseudo, targname, alltarget, subpathend, &new);

	if(new) {
		if(target[0] == '\0') {
			/* at leaf pathname component */
			add_xattr(&ent->xattr, xattr);
		} else {
			/* recurse adding child components */
			ent->pseudo = add_pseudo_xattr(NULL, xattr,
				target, alltarget);
		}
	} else {
		/* existing matching entry */

		free(targname);

		if(target[0] == '\0') {
			/* Add xattr to this entry */
			add_xattr(&ent->xattr, xattr);
		} else {
			/* recurse adding child components */
			ent->pseudo = add_pseudo_xattr(ent->pseudo, xattr, target, alltarget);
		}
	}

	return pseudo;
}


struct pseudo *add_pseudo_xattr_definition(struct pseudo *pseudo,
	struct xattr_add *xattr, char *target, char *alltarget)
{
	/* special case if a root pseudo definition is being added */
	if(strcmp(target, "/") == 0) {
		/* if already have a root pseudo just add xattr */
		if(pseudo && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0) {
			add_xattr(&pseudo->head->xattr, xattr);
			return pseudo;
		} else {
			struct pseudo *new = malloc(sizeof(struct pseudo));
			if(new == NULL)
				MEM_ERROR();

			new->names = 1;
			new->current = NULL;
			new->head = malloc(sizeof(struct pseudo_entry));
			if(new->head == NULL)
				MEM_ERROR();

			new->head->name = "/";
			new->head->pseudo = pseudo;
			new->head->pathname = "/";
			new->head->dev = NULL;
			new->head->xattr = NULL;
			new->head->next = NULL;
			add_xattr(&new->head->xattr, xattr);
			return new;
		}
	}

	/* if there's a root pseudo definition, skip it before walking target */
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0) {
		pseudo->head->pseudo = add_pseudo_xattr(pseudo->head->pseudo, xattr, target, alltarget);
		return pseudo;
	} else
		return add_pseudo_xattr(pseudo, xattr, target, alltarget);
}


struct xattr_add *read_pseudo_xattr(char *def)
{
	return xattr_parse(def, "", "pseudo xattr");
}
