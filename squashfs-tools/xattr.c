/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2008, 2009, 2010, 2012, 2014, 2019, 2021, 2022
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
 * xattr.c
 */

#include "endian_compat.h"

#define TRUE 1
#define FALSE 0

#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <sys/xattr.h>
#include <regex.h>

#include "squashfs_fs.h"
#include "squashfs_swap.h"
#include "mksquashfs.h"
#include "xattr.h"
#include "mksquashfs_error.h"
#include "progressbar.h"
#include "pseudo.h"
#include "tar.h"
#include "action.h"
#include "merge_sort.h"

#ifdef XATTR_NOFOLLOW /* Apple's xattrs */
	#define llistxattr(path_, buf_, sz_) \
		listxattr(path_, buf_, sz_, XATTR_NOFOLLOW)
	#define lgetxattr(path_, name_, val_, sz_) \
		getxattr(path_, name_, val_, sz_, 0, XATTR_NOFOLLOW)
#endif

/* compressed xattr table */
static char *xattr_table = NULL;
static unsigned int xattr_size = 0;

/* cached uncompressed xattr data */
static char *data_cache = NULL;
static int cache_bytes = 0, cache_size = 0;

/* cached uncompressed xattr id table */
static struct squashfs_xattr_id *xattr_id_table = NULL;
static int xattr_ids = 0;

/* saved compressed xattr table */
unsigned int sxattr_bytes = 0, stotal_xattr_bytes = 0;

/* saved cached uncompressed xattr data */
static char *sdata_cache = NULL;
static int scache_bytes = 0;

/* saved cached uncompressed xattr id table */
static int sxattr_ids = 0;

/* xattr hash table for value duplicate detection */
static struct xattr_list *dupl_value[65536];

/* xattr hash table for id duplicate detection */
static struct dupl_id *dupl_id[65536];

/* xattr-add option names and values */
static struct xattr_add *xattr_add_list = NULL;
static int xattr_add_count = 0;

/* file system globals from mksquashfs.c */
extern int no_xattrs, noX;
extern long long bytes;
extern int fd;
extern unsigned int xattr_bytes, total_xattr_bytes;
extern regex_t *xattr_exclude_preg;
extern regex_t *xattr_include_preg;

/* helper functions from mksquashfs.c */
extern unsigned short get_checksum(char *, int, unsigned short);
extern void write_destination(int, long long, long long, void *);
extern long long generic_write_table(long long, void *, int, void *, int);
extern int mangle(char *, char *, int, int, int, int);
extern char *pathname(struct dir_ent *);

/* helper functions and definitions from read_xattrs.c */
extern unsigned int read_xattrs_from_disk(int, struct squashfs_super_block *, int, long long *);
extern struct xattr_list *get_xattr(int, unsigned int *, int *);
extern struct prefix prefix_table[];


static int xattr_get_type(char *name)
{
	int i;

	for(i = 0; prefix_table[i].type != -1; i++) {
		struct prefix *p = &prefix_table[i];
		if(strncmp(name, p->prefix, strlen(p->prefix)) == 0)
			break;
	}

	return prefix_table[i].type;
}


static void xattr_copy_prefix(struct xattr_list *xattr, int t, char *name)
{
	xattr->full_name = strdup(name);
	xattr->name = xattr->full_name + strlen(prefix_table[t].prefix);
	xattr->size = strlen(xattr->name);
}


int xattr_get_prefix(struct xattr_list *xattr, char *name)
{
	int type = xattr_get_type(name);

	if(type != -1)
		xattr_copy_prefix(xattr, type, name);

	return type;
}

	
static int read_xattrs_from_system(struct dir_ent *dir_ent, char *filename,
						struct xattr_list **xattrs)
{
	ssize_t size, vsize;
	char *xattr_names, *p;
	int i = 0;
	struct xattr_list *xattr_list = NULL;
	struct xattr_data *xattr_exc_list;
	struct xattr_data *xattr_inc_list;

	while(1) {
		size = llistxattr(filename, NULL, 0);
		if(size <= 0) {
			if(size < 0 && errno != ENOTSUP) {
				ERROR_START("llistxattr for %s failed in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
			}
			return 0;
		}

		xattr_names = malloc(size);
		if(xattr_names == NULL)
			MEM_ERROR();

		size = llistxattr(filename, xattr_names, size);
		if(size < 0) {
			free(xattr_names);
			if(errno == ERANGE)
				/* xattr list grew?  Try again */
				continue;
			else {
				ERROR_START("llistxattr for %s failed in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
				return 0;
			}
		}

		break;
	}

	xattr_exc_list = eval_xattr_exc_actions(root_dir, dir_ent);
	xattr_inc_list = eval_xattr_inc_actions(root_dir, dir_ent);

	for(p = xattr_names; p < xattr_names + size;) {
		struct xattr_list *x;
		int res;

		res = match_xattr_exc_actions(xattr_exc_list, p);
		if(res) {
			p += strlen(p) + 1;
			continue;
		}

		if(xattr_exclude_preg) {
			res = regexec(xattr_exclude_preg, p, (size_t) 0, NULL, 0);
			if(res == 0) {
				p += strlen(p) + 1;
				continue;
			}
		}

		res = match_xattr_inc_actions(xattr_inc_list, p);
		if(res) {
			p += strlen(p) + 1;
			continue;
		}

		if(xattr_include_preg) {
			res = regexec(xattr_include_preg, p, (size_t) 0, NULL, 0);
			if(res) {
				p += strlen(p) + 1;
				continue;
			}
		}

		x = realloc(xattr_list, (i + 1) * sizeof(struct xattr_list));
		if(x == NULL)
			MEM_ERROR();
		xattr_list = x;

		xattr_list[i].type = xattr_get_prefix(&xattr_list[i], p);

		if(xattr_list[i].type == -1) {
			ERROR("Unrecognised xattr prefix %s\n", p);
			p += strlen(p) + 1;
			continue;
		}

		p += strlen(p) + 1;

		while(1) {
			vsize = lgetxattr(filename, xattr_list[i].full_name,
								NULL, 0);
			if(vsize < 0) {
				ERROR_START("lgetxattr failed for %s in "
					"read_attrs, because %s", filename,
					strerror(errno));
				ERROR_EXIT(".  Ignoring\n");
				free(xattr_list[i].full_name);
				goto failed;
			}

			xattr_list[i].value = malloc(vsize);
			if(xattr_list[i].value == NULL)
				MEM_ERROR();

			vsize = lgetxattr(filename, xattr_list[i].full_name,
						xattr_list[i].value, vsize);
			if(vsize < 0) {
				free(xattr_list[i].value);
				if(errno == ERANGE)
					/* xattr grew?  Try again */
					continue;
				else {
					ERROR_START("lgetxattr failed for %s "
						"in read_attrs, because %s",
						filename, strerror(errno));
					ERROR_EXIT(".  Ignoring\n");
					free(xattr_list[i].full_name);
					goto failed;
				}
			}
			
			break;
		}

		xattr_list[i].vsize = vsize;

		TRACE("read_xattrs_from_system: filename %s, xattr name %s,"
			" vsize %d\n", filename, xattr_list[i].full_name,
			xattr_list[i].vsize);
		i++;
	}

	free(xattr_names);

	if(i > 0)
		*xattrs = xattr_list;
	else
		free(xattr_list);
	return i;

failed:
	while(--i >= 0) {
		free(xattr_list[i].full_name);
		free(xattr_list[i].value);
	}
	free(xattr_list);
	free(xattr_names);
	return 0;
}


static int get_xattr_size(struct xattr_list *xattr)
{
	int size = sizeof(struct squashfs_xattr_entry) +
		sizeof(struct squashfs_xattr_val) + xattr->size;

	if(xattr->type & XATTR_VALUE_OOL)
		size += XATTR_VALUE_OOL_SIZE;
	else
		size += xattr->vsize;

	return size;
}


static void *get_xattr_space(unsigned int req_size, long long *disk)
{
	int data_space;
	unsigned short c_byte;

	/*
	 * Move and compress cached uncompressed data into xattr table.
	 */
	while(cache_bytes >= SQUASHFS_METADATA_SIZE) {
		if((xattr_size - xattr_bytes) <
				((SQUASHFS_METADATA_SIZE << 1)) + 2) {
			xattr_table = realloc(xattr_table, xattr_size +
				(SQUASHFS_METADATA_SIZE << 1) + 2);
			if(xattr_table == NULL)
				MEM_ERROR();
			xattr_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}

		c_byte = mangle(xattr_table + xattr_bytes + BLOCK_OFFSET,
			data_cache, SQUASHFS_METADATA_SIZE,
			SQUASHFS_METADATA_SIZE, noX, 0);
		TRACE("Xattr block @ 0x%x, size %d\n", xattr_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, xattr_table + xattr_bytes, 1);
		xattr_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		memmove(data_cache, data_cache + SQUASHFS_METADATA_SIZE,
			cache_bytes - SQUASHFS_METADATA_SIZE);
		cache_bytes -= SQUASHFS_METADATA_SIZE;
	}

	/*
	 * Ensure there's enough space in the uncompressed data cache
	 */
	data_space = cache_size - cache_bytes;
	if(data_space < req_size) {
			int realloc_size = req_size - data_space;
			data_cache = realloc(data_cache, cache_size +
				realloc_size);
			if(data_cache == NULL)
				MEM_ERROR();
			cache_size += realloc_size;
	}

	if(disk)
		*disk = ((long long) xattr_bytes << 16) | cache_bytes;
	cache_bytes += req_size;
	return data_cache + cache_bytes - req_size;
}


static struct dupl_id *check_id_dupl(struct xattr_list *xattr_list, int xattrs)
{
	struct dupl_id *entry;
	int i;
	unsigned short checksum = 0;

	/* compute checksum over all xattrs */
	for(i = 0; i < xattrs; i++) {
		struct xattr_list *xattr = &xattr_list[i];

		checksum = get_checksum(xattr->full_name,
					strlen(xattr->full_name), checksum);
		checksum = get_checksum(xattr->value,
					xattr->vsize, checksum);
	}

	for(entry = dupl_id[checksum]; entry; entry = entry->next) {
		if (entry->xattrs != xattrs)
			continue;

		for(i = 0; i < xattrs; i++) {
			struct xattr_list *xattr = &xattr_list[i];
			struct xattr_list *dup_xattr = &entry->xattr_list[i];

			if(strcmp(xattr->full_name, dup_xattr->full_name))
				break;

			if(xattr->vsize != dup_xattr->vsize)
				break;

			if(memcmp(xattr->value, dup_xattr->value, xattr->vsize))
				break;
		}
		
		if(i == xattrs)
			break;
	}

	if(entry == NULL) {
		/* no duplicate exists */
		entry = malloc(sizeof(*entry));
		if(entry == NULL)
			MEM_ERROR();
		entry->xattrs = xattrs;
		entry->xattr_list = xattr_list;
		entry->xattr_id = SQUASHFS_INVALID_XATTR;
		entry->next = dupl_id[checksum];
		dupl_id[checksum] = entry;
	}
		
	return entry;
}


static void check_value_dupl(struct xattr_list *xattr)
{
	struct xattr_list *entry;

	if(xattr->vsize < XATTR_VALUE_OOL_SIZE)
		return;

	/* Check if this is a duplicate of an existing value */
	xattr->vchecksum = get_checksum(xattr->value, xattr->vsize, 0);
	for(entry = dupl_value[xattr->vchecksum]; entry; entry = entry->vnext) {
		if(entry->vsize != xattr->vsize)
			continue;
		
		if(memcmp(entry->value, xattr->value, xattr->vsize) == 0)
			break;
	}

	if(entry == NULL) {
		/*
		 * No duplicate exists, add to hash table, and mark as
		 * requiring writing
		 */
		xattr->vnext = dupl_value[xattr->vchecksum];
		dupl_value[xattr->vchecksum] = xattr;
		xattr->ool_value = SQUASHFS_INVALID_BLK;
	} else {
		/*
		 * Duplicate exists, make type XATTR_VALUE_OOL, and
		 * remember where the duplicate is
		 */
		xattr->type |= XATTR_VALUE_OOL;
		xattr->ool_value = entry->ool_value;
		/* on appending don't free duplicate values because the
		 * duplicate value already points to the non-duplicate value */
		if(xattr->value != entry->value) {
			free(xattr->value);
			xattr->value = entry->value;
		}
	}
}


static int get_xattr_id(int xattrs, struct xattr_list *xattr_list,
		long long xattr_disk, struct dupl_id *xattr_dupl)
{
	int i, size = 0;
	struct squashfs_xattr_id *xattr_id;

	xattr_id_table = realloc(xattr_id_table, (xattr_ids + 1) *
		sizeof(struct squashfs_xattr_id));
	if(xattr_id_table == NULL)
		MEM_ERROR();

	/* get total uncompressed size of xattr data, needed for stat */
	for(i = 0; i < xattrs; i++)
		size += strlen(xattr_list[i].full_name) + 1 +
			xattr_list[i].vsize;

	xattr_id = &xattr_id_table[xattr_ids];
	xattr_id->xattr = xattr_disk;
	xattr_id->count = xattrs;
	xattr_id->size = size;

	/*
	 * keep track of total uncompressed xattr data, needed for mksquashfs
	 * file system summary
	 */
	total_xattr_bytes += size;

	xattr_dupl->xattr_id = xattr_ids ++;
	return xattr_dupl->xattr_id;
}
	

long long write_xattrs()
{
	unsigned short c_byte;
	int i, avail_bytes;
	char *datap = data_cache;
	long long start_bytes = bytes;
	struct squashfs_xattr_table header = {};

	if(xattr_ids == 0)
		return SQUASHFS_INVALID_BLK;

	/*
	 * Move and compress cached uncompressed data into xattr table.
	 */
	while(cache_bytes) {
		if((xattr_size - xattr_bytes) <
				((SQUASHFS_METADATA_SIZE << 1)) + 2) {
			xattr_table = realloc(xattr_table, xattr_size +
				(SQUASHFS_METADATA_SIZE << 1) + 2);
			if(xattr_table == NULL)
				MEM_ERROR();
			xattr_size += (SQUASHFS_METADATA_SIZE << 1) + 2;
		}

		avail_bytes = cache_bytes > SQUASHFS_METADATA_SIZE ?
			SQUASHFS_METADATA_SIZE : cache_bytes;
		c_byte = mangle(xattr_table + xattr_bytes + BLOCK_OFFSET, datap,
			avail_bytes, SQUASHFS_METADATA_SIZE, noX, 0);
		TRACE("Xattr block @ 0x%x, size %d\n", xattr_bytes, c_byte);
		SQUASHFS_SWAP_SHORTS(&c_byte, xattr_table + xattr_bytes, 1);
		xattr_bytes += SQUASHFS_COMPRESSED_SIZE(c_byte) + BLOCK_OFFSET;
		datap += avail_bytes;
		cache_bytes -= avail_bytes;
	}

	/*
	 * Write compressed xattr table to file system
	 */
	write_destination(fd, bytes, xattr_bytes, xattr_table);
        bytes += xattr_bytes;

	/*
	 * Swap if necessary the xattr id table
	 */
	for(i = 0; i < xattr_ids; i++)
		SQUASHFS_INSWAP_XATTR_ID(&xattr_id_table[i]);

	header.xattr_ids = xattr_ids;
	header.xattr_table_start = start_bytes;
	SQUASHFS_INSWAP_XATTR_TABLE(&header);

	return generic_write_table(xattr_ids * sizeof(struct squashfs_xattr_id),
		xattr_id_table, sizeof(header), &header, noX);
}


void free_xattr_list(int xattrs, struct xattr_list *xattr_list)
{
	int i;

	for(i = 0; i < xattrs; i++) {
		free(xattr_list[i].full_name);
		free(xattr_list[i].value);
	}

	free(xattr_list);
}


int generate_xattrs(int xattrs, struct xattr_list *xattr_list)
{
	int total_size, i;
	int xattr_value_max;
	void *xp;
	long long xattr_disk;
	struct dupl_id *xattr_dupl;

	/*
	 * check if the file xattrs are a complete duplicate of a pre-existing
	 * id
	 */
	xattr_dupl = check_id_dupl(xattr_list, xattrs);
	if(xattr_dupl->xattr_id != SQUASHFS_INVALID_XATTR) {
		free_xattr_list(xattrs, xattr_list);
		return xattr_dupl->xattr_id;
	}
	 
	/*
	 * Scan the xattr_list deciding which type to assign to each
	 * xattr.  The choice is fairly straightforward, and depends on the
	 * size of each xattr name/value and the overall size of the
	 * resultant xattr list stored in the xattr metadata table.
	 *
	 * Choices are whether to store data inline or out of line.
	 *
	 * The overall goal is to optimise xattr scanning and lookup, and
	 * to enable the file system layout to scale from a couple of
	 * small xattr name/values to a large number of large xattr
	 * names/values without affecting performance.  While hopefully
	 * enabling the common case of a couple of small xattr name/values
	 * to be stored efficiently
	 *
	 * Code repeatedly scans, doing the following
	 *		move xattr data out of line if it exceeds
	 *		xattr_value_max.  Where xattr_value_max is
	 *		initially XATTR_INLINE_MAX.  If the final uncompressed
	 *		xattr list is larger than XATTR_TARGET_MAX then more
	 *		aggressively move xattr data out of line by repeatedly
	 *	 	setting inline threshold to 1/2, then 1/4, 1/8 of
	 *		XATTR_INLINE_MAX until target achieved or there's
	 *		nothing left to move out of line
	 */
	xattr_value_max = XATTR_INLINE_MAX;
	while(1) {
		for(total_size = 0, i = 0; i < xattrs; i++) {
			struct xattr_list *xattr = &xattr_list[i];
			xattr->type &= XATTR_PREFIX_MASK; /* all inline */
			if (xattr->vsize > xattr_value_max)
				xattr->type |= XATTR_VALUE_OOL;

			total_size += get_xattr_size(xattr);
		}

		/*
		 * If the total size of the uncompressed xattr list is <=
		 * XATTR_TARGET_MAX we're done
		 */
		if(total_size <= XATTR_TARGET_MAX)
			break;

		if(xattr_value_max == XATTR_VALUE_OOL_SIZE)
			break;

		/*
		 * Inline target not yet at minimum and so reduce it, and
		 * try again
		 */
		xattr_value_max /= 2;
		if(xattr_value_max < XATTR_VALUE_OOL_SIZE)
			xattr_value_max = XATTR_VALUE_OOL_SIZE;
	}

	/*
	 * Check xattr values for duplicates
	 */
	for(i = 0; i < xattrs; i++) {
		check_value_dupl(&xattr_list[i]);
	}

	/*
	 * Add each out of line value to the file system xattr table
	 * if it doesn't already exist as a duplicate
	 */
	for(i = 0; i < xattrs; i++) {
		struct xattr_list *xattr = &xattr_list[i];

		if((xattr->type & XATTR_VALUE_OOL) &&
				(xattr->ool_value == SQUASHFS_INVALID_BLK)) {
			struct squashfs_xattr_val val;
			int size = sizeof(val) + xattr->vsize;
			xp = get_xattr_space(size, &xattr->ool_value);
			val.vsize = xattr->vsize;
			SQUASHFS_SWAP_XATTR_VAL(&val, xp);
			memcpy(xp + sizeof(val), xattr->value, xattr->vsize);
		}
	}

	/*
	 * Create xattr list and add to file system xattr table
	 */
	get_xattr_space(0, &xattr_disk);
	for(i = 0; i < xattrs; i++) {
		struct xattr_list *xattr = &xattr_list[i];
		struct squashfs_xattr_entry entry;
		struct squashfs_xattr_val val;

		xp = get_xattr_space(sizeof(entry) + xattr->size, NULL);
		entry.type = xattr->type;
		entry.size = xattr->size;
		SQUASHFS_SWAP_XATTR_ENTRY(&entry, xp);
		memcpy(xp + sizeof(entry), xattr->name, xattr->size);

		if(xattr->type & XATTR_VALUE_OOL) {
			int size = sizeof(val) + XATTR_VALUE_OOL_SIZE;
			xp = get_xattr_space(size, NULL);
			val.vsize = XATTR_VALUE_OOL_SIZE;
			SQUASHFS_SWAP_XATTR_VAL(&val, xp);
			SQUASHFS_SWAP_LONG_LONGS(&xattr->ool_value, xp +
				sizeof(val), 1);
		} else {
			int size = sizeof(val) + xattr->vsize;
			xp = get_xattr_space(size, &xattr->ool_value);
			val.vsize = xattr->vsize;
			SQUASHFS_SWAP_XATTR_VAL(&val, xp);
			memcpy(xp + sizeof(val), xattr->value, xattr->vsize);
		}
	}

	/*
	 * Add to xattr id lookup table
	 */
	return get_xattr_id(xattrs, xattr_list, xattr_disk, xattr_dupl);
}


/*
 * Instantiate two implementations of merge sort with different types and names
 */
SORT(sort_list, xattr_add, name, next);
SORT(sort_xattr_list, xattr_list, full_name, vnext);


int read_xattrs(void *d, int type)
{
	struct dir_ent *dir_ent = d;
	struct inode_info *inode = dir_ent->inode;
	char *filename = pathname(dir_ent);
	struct xattr_list *xattr_list = NULL, *head;
	int count, i = 0, j;
	struct xattr_add *l1 = xattr_add_list, *l2 = NULL, *l3 = NULL;
	struct xattr_add *action_add_list;

	if(no_xattrs || inode->root_entry)
		return SQUASHFS_INVALID_XATTR;

	if(IS_TARFILE(inode))
		i = read_xattrs_from_tarfile(inode, &xattr_list);
	else if(!inode->dummy_root_dir && !IS_PSEUDO(inode))
		i = read_xattrs_from_system(dir_ent, filename, &xattr_list);

	action_add_list = eval_xattr_add_actions(root_dir, dir_ent, &count);

	/*
	 * At this point we may have up to 3 lists of xattrs:
	 *
	 * 1. a list of xattrs created by the global xattrs-add command line
	 * 2. a list of xattrs created by one or more pseudo xattr definitions
	 *    on this file.
	 * 3. a list of xattrs created by one or more xattr add actions on this
	 *    file.
	 *
	 * The global xattrs are sorted, but, the pseudo xattr list and action
	 * xattr list are not.
	 *
	 * So sort the pseudo and action lists, and merge the three sorted lists
	 * together whilst adding them to the xattr_list
	 */

	if(inode->xattr) {
		sort_list(&(inode->xattr->xattr), inode->xattr->count);
		l2 = inode->xattr->xattr;
	}

	if(action_add_list) {
		sort_list(&action_add_list, count);
		l3 = action_add_list;
	}

	while(l1 || l2 || l3) {
		struct xattr_list *x;
		struct xattr_add *entry;

		if(l1 && l2 && l3) {
			if(strcmp(l1->name, l2->name) <= 0) {
				if(strcmp(l1->name, l3->name) <= 0) {
					entry= l1;
					l1 = l1->next;
				} else {
					entry = l3;
					l3 = l3->next;
				}
			} else {
				if(strcmp(l2->name, l3->name) <= 0) {
					entry = l2;
					l2 = l2->next;
				} else {
					entry = l3;
					l3 = l3->next;
				}
			}
		} else if(l1 && l2) {
			if(strcmp(l1->name, l2->name) <= 0) {
				entry = l1;
				l1 = l1->next;
			} else {
				entry = l2;
				l2 = l2->next;
			}
		} else if(l1 && l3) {
			if(strcmp(l1->name, l3->name) <= 0) {
				entry = l1;
				l1 = l1->next;
			} else {
				entry = l3;
				l3 = l3->next;
			}
		} else if(l2 && l3) {
			if(strcmp(l2->name, l3->name) <= 0) {
				entry = l2;
				l2 = l2->next;
			} else {
				entry = l3;
				l3 = l3->next;
			}
		} else if(l1) {
			entry = l1;
			l1 = l1->next;
		} else if(l2) {
			entry = l2;
			l2 = l2->next;
		} else {
			entry = l3;
			l3 = l3->next;
		}

		/*
		 * User extended attributes are only allowed for files and
		 * directories.  See man 7 xattr for explanation.
		 */
		if((entry->type == SQUASHFS_XATTR_USER) &&
				(type != SQUASHFS_FILE_TYPE &&
				 type != SQUASHFS_DIR_TYPE))
			continue;

		x = realloc(xattr_list, (i + 1) * sizeof(struct xattr_list));
		if(x == NULL)
			MEM_ERROR();
		xattr_list = x;

		xattr_list[i].type = entry->type;
		xattr_copy_prefix(&xattr_list[i], entry->type, entry->name);

		xattr_list[i].value = malloc(entry->vsize);
		if(xattr_list[i].value == NULL)
			MEM_ERROR();

		memcpy(xattr_list[i].value, entry->value, entry->vsize);
		xattr_list[i].vsize = entry->vsize;

		TRACE("read_xattrs: filename %s, xattr name %s,"
			" vsize %d\n", filename, xattr_list[i].full_name,
			xattr_list[i].vsize);
		i++;
	}

	if(i == 0)
		return SQUASHFS_INVALID_XATTR;
	else if(i == 1)
		goto skip_dup_check;

	/*
	 * Sort and check xattr list for duplicates
	 */
	for(j = 1;  j < i; j++)
		xattr_list[j - 1].vnext = &xattr_list[j];

	xattr_list[i - 1].vnext = NULL;
	head = xattr_list;

	sort_xattr_list(&head, i);

	for(j = 0; j < i - 1; head=head->vnext, j++)
		if(strcmp(head->full_name, head->vnext->full_name) == 0)
			BAD_ERROR("Duplicate xattr name %s in file %s\n",
					head->full_name, filename);

skip_dup_check:
	return generate_xattrs(i, xattr_list);
}


/*
 * Add the existing xattr ids and xattr metadata in the file system being
 * appended to, to the in-memory xattr cache.  This allows duplicate checking to
 * take place against the xattrs already in the file system being appended to,
 * and ensures the pre-existing xattrs are written out along with any new xattrs
 */
int get_xattrs(int fd, struct squashfs_super_block *sBlk)
{
	int res, i, id;
	unsigned int count, ids;

	TRACE("get_xattrs\n");

	if(sBlk->xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return SQUASHFS_INVALID_BLK;

	ids = read_xattrs_from_disk(fd, sBlk, FALSE, NULL);
	if(ids == 0)
		EXIT_MKSQUASHFS();

	/*
	 * for each xattr id read and construct its list of xattr
	 * name:value pairs, and add them to the in-memory xattr cache
	 */
	for(i = 0; i < ids; i++) {
		struct xattr_list *xattr_list = get_xattr(i, &count, &res);
		if(xattr_list == NULL && res == FALSE)
			EXIT_MKSQUASHFS();

		if(res) {
			free_xattr(xattr_list, count);
			return FALSE;
		}
		id = generate_xattrs(count, xattr_list);

		/*
		 * Sanity check, the new xattr id should be the same as the
		 * xattr id in the original file system
		 */
		if(id != i) {
			ERROR("BUG, different xattr_id in get_xattrs\n");
			return FALSE;
		}
	}

	return TRUE;
}


/*
 * Save current state of xattrs, needed for restoring state in the event of an
 * abort in appending
 */
void save_xattrs()
{
	/* save the current state of the compressed xattr data */
	sxattr_bytes = xattr_bytes;
	stotal_xattr_bytes = total_xattr_bytes;

	/*
	 * save the current state of the cached uncompressed xattr data.
	 * Note we have to save the contents of the data cache because future
	 * operations will delete the current contents
	 */
	sdata_cache = malloc(cache_bytes);
	if(sdata_cache == NULL)
		MEM_ERROR();

	memcpy(sdata_cache, data_cache, cache_bytes);
	scache_bytes = cache_bytes;

	/* save the current state of the xattr id table */
	sxattr_ids = xattr_ids;
}


/*
 * Restore xattrs in the event of an abort in appending
 */
void restore_xattrs()
{
	/* restore the state of the compressed xattr data */
	xattr_bytes = sxattr_bytes;
	total_xattr_bytes = stotal_xattr_bytes;

	/* restore the state of the uncomoressed xattr data */
	memcpy(data_cache, sdata_cache, scache_bytes);
	cache_bytes = scache_bytes;

	/* restore the state of the xattr id table */
	xattr_ids = sxattr_ids;
}


regex_t *xattr_regex(char *pattern, char *option)
{
	int error;
	regex_t *preg = malloc(sizeof(regex_t));

	if(preg == NULL)
		MEM_ERROR();

	error = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);

	if(error) {
		char str[1024]; /* overflow safe */

		regerror(error, preg, str, 1024);
		BAD_ERROR("invalid regex %s in xattrs-%s option, because %s\n",
				pattern, option, str);
	}

	return preg;
}


char *base64_decode(char *source, int size, int *bytes)
{
	char *dest;
	unsigned char *dest_ptr, *source_ptr = (unsigned char *) source;
	int bit_pos = 0;
	int output = 0;
	int count;

	if(size % 4 == 0) {
		/* Check for and ignore any end padding */
		if(source_ptr[size - 2] == '=' && source_ptr[size - 1] == '=')
			size -= 2;
		else if(source_ptr[size - 1] == '=')
			size --;
	}

	/* Calculate number of bytes the base64 encoding represents */
	count = size * 3 / 4;

	dest = malloc(count);

	for(dest_ptr = (unsigned char *) dest; size; size --, source_ptr ++) {
		int value = *source_ptr;

		if(value >= 'A' && value <= 'Z')
			value -= 'A';
		else if(value >= 'a' && value <= 'z')
			value -= 'a' - 26;
		else if(value >= '0' && value <= '9')
			value -= '0' - 52;
		else if(value == '+')
			value = 62;
		else if(value == '/')
			value = 63;
		else
			goto failed;

		if(bit_pos == 24) {
			dest_ptr[0] = output >> 16;
			dest_ptr[1] = (output >> 8) & 0xff;
			dest_ptr[2] = output & 0xff;
			bit_pos = 0;
			output = 0;
			dest_ptr += 3;
		}

		output = (output << 6) | value;
		bit_pos += 6;
	}

	output = output << (24 - bit_pos);

	if(bit_pos == 6)
		goto failed;

	if(bit_pos >= 12)
		dest_ptr[0] = output >> 16;

	if(bit_pos >= 18)
		dest_ptr[1] = (output >> 8) & 0xff;

	if(bit_pos == 24)
		dest_ptr[2] = output & 0xff;

	*bytes = (dest_ptr - (unsigned char *) dest) + (bit_pos / 8);
	return dest;

failed:
	free(dest);
	return NULL;
}


char *hex_decode(char *source, int size, int *bytes)
{
	char *dest;
	unsigned char *dest_ptr, *source_ptr = (unsigned char *) source;
	int first = 0;

	if(size % 2 != 0)
		return NULL;

	dest = malloc(size >> 2);
	if(dest == NULL)
		MEM_ERROR();

	for(dest_ptr = (unsigned char *) dest ; size; size --) {
		int digit = *source_ptr ++;

		if(digit >= 'A' && digit <= 'F')
			digit -= 'A' - 10;
		else if(digit >= 'a' && digit <= 'f')
			digit -= 'a' - 10;
		else if(digit >= '0' && digit <= '9')
			digit -= '0';
		else
			goto failed;

		if(size % 2 == 0)
			first = digit;
		else
			*dest_ptr ++ = (first << 4) | digit; 
	}

	*bytes = dest_ptr - (unsigned char *) dest;

	return dest;

failed:
	free(dest);
	return NULL;
}


int decode_octal(unsigned char *ptr)
{
	int i, output = 0;

	for(i = 0; i < 3; i++) {
		int val = *ptr ++;

		if(val < '0' || val > '7')
			return -1;

		output = (output << 3) | (val - '0');
	}

	return output < 256 ? output : -1;
}


char *text_decode(char *source, int *bytes)
{
	unsigned char *dest, *dest_ptr, *ptr = (unsigned char *) source;
	int size = 0;

	for(; *ptr; size ++, ptr ++) {
		if(*ptr == '\\') {
			if(ptr[1] != '\0' && ptr[2] != '\0' && ptr[3] != '\0')
				ptr += 3;
			else
				return NULL;
		}
	}

	dest = malloc(size);
	if(dest == NULL)
		MEM_ERROR();

	*bytes = size;

	for(ptr = (unsigned char *) source, dest_ptr = dest; size; size --) {
		if(*ptr == '\\') {
			int res = decode_octal(++ ptr);

			if(res == -1)
				goto failed;

			*dest_ptr ++ = res;
			ptr += 3;
		} else
			*dest_ptr ++ = *ptr ++;
	}

	return (char *) dest;

failed:
	free(dest);
	return NULL;
}


struct xattr_add *xattr_parse(char *str, char *pre, char *option)
{
	struct xattr_add *entry;
	char *value;
	int prefix, size;

	/*
	 * Look for the "=" separating the xattr name from the value
	 */
	for(value = str; *value != '=' && *value != '\0'; value ++);
	if(*value == '\0') {
		ERROR("%sinvalid argument \"%s\" in %s option, because no "
				"`=` found\n", pre, str, option);
		goto failed;
	}

	if(value == str) {
		ERROR("%sinvalid argument \"%s\" in %s option, because xattr "
				"name is empty\n", pre, str, option);
		goto failed;
	}

	if(*(value + 1) == '\0') {
		ERROR("%sinvalid argument \"%s\" in %s option, because xattr "
				"value is empty\n", pre, str, option);
		goto failed;
	}

	entry = malloc(sizeof(struct xattr_add));
	if(entry == NULL)
		MEM_ERROR();

	entry->name = strndup(str, value++ - str);
	entry->type = xattr_get_type(entry->name);

	if(entry->type == -1) {
		ERROR("%s%s: unrecognised xattr prefix in %s\n", pre, option,
								entry->name);
		goto failed2;
	}

	/*
	 * Evaluate the format prefix (if any)
	 */
	if(*(value + 1) == '\0')
		/*
		 * By definition an xattr value of 1 byte hasn't a prefix,
		 * and should be treated as binary
		 */
		prefix = 0;
	else
		prefix = (*value << 8) + *(value + 1);

	switch(prefix) {
	case PREFIX_BASE64_0S:
	case PREFIX_BASE64_0s:
		value += 2;
		if(*value == 0) {
			ERROR("%sinvalid argument %s in %s option, because "
				"xattr value is empty after format prefix 0S "
				"or 0s\n", pre, str, option);
			goto failed2;
		}

		entry->value = base64_decode(value, strlen(value), &size);
		entry->vsize = size;

		if(entry->value == NULL) {
			ERROR("%sinvalid argument %s in %s option, because "
				"invalid base64 value\n", pre, str, option);
			goto failed2;
		}
		break;

	case PREFIX_HEX_0X:
	case PREFIX_HEX_0x:
		value += 2;
		if(*value == 0) {
			ERROR("%sinvalid argument %s in %s option, because "
				"xattr value is empty after format prefix 0X "
				"or 0x\n", pre, str, option);
			goto failed2;
		}

		entry->value = hex_decode(value, strlen(value), &size);
		entry->vsize = size;

		if(entry->value == NULL) {
			ERROR("%sinvalid argument %s in %s option, because "
				"invalid hexidecimal value\n", pre, str, option);
			goto failed2;
		}
		break;

	case PREFIX_TEXT_0T:
	case PREFIX_TEXT_0t:
		value += 2;
		if(*value == 0) {
			ERROR("%sinvalid argument %s in %s option, because "
				"xattr value is empty after format prefix 0T "
				"or 0t\n", pre, str, option);
			goto failed2;
		}

		entry->value = text_decode(value, &size);
		entry->vsize = size;

		if(entry->value == NULL) {
			ERROR("%sinvalid argument %s in %s option, because "
				"invalid text value\n", pre, str, option);
			goto failed2;
		}
		break;

	case PREFIX_BINARY_0B:
	case PREFIX_BINARY_0b:
		value += 2;
		if(*value == 0) {
			ERROR("%sinvalid argument %s in %s option, because "
				"xattr value is empty after format prefix 0B "
				"or 0b\n", pre, str, option);
			goto failed2;
		}

		/* fall through */
	default:
		entry->vsize = strlen(value);
		entry->value = malloc(entry->vsize);

		if(entry->value == NULL)
			MEM_ERROR();

		memcpy(entry->value, value, entry->vsize);
	}

	return entry;

failed2:
	free(entry->name);
	free(entry);
failed:
	return NULL;
}


void xattrs_add(char *str)
{
	struct xattr_add *entry;

	entry = xattr_parse(str, "FATAL ERROR: ", "xattrs-add");

	if(entry) {
		entry->next = xattr_add_list;
		xattr_add_list = entry;

		xattr_add_count ++;
	} else
		exit(1);
}


int add_xattrs(void) {
	return xattr_add_count;
}


void sort_xattr_add_list(void)
{
	sort_list(&xattr_add_list, xattr_add_count);
}
