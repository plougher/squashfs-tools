#ifndef XATTR_H
#define XATTR_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2010, 2012, 2013, 2014, 2019, 2021, 2022
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
 * xattr.h
 */

#define XATTR_VALUE_OOL		SQUASHFS_XATTR_VALUE_OOL
#define XATTR_PREFIX_MASK	SQUASHFS_XATTR_PREFIX_MASK

#define XATTR_VALUE_OOL_SIZE	sizeof(long long)

/* maximum size of xattr value data that will be inlined */
#define XATTR_INLINE_MAX 	128

/* the target size of an inode's xattr name:value list.  If it
 * exceeds this, then xattr value data will be successively out of lined
 * until it meets the target */
#define XATTR_TARGET_MAX	65536

#define IS_XATTR(a)		(a != SQUASHFS_INVALID_XATTR)

#define PREFIX_BASE64_0S	(0x3000 + 0x53)
#define PREFIX_BASE64_0s	(0x3000 + 0x73)
#define PREFIX_BINARY_0B	(0x3000 + 0x42)
#define PREFIX_BINARY_0b	(0x3000 + 0x62)
#define PREFIX_HEX_0X		(0x3000 + 0x58)
#define PREFIX_HEX_0x		(0x3000 + 0x78)
#define PREFIX_TEXT_0T		(0x3000 + 0x54)
#define PREFIX_TEXT_0t		(0x3000 + 0x74)

struct xattr_list {
	char			*name;
	char			*full_name;
	int			size;
	int			vsize;
	void			*value;
	int			type;
	long long		ool_value;
	unsigned short		vchecksum;
	struct xattr_list	*vnext;
};

struct dupl_id {
	struct xattr_list	*xattr_list;
	int			xattrs;
	int			xattr_id;
	struct dupl_id		*next;
};

struct prefix {
	char			*prefix;
	int			type;
};

struct xattr_add {
	char			*name;
	char			*value;
	unsigned int		vsize;
	int			type;
	struct xattr_add	*next;
};

extern int generate_xattrs(int, struct xattr_list *);

#ifdef XATTR_SUPPORT
extern int get_xattrs(int, struct squashfs_super_block *);
extern int read_xattrs(void *, int type);
extern long long write_xattrs();
extern void save_xattrs();
extern void restore_xattrs();
extern unsigned int xattr_bytes, total_xattr_bytes;
extern int write_xattr(char *, unsigned int);
extern unsigned int read_xattrs_from_disk(int, struct squashfs_super_block *, int, long long *);
extern struct xattr_list *get_xattr(int, unsigned int *, int *);
extern void free_xattr(struct xattr_list *, int);
extern regex_t *xattr_regex(char *pattern, char *option);
extern void xattrs_add(char *str);
extern void sort_xattr_add_list(void);
extern char *base64_decode(char *source, int size, int *bytes);
extern int add_xattrs(void);
extern struct xattr_add *xattr_parse(char *, char *, char *);
extern int read_pseudo_xattr(char *orig_def, char *filename, char *name, char *def);
extern void print_xattr(char *, unsigned int, int);
extern int has_xattrs(unsigned int);
#else
#include "squashfs_swap.h"

static inline int get_xattrs(int fd, struct squashfs_super_block *sBlk)
{
	if(sBlk->xattr_id_table_start != SQUASHFS_INVALID_BLK) {
		fprintf(stderr, "Xattrs in filesystem! These are not "
			"supported on this build of Mksquashfs\n");
		return 0;
	} else
		return SQUASHFS_INVALID_BLK;
}


static inline int read_xattrs(void *dir_ent, int type)
{
	return SQUASHFS_INVALID_XATTR;
}


static inline long long write_xattrs()
{
	return SQUASHFS_INVALID_BLK;
}


static inline void save_xattrs()
{
}


static inline void restore_xattrs()
{
}


static inline int write_xattr(char *pathname, unsigned int xattr)
{
	return 1;
}


static inline unsigned int read_xattrs_from_disk(int fd, struct squashfs_super_block *sBlk, int sanity_only, long long *table_start)
{
	int res;
	struct squashfs_xattr_table id_table;

	/*
	 * Read sufficient xattr metadata to obtain the start of the xattr
	 * metadata on disk (table_start).  This value is needed to do
	 * sanity checking of the filesystem.
	 */
	res = read_fs_bytes(fd, sBlk->xattr_id_table_start, sizeof(id_table), &id_table);
	if(res == 0)
		return 0;

	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);

	/*
	 * id_table.xattr_table_start stores the start of the compressed xattr
	 * metadata blocks.  This by definition is also the end of the previous
	 * filesystem table - the id lookup table.
	 */
	if(table_start != NULL)
		*table_start = id_table.xattr_table_start;

	return id_table.xattr_ids;
}


static inline struct xattr_list *get_xattr(int i, unsigned int *count, int j)
{
	return NULL;
}

static inline regex_t *xattr_regex(char *pattern, char *option)
{
	return NULL;
}

static inline void xattrs_add(char *str)
{
}

static inline void sort_xattr_add_list(void)
{
}

static inline int add_xattrs(void)
{
	return 0;
}

static inline struct xattr_add *xattr_parse(char *a, char *b, char *c)
{
	return NULL;
}


static inline int read_pseudo_xattr(char *orig_def, char *filename, char *name, char *def)
{
	free(filename);
	fprintf(stderr, "Xattrs are unsupported in this build\n");

	return 0;
}


static inline void print_xattr(char *pathname, unsigned int xattr, int writer_fd)
{
}


static inline int has_xattrs(unsigned int xattr)
{
	return 0;
}
#endif

#ifdef XATTR_SUPPORT
#define xattrs_supported() TRUE
#ifdef XATTR_DEFAULT
#define NOXOPT_STR
#define XOPT_STR " (default)"
#define XATTR_DEF 0
#else
#define NOXOPT_STR " (default)"
#define XOPT_STR
#define XATTR_DEF 1
#endif
#else
#define xattrs_supported() FALSE
#define NOXOPT_STR " (default)"
#define XOPT_STR " (unsupported)"
#define XATTR_DEF 1
#endif
#endif
