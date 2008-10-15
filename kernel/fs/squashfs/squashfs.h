/*
 * Squashfs - a compressed read only filesystem for Linux
 *
 * Copyright (c) 2002, 2003, 2004, 2005, 2006, 2007, 2008
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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
 * squashfs.h
 */

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...)	printk(KERN_NOTICE "SQUASHFS: "s, ## args)
#else
#define TRACE(s, args...)	{}
#endif

#define ERROR(s, args...)	printk(KERN_ERR "SQUASHFS error: "s, ## args)

#define SERROR(s, args...)	\
		do { \
			if (!silent) \
				printk(KERN_ERR "SQUASHFS error: "s, ## args);\
		} while (0)

#define WARNING(s, args...)	printk(KERN_WARNING "SQUASHFS: "s, ## args)

static inline struct squashfs_inode_info *SQUASHFS_I(struct inode *inode)
{
	return list_entry(inode, struct squashfs_inode_info, vfs_inode);
}

/* block.c */
extern unsigned int squashfs_read_data(struct super_block *, void *,
				long long, unsigned int, long long *, int);

/* cache.c */
extern struct squashfs_cache *squashfs_cache_init(char *, int, int, int);
extern void squashfs_cache_delete(struct squashfs_cache *);
struct squashfs_cache_entry *squashfs_cache_get(struct super_block *,
				struct squashfs_cache *, long long, int);
void squashfs_cache_put(struct squashfs_cache *, struct squashfs_cache_entry *);
extern int squashfs_read_metadata(struct super_block *, void *,
				long long, unsigned int, int, long long *,
				unsigned int *);
extern struct squashfs_cache_entry *get_cached_fragment(struct super_block *,
				long long, int);
extern void release_cached_fragment(struct squashfs_sb_info *,
				struct squashfs_cache_entry *);

/* export.c */
extern __le64 *read_inode_lookup_table(struct super_block *, long long,
			unsigned int);

/* fragment.c */
extern int get_fragment_location(struct super_block *, unsigned int,
				long long *);
extern __le64 *read_fragment_index_table(struct super_block *, long long,
				unsigned int);

/* id.c */
extern int squashfs_get_id(struct super_block *, unsigned int, unsigned int *);
extern __le64 *read_id_index_table(struct super_block *, long long,
			unsigned short);

/* inode.c */
extern struct inode *squashfs_iget(struct super_block *, long long,
			unsigned int);
extern int squashfs_read_inode(struct inode *, long long);

/*
 * Inodes and files operations
 */

/* dir.c */
extern const struct file_operations squashfs_dir_ops;

/* export.c */
extern const struct export_operations squashfs_export_ops;

/* file.c */
extern const struct address_space_operations squashfs_aops;

/* namei.c */
extern const struct inode_operations squashfs_dir_inode_ops;

/* symlink.c */
extern const struct address_space_operations squashfs_symlink_aops;
