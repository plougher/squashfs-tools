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

#ifdef CONFIG_SQUASHFS_1_0_COMPATIBILITY
#undef CONFIG_SQUASHFS_1_0_COMPATIBILITY
#endif

#ifdef SQUASHFS_TRACE
#define TRACE(s, args...)	printk(KERN_NOTICE "SQUASHFS: "s, ## args)
#else
#define TRACE(s, args...)	{}
#endif

#define ERROR(s, args...)	printk(KERN_ERR "SQUASHFS error: "s, ## args)

#define SERROR(s, args...)	do { \
				if (!silent) \
				printk(KERN_ERR "SQUASHFS error: "s, ## args);\
				} while(0)

#define WARNING(s, args...)	printk(KERN_WARNING "SQUASHFS: "s, ## args)

static inline struct squashfs_inode_info *SQUASHFS_I(struct inode *inode)
{
	return list_entry(inode, struct squashfs_inode_info, vfs_inode);
}

/* block.c */
extern unsigned int squashfs_read_data(struct super_block *s, char *buffer,
				long long index, unsigned int length,
				long long *next_index, int srclength);
extern int squashfs_get_cached_block(struct super_block *s, void *buffer,
				long long block, unsigned int offset,
				int length, long long *next_block,
				unsigned int *next_offset);

/* cache.c */
extern struct squashfs_cache_entry *squashfs_cache_get(struct super_block *s,
	struct squashfs_cache *cache, long long block, int length);
extern void squashfs_cache_put(struct squashfs_cache *cache,
				struct squashfs_cache_entry *entry);
extern void squashfs_cache_delete(struct squashfs_cache *cache);
extern struct squashfs_cache *squashfs_cache_init(char *name, int entries,
	int block_size, int use_vmalloc);

/* export.c */
extern int read_inode_lookup_table(struct super_block *s);

/* file.c */
extern long long read_blocklist(struct inode *inode, int index,
				int readahead_blks, char *block_list,
				unsigned short **block_p, unsigned int *bsize);

/* fragment.c */
extern int get_fragment_location(struct super_block *s, unsigned int fragment,
				long long *fragment_start_block,
				unsigned int *fragment_size);
extern void release_cached_fragment(struct squashfs_sb_info *msblk,
				struct squashfs_cache_entry *fragment);
extern struct squashfs_cache_entry *get_cached_fragment(struct super_block *s,
				long long start_block, int length);
extern int read_fragment_index_table(struct super_block *s);

/* id.c */
extern int get_id(struct super_block *s, unsigned int index, unsigned int *id);
extern int read_id_index_table(struct super_block *s);

/* inode.c */
extern struct inode *squashfs_iget(struct super_block *s,
				squashfs_inode_t inode, unsigned int inode_number);
extern int squashfs_read_inode(struct inode *i, squashfs_inode_t inode);


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

#ifdef CONFIG_SQUASHFS_1_0_COMPATIBILITY
extern int squashfs_1_0_supported(struct squashfs_sb_info *msblk);
#else
static inline int squashfs_1_0_supported(struct squashfs_sb_info *msblk)
{
	return 0;
}
#endif

#ifdef CONFIG_SQUASHFS_2_0_COMPATIBILITY
extern int squashfs_2_0_supported(struct squashfs_sb_info *msblk);
#else
static inline int squashfs_2_0_supported(struct squashfs_sb_info *msblk)
{
	return 0;
}
#endif
