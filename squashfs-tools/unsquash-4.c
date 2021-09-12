/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2019, 2021
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
 * unsquash-4.c
 */

#include "unsquashfs.h"
#include "squashfs_swap.h"
#include "xattr.h"
#include "compressor.h"

static struct squashfs_fragment_entry *fragment_table;
static unsigned int *id_table;
static squashfs_operations ops;

static void read_block_list(unsigned int *block_list, long long start,
					unsigned int offset, int blocks)
{
	int res;

	TRACE("read_block_list: blocks %d\n", blocks);

	res = read_inode_data(block_list, &start, &offset, blocks * sizeof(unsigned int));
	if(res == FALSE)
		EXIT_UNSQUASH("read_block_list: failed to read "
			"inode index %lld:%d\n", start, offset);

	SQUASHFS_INSWAP_INTS(block_list, blocks);
}


static int read_fragment_table(long long *table_start)
{
	/*
	 * Note on overflow limits:
	 * Size of SBlk.s.fragments is 2^32 (unsigned int)
	 * Max size of bytes is 2^32*16 or 2^36
	 * Max indexes is (2^32*16)/8K or 2^23
	 * Max length is ((2^32*16)/8K)*8 or 2^26 or 64M
	 */
	int res;
	unsigned int i;
	long long bytes = SQUASHFS_FRAGMENT_BYTES((long long) sBlk.s.fragments);
	int indexes = SQUASHFS_FRAGMENT_INDEXES((long long) sBlk.s.fragments);
	int length = SQUASHFS_FRAGMENT_INDEX_BYTES((long long) sBlk.s.fragments);
	long long *fragment_table_index;

	/*
	 * The size of the index table (length bytes) should match the
	 * table start and end points
	 */
	if(length != (*table_start - sBlk.s.fragment_table_start)) {
		ERROR("read_fragment_table: Bad fragment count in super block\n");
		return FALSE;
	}

	TRACE("read_fragment_table: %u fragments, reading %d fragment indexes "
		"from 0x%llx\n", sBlk.s.fragments, indexes,
		sBlk.s.fragment_table_start);

	fragment_table_index = alloc_index_table(indexes);
	fragment_table = malloc(bytes);
	if(fragment_table == NULL)
		MEM_ERROR();

	res = read_fs_bytes(fd, sBlk.s.fragment_table_start, length,
							fragment_table_index);
	if(res == FALSE) {
		ERROR("read_fragment_table: failed to read fragment table "
			"index\n");
		return FALSE;
	}
	SQUASHFS_INSWAP_FRAGMENT_INDEXES(fragment_table_index, indexes);

	for(i = 0; i < indexes; i++) {
		int expected = (i + 1) != indexes ? SQUASHFS_METADATA_SIZE :
					bytes & (SQUASHFS_METADATA_SIZE - 1);
		int length = read_block(fd, fragment_table_index[i], NULL,
			expected, ((char *) fragment_table) + (i *
			SQUASHFS_METADATA_SIZE));
		TRACE("Read fragment table block %d, from 0x%llx, length %d\n",
			i, fragment_table_index[i], length);
		if(length == FALSE) {
			ERROR("read_fragment_table: failed to read fragment "
				"table index\n");
			return FALSE;
		}
	}

	for(i = 0; i < sBlk.s.fragments; i++) 
		SQUASHFS_INSWAP_FRAGMENT_ENTRY(&fragment_table[i]);

	*table_start = fragment_table_index[0];
	return TRUE;
}


static void read_fragment(unsigned int fragment, long long *start_block, int *size)
{
	TRACE("read_fragment: reading fragment %d\n", fragment);

	struct squashfs_fragment_entry *fragment_entry;

	fragment_entry = &fragment_table[fragment];
	*start_block = fragment_entry->start_block;
	*size = fragment_entry->size;
}


static struct inode *read_inode(unsigned int start_block, unsigned int offset)
{
	static union squashfs_inode_header header;
	long long start = sBlk.s.inode_table_start + start_block;
	long long st = start;
	unsigned int off = offset;
	static struct inode i;
	int res;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	res = read_inode_data(&header.base, &st, &off, sizeof(header.base));
	if(res == FALSE)
		EXIT_UNSQUASH("read_inode: failed to read inode %lld:%d\n", st, off);

	SQUASHFS_INSWAP_BASE_INODE_HEADER(&header.base);

	i.uid = (uid_t) id_table[header.base.uid];
	i.gid = (uid_t) id_table[header.base.guid];
	i.mode = lookup_type[header.base.inode_type] | header.base.mode;
	i.type = header.base.inode_type;
	i.time = header.base.mtime;
	i.inode_number = header.base.inode_number;

	switch(header.base.inode_type) {
		case SQUASHFS_DIR_TYPE: {
			struct squashfs_dir_inode_header *inode = &header.dir;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_DIR_INODE_HEADER(inode);

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			i.xattr = SQUASHFS_INVALID_XATTR;
			break;
		}
		case SQUASHFS_LDIR_TYPE: {
			struct squashfs_ldir_inode_header *inode = &header.ldir;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_LDIR_INODE_HEADER(inode);

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			i.xattr = inode->xattr;
			break;
		}
		case SQUASHFS_FILE_TYPE: {
			struct squashfs_reg_inode_header *inode = &header.reg;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_REG_INODE_HEADER(inode);

			i.data = inode->file_size;
			i.frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % sBlk.s.block_size;
			i.fragment = inode->fragment;
			i.offset = inode->offset;
			i.blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(i.data + sBlk.s.block_size - 1) >>
				sBlk.s.block_log :
				i.data >> sBlk.s.block_log;
			i.start = inode->start_block;
			i.block_start = start;
			i.block_offset = offset;
			i.sparse = 0;
			i.xattr = SQUASHFS_INVALID_XATTR;
			break;
		}	
		case SQUASHFS_LREG_TYPE: {
			struct squashfs_lreg_inode_header *inode = &header.lreg;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_LREG_INODE_HEADER(inode);

			i.data = inode->file_size;
			i.frag_bytes = inode->fragment == SQUASHFS_INVALID_FRAG
				?  0 : inode->file_size % sBlk.s.block_size;
			i.fragment = inode->fragment;
			i.offset = inode->offset;
			i.blocks = inode->fragment == SQUASHFS_INVALID_FRAG ?
				(inode->file_size + sBlk.s.block_size - 1) >>
				sBlk.s.block_log :
				inode->file_size >> sBlk.s.block_log;
			i.start = inode->start_block;
			i.block_start = start;
			i.block_offset = offset;
			i.sparse = inode->sparse != 0;
			i.xattr = inode->xattr;
			break;
		}	
		case SQUASHFS_SYMLINK_TYPE:
		case SQUASHFS_LSYMLINK_TYPE: {
			struct squashfs_symlink_inode_header *inode = &header.symlink;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_SYMLINK_INODE_HEADER(inode);

			i.symlink = malloc(inode->symlink_size + 1);
			if(i.symlink == NULL)
				MEM_ERROR();

			res = read_inode_data(i.symlink, &start, &offset, inode->symlink_size);
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode symbolic link %lld:%d\n", start, offset);

			i.symlink[inode->symlink_size] = '\0';
			i.data = inode->symlink_size;

			if(header.base.inode_type == SQUASHFS_LSYMLINK_TYPE) {
				res = read_inode_data(&i.xattr, &start, &offset, sizeof(unsigned int));
				SQUASHFS_INSWAP_INTS(&i.xattr, 1);
			} else
				i.xattr = SQUASHFS_INVALID_XATTR;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE: {
			struct squashfs_dev_inode_header *inode = &header.dev;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_DEV_INODE_HEADER(inode);

			i.data = inode->rdev;
			i.xattr = SQUASHFS_INVALID_XATTR;
			break;
		}
 		case SQUASHFS_LBLKDEV_TYPE:
	 	case SQUASHFS_LCHRDEV_TYPE: {
			struct squashfs_ldev_inode_header *inode = &header.ldev;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_LDEV_INODE_HEADER(inode);

			i.data = inode->rdev;
			i.xattr = inode->xattr;
			break;
		}
		case SQUASHFS_FIFO_TYPE:
		case SQUASHFS_SOCKET_TYPE:
			i.data = 0;
			i.xattr = SQUASHFS_INVALID_XATTR;
			break;
		case SQUASHFS_LFIFO_TYPE:
		case SQUASHFS_LSOCKET_TYPE: {
			struct squashfs_lipc_inode_header *inode = &header.lipc;

			res = read_inode_data(inode, &start, &offset, sizeof(*inode));
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			SQUASHFS_INSWAP_LIPC_INODE_HEADER(inode);

			i.data = 0;
			i.xattr = inode->xattr;
			break;
		}
		default:
			EXIT_UNSQUASH("Unknown inode type %d in read_inode!\n",
				header.base.inode_type);
	}
	return &i;
}


static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	struct squashfs_dir_header dirh;
	char buffer[sizeof(struct squashfs_dir_entry) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	struct squashfs_dir_entry *dire = (struct squashfs_dir_entry *) buffer;
	long long start;
	int bytes = 0, dir_count, size, res;
	struct dir_ent *ent, *cur_ent = NULL;
	struct dir *dir;

	TRACE("squashfs_opendir: inode start block %d, offset %d\n",
		block_start, offset);

	*i = read_inode(block_start, offset);

	dir = malloc(sizeof(struct dir));
	if(dir == NULL)
		MEM_ERROR();

	dir->dir_count = 0;
	dir->cur_entry = NULL;
	dir->mode = (*i)->mode;
	dir->uid = (*i)->uid;
	dir->guid = (*i)->gid;
	dir->mtime = (*i)->time;
	dir->xattr = (*i)->xattr;
	dir->dirs = NULL;

	if ((*i)->data == 3)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;

	start = sBlk.s.directory_table_start + (*i)->start;
	offset = (*i)->offset;
	size = (*i)->data + bytes - 3;

	while(bytes < size) {			
		res = read_directory_data(&dirh, &start, &offset, sizeof(dirh));
		if(res == FALSE)
			goto corrupted;

		SQUASHFS_INSWAP_DIR_HEADER(&dirh);
	
		dir_count = dirh.count + 1;
		TRACE("squashfs_opendir: Read directory header @ byte position "
			"%d, %d directory entries\n", bytes, dir_count);
		bytes += sizeof(dirh);

		/* dir_count should never be larger than SQUASHFS_DIR_COUNT */
		if(dir_count > SQUASHFS_DIR_COUNT) {
			ERROR("File system corrupted: too many entries in directory\n");
			goto corrupted;
		}

		while(dir_count--) {
			res = read_directory_data(dire, &start, &offset, sizeof(*dire));
			if(res == FALSE)
				goto corrupted;

			SQUASHFS_INSWAP_DIR_ENTRY(dire);

			bytes += sizeof(*dire);

			/* size should never be SQUASHFS_NAME_LEN or larger */
			if(dire->size >= SQUASHFS_NAME_LEN) {
				ERROR("File system corrupted: filename too long\n");
				goto corrupted;
			}

			res = read_directory_data(dire->name, &start, &offset,
								dire->size + 1);
			if(res == FALSE)
				goto corrupted;

			dire->name[dire->size + 1] = '\0';

			/* check name for invalid characters (i.e /, ., ..) */
			if(check_name(dire->name, dire->size + 1) == FALSE) {
				ERROR("File system corrupted: invalid characters in name\n");
				goto corrupted;
			}

			TRACE("squashfs_opendir: directory entry %s, inode "
				"%d:%d, type %d\n", dire->name,
				dirh.start_block, dire->offset, dire->type);

			ent = malloc(sizeof(struct dir_ent));
			if(ent == NULL)
				MEM_ERROR();

			ent->name = strdup(dire->name);
			ent->start_block = dirh.start_block;
			ent->offset = dire->offset;
			ent->type = dire->type;
			ent->next = NULL;
			if(cur_ent == NULL)
				dir->dirs = ent;
			else
				cur_ent->next = ent;
			cur_ent = ent;
			dir->dir_count ++;
			bytes += dire->size + 1;
		}
	}

	/* check directory for duplicate names and sorting */
	if(check_directory(dir) == FALSE) {
		ERROR("File system corrupted: directory has duplicate names or is unsorted\n");
		goto corrupted;
	}

	return dir;

corrupted:
	squashfs_closedir(dir);
	return NULL;
}


static int read_id_table(long long *table_start)
{
	/*
	 * Note on overflow limits:
	 * Size of SBlk.s.no_ids is 2^16 (unsigned short)
	 * Max size of bytes is 2^16*4 or 256K
	 * Max indexes is (2^16*4)/8K or 32
	 * Max length is ((2^16*4)/8K)*8 or 256
	 */
	int res, i;
	int bytes = SQUASHFS_ID_BYTES(sBlk.s.no_ids);
	int indexes = SQUASHFS_ID_BLOCKS(sBlk.s.no_ids);
	int length = SQUASHFS_ID_BLOCK_BYTES(sBlk.s.no_ids);
	long long *id_index_table;

	/*
	 * The size of the index table (length bytes) should match the
	 * table start and end points
	 */
	if(length != (*table_start - sBlk.s.id_table_start)) {
		ERROR("read_id_table: Bad id count in super block\n");
		return FALSE;
	}

	TRACE("read_id_table: no_ids %d\n", sBlk.s.no_ids);

	id_index_table = alloc_index_table(indexes);
	id_table = malloc(bytes);
	if(id_table == NULL) {
		ERROR("read_id_table: failed to allocate id table\n");
		return FALSE;
	}

	res = read_fs_bytes(fd, sBlk.s.id_table_start, length, id_index_table);
	if(res == FALSE) {
		ERROR("read_id_table: failed to read id index table\n");
		return FALSE;
	}
	SQUASHFS_INSWAP_ID_BLOCKS(id_index_table, indexes);

	/*
	 * id_index_table[0] stores the start of the compressed id blocks.
	 * This by definition is also the end of the previous filesystem
	 * table - this may be the exports table if it is present, or the
	 * fragments table if it isn't.
	 */
	*table_start = id_index_table[0];

	for(i = 0; i < indexes; i++) {
		int expected = (i + 1) != indexes ? SQUASHFS_METADATA_SIZE :
					bytes & (SQUASHFS_METADATA_SIZE - 1);
		res = read_block(fd, id_index_table[i], NULL, expected,
			((char *) id_table) + i * SQUASHFS_METADATA_SIZE);
		if(res == FALSE) {
			ERROR("read_id_table: failed to read id table block"
				"\n");
			return FALSE;
		}
	}

	SQUASHFS_INSWAP_INTS(id_table, sBlk.s.no_ids);

	return TRUE;
}


static int parse_exports_table(long long *table_start)
{
	/*
	 * Note on overflow limits:
	 * Size of SBlk.s.inodes is 2^32 (unsigned int)
	 * Max indexes is (2^32*8)/8K or 2^22
	 * Max length is ((2^32*8)/8K)*8 or 2^25
	 */
	int res;
	int indexes = SQUASHFS_LOOKUP_BLOCKS((long long) sBlk.s.inodes);
	int length = SQUASHFS_LOOKUP_BLOCK_BYTES((long long) sBlk.s.inodes);
	long long *export_index_table;

	/*
	 * The size of the index table (length bytes) should match the
	 * table start and end points
	 */
	if(length != (*table_start - sBlk.s.lookup_table_start)) {
		ERROR("parse_exports_table: Bad inode count in super block\n");
		return FALSE;
	}

	export_index_table = alloc_index_table(indexes);

	res = read_fs_bytes(fd, sBlk.s.lookup_table_start, length,
							export_index_table);
	if(res == FALSE) {
		ERROR("parse_exports_table: failed to read export index table\n");
		return FALSE;
	}
	SQUASHFS_INSWAP_LOOKUP_BLOCKS(export_index_table, indexes);

	/*
	 * export_index_table[0] stores the start of the compressed export blocks.
	 * This by definition is also the end of the previous filesystem
	 * table - the fragment table.
	 */
	*table_start = export_index_table[0];

	return TRUE;
}


static int read_filesystem_tables()
{
	long long table_start;
	int res;

	/* Read xattrs */
	if(sBlk.s.xattr_id_table_start != SQUASHFS_INVALID_BLK) {
		/* sanity check super block contents */
		if(sBlk.s.xattr_id_table_start >= sBlk.s.bytes_used) {
			ERROR("read_filesystem_tables: xattr id table start too large in super block\n");
			goto corrupted;
		}

		res = read_xattrs_from_disk(fd, &sBlk.s, no_xattrs, &table_start);
		if(res == 0)
			goto corrupted;
		else if(res == -1)
			exit(1);
	} else
		table_start = sBlk.s.bytes_used;

	/* Read id lookup table */

	/* Sanity check super block contents */
	if(sBlk.s.id_table_start >= table_start) {
		ERROR("read_filesystem_tables: id table start too large in super block\n");
		goto corrupted;
	}

	/* there should always be at least one id */
	if(sBlk.s.no_ids == 0) {
		ERROR("read_filesystem_tables: Bad id count in super block\n");
		goto corrupted;
	}

	/*
	 * the number of ids can never be more than double the number of inodes
	 * (the maximum is a unique uid and gid for each inode).
	 */
	if(sBlk.s.no_ids > (sBlk.s.inodes * 2LL)) {
		ERROR("read_filesystem_tables: Bad id count in super block\n");
		goto corrupted;
	}

	if(read_id_table(&table_start) == FALSE)
		goto corrupted;

	/* Read exports table */
	if(sBlk.s.lookup_table_start != SQUASHFS_INVALID_BLK) {

		/* sanity check super block contents */
		if(sBlk.s.lookup_table_start >= table_start) {
			ERROR("read_filesystem_tables: lookup table start too large in super block\n");
			goto corrupted;
		}

		if(parse_exports_table(&table_start) == FALSE)
			goto corrupted;
	}

	/* Read fragment table */
	if(sBlk.s.fragments != 0) {

		/* Sanity check super block contents */
		if(sBlk.s.fragment_table_start >= table_start) {
			ERROR("read_filesystem_tables: fragment table start too large in super block\n");
			goto corrupted;
		}

		/* The number of fragments should not exceed the number of inodes */
		if(sBlk.s.fragments > sBlk.s.inodes) {
			ERROR("read_filesystem_tables: Bad fragment count in super block\n");
			goto corrupted;
		}

		if(read_fragment_table(&table_start) == FALSE)
			goto corrupted;
	}

	/* Sanity check super block directory table values */
	if(sBlk.s.directory_table_start > table_start) {
		ERROR("read_filesystem_tables: directory table start too large in super block\n");
		goto corrupted;
	}

	/* Sanity check super block inode table values */
	if(sBlk.s.inode_table_start >= sBlk.s.directory_table_start) {
		ERROR("read_filesystem_tables: inode table start too large in super block\n");
		goto corrupted;
	}

	if(no_xattrs)
		sBlk.s.xattr_id_table_start = SQUASHFS_INVALID_BLK;

	alloc_index_table(0);

	return TRUE;

corrupted:
	alloc_index_table(0);

	return FALSE;
}


int read_super_4(squashfs_operations **s_ops)
{
	struct squashfs_super_block sBlk_4;

	/*
	 * Try to read a Squashfs 4 superblock
	 */
	int res = read_fs_bytes(fd, SQUASHFS_START,
			sizeof(struct squashfs_super_block), &sBlk_4);

	if(res == FALSE)
		return res;

	swap = sBlk_4.s_magic != SQUASHFS_MAGIC;
	SQUASHFS_INSWAP_SUPER_BLOCK(&sBlk_4);

	if(sBlk_4.s_magic == SQUASHFS_MAGIC && sBlk_4.s_major == 4 &&
			sBlk_4.s_minor == 0) {
		*s_ops = &ops;
		memcpy(&sBlk, &sBlk_4, sizeof(sBlk_4));

		/*
		 * Check the compression type
		 */
		comp = lookup_compressor_id(sBlk.s.compression);
		return TRUE;
	}

	return -1;
}


static long long read_xattr_ids()
{
	int res;
	struct squashfs_xattr_table id_table;

	if(sBlk.s.xattr_id_table_start == SQUASHFS_INVALID_BLK)
		return 0;

	/*
	 * Read xattr id table, containing start of xattr metadata and the
	 * number of xattrs in the file system
	 */
	res = read_fs_bytes(fd, sBlk.s.xattr_id_table_start, sizeof(id_table),
		&id_table);
	if(res == FALSE)
		return -1;

	SQUASHFS_INSWAP_XATTR_TABLE(&id_table);

	return id_table.xattr_ids;
}


static void squashfs_stat(char *source)
{
	time_t mkfs_time = (time_t) sBlk.s.mkfs_time;
	struct tm *t = use_localtime ? localtime(&mkfs_time) :
					gmtime(&mkfs_time);
	char *mkfs_str = asctime(t);
	long long xattr_ids = read_xattr_ids();

	if(xattr_ids == -1)
		EXIT_UNSQUASH("File system corruption detected\n");

	printf("Found a valid SQUASHFS 4:0 superblock on %s.\n", source);
	printf("Creation or last append time %s", mkfs_str ? mkfs_str :
		"failed to get time\n");
	printf("Filesystem size %llu bytes (%.2f Kbytes / %.2f Mbytes)\n",
		sBlk.s.bytes_used, sBlk.s.bytes_used / 1024.0,
		sBlk.s.bytes_used / (1024.0 * 1024.0));
	printf("Compression %s\n", comp->name);

	if(SQUASHFS_COMP_OPTS(sBlk.s.flags)) {
		char buffer[SQUASHFS_METADATA_SIZE] __attribute__ ((aligned));
		int bytes;

		if(!comp->supported)
			printf("\tCould not display compressor options, because"
				" %s compression is not supported\n",
				comp->name);
		else {
			bytes = read_block(fd, sizeof(sBlk.s), NULL, 0, buffer);
			if(bytes == 0) {
				ERROR("Failed to read compressor options\n");
				return;
			}

			compressor_display_options(comp, buffer, bytes);
		}
	}

	printf("Block size %d\n", sBlk.s.block_size);
	printf("Filesystem is %sexportable via NFS\n",
		SQUASHFS_EXPORTABLE(sBlk.s.flags) ? "" : "not ");
	printf("Inodes are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_INODES(sBlk.s.flags) ? "un" : "");
	printf("Data is %scompressed\n",
		SQUASHFS_UNCOMPRESSED_DATA(sBlk.s.flags) ? "un" : "");
	printf("Uids/Gids (Id table) are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_INODES(sBlk.s.flags) ||
		SQUASHFS_UNCOMPRESSED_IDS(sBlk.s.flags) ? "un" : "");

	if(SQUASHFS_NO_FRAGMENTS(sBlk.s.flags))
		printf("Fragments are not stored\n");
	else {
		printf("Fragments are %scompressed\n",
			SQUASHFS_UNCOMPRESSED_FRAGMENTS(sBlk.s.flags) ?
			"un" : "");
		printf("Always-use-fragments option is %sspecified\n",
			SQUASHFS_ALWAYS_FRAGMENTS(sBlk.s.flags) ? "" : "not ");
	}

	if(SQUASHFS_NO_XATTRS(sBlk.s.flags))
		printf("Xattrs are not stored\n");
	else
		printf("Xattrs are %scompressed\n",
			SQUASHFS_UNCOMPRESSED_XATTRS(sBlk.s.flags) ?  "un" : "");

	printf("Duplicates are %sremoved\n", SQUASHFS_DUPLICATES(sBlk.s.flags)
			? "" : "not ");
	printf("Number of fragments %u\n", sBlk.s.fragments);
	printf("Number of inodes %u\n", sBlk.s.inodes);
	printf("Number of ids %d\n", sBlk.s.no_ids);

	if(!SQUASHFS_NO_XATTRS(sBlk.s.flags))
		printf("Number of xattr ids %lld\n", xattr_ids);

	TRACE("sBlk.s.inode_table_start 0x%llx\n", sBlk.s.inode_table_start);
	TRACE("sBlk.s.directory_table_start 0x%llx\n", sBlk.s.directory_table_start);
	TRACE("sBlk.s.fragment_table_start 0x%llx\n", sBlk.s.fragment_table_start);
	TRACE("sBlk.s.lookup_table_start 0x%llx\n", sBlk.s.lookup_table_start);
	TRACE("sBlk.s.id_table_start 0x%llx\n", sBlk.s.id_table_start);
	TRACE("sBlk.s.xattr_id_table_start 0x%llx\n", sBlk.s.xattr_id_table_start);
}


static squashfs_operations ops = {
	.opendir = squashfs_opendir,
	.read_fragment = read_fragment,
	.read_block_list = read_block_list,
	.read_inode = read_inode,
	.read_filesystem_tables = read_filesystem_tables,
	.stat = squashfs_stat
};
