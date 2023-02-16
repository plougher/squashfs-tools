/*
 * Unsquash a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2011, 2012, 2019, 2021, 2022, 2023
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
 * unsquash-1.c
 */

#include "unsquashfs.h"
#include "squashfs_compat.h"
#include "compressor.h"

static unsigned int *uid_table, *guid_table;
static squashfs_operations ops;

static void read_block_list(unsigned int *block_list, long long start,
	unsigned int offset, int blocks)
{
	unsigned short *source;
	int i, res;

	TRACE("read_block_list: blocks %d\n", blocks);

	source = malloc(blocks * sizeof(unsigned short));
	if(source == NULL)
		MEM_ERROR();

	if(swap) {
		char *swap_buff;

		swap_buff = malloc(blocks * sizeof(unsigned short));
		if(swap_buff == NULL)
			MEM_ERROR();

		res = read_inode_data(swap_buff, &start, &offset, blocks * sizeof(unsigned short));
		if(res == FALSE)
			EXIT_UNSQUASH("read_block_list: failed to read "
					"inode index %lld:%d\n", start, offset);
		SQUASHFS_SWAP_SHORTS_3(source, swap_buff, blocks);
		free(swap_buff);
	} else {
		res = read_inode_data(source, &start, &offset, blocks * sizeof(unsigned short));
		if(res == FALSE)
			EXIT_UNSQUASH("read_block_list: failed to read "
					"inode index %lld:%d\n", start, offset);
	}

	for(i = 0; i < blocks; i++)
		block_list[i] = SQUASHFS_COMPRESSED_SIZE(source[i]) |
			(SQUASHFS_COMPRESSED(source[i]) ? 0 :
			SQUASHFS_COMPRESSED_BIT_BLOCK);
	free(source);
}


static struct inode *read_inode(unsigned int start_block, unsigned int offset)
{
	static union squashfs_inode_header_1 header;
	long long start = sBlk.s.inode_table_start + start_block;
	long long st = start;
	unsigned int off = offset, uid;
	static struct inode i;
	int res;

	TRACE("read_inode: reading inode [%d:%d]\n", start_block,  offset);

	if(swap) {
		squashfs_base_inode_header_1 sinode;
		res = read_inode_data(&sinode, &st, &off, sizeof(sinode));
		if(res)
			SQUASHFS_SWAP_BASE_INODE_HEADER_1(&header.base, &sinode,
				sizeof(squashfs_base_inode_header_1));
	} else
		res = read_inode_data(&header.base, &st, &off, sizeof(header.base));

	if(res == FALSE)
		EXIT_UNSQUASH("read_inode: failed to read inode %lld:%d\n", st, off);

	uid = (header.base.inode_type - 1) / SQUASHFS_TYPES * 16 + header.base.uid;

	if(uid >= sBlk.no_uids)
		EXIT_UNSQUASH("File system corrupted - uid index in inode too large (uid: %u)\n", uid);

	i.uid = (uid_t) uid_table[uid];

	if(header.base.inode_type == SQUASHFS_IPC_TYPE) {
		squashfs_ipc_inode_header_1 *inodep = &header.ipc;

		if(swap) {
			squashfs_ipc_inode_header_1 sinodep;
			res = read_inode_data(&sinodep, &start, &offset, sizeof(sinodep));
			if(res)
				SQUASHFS_SWAP_IPC_INODE_HEADER_1(inodep, &sinodep);
		} else
			res = read_inode_data(inodep, &start, &offset, sizeof(*inodep));

		if(res == FALSE)
			EXIT_UNSQUASH("read_inode: failed to read "
				"inode %lld:%d\n", start, offset);

		if(inodep->type == SQUASHFS_SOCKET_TYPE) {
			i.mode = S_IFSOCK | header.base.mode;
			i.type = SQUASHFS_SOCKET_TYPE;
		} else {
			i.mode = S_IFIFO | header.base.mode;
			i.type = SQUASHFS_FIFO_TYPE;
		}

		uid = inodep->offset * 16 + inodep->uid;
		if(uid >= sBlk.no_uids)
			EXIT_UNSQUASH("File system corrupted - uid index in inode too large (uid: %u)\n", uid);

		i.uid = (uid_t) uid_table[uid];
	} else {
		i.mode = lookup_type[(header.base.inode_type - 1) %
			SQUASHFS_TYPES + 1] | header.base.mode;
		i.type = (header.base.inode_type - 1) % SQUASHFS_TYPES + 1;
	}

	i.xattr = SQUASHFS_INVALID_XATTR;

	if(header.base.guid == 15)
		i.gid = i.uid;
	else if(header.base.guid >= sBlk.no_guids)
		EXIT_UNSQUASH("File system corrupted - gid index in inode too large (gid: %u)\n", header.base.guid);
	else
		i.gid = (uid_t) guid_table[header.base.guid];

	i.inode_number = inode_number ++;

	switch(i.type) {
		case SQUASHFS_DIR_TYPE: {
			squashfs_dir_inode_header_1 *inode = &header.dir;

			if(swap) {
				squashfs_dir_inode_header_1 sinode;
				res = read_inode_data(&sinode, &start, &offset, sizeof(sinode));
				if(res)
					SQUASHFS_SWAP_DIR_INODE_HEADER_1(inode,
						&sinode);
			} else
				res = read_inode_data(inode, &start, &offset, sizeof(*inode));

			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			i.data = inode->file_size;
			i.offset = inode->offset;
			i.start = inode->start_block;
			if(time_opt)
				i.time = timeval;
			else
				i.time = inode->mtime;
			break;
		}
		case SQUASHFS_FILE_TYPE: {
			squashfs_reg_inode_header_1 *inode = &header.reg;

			if(swap) {
				squashfs_reg_inode_header_1 sinode;
				res = read_inode_data(&sinode, &start, &offset, sizeof(sinode));
				if(res)
					SQUASHFS_SWAP_REG_INODE_HEADER_1(inode,
						&sinode);
			} else
				res = read_inode_data(inode, &start, &offset, sizeof(*inode));

			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			i.data = inode->file_size;
			if(time_opt)
				i.time = timeval;
			else
				i.time = inode->mtime;
			i.blocks = (i.data + sBlk.s.block_size - 1) >>
				sBlk.s.block_log;
			i.start = inode->start_block;
			i.block_start = start;
			i.block_offset = offset;
			i.fragment = 0;
			i.frag_bytes = 0;
			i.offset = 0;
			i.sparse = 0;
			break;
		}	
		case SQUASHFS_SYMLINK_TYPE: {
			squashfs_symlink_inode_header_1 *inodep =
				&header.symlink;

			if(swap) {
				squashfs_symlink_inode_header_1 sinodep;
				res = read_inode_data(&sinodep, &start, &offset, sizeof(sinodep));
				if(res)
					SQUASHFS_SWAP_SYMLINK_INODE_HEADER_1(inodep,
						&sinodep);
			} else
				res = read_inode_data(inodep, &start, &offset, sizeof(*inodep));

			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			i.symlink = malloc(inodep->symlink_size + 1);
			if(i.symlink == NULL)
				MEM_ERROR();

			res = read_inode_data(i.symlink, &start, &offset, inodep->symlink_size);
			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode symbolic link %lld:%d\n", start, offset);
			i.symlink[inodep->symlink_size] = '\0';
			i.data = inodep->symlink_size;
			if(time_opt)
				i.time = timeval;
			else
				i.time = sBlk.s.mkfs_time;
			break;
		}
 		case SQUASHFS_BLKDEV_TYPE:
	 	case SQUASHFS_CHRDEV_TYPE: {
			squashfs_dev_inode_header_1 *inodep = &header.dev;

			if(swap) {
				squashfs_dev_inode_header_1 sinodep;
				res = read_inode_data(&sinodep, &start, &offset, sizeof(sinodep));
				if(res)
					SQUASHFS_SWAP_DEV_INODE_HEADER_1(inodep,
						&sinodep);
			} else
				res = read_inode_data(inodep, &start, &offset, sizeof(*inodep));

			if(res == FALSE)
				EXIT_UNSQUASH("read_inode: failed to read "
					"inode %lld:%d\n", start, offset);

			i.data = inodep->rdev;
			if(time_opt)
				i.time = timeval;
			else
				i.time = sBlk.s.mkfs_time;
			break;
			}
		case SQUASHFS_FIFO_TYPE:
		case SQUASHFS_SOCKET_TYPE: {
			i.data = 0;
			if(time_opt)
				i.time = timeval;
			else
				i.time = sBlk.s.mkfs_time;
			break;
			}
		default:
			EXIT_UNSQUASH("Unknown inode type %d in "
				" read_inode_header_1!\n",
				header.base.inode_type);
	}
	return &i;
}


static struct dir *squashfs_opendir(unsigned int block_start, unsigned int offset,
	struct inode **i)
{
	squashfs_dir_header_2 dirh;
	char buffer[sizeof(squashfs_dir_entry_2) + SQUASHFS_NAME_LEN + 1]
		__attribute__((aligned));
	squashfs_dir_entry_2 *dire = (squashfs_dir_entry_2 *) buffer;
	long long start;
	int bytes = 0;
	int dir_count, size, res;
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

	if ((*i)->data == 0)
		/*
		 * if the directory is empty, skip the unnecessary
		 * lookup_entry, this fixes the corner case with
		 * completely empty filesystems where lookup_entry correctly
		 * returning -1 is incorrectly treated as an error
		 */
		return dir;
		
	start = sBlk.s.directory_table_start + (*i)->start;
	offset = (*i)->offset;
	size = (*i)->data + bytes;

	while(bytes < size) {			
		if(swap) {
			squashfs_dir_header_2 sdirh;
			res = read_directory_data(&sdirh, &start, &offset, sizeof(sdirh));
			if(res)
				SQUASHFS_SWAP_DIR_HEADER_2(&dirh, &sdirh);
		} else
			res = read_directory_data(&dirh, &start, &offset, sizeof(dirh));

		if(res == FALSE)
			goto corrupted;
	
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
			if(swap) {
				squashfs_dir_entry_2 sdire;
				res = read_directory_data(&sdire, &start,
					&offset, sizeof(sdire));
				if(res)
					SQUASHFS_SWAP_DIR_ENTRY_2(dire, &sdire);
			} else
				res = read_directory_data(dire, &start,
					&offset, sizeof(*dire));

			if(res == FALSE)
				goto corrupted;

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

	/* check directory for duplicate names.  Need to sort directory first */
	sort_directory(&(dir->dirs), dir->dir_count);
	if(check_directory(dir) == FALSE) {
		ERROR("File system corrupted: directory has duplicate names\n");
		goto corrupted;
	}
	return dir;

corrupted:
	squashfs_closedir(dir);
	return NULL;
}


static int read_filesystem_tables()
{
	long long table_start;

	/* Read uid and gid lookup tables */

	/* Sanity check super block contents */
	if(sBlk.no_guids) {
		if(sBlk.guid_start >= sBlk.s.bytes_used) {
			ERROR("read_filesystem_tables: gid start too large in super block\n");
			goto corrupted;
		}

		/* In 1.x filesystems, there should never be more than 15 gids */
		if(sBlk.no_guids > 15) {
			ERROR("read_filesystem_tables: gids too large in super block\n");
			goto corrupted;
		}

		if(read_ids(sBlk.no_guids, sBlk.guid_start, sBlk.s.bytes_used, &guid_table) == FALSE)
			goto corrupted;

		table_start = sBlk.guid_start;
	} else {
		/* no guids, guid_start should be 0 */
		if(sBlk.guid_start != 0) {
			ERROR("read_filesystem_tables: gid start too large in super block\n");
			goto corrupted;
		}

		table_start = sBlk.s.bytes_used;
	}

	if(sBlk.uid_start >= table_start) {
		ERROR("read_filesystem_tables: uid start too large in super block\n");
		goto corrupted;
	}

	/* There should be at least one uid */
	if(sBlk.no_uids == 0) {
		ERROR("read_filesystem_tables: uid count bad in super block\n");
		goto corrupted;
	}

	/* In 1.x filesystems, there should never be more than 48 uids */
	if(sBlk.no_uids > 48) {
		ERROR("read_filesystem_tables: uids too large in super block\n");
		goto corrupted;
	}

	if(read_ids(sBlk.no_uids, sBlk.uid_start, table_start, &uid_table) == FALSE)
		goto corrupted;

	table_start = sBlk.uid_start;

	/* Sanity check super block directory table values */
	if(sBlk.s.directory_table_start > table_start) {
		ERROR("read_filesystem_tables: directory table start too large in super block\n");
		goto corrupted;
	}

	/* Sanity check super block inode table values  */
	if(sBlk.s.inode_table_start >= sBlk.s.directory_table_start) {
		ERROR("read_filesystem_tables: inode table start too large in super block\n");
		goto corrupted;
	}

	return TRUE;

corrupted:
	return FALSE;
}


int read_super_1(squashfs_operations **s_ops, void *s)
{
	squashfs_super_block_3 *sBlk_3 = s;

	if(sBlk_3->s_magic != SQUASHFS_MAGIC || sBlk_3->s_major != 1 ||
							sBlk_3->s_minor != 0)
		return -1;

	sBlk.s.s_magic = sBlk_3->s_magic;
	sBlk.s.inodes = sBlk_3->inodes;
	sBlk.s.mkfs_time = sBlk_3->mkfs_time;
	sBlk.s.block_size = sBlk_3->block_size_1;
	sBlk.s.fragments = 0;
	sBlk.s.block_log = sBlk_3->block_log;
	sBlk.s.flags = sBlk_3->flags;
	sBlk.s.s_major = sBlk_3->s_major;
	sBlk.s.s_minor = sBlk_3->s_minor;
	sBlk.s.root_inode = sBlk_3->root_inode;
	sBlk.s.bytes_used = sBlk_3->bytes_used_2;
	sBlk.s.inode_table_start = sBlk_3->inode_table_start_2;
	sBlk.s.directory_table_start = sBlk_3->directory_table_start_2;
	sBlk.s.fragment_table_start = SQUASHFS_INVALID_BLK;
	sBlk.s.lookup_table_start = sBlk_3->lookup_table_start;
	sBlk.no_uids = sBlk_3->no_uids;
	sBlk.no_guids = sBlk_3->no_guids;
	sBlk.uid_start = sBlk_3->uid_start_2;
	sBlk.guid_start = sBlk_3->guid_start_2;
	sBlk.s.xattr_id_table_start = SQUASHFS_INVALID_BLK;

	*s_ops = &ops;

	/*
	 * 1.x filesystems use gzip compression.
	 */
	comp = lookup_compressor("gzip");
	return TRUE;
}


static void squashfs_stat(char *source)
{
	time_t mkfs_time = (time_t) sBlk.s.mkfs_time;
	struct tm *t = use_localtime ? localtime(&mkfs_time) :
					gmtime(&mkfs_time);
	char *mkfs_str = asctime(t);

#if __BYTE_ORDER == __BIG_ENDIAN
	printf("Found a valid %sSQUASHFS %d:%d superblock on %s.\n",
		swap ? "little endian " : "big endian ", sBlk.s.s_major,
		sBlk.s.s_minor, source);
#else
	printf("Found a valid %sSQUASHFS %d:%d superblock on %s.\n",
		swap ? "big endian " : "little endian ", sBlk.s.s_major,
		sBlk.s.s_minor, source);
#endif

	printf("Creation or last append time %s", mkfs_str ? mkfs_str :
		"failed to get time\n");
	printf("Filesystem size %llu bytes (%.2f Kbytes / %.2f Mbytes)\n",
		sBlk.s.bytes_used, sBlk.s.bytes_used / 1024.0,
		sBlk.s.bytes_used / (1024.0 * 1024.0));
	printf("Block size %d\n", sBlk.s.block_size);
	printf("Filesystem is %sexportable via NFS\n",
		SQUASHFS_EXPORTABLE(sBlk.s.flags) ? "" : "not ");
	printf("Inodes are %scompressed\n",
		SQUASHFS_UNCOMPRESSED_INODES(sBlk.s.flags) ? "un" : "");
	printf("Data is %scompressed\n",
		SQUASHFS_UNCOMPRESSED_DATA(sBlk.s.flags) ? "un" : "");
	printf("Check data is %spresent in the filesystem\n",
		SQUASHFS_CHECK_DATA(sBlk.s.flags) ? "" : "not ");
	printf("Duplicates are removed\n");
	printf("Number of inodes %d\n", sBlk.s.inodes);
	printf("Number of uids %d\n", sBlk.no_uids);
	printf("Number of gids %d\n", sBlk.no_guids);

	TRACE("sBlk.s.inode_table_start 0x%llx\n", sBlk.s.inode_table_start);
	TRACE("sBlk.s.directory_table_start 0x%llx\n", sBlk.s.directory_table_start);
	TRACE("sBlk.uid_start 0x%llx\n", sBlk.uid_start);
	TRACE("sBlk.guid_start 0x%llx\n", sBlk.guid_start);
}


static squashfs_operations ops = {
	.opendir = squashfs_opendir,
	.read_block_list = read_block_list,
	.read_inode = read_inode,
	.read_filesystem_tables = read_filesystem_tables,
	.stat = squashfs_stat
};
