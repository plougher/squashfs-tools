#ifndef ZIPFILE_H
#define ZIPFILE_H

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
 * zipfile.h
 */

/*
 * The zipfile reader accepts one or more zip archives as input.  Unlike the
 * tar reader (which processes a serial stdin stream), it uses each archive's
 * central directory (its index) to enumerate every entry up front, and then
 * reads and inflates the entries with multiple reader threads in parallel.
 *
 * Entries are opened via seekable regular files (not stdin), which is a
 * requirement of using the index for parallel reads.
 */

/* Local file header / central directory / end-of-central-directory magics */
#define ZIP_LOCAL_MAGIC		0x04034b50
#define ZIP_CENTRAL_MAGIC	0x02014b50
#define ZIP_EOCD_MAGIC		0x06054b50
#define ZIP_ZIP64_EOCD_MAGIC	0x06064b50
#define ZIP_ZIP64_LOC_MAGIC	0x07064b50

#define ZIP_LOCAL_SIZE		30
#define ZIP_CENTRAL_SIZE	46
#define ZIP_EOCD_SIZE		22
#define ZIP_ZIP64_LOC_SIZE	20

/* Compression methods we support */
#define ZIP_STORED		0
#define ZIP_DEFLATE		8

/* Host system in the "version made by" field (upper byte) */
#define ZIP_HOST_UNIX		3

/* General purpose bit flag bits */
#define ZIP_FLAG_UTF8		(1 << 11)

/* Extra field record IDs we understand */
#define ZIP_EXTRA_ZIP64		0x0001	/* ZIP64 extended information */
#define ZIP_EXTRA_UT		0x5455	/* extended timestamp (Info-ZIP) */
#define ZIP_EXTRA_NEW_UNIX	0x7875	/* Info-ZIP new unix (uid/gid) */
/*
 * Extended attributes.  There is no standardised way to carry POSIX extended
 * attributes in a zip archive, so mksquashfs uses its own extra-field record.
 * The record payload is a sequence of:
 *
 *	uint16 name_length
 *	uint8  name[name_length]	(e.g. "user.foo", no trailing NUL)
 *	uint32 value_length
 *	uint8  value[value_length]
 */
#define ZIP_EXTRA_XATTR		0x7378	/* 'xs' - squashfs xattr record */

/*
 * A single surviving entry from the merged set of all input archives.  The
 * staging metadata (pathname, stat, symlink target, xattrs) lives in a
 * struct tar_file, which is reused verbatim from the tar reader so that the
 * generic tree-building, write_file() and xattr machinery can be shared.
 */
struct zip_entry {
	struct tar_file	*file;		/* parsed metadata (reused from tar) */
	int		zip;		/* index into zip_fd[] / zip_name[] */
	long long	offset;		/* local file header offset */
	long long	comp_size;	/* compressed size */
	long long	uncomp_size;	/* uncompressed size */
	int		method;		/* ZIP_STORED or ZIP_DEFLATE */
	int		excluded;	/* matched an -e/-ef pattern, drop it */
};

extern void read_zip_data(struct reader *reader, struct read_entry *ent);
extern squashfs_inode process_zip_file(int progress);

#endif
