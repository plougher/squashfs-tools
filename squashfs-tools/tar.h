#ifndef TAR_H 
#define TAR_H

/*
 * Squashfs
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
 * tar.h
 */

struct tar_header {
	union {
		unsigned char	udata[512];
		signed char	sdata[512];
		struct {
			char	name[100];
			char	mode[8];
			char	uid[8];
			char	gid[8];
			char	size[12];
			char	mtime[12];
			char	checksum[8];
			char 	type;
			char	link[100];
			char	magic[8];
			char	user[32];
			char	group[32];
			char	major[8];
			char	minor[8];
			char	prefix[155];
		};
	};
};


struct tar_file {
	struct stat		buf;
	struct file_info	*file;
	char			*pathname;
	char			*link;
	char			*uname;
	char			*gname;
	char			have_size;
	char			have_uid;
	char			have_gid;
	int			duplicate;
};

#define IS_TARFILE(a)	(a->tarfile)
#define TAR_NORMAL1	'0'
#define TAR_NORMAL2	'\0'
#define TAR_HARD	'1'
#define TAR_SYM		'2'
#define TAR_CHAR	'3'
#define TAR_BLOCK	'4'
#define TAR_DIR		'5'
#define TAR_FIFO	'6'
#define TAR_NORMAL3	'7'
#define TAR_GXHDR	'g'
#define TAR_XHDR	'x'

#define V7_MAGIC	"\0\0\0\0\0\0\0"
#define GNU_MAGIC	"ustar  "
#define USTAR_MAGIC	"ustar\00000"

#define S_IFHRD S_IFMT

#define S_ISHRD(a)	((a & S_IFMT) == S_IFHRD)

#define TAR_OK		0
#define TAR_EOF		1
#define TAR_ERROR	2
#define TAR_IGNORED	3

#define GNUTAR_LONG_NAME	'L'
#define GNUTAR_LONG_LINK	'K'

extern void read_tar_file();
extern squashfs_inode process_tar_file(int progress);
#endif
