#ifndef PSEUDO_H
#define PSEUDO_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2014, 2017, 2021
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
 * pseudo.h
 */

#define PSEUDO_FILE_OTHER	1
#define PSEUDO_FILE_PROCESS	2
#define PSEUDO_FILE_DATA	4

#define IS_PSEUDO(a)		((a)->pseudo)
#define IS_PSEUDO_PROCESS(a)	((a)->pseudo && ((a)->pseudo->pseudo_type & PSEUDO_FILE_PROCESS))
#define IS_PSEUDO_OTHER(a)	((a)->pseudo && ((a)->pseudo->pseudo_type & PSEUDO_FILE_OTHER))
#define IS_PSEUDO_DATA(a)	((a)->pseudo && ((a)->pseudo->pseudo_type & PSEUDO_FILE_DATA))

struct pseudo_stat {
	unsigned int	mode;
	unsigned int	uid;
	unsigned int	gid;
	unsigned int	major;
	unsigned int	minor;
	time_t		mtime;
	int		ino;
};

struct pseudo_file {
	char		*filename;
	long long	start;
	int		fd;
};

struct pseudo_data {
	struct pseudo_file	*file;
	long long		offset;
	long long		length;
};

struct pseudo_dev {
	char				type;
	int				pseudo_type;
	union {
		struct pseudo_stat	*buf;
		struct stat		*linkbuf;
	};
	union {
		struct pseudo_data	*data;
		char			*command;
		char			*symlink;
		char			*linkname;
	};
};

struct pseudo_entry {
	char			*name;
	char			*pathname;
	struct pseudo		*pseudo;
	struct pseudo_dev	*dev;
};
	
struct pseudo {
	int			names;
	int			count;
	struct pseudo_entry	*name;
};

extern long long read_bytes(int, void *, long long);
extern int read_pseudo_definition(char *, char *);
extern int read_pseudo_file(char *, char *);
extern struct pseudo *pseudo_subdir(char *, struct pseudo *);
extern struct pseudo_entry *pseudo_readdir(struct pseudo *);
extern struct pseudo_dev *get_pseudo_file(int);
extern int pseudo_exec_file(struct pseudo_dev *, int *);
extern struct pseudo *get_pseudo();
extern void dump_pseudos();
#endif
