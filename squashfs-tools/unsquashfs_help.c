/*
 * Squashfs
 *
 * Copyright (c) 2024
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
 * unsquashfs_help.c
 */

#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>

#include "unsquashfs_help.h"
#include "unsquashfs_error.h"
#include "print_pager.h"
#include "compressor.h"

#define UNSQUASHFS_SYNTAX "SYNTAX: %s [OPTIONS] FILESYSTEM [files to extract or exclude (with -excludes) or cat (with -cat )]\n\n"

static char *unsquashfs_text[]= {
	"Filesystem extraction (filtering) options:", "\n",
	"\t-d[est] <pathname>\textract to <pathname>, default \"squashfs-root\".  This option ", "also sets the prefix used when listing the filesystem\n",
	"\t-max[-depth] <levels>\tdescend at most <levels> of directories when extracting\n",
	"\t-excludes\t\ttreat files on command line as exclude files\n",
	"\t-ex[clude-list]\t\tlist of files to be excluded, terminated with ; e.g. file1 file2 ;\n",
	"\t-extract-file <file>\tlist of directories or files to extract.  One per line\n",
	"\t-exclude-file <file>\tlist of directories or files to exclude.  One per line\n",
	"\t-match\t\t\tabort if any extract file does not match on\n\t\t\t\tanything, and can not be resolved.  Implies -missing-symlinks and -no-wildcards\n",
	"\t-follow[-symlinks]\tfollow symlinks in extract files, and add all files/symlinks needed to resolve extract file.  Implies -no-wildcards\n",
	"\t-missing[-symlinks]\tUnsquashfs will abort if any symlink can't be resolved in -follow-symlinks\n",
	"\t-no-wild[cards]\t\tdo not use wildcard matching in extract and exclude names\n",
	"\t-r[egex]\t\ttreat extract names as POSIX regular expressions rather than use the default shell wildcard expansion (globbing)\n",
	"\t-all[-time] <time>\tset all file timestamps to <time>, rather than the time stored in the filesystem inode.  <time> can be an unsigned 32-bit int indicating seconds since the epoch (1970-01-01) or a string value which is passed to the \"date\" command to parse. Any string value which the date command recognises can be used such as \"now\", \"last week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"\t-cat\t\t\tcat the files on the command line to stdout\n",
	"\t-f[orce]\t\tif destination directory already exists, descend into it and any sub-directories, and unlink (delete) files if they already exist before extracting to them\n",
	"\t-pf <file>\t\toutput a pseudo file equivalent of the input Squashfs filesystem, use - for stdout\n",
	"\n", "Filesystem information and listing options:", "\n",
	"\t-s[tat]\t\t\tdisplay filesystem superblock information\n",
	"\t-max[-depth] <levels>\tdescend at most <levels> of directories when listing\n",
	"\t-i[nfo]\t\t\tprint files as they are extracted\n",
	"\t-li[nfo]\t\tprint files as they are extracted with file tattributes (like ls -l output)\n",
	"\t-l[s]\t\t\tlist filesystem, but do not extract files\n",
	"\t-ll[s]\t\t\tlist filesystem with file attributes (like ls -l output), but do not extract files\n",
	"\t-lln[umeric]\t\tsame as -lls but with numeric uids and gids\n",
	"\t-lc\t\t\tlist filesystem concisely, displaying only files and empty directories.  Do not extract files\n",
	"\t-llc\t\t\tlist filesystem concisely with file attributes, displaying only files and empty directories.  Do not extract files\n",
	"\t-full[-precision]\tuse full precision when displaying times including seconds.  Use with -linfo, -lls, -lln and -llc\n",
	"\t-UTC\t\t\tuse UTC rather than local time zone when displaying time\n",
	"\t-mkfs-time\t\tdisplay filesystem superblock time, which is an unsigned 32-bit int representing the time in seconds since the epoch (1970-01-01)\n",
	"\n", "Filesystem extended attribute (xattrs) options:", "\n",
	"\t-no[-xattrs]\t\tdo not extract xattrs in file system", NOXOPT_STR"\n",
	"\t-x[attrs]\t\textract xattrs in file system" XOPT_STR "\n",
	"\t-xattrs-exclude <regex>\texclude any xattr names matching <regex>.  <regex> is a POSIX regular expression, e.g. -xattrs-exclude '^user.' excludes xattrs from the user namespace\n",
	"\t-xattrs-include <regex>\tinclude any xattr names matching <regex>.  <regex> is a POSIX regular expression, e.g. -xattrs-include '^user.' includes xattrs from the user namespace\n",
	"\n", "Unsquashfs runtime options:", "\n",
	"\t-v[ersion]\t\tprint version, licence and copyright information\n",
	"\t-p[rocessors] <number>\tuse <number> processors.  By default will use the number of processors available\n",
	"\t-mem <size>\t\tuse <size> physical memory for caches.  Use K, M or G to specify Kbytes, Mbytes or Gbytes respectively.  Default 512 Mbytes\n",
	"\t-mem-percent <percent>\tuse <percent> physical memory for caches.\n",
	"\t-q[uiet]\t\tno verbose output\n",
	"\t-n[o-progress]\t\tdo not display the progress bar\n",
	"\t-percentage\t\tdisplay a percentage rather than the full progress bar.  Can be used with dialog --gauge etc.\n",
	"\t-ig[nore-errors]\ttreat errors writing files to output as non-fatal\n",
	"\t-st[rict-errors]\ttreat all errors as fatal\n",
	"\t-no-exit[-code]\t\tdo not set exit code (to nonzero) on non-fatal errors\n",
	"\n", "Miscellaneous options:", "\n",
	"\t-h[elp]\t\t\toutput this options text to stdout\n",
	"\t-o[ffset] <bytes>\tskip <bytes> at start of FILESYSTEM.  Optionally a suffix of K, M or G can be given to specify Kbytes, Mbytes or Gbytes respectively (default 0 bytes).\n",
	"\t-fstime\t\t\tsynonym for -mkfs-time\n",
	"\t-e[f] <extract file>\tsynonym for -extract-file\n",
	"\t-exc[f] <exclude file>\tsynonym for -exclude-file\n",
	"\t-L\t\t\tsynonym for -follow-symlinks\n",
	"\t-pseudo-file <file>\talternative name for -pf\n",
	"\n", "Exit status:", "\n",
	"  0\tThe filesystem listed or extracted OK.\n",
	"  1\tFATAL errors occurred, e.g. filesystem corruption, I/O errors.  Unsquashfs did not continue and aborted.\n",
	"  2\tNon-fatal errors occurred, e.g. no support for XATTRs, Symbolic links in output filesystem or couldn't write permissions to output filesystem.  Unsquashfs continued and did not abort.\n",
	"\nSee -ignore-errors, -strict-errors and -no-exit-code options for how they affect the exit status.\n",
	"\n", "See also:", "\n",
	"The README for the Squashfs-tools 4.6.1 release, describing the new features can be read here https://github.com/plougher/squashfs-tools/blob/master/README-4.6.1\n",
	"\nThe Squashfs-tools USAGE guide can be read here https://github.com/plougher/squashfs-tools/blob/master/USAGE-4.6\n",
	NULL
};

static void print_help_all(char *name, char *syntax, char **options_text)
{
	int i, cols, tty = isatty(STDOUT_FILENO);
	pid_t pager_pid;
	FILE *pager;

	if(tty) {
		cols = get_column_width();

		pager = exec_pager(&pager_pid);
		if(pager == NULL)
			exit(1);
	} else {
		cols = 80;
		pager = stdout;
	}

	autowrap_printf(pager, cols, syntax, name);

	for(i = 0; options_text[i] != NULL; i++)
		autowrap_print(pager, options_text[i], cols);

	autowrap_print(pager, "\nDecompressors available:\n", cols);

	display_compressors(pager, "", "");

	if(tty) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}


void unsquashfs_help_all(char *name)
{
        print_help_all(name, UNSQUASHFS_SYNTAX, unsquashfs_text);
}
