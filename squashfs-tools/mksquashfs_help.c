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
 * mksquashfs_help.c
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "mksquashfs_error.h"
#include "mksquashfs_help.h"
#include "compressor.h"

extern long long read_bytes(int, void *, long long);

static char *pager_command = "/usr/bin/pager";
static char *pager_name = "pager";
static int pager_from_env_var = FALSE;

#define MKSQUASHFS_SYNTAX "SYNTAX:%s source1 source2 ...  FILESYSTEM " \
	"[OPTIONS] [-e list of exclude dirs/files]\n\n"

#define SQFSTAR_SYNTAX "SYNTAX:%s [OPTIONS] FILESYSTEM [list of exclude dirs/files]\n\n"

static char *mksquashfs_options[] = {
	"", "", "-b", "-comp", "-noI", "-noId", "-noD", "-noF", "-noX",
	"-no-compression", "", "", "", "-tar", "-no-strip", "-tarstyle",
	"-cpiostyle", "-cpiostyle0", "-reproducible", "-not-reproducible",
	"-mkfs-time", "-all-time", "-root-time", "-root-mode", "-root-uid",
	"-root-gid", "-all-root", "-force-uid", "-force-gid",
	"-pseudo-override", "-no-exports", "-exports", "-no-sparse",
	"-no-tailends", "-tailends", "-no-fragments", "-no-duplicates",
	"-no-hardlinks", "-keep-as-directory", "", "", "", "-p", "-pd", "-pd",
	"-pf", "-sort", "-ef", "-wildcards", "-regex", "-max-depth",
	"-one-file-system", "-one-file-system-x", "", "", "", "-no-xattrs",
	"-xattrs", "-xattrs-exclude", "-xattrs-include", "-xattrs-add", "",
	"", "", "-version", "-exit-on-error", "-quiet", "-info", "-no-progress",
	"-progress", "-percentage", "-throttle", "-limit", "-processors",
	"-mem", "-mem-percent", "-mem-default", "", "", "", "-noappend",
	"-root-becomes", "-no-recovery", "-recovery-path", "-recover", "", "",
	"", "-action", "-log-action", "-true-action", "-false-action",
	"-action-file", "-log-action-file", "-true-action-file",
	"-false-action-file", "", "", "", "-default-mode", "-default-uid",
	"-default-gid", "-ignore-zeros", "", "", "", "-nopad", "-offset", "-o",
	"", "", "", "-help", "-help-option", "-help-section", "help-comp",
	"-help-all", "-Xhelp", "-h", "-ho", "-hs", "-ha", "", "", "",
	"-fstime", "-always-use-fragments", "-root-owned",
	"-noInodeCompression", "-noIdTableCompression", "-noDataCompression",
	"-noFragmentCompression", "-noXattrCompression", "-pseudo-dir", NULL,
};

static char *sqfstar_options[]={
	"", "", "-b", "-comp", "-noI", "-noId", "-noD", "-noF", "-noX",
	"-no-compression", "", "", "", "-reproducible", "-not-reproducible",
	"-mkfs-time", "-all-time", "-root-time", "-root-mode", "-root-uid",
	"-root-gid", "-all-root", "-force-uid", "-force-gid", "-default-mode",
	"-default-uid", "-default-gid", "-pseudo-override", "-exports",
	"-no-sparse", "-no-fragments", "-no-tailends", "-no-duplicates",
	"-no-hardlinks", "", "", "", "-p", "-pd", "-pd", "-pf", "-ef", "-regex",
	"-ignore-zeros", "", "", "", "-no-xattrs", "-xattrs", "-xattrs-exclude",
	"-xattrs-include", "-xattrs-add", "", "","", "-version", "-force",
	"-exit-on-error", "-quiet", "-info", "-no-progress", "-progress",
	"-percentage", "-throttle", "-limit", "-processors", "-mem",
	"-mem-percent", "-mem-default", "", "", "", "-nopad", "-offset", "-o",
	"", "", "", "-fstime", "-root-owned", "-noInodeCompression",
	"-noIdTableCompression", "-noDataCompression", "-noFragmentCompression",
	"-noXattrCompression", "", "-help", "help-option", "-help-section",
	"-help-all", "-Xhelp", "-h", "-ho", "-hs", "-ha", NULL
};

static char *mksquashfs_args[]={
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "<time>", "<time>", "<time>", "<mode>", "<value>", "<value>",
	"", "<value>", "<value>", "", "", "", "", "", "", "", "", "", "", "",
	"", "", "", "<d mode uid gid>", "<D time mode uid gid>",
	"<pseudo-file>", "<sort-file>", "<exclude-file>", "", "", "<levels>",
	"", "", "", "", "", "", "", "<regex>", "<regex>", "<name=val>", "", "",
	"", "", "", "", "", "", "", "", "<percentage>", "<percentage>",
	"<number>", "<size>", "<percent>", "", "", "", "", "", "<name>", "",
	"<name>", "<name>", "", "", "", "<action@expression>",
	"<action@expression>", "<action@expression>", "<action@expression>",
	"<file>", "<file>", "<file>", "<file>", "", "", "", "<mode>", "<value>",
	"<value>", "", "", "", "", "", "<offset>", "<offset>", "", "", "", "",
	"<regex>", "<section>", "comp", "", "", "", "<regex>", "<section>", "",
	"", "", "", "<time>", "", "", "", "", "", "", "", ""
};

static char *sqfstar_args[]={
	"", "", "<block-size>", "<comp>",  "", "", "", "", "", "", "", "", "",
	"", "", "<time>", "<time>", "<time>", "<mode>", "<value>", "<value>",
	"", "<value>", "<value>", "<mode>", "<value>", "<value>", "", "", "",
	"", "", "", "", "", "", "", "<pseudo-definition>", "<d mode uid gid>",
	"<D time mode u g>", "<pseudo-file>", "<exclude-file>", "", "", "", "",
	"", "", "", "<regex>", "<regex>", "<name=val>", "", "","", "", "", "",
	"", "", "", "", "", "<percentage>", "<percentage>", "<number>",
	"<size>", "<percent>", "", "", "", "", "", "<offset>", "<offset>", "",
	"", "", "<time>", "", "", "", "", "", "", "", "", "<regex>",
	"<section>", "", "", "", "<regex>", "<section>", ""
};

static char *mksquashfs_sections[]={
	"compression", "build", "filter", "xattrs", "runtime", "append",
	"actions", "tar", "expert", "help", "misc", "pseudo", "environment",
	"exit", "extra", NULL
};

static char *sqfstar_sections[]={
	"compression", "build", "filter", "xattrs", "runtime", "expert",
	"misc", "pseudo", "environment", "exit", "extra", NULL
};

static char *mksquashfs_text[]={
	"Filesystem compression options:", "\n",
	"-b <block-size>\t\tset data block to <block-size>.  Default 128 "
		"Kbytes.  Optionally a suffix of K, KB, Kbytes or M, MB, "
		"Mbytes can be given to specify Kbytes or Mbytes "
		"respectively\n",
	"-comp <comp>\t\tselect <comp> compression.  Run -help-comp <comp> to "
		"get compressor options.\n\t\t\tCompressors available:\n"
		"\t\t\t\t" COMPRESSORS "\n",
	"-noI\t\t\tdo not compress inode table\n",
	"-noId\t\t\tdo not compress the uid/gid table (implied by -noI)\n",
	"-noD\t\t\tdo not compress data blocks\n",
	"-noF\t\t\tdo not compress fragment blocks\n",
	"-noX\t\t\tdo not compress extended attributes\n",
	"-no-compression\t\tdo not compress any of the data or metadata.  "
		"This is equivalent to specifying -noI -noD -noF and -noX\n",
	"\n", "Filesystem build options:", "\n",
	"-tar\t\t\tread uncompressed tar file from standard in (stdin)\n",
	"-no-strip\t\tact like tar, and do not strip leading directories from "
		"source files\n",
	"-tarstyle\t\talternative name for -no-strip\n",
	"-cpiostyle\t\tact like cpio, and read file pathnames from standard in "
		"(stdin)\n",
	"-cpiostyle0\t\tlike -cpiostyle, but filenames are null terminated.  "
		"Can be used with find -print0 action\n",
	"-reproducible\t\tbuild filesystems that are reproducible" REP_STR "\n",
	"-not-reproducible\tbuild filesystems that are not reproducible"
		NOREP_STR "\n",
	"-mkfs-time <time>\tset filesystem creation timestamp to <time>. "
		"<time> can be an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-all-time <time>\tset all file timestamps to <time>. <time> can be an "
		"unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-root-time <time>\tset root directory time to <time>. <time> can be "
		"an unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-root-mode <mode>\tset root directory permissions to octal <mode>\n",
	"-root-uid <value>\tset root directory owner to specified <value>, "
		"<value> can be either an integer uid or user name\n",
	"-root-gid <value>\tset root directory group to specified <value>, "
		"<value> can be either an integer gid or group name\n",
	"-all-root\t\tmake all files owned by root\n",
	"-force-uid <value>\tset all file uids to specified <value>, <value> "
		"can be either an integer uid or user name\n",
	"-force-gid <value>\tset all file gids to specified <value>, <value> "
		"can be either an integer gid or group name\n",
	"-pseudo-override\tmake pseudo file uids and gids override -all-root, "
		"-force-uid and -force-gid options\n",
	"-no-exports\t\tdo not make filesystem exportable via NFS (-tar "
		"default)\n",
	"-exports\t\tmake filesystem exportable via NFS (default)\n",
	"-no-sparse\t\tdo not detect sparse files\n",
	"-no-tailends\t\tdo not pack tail ends into fragments (default)\n",
	"-tailends\t\tpack tail ends into fragments\n",
	"-no-fragments\t\tdo not use fragments\n",
	"-no-duplicates\t\tdo not perform duplicate checking\n",
	"-no-hardlinks\t\tdo not hardlink files, instead store duplicates\n",
	"-keep-as-directory\tif one source directory is specified, create a "
		"root directory containing that directory, rather than the "
		"contents of the directory\n",
	"\n", "Filesystem filter options:", "\n",
	"-p <pseudo-definition>\tadd pseudo file definition.  The definition "
		"should be quoted.  See section \"Pseudo file definition "
		"format\" later for format details\n",
	"-pd <d mode uid gid>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  This also allows pseudo definitions to be "
		"specified without specifying all the directories in the "
		"pathname.  The definition should be quoted\n",
	"-pd <D time mode u g>\tas above, but also allow a timestamp to be "
		"specified\n",
	"-pf <pseudo-file>\tadd list of pseudo file definitions from "
		"<pseudo-file>, use - for stdin.  Pseudo file definitions "
		"should not be quoted\n",
	"-sort <sort-file>\tsort files according to priorities in <sort-file>."
		"  One file or dir with priority per line.  Priority -32768 "
		"to 32767, default priority 0\n",
	"-ef <exclude-file>\tlist of exclude dirs/files.  One per line\n",
	"-wildcards\t\tallow extended shell wildcards (globbing) to be used "
		"in exclude dirs/files\n",
	"-regex\t\t\tallow POSIX regular expressions to be used in exclude "
		"dirs/files\n",
	"-max-depth <levels>\tdescend at most <levels> of directories when "
		"scanning filesystem\n",
	"-one-file-system\tdo not cross filesystem boundaries.  If a "
		"directory crosses the boundary, create an empty directory "
		"for each mount point.  If a file crosses the boundary ignore "
		"it\n",
	"-one-file-system-x\tdo not cross filesystem boundaries. Like "
		"-one-file-system option except directories are also ignored "
		"if they cross the boundary\n",
	"\n", "Filesystem extended attribute (xattrs) options:", "\n",
	"-no-xattrs\t\tdo not store extended attributes" NOXOPT_STR "\n",
	"-xattrs\t\t\tstore extended attributes" XOPT_STR "\n",
	"-xattrs-exclude <regex>\texclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-exclude "
		"'^user.' excludes xattrs from the user namespace\n",
	"-xattrs-include <regex>\tinclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-include "
		"'^user.' includes xattrs from the user namespace\n",
	"-xattrs-add <name=val>\tadd the xattr <name> with <val> to files.  "
		"If an user xattr it will be added to regular files and "
		"directories (see man 7 xattr).  Otherwise it will be added "
		"to all files.  <val> by default will be treated as binary "
		"(i.e. an uninterpreted byte sequence), but it can be "
		"prefixed with 0s, where it will be treated as base64 "
		"encoded, or prefixed with 0x, where val will be treated as "
		"hexidecimal.  Additionally it can be prefixed with 0t where "
		"this encoding is similar to binary encoding, except "
		"backslashes are specially treated, and a backslash followed "
		"by 3 octal digits can be used to encode any ASCII character, "
		"which obviously can be used to encode control codes.  The "
		"option can be repeated multiple times to add multiple "
		"xattrs\n",
	"\n", "Mksquashfs runtime options:", "\n",
	"-version\t\tprint version, licence and copyright message\n",
	"-exit-on-error\t\ttreat normally ignored errors as fatal\n",
	"-quiet\t\t\tno verbose output\n",
	"-info\t\t\tprint files written to filesystem\n",
	"-no-progress\t\tdo not display the progress bar\n",
	"-progress\t\tdisplay progress bar when using the -info option\n",
	"-percentage\t\tdisplay a percentage rather than the full progress bar."
		"  Can be used with dialog --gauge etc.\n",
	"-throttle <percentage>\tthrottle the I/O input rate by the given "
		"percentage.  This can be used to reduce the I/O and CPU "
		"consumption of Mksquashfs\n",
	"-limit <percentage>\tlimit the I/O input rate to the given percentage."
		"  This can be used to reduce the I/O and CPU consumption of "
		"Mksquashfs (alternative to -throttle)\n",
	"-processors <number>\tuse <number> processors.  By default will use "
		"number of processors available\n",
	"-mem <size>\t\tuse <size> physical memory for caches.  Use K, M or G "
		"to specify Kbytes, Mbytes or Gbytes respectively\n",
	"-mem-percent <percent>\tuse <percent> physical memory for caches.  "
		"Default 25%\n",
	"-mem-default\t\tprint default memory usage in Mbytes\n",
	"\n", "Filesystem append options:", "\n",
	"-noappend\t\tdo not append to existing filesystem\n",
	"-root-becomes <name>\twhen appending source files/directories, make "
		"the original root become a subdirectory in the new root "
		"called <name>, rather than adding the new source items to the "
		"original root\n",
	"-no-recovery\t\tdo not generate a recovery file\n",
	"-recovery-path <name>\tuse <name> as the directory to store the "
		"recovery file\n",
	"-recover <name>\t\trecover filesystem data using recovery file "
		"<name>\n",
	"\n", "Filesystem actions options:", "\n",
	"-action <action@expr>\tevaluate <expr> on every file, and execute "
		"<action> if it returns TRUE\n",
	"-log-action <act@expr>\tas above, but log expression evaluation "
		"results and actions performed\n",
	"-true-action <act@expr>\tas above, but only log expressions which "
		"return TRUE\n",
	"-false-action <act@exp>\tas above, but only log expressions which "
		"return FALSE\n",
	"-action-file <file>\tas action, but read actions from <file>\n",
	"-log-action-file <file>\tas -log-action, but read actions from "
		"<file>\n",
	"-true-action-file <f>\tas -true-action, but read actions from <f>\n",
	"-false-action-file <f>\tas -false-action, but read actions from <f>\n",
	"\n", "Tar file only options:", "\n",
	"-default-mode <mode>\ttar files often do not store permissions for "
		"intermediate directories.  This option sets the default "
		"directory permissions to octal <mode>, rather than 0755.  "
		"This also sets the root inode mode\n",
	"-default-uid <value>\ttar files often do not store uids for "
		"intermediate directories.  This option sets the default "
		"directory owner to <value>, rather than the user running "
		"Mksquashfs.  <value> can be either an integer uid or user "
		"name.  This also sets the root inode uid\n",
	"-default-gid <value>\ttar files often do not store gids for "
		"intermediate directories.  This option sets the default "
		"directory group to <value>, rather than the group of the user "
		"running Mksquashfs.  <value> can be either an integer uid or "
		"group name.  This also sets the root inode gid\n",
	"-ignore-zeros\t\tallow tar files to be concatenated together and fed "
		"to Mksquashfs.  Normally a tarfile has two consecutive 512 "
		"byte blocks filled with zeros which means EOF and Mksquashfs "
		"will stop reading after the first tar file on encountering "
		"them. This option makes Mksquashfs ignore the zero filled "
		"blocks\n",
	"\n", "Expert options (these may make the filesystem unmountable):",
	"\n",
	"-nopad\t\t\tdo not pad filesystem to a multiple of 4K\n",
	"-offset <offset>\tskip <offset> bytes at the beginning of FILESYSTEM."
		"  Optionally a suffix of K, M or G can be given to specify "
		"Kbytes, Mbytes or Gbytes respectively.  Default 0 bytes\n",
	"-o <offset>\t\tsynonym for -offset\n",
	"\n", "Help options:", "\n",
	"-help\t\t\tprint help summary information to stdout\n",
	"-help-option <regex>\tprint the help information for Mksquashfs "
		"options matching <regex> to stdout\n",
	"-help-section <section>\tprint the help information for section "
		"<section> to stdout.  Use \"sections\" or \"h\" as section "
		"name to get a list of sections and their names\n",
	"-help-comp <comp>\tprint compressor options for compressor <comp>\n",
	"-help-all\t\tprint help information for all Mksquashfs options and "
		"sections to stdout\n",
	"-Xhelp\t\t\tprint compressor options for selected compressor\n",
	"-h\t\t\tshorthand alternative to -help\n",
	"-ho <regex>\t\tshorthand aternative to -help-option\n",
	"-hs <section>\t\tshorthand alternative to -help-section\n",
	"-ha\t\t\tshorthand alternative to -help-all\n",
	"\n", "Miscellaneous options:", "\n",
	"-fstime <time>\t\talternative name for -mkfs-time\n",
	"-always-use-fragments\talternative name for -tailends\n",
	"-root-owned\t\talternative name for -all-root\n",
	"-noInodeCompression\talternative name for -noI\n",
	"-noIdTableCompression\talternative name for -noId\n",
	"-noDataCompression\talternative name for -noD\n",
	"-noFragmentCompression\talternative name for -noF\n",
	"-noXattrCompression\talternative name for -noX\n",
	"-pseudo-dir\t\talternative name for -pd\n",
	"\n", "Pseudo file definition format:", "\n",
	"\"filename d mode uid gid\"\t\tcreate a directory\n",
	"\"filename m mode uid gid\"\t\tmodify filename\n",
	"\"filename b mode uid gid major minor\"\tcreate a block device\n",
	"\"filename c mode uid gid major minor\"\tcreate a character device\n",
	"\"filename f mode uid gid command\"\tcreate file from stdout of "
		"command\n",
	"\"filename s mode uid gid symlink\"\tcreate a symbolic link\n",
	"\"filename i mode uid gid [s|f]\"\t\tcreate a socket (s) or FIFO "
		"(f)\n",
	"\"filename x name=val\"\t\t\tcreate an extended attribute\n",
	"\"filename l linkname\"\t\t\tcreate a hard-link to linkname\n",
	"\"filename L pseudo_filename\"\t\tsame, but link to pseudo file\n",
	"\"filename D time mode uid gid\"\t\tcreate a directory with timestamp "
		"time\n",
	"\"filename M time mode uid gid\"\t\tmodify a file with timestamp "
		"time\n",
	"\"filename B time mode uid gid major minor\"\n\t\t\t\t\tcreate block "
		"device with timestamp time\n",
	"\"filename C time mode uid gid major minor\"\n\t\t\t\t\tcreate char "
		"device with timestamp time\n",
	"\"filename F time mode uid gid command\"\tcreate file with timestamp "
		"time\n",
	"\"filename S time mode uid gid symlink\"\tcreate symlink with "
		"timestamp time\n",
	"\"filename I time mode uid gid [s|f]\"\tcreate socket/fifo with "
		"timestamp time\n",
	"\n", "Environment:", "\n",
	"SOURCE_DATE_EPOCH\tIf set, this is used as the filesystem creation "
		"timestamp.  Also any file timestamps which are after "
		"SOURCE_DATE_EPOCH will be clamped to SOURCE_DATE_EPOCH.  "
		"See https://reproducible-builds.org/docs/source-date-epoch/"
		" for more information\n", "\n",
	"PAGER\t\t\tIf set, this is used as the name of the program used to "
		"display the help text.  The value can be a simple command or "
		"a pathname.  The default is /usr/bin/pager\n",
	"\n", "Exit status:", "\n",
	"  0\tMksquashfs successfully generated a filesystem.\n"
	"  1\tFatal errors occurred, Mksquashfs aborted and did not generate a "
		"filesystem (or update if appending).\n",
	"\n","See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.6.1 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/README-4.6.1\n",
	"\nThe Squashfs-tools USAGE guide can be read here https://github.com/"
		"plougher/squashfs-tools/blob/master/USAGE-4.6\n",
	"\nThe ACTIONS-README file describing how to use the new actions "
		"feature can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/ACTIONS-README\n",
	NULL
};


static char *sqfstar_text[]={
	"Filesystem compression options:", "\n",
	"-b <block-size>\t\tset data block to <block-size>.  Default 128 "
		"Kbytes. Optionally a suffix of K, KB, Kbytes or M, MB, Mbytes "
		"can be given to specify Kbytes or Mbytes respectively\n",
	"-comp <comp>\t\tselect <comp> compression\n\t\t\tCompressors "
		"available:\n\t\t\t\t" COMPRESSORS "\n",
	"-noI\t\t\tdo not compress inode table\n",
	"-noId\t\t\tdo not compress the uid/gid table (implied by -noI)\n",
	"-noD\t\t\tdo not compress data blocks\n",
	"-noF\t\t\tdo not compress fragment blocks\n",
	"-noX\t\t\tdo not compress extended attributes\n",
	"-no-compression\t\tdo not compress any of the data or metadata.  This "
		"is equivalent to specifying -noI -noD -noF and -noX\n",
	"\n", "Filesystem build options:", "\n",
	"-reproducible\t\tbuild filesystems that are reproducible" REP_STR
		"\n",
	"-not-reproducible\tbuild filesystems that are not reproducible"
		NOREP_STR "\n",
	"-mkfs-time <time>\tset filesystem creation timestamp to <time>. "
		"<time> can be an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-all-time <time>\tset all file timestamps to <time>. <time> can be an "
		"unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-root-time <time>\tset root directory time to " "<time>. <time> can "
		"be an unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-root-mode <mode>\tset root directory permissions to octal <mode>\n",
	"-root-uid <value>\tset root directory owner to specified <value>, "
		"<value> can be either an integer uid or user name\n",
	"-root-gid <value>\tset root directory group to specified <value>, "
		"<value> can be either an integer gid or group name\n",
	"-all-root\t\tmake all files owned by root\n",
	"-force-uid <value>\tset all file uids to specified <value>, <value> "
		"can be either an integer uid or user name\n",
	"-force-gid <value>\tset all file gids to specified <value>, <value> "
		"can be either an integer gid or group name\n",
	"-default-mode <mode>\ttar files often do not store permissions for "
		"intermediate directories.  This option sets the default "
		"directory permissions to octal <mode>, rather than 0755.  "
		"This also sets the root inode mode\n",
	"-default-uid <value>\ttar files often do not store uids for "
	"intermediate directories.  This option sets the default directory "
	"owner to <value>, rather than the user running Sqfstar.  <value> can "
		"be either an integer uid or user name.  This also sets the "
		"root inode uid\n",
	"-default-gid <value>\ttar files often do not store gids for "
		"intermediate directories.  This option sets the default "
		"directory group to <value>, rather than the group of the "
		"user running Sqfstar.  <value> can be either an integer uid "
		"or group name.  This also sets the root inode gid\n",
	"-pseudo-override\tmake pseudo file uids and gids override -all-root, "
		"-force-uid and -force-gid options\n",
	"-exports\t\tmake the filesystem exportable via NFS\n",
	"-no-sparse\t\tdo not detect sparse files\n",
	"-no-fragments\t\tdo not use fragments\n",
	"-no-tailends\t\tdo not pack tail ends into fragments\n",
	"-no-duplicates\t\tdo not perform duplicate checking\n",
	"-no-hardlinks\t\tdo not hardlink files, instead store duplicates\n",
	"\n", "Filesystem filter options:", "\n",
	"-p <pseudo-definition>\tadd pseudo file definition.  The definition "
		"should be quoted.  See section \"Pseudo file definition "
		"format\" later for format details\n",
	"-pd <d mode uid gid>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  This also allows pseudo definitions to be "
		"specified without specifying all the directories in the "
		"pathname.  The definition should be quoted\n",
	"-pd <D time mode u g>\tas above, but also allow a timestamp to be "
		"specified\n",
	"-pf <pseudo-file>\tadd list of pseudo file definitions.  Pseudo file "
		"definitions in pseudo-files should not be quoted\n",
	"-ef <exclude-file>\tlist of exclude dirs/files.  One per line\n",
	"-regex\t\t\tallow POSIX regular expressions to be used in exclude "
		"dirs/files\n",
	"-ignore-zeros\t\tallow tar files to be concatenated together and fed "
		"to Sqfstar.  Normally a tarfile has two consecutive 512 byte "
		"blocks filled with zeros which means EOF and Sqfstar will "
		"stop reading after the first tar file on encountering them. "
		"This option makes Sqfstar ignore the zero filled blocks\n",
	"\n", "Filesystem extended attribute (xattrs) options:", "\n",
	"-no-xattrs\t\tdo not store extended attributes" NOXOPT_STR "\n",
	"-xattrs\t\t\tstore extended attributes" XOPT_STR "\n",
	"-xattrs-exclude <regex>\texclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-exclude "
		"'^user.' excludes xattrs from the user namespace\n",
	"-xattrs-include <regex>\tinclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-include "
		"'^user.' includes xattrs from the user namespace\n",
	"-xattrs-add <name=val>\tadd the xattr <name> with <val> to files.  If "
		"an user xattr it will be added to regular files and "
		"directories (see man 7 xattr).  Otherwise it will be added to "
		"all files.  <val> by default will be treated as binary (i.e. "
		"an uninterpreted byte sequence), but it can be prefixed with "
		"0s, where it will be treated as base64 encoded, or prefixed "
		"with 0x, where val will be treated as hexidecimal.  "
		"Additionally it can be prefixed with 0t where this encoding "
		"is similar to binary encoding, except backslashes are "
		"specially treated, and a backslash followed by 3 octal digits "
		"can be used to encode any ASCII character, which obviously "
		"can be used to encode control codes.  The option can be "
		"repeated multiple times to add multiple xattrs\n",
	"\n", "Sqfstar runtime options:","\n",
	"-version\t\tprint version, licence and copyright message\n",
	"-force\t\t\tforce Sqfstar to write to block device or file\n",
	"-exit-on-error\t\ttreat normally ignored errors as fatal\n",
	"-quiet\t\t\tno verbose output\n",
	"-info\t\t\tprint files written to filesystem\n",
	"-no-progress\t\tdo not display the progress bar\n",
	"-progress\t\tdisplay progress bar when using the -info option\n",
	"-percentage\t\tdisplay a percentage rather than the full progress "
		"bar.  Can be used with dialog --gauge etc.\n",
	"-throttle <percentage>\tthrottle the I/O input rate by the given "
		"percentage.  This can be used to reduce the I/O and CPU "
		"consumption of Sqfstar\n",
	"-limit <percentage>\tlimit the I/O input rate to the given "
		"percentage.  This can be used to reduce the I/O and CPU "
		"consumption of Sqfstar (alternative to -throttle)\n",
	"-processors <number>\tuse <number> processors.  By default will use "
		"number of processors available\n",
	"-mem <size>\t\tuse <size> physical memory for caches.  Use K, M or G "
		"to specify Kbytes, Mbytes or Gbytes respectively\n",
	"-mem-percent <percent>\tuse <percent> physical memory for caches.  "
		"Default 25%\n",
	"-mem-default\t\tprint default memory usage in Mbytes\n",
	"\n", "Expert options (these may make the filesystem unmountable):", "\n",
	"-nopad\t\t\tdo not pad filesystem to a multiple of 4K\n",
	"-offset <offset>\tskip <offset> bytes at the beginning of "
		"FILESYSTEM.  Optionally a suffix of K, M or G can be given to "
		"specify Kbytes, Mbytes or Gbytes respectively.  Default 0 "
		"bytes\n",
	"-o <offset>\t\tsynonym for -offset\n",
	"\n", "Miscellaneous options:", "\n",
	"-fstime <time>\t\talternative name for mkfs-time\n",
	"-root-owned\t\talternative name for -all-root\n",
	"-noInodeCompression\talternative name for -noI\n",
	"-noIdTableCompression\talternative name for -noId\n",
	"-noDataCompression\talternative name for -noD\n",
	"-noFragmentCompression\talternative name for -noF\n",
	"-noXattrCompression\talternative name for -noX\n",
	"\n", "-help\t\t\tprint help summary information to stdout\n",
	"-help-option <regex>\tprint the help information for Sqfstar "
		"options matching <regex> to stdout\n",
	"-help-section <section>\tprint the help information for section "
		"<section> to stdout.  Use \"sections\" or \"h\" as section "
		"name to get a list of sections and their names\n",
	"-help-all\t\tprint help information for all Sqfstar options and "
		"sections to stdout\n",
	"-Xhelp\t\t\tprint compressor options for selected compressor\n",
	"-h\t\t\tshorthand alternative to -help\n",
	"-ho <regex>\t\tshorthand alternative to -help-option\n",
	"-hs <section>\t\tshorthand alternative to -help-section\n",
	"-ha\t\t\tshorthand alternative to -help-all\n",
	"\n","Pseudo file definition format:", "\n",
	"\"filename d mode uid gid\"\t\tcreate a directory\n",
	"\"filename m mode uid gid\"\t\tmodify filename\n",
	"\"filename b mode uid gid major minor\"\tcreate a block device\n",
	"\"filename c mode uid gid major minor\"\tcreate a character device\n",
	"\"filename f mode uid gid command\"\tcreate file from stdout of "
		"command\n",
	"\"filename s mode uid gid symlink\"\tcreate a symbolic link\n",
	"\"filename i mode uid gid [s|f]\"\t\tcreate a socket (s) or FIFO "
		"(f)\n",
	"\"filename x name=val\"\t\t\tcreate an extended attribute\n",
	"\"filename l linkname\"\t\t\tcreate a hard-link to linkname\n",
	"\"filename L pseudo_filename\"\t\tsame, but link to pseudo file\n",
	"\"filename D time mode uid gid\"\t\tcreate a directory with timestamp "
		"time\n",
	"\"filename M time mode uid gid\"\t\tmodify a file with timestamp "
		"time\n",
	"\"filename B time mode uid gid major minor\"\n\t\t\t\t\tcreate block "
		"device with timestamp time\n",
	"\"filename C time mode uid gid major minor\"\n\t\t\t\t\tcreate char "
		"device with timestamp time\n",
	"\"filename F time mode uid gid command\"\tcreate file with timestamp "
		"time\n",
	"\"filename S time mode uid gid symlink\"\tcreate symlink with "
		"timestamp time\n",
	"\"filename I time mode uid gid [s|f]\"\tcreate socket/fifo with "
		"timestamp time\n",
	"\n", "Environment:", "\n",
	"SOURCE_DATE_EPOCH\tIf set, this is used as the filesystem creation "
		"timestamp.  Also any file timestamps which are after "
		"SOURCE_DATE_EPOCH will be clamped to SOURCE_DATE_EPOCH.  "
		"See https://reproducible-builds.org/docs/source-date-epoch/ "
		"for more information\n", "\n",
	"PAGER\t\t\tIf set, this is used as the name of the program used to "
		"display the help text.  The value can be a simple command or "
		"a pathname.  The default is /usr/bin/pager\n",
	"\n", "Exit status:", "\n",
	"  0\tSqfstar successfully generated a filesystem.\n",
	"  1\tFatal errors occurred, Sqfstar aborted and did not generate a "
		"filesystem.\n",
	"\n","See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.6.1 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/README-4.6.1\n",
	"\nThe Squashfs-tools USAGE guide can be read here https://github.com/"
		"plougher/squashfs-tools/blob/master/USAGE-4.6\n",
	NULL
};


static char *get_base(char *pathname)
{
	char *cur = pathname, *sow = NULL, *eow = NULL;

	while(*cur != '\0') {
		if(*cur == '/')
			cur ++;
		else if(strcmp(cur, ".") == 0)
			cur ++;
		else if(strcmp(cur, "..") == 0)
			cur += 2;
		else if(strncmp(cur, "./", 2) == 0)
			cur +=2;
		else if(strncmp(cur, "../", 3) == 0)
			cur += 3;
		else {
			sow = cur;

			do {
				cur ++;
			} while(*cur != '/' && *cur != '\0');

			eow = cur;
		}
	}

	if(sow == NULL || eow != cur)
		return NULL;
	else
		return sow;
}


int check_and_set_pager(char *pager)
{
	int i, length = strlen(pager);
	char *base;

	/* Check string :-
	 * 1. Isn't empty,
	 * 2. Doesn't contain spaces, tabs, pipes, command separators or file
	 *    redirects.
	 *
	 * Note: this isn't an exhaustive check of what can't be in the
	 *	 pager name, as the execlp() will do this.  It is more
	 *	 intended to check for common shell metacharacters and
	 *	 warn users this isn't supported in a friendlier way.
	 */
	if(length == 0) {
		ERROR("PAGER environment variable is empty!\n");
		return FALSE;
	}

	base = get_base(pager);
	if(base == NULL) {
		ERROR("PAGER doesn't have a name in it or has trailing '/', '.' or '..' characters!\n");
		return FALSE;
	}

	for(i = 0; i < length; i ++) {
		if(pager[i] == ' ' || pager[i] == '\t') {
			ERROR("PAGER cannot have spaces or tabs!\n");
			goto failed;
		} else if(pager[i] == '|' || pager[i] == ';') {
			ERROR("PAGER cannot have pipes or command separators!\n");
			goto failed;
		} else if(pager[i] == '<' || pager[i] == '>' || pager[i] == '&') {
			ERROR("PAGER cannot have file redirections!\n");
			goto failed;
		}
	}

	pager_command = pager;
	pager_name = base;
	pager_from_env_var = TRUE;
	return TRUE;

failed:
	ERROR("If you want to do this, please use a wrapper script!\n");
	return FALSE;
}


int determine_pager(void)
{
	int bytes, status, res, pipefd[2];
	pid_t child;
	char buffer[1024];

	res = pipe(pipefd);
	if(res == -1) {
		ERROR("Error determining pager, pipe failed\n");
		return UNKNOWN_PAGER;
	}

	child = fork();
	if(child == -1) {
		ERROR("Error determining pager, fork failed\n");
		close(pipefd[0]);
		close(pipefd[1]);
		return UNKNOWN_PAGER;
	}

	if(child == 0) { /* child */
		close(pipefd[0]);
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if(res == -1)
			exit(EXIT_FAILURE);

		execlp(pager_command, pager_name, "--version", (char *) NULL);
		close(pipefd[1]);
		exit(EXIT_FAILURE);
	}

	/* parent */
	close(pipefd[1]);

	bytes = read_bytes(pipefd[0], buffer, 1024);

	if(bytes == -1) {
		ERROR("Error determining pager\n");
		close(pipefd[0]);
		return UNKNOWN_PAGER;
	}

	if(res == 1024) {
		ERROR("Pager returned unexpectedly large amount of data for --version\n");
		close(pipefd[0]);
		return UNKNOWN_PAGER;
	}

	while(1) {
		res = waitpid(child, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR) {
			ERROR("Error determining pager, waitpid failed\n");
			close(pipefd[0]);
			return UNKNOWN_PAGER;
		}
	}

	close(pipefd[0]);

	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		/* Pager didn't understand --version?  Return unknown pager */
		return UNKNOWN_PAGER;
	}

	if(strncmp(buffer, "less", strlen("less")) == 0)
		return LESS_PAGER;
	else if(strncmp(buffer, "more", strlen("more")) == 0 ||
				strncmp(buffer, "pager", strlen("pager")) == 0)
		return MORE_PAGER;
	else
		return UNKNOWN_PAGER;
}


void wait_to_die(pid_t process)
{
	int res, status;

	while(1) {
		res = waitpid(process, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR) {
			ERROR("Error executing pager, waitpid failed\n");
			return;
		}
	}

	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		ERROR("Pager failed to run or failed with an error status\n");
}


FILE *exec_pager(pid_t *process)
{
	FILE *file;
	int res, pipefd[2], pager = determine_pager();
	pid_t child;

	res = pipe(pipefd);
	if(res == -1) {
		ERROR("Error executing pager, pipe failed\n");
		return NULL;
	}

	child = fork();
	if(child == -1) {
		ERROR("Error executing pager, fork failed\n");
		close(pipefd[0]);
		close(pipefd[1]);
		return NULL;
	}

	if(child == 0) { /* child */
		close(pipefd[1]);
		close(STDIN_FILENO);
		res = dup(pipefd[0]);
		if(res == -1)
			exit(EXIT_FAILURE);

		if(pager == LESS_PAGER)
			execlp(pager_command, pager_name, "--quit-if-one-screen", (char *) NULL);
		else if(pager == MORE_PAGER)
			execlp(pager_command, pager_name, "--exit-on-eof", (char *) NULL);
		else
			execlp(pager_command, pager_name,  (char *) NULL);

		if(pager_from_env_var == FALSE) {
			execl("/usr/bin/less", "less", "--quit-if-one-screen", (char *) NULL);
			execl("/usr/bin/more", "more", "--exit-on-eof", (char *) NULL);
			execl("/usr/bin/cat", "cat", (char *) NULL);
		}

		close(pipefd[0]);
		exit(EXIT_FAILURE);
	}

	/* parent */
	close(pipefd[0]);

	file = fdopen(pipefd[1], "w");
	if(file == NULL) {
		ERROR("Error executing pager, fdopen failed\n");
		goto failed;
	}

	*process = child;
	return file;

failed:
	res = kill(child, SIGKILL);
	if(res == -1)
	ERROR("Error executing pager, kill failed\n");
	close(pipefd[1]);
	return NULL;
}


int get_column_width()
{
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		return 80;
	} else
		return winsize.ws_col;
}


void autowrap_print(FILE *stream, char *text, int maxl)
{
	char *cur = text;
	int first_line = TRUE, tab_out = 0, length = 0;

	while(*cur != '\0') {
		char *sol = cur, *lw = NULL, *eow = NULL;
		int wrapped = FALSE;

		while(length <= maxl && *cur != '\n' && *cur != '\0') {
			if(*cur == '\t') {
				length = (length + 8) & ~7;
				if(first_line)
					tab_out = length;
			} else
				length ++;

			if(*cur == '\t' || *cur == ' ')
				eow = lw;
			else
				lw = cur;

			if(length <= maxl)
				cur ++;
		}

		first_line = FALSE;

		if(*cur == '\n')
			cur ++;
		else if(*cur != '\0') {
			if(eow)
				cur = eow + 1;
			else if(cur - sol == 0)
				cur ++;

			if(tab_out >= maxl)
				tab_out = 0;

			wrapped = TRUE;
		}

		while(sol < cur)
			fputc(*sol ++, stream);

		if(wrapped) {
			fputc('\n', stream);

			for(length = 0; length < tab_out; length += 8)
				fputc('\t', stream);

			while(*cur == ' ')
				cur ++;
		} else
			length = 0;
	}
}


void autowrap_printf(FILE *stream, int maxl, char *fmt, ...)
{
	va_list ap;
	char *text;
	int res;

	va_start(ap, fmt);
	res = vasprintf(&text, fmt, ap);
	va_end(ap);

	if(res == -1)
		BAD_ERROR("Vasprintf failed in autowrap_printf\n");

	autowrap_print(stream, text, maxl);
	free(text);
}


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

	autowrap_print(pager, "\nCompressors available and compressor specific options:\n", cols);

	display_compressor_usage(pager, COMP_DEFAULT);

	if(tty) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}


static void print_option(char *prog_name, char *opt_name, char *pattern, char **options,
					char **options_args, char **options_text)
{
	int i, res, matched = FALSE;
	regex_t *preg = malloc(sizeof(regex_t));
	int cols = get_column_width();

	if(preg == NULL)
		MEM_ERROR();

	res = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);

	if(res) {
		char str[1024]; /* overflow safe */

		regerror(res, preg, str, 1024);
		autowrap_printf(stderr, cols, "%s: %s invalid regex %s because %s\n", prog_name, opt_name, pattern, str);
		exit(1);
	}

	for(i = 0; options[i] != NULL; i++) {
		res = regexec(preg, options[i], (size_t) 0, NULL, 0);
		if(res)
			res = regexec(preg, options_args[i], (size_t) 0, NULL, 0);
		if(!res) {
			matched = TRUE;
			autowrap_print(stdout, options_text[i], cols);
		}
	}

	if(!matched) {
		autowrap_printf(stderr, cols, "%s: %s %s does not match any %s option\n", prog_name, opt_name, pattern, prog_name);
		exit(1);
	} else
		exit(0);
}


static int is_header(int i, char **options_text)
{
	int length = strlen(options_text[i]);

	return length && options_text[i][length - 1] == ':';
}


static void print_section_names(FILE *out, char *string, int cols, char **sections, char **options_text)
{
	int i, j;

	autowrap_printf(out, cols, "%sSECTION NAME\t\tSECTION\n", string);

	for(i = 0, j = 0; sections[i] != NULL; j++)
		if(is_header(j, options_text)) {
			autowrap_printf(out, cols, "%s%s\t\t%s%s\n", string, sections[i], strlen(sections[i]) > 7 ? "" : "\t", options_text[j]);
			i++;
		}
}


static void print_section(char *prog_name, char *opt_name, char *sec_name, char **sections, char **options_text)
{
	int i, j, secs, cols, tty = isatty(STDOUT_FILENO);
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

	if(strcmp(sec_name, "sections") == 0 || strcmp(sec_name, "h") == 0) {
		autowrap_printf(pager, cols, "\nUse following section name to print %s help information for that section\n\n", prog_name);
		print_section_names(pager , "", cols, sections, options_text);
		goto finish;
	}

	for(i = 0; sections[i] != NULL; i++)
		if(strcmp(sections[i], sec_name) == 0)
			break;

	if(sections[i] == NULL) {
		autowrap_printf(pager, cols, "%s: %s %s does not match any section name\n", prog_name, opt_name, sec_name);
		print_section_names(pager, "", cols, sections, options_text);
		goto finish;
	}

	i++;

	for(j = 0, secs = 0; options_text[j] != NULL && secs <= i; j ++) {
		if(is_header(j, options_text))
			secs++;
		if(i == secs)
			autowrap_print(pager, options_text[j], cols);
	}

finish:
	if(tty) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}


static void handle_invalid_option(char *prog_name, char *opt_name, char **sections, char **options_text)
{
	int cols = get_column_width();

	autowrap_printf(stderr, cols, "%s: %s is an invalid option\n\n", prog_name, opt_name);
	fprintf(stderr, "Run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stderr, "\t", cols, sections, options_text);
	autowrap_printf(stderr, cols, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	autowrap_printf(stderr, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(1);
}


static void print_help(int error, char *prog_name, char *syntax, char **sections, char **options_text)
{
	FILE *stream = error ? stderr : stdout;
	int cols = get_column_width();

	autowrap_printf(stream, cols, syntax, prog_name);
	autowrap_printf(stream, cols, "Run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stream, "\t", cols, sections, options_text);
	autowrap_printf(stream, cols, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	autowrap_printf(stream, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(error);
}


static void print_option_help(char *prog_name, char *option, char **sections, char **options_text)
{
	int cols = get_column_width();

	autowrap_printf(stderr, cols, "\nRun\n  \"%s -help-option %s$\" to get help on %s option\n", prog_name, option, option);
	autowrap_printf(stderr, cols, "Or run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stderr, "\t", cols, sections, options_text);
	autowrap_printf(stderr, cols, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	autowrap_printf(stderr, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(1);
}


void mksquashfs_help_all(char *name)
{
	print_help_all(name, MKSQUASHFS_SYNTAX, mksquashfs_text);
}


void sqfstar_help_all(char *name)
{
	print_help_all(name, SQFSTAR_SYNTAX, sqfstar_text);
}


void mksquashfs_option(char *prog_name, char *opt_name, char *pattern)
{
	print_option(prog_name, opt_name, pattern, mksquashfs_options, mksquashfs_args, mksquashfs_text);
}


void sqfstar_option(char *prog_name, char *opt_name, char *pattern)
{
	print_option(prog_name, opt_name, pattern, sqfstar_options, sqfstar_args, sqfstar_text);
}

void mksquashfs_section(char *prog_name, char *opt_name, char *sec_name)
{
	print_section(prog_name, opt_name, sec_name, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_section(char *prog_name, char *opt_name, char *sec_name)
{
	print_section(prog_name, opt_name, sec_name, sqfstar_sections, sqfstar_text);
}

void mksquashfs_help(int error, char *prog_name)
{
	print_help(error, prog_name, MKSQUASHFS_SYNTAX, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_help(int error, char *prog_name)
{
	print_help(error, prog_name, SQFSTAR_SYNTAX, sqfstar_sections, sqfstar_text);
}

void mksquashfs_invalid_option(char *prog_name, char *opt_name)
{
	handle_invalid_option(prog_name, opt_name, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_invalid_option(char *prog_name, char *opt_name)
{
	handle_invalid_option(prog_name, opt_name, sqfstar_sections, sqfstar_text);
}

void mksquashfs_option_help(char *prog_name, char *option)
{
	print_option_help(prog_name, option, mksquashfs_sections, mksquashfs_text);
}
