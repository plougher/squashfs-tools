/*
 * Squashfs
 *
 * Copyright (c) 2024, 2025
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

#include <stdio.h>
#include <string.h>
#include <regex.h>
#include <stdlib.h>
#include <unistd.h>

#include "mksquashfs_error.h"
#include "mksquashfs_help.h"
#include "print_pager.h"
#include "compressor.h"
#include "alloc.h"
#include "thread.h"

#define MKSQUASHFS_SYNTAX "SYNTAX: %s source1 source2 ...  FILESYSTEM " \
	"[OPTIONS] [-e list of exclude dirs/files]\n\n"

#define SQFSTAR_SYNTAX "SYNTAX: %s [OPTIONS] FILESYSTEM [list of exclude dirs/files]\n\n"

static char *mksquashfs_options[]={
	/* compression options */
	"", "", "-b", "-comp", "-noI", "-noId", "-noD", "-noF", "-noX",
	"-no-compression", "", "", "",
	/* build options */
	"-tar", "-no-strip", "-tarstyle", "-cpiostyle", "-cpiostyle0",
	"-no-exports", "-exports", "-no-sparse", "-no-tailends", "-tailends",
	"-no-fragments", "-no-duplicates", "-no-hardlinks",
	"-keep-as-directory", "", "", "",
	/* time options */
	"-mkfs-time", "-inode-time", "-root-time", "", "", "",
	/* permissions options */
	"-all-root", "-root-mode", "-root-uid", "-root-gid", "-force-file-mode",
	"-force-dir-mode", "-force-uid", "-force-gid", "-uid-gid-offset", "",
	"", "",
	/* pseudo options */
	"-p", "-pd", "-pd", "-pf", "-pseudo-override", "", "", "",
	/* filter options */
	"-sort", "-ef", "-wildcards", "-regex", "-max-depth", "-one-file-system",
	"-one-file-system-x", "", "", "",
	/* xattrs options */
	"-no-xattrs", "-xattrs", "-xattrs-exclude", "-xattrs-include",
	"-xattrs-add", "", "", "",
	/* runtime options */
	"-version", "-exit-on-error", "-quiet", "-info", "-info-file",
	"-no-progress", "-progress", "-percentage", "-throttle", "-limit",
	"-processors", "-mem", "-mem-percent", "-mem-default",
	"-single-reader", "-small-readers", "-block-readers", "-overcommit", "",
	"", "",
	/* append options */
	"-noappend", "-root-becomes", "-no-recovery", "-recovery-path",
	"-recover", "", "", "",
	/* actions options */
	"-action", "-log-action", "-true-action", "-false-action",
	"-action-file", "-log-action-file", "-true-action-file",
	"-false-action-file", "", "", "",
	/* tar options */
	"-default-mode", "-default-uid", "-default-gid", "-ignore-zeros", "",
	"", "",
	/* expert options */
	"-nopad", "-offset", "-o", "", "", "",
	/* help options */
	"-help", "-help-option", "-help-section", "-help-comp", "-help-all",
	"-Xhelp", "-h", "-ho", "-hs", "-ha", "", "", "",
	/* misc options */
	"-fstime", "-always-use-fragments", "-root-owned",
	"-noInodeCompression", "-noIdTableCompression", "-noDataCompression",
	"-noFragmentCompression", "-noXattrCompression", "-pseudo-dir", NULL,
};

static char *sqfstar_options[]={
	/* compression options */
	"", "", "-b", "-comp", "-noI", "-noId", "-noD", "-noF", "-noX",
	"-no-compression", "", "", "",
	/* build options */
	"-exports", "-no-sparse", "-no-fragments", "-no-tailends",
	"-no-duplicates", "-no-hardlinks", "-regex", "-ignore-zeros", "-ef", "",
	"", "",
	/* time options */
	"-mkfs-time", "-inode-time", "-root-time", "", "", "",
	/* permissions options */
	"-all-root", "-root-mode", "-root-uid", "-root-gid", "-force-file-mode",
	"-force-dir-mode", "-force-uid", "-force-gid", "-uid-gid-offset",
	"-default-mode", "-default-uid", "-default-gid", "", "", "",
	/* pseudo options */
	"-p", "-pd", "-pd", "-pf", "-pseudo-override", "", "", "",
	/* xattr options */
	"-no-xattrs", "-xattrs", "-xattrs-exclude", "-xattrs-include",
	"-xattrs-add", "", "","",
	/* runtime options */
	"-version", "-force", "-exit-on-error", "-quiet", "-info", "-info-file",
	"-no-progress", "-progress", "-percentage", "-throttle", "-limit",
	"-processors", "-mem", "-mem-percent", "-mem-default", "-overcommit",
	"", "", "",
	/* expert options */
	"-nopad", "-offset", "-o", "", "", "",
	 /* help options */
	 "-help", "help-option", "-help-section", "-help-comp", "-help-all",
	 "-Xhelp", "-h", "-ho", "-hs", "-ha", "", "", "",
	/* misc options */
	"-fstime", "-root-owned", "-noInodeCompression",
	"-noIdTableCompression", "-noDataCompression", "-noFragmentCompression",
	 "-noXattrCompression", NULL
};

static char *mksquashfs_args[]={
	/* compression options */
	"", "", "<block-size>", "<comp>", "", "", "", "", "", "", "", "", "",
	/* build options */
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "","", "",
	/* time options */
	"<time>", "<time>", "<time>", "", "", "",
	/* permissions options */
	"", "<mode>", "<user>", "<group>", "<mode>", "<mode>", "<user>",
	"<group>", "<value>", "", "", "",
	/* pseudo options */
	"<pseudo-definition>", "<d mode uid gid>", "<D time mode uid gid>",
	"<pseudo-file>", "", "", "", "",
	/* filter options */
	"<sort-file>", "<exclude-file>", "", "", "<levels>", "", "", "", "", "",
	/* xattrs options */
	"", "", "<regex>", "<regex>", "<name=val>", "", "", "",
	/* runtime options */
	"", "", "", "", "<file>", "", "", "", "<percentage>", "<percentage>",
	"<number>", "<size>", "<percent>", "", "", "<n>", "<n>", "<percentage>",
	"", "", "",
	/* append options **/
	"", "<name>", "", "<name>", "<name>", "", "", "",
	/* actions options */
	"<action@expression>", "<action@expression>", "<action@expression>",
	"<action@expression>", "<file>", "<file>", "<file>", "<file>", "", "",
	"",
	/* tar options */
	"<mode>", "<value>", "<value>", "", "", "", "",
	/* expert options */
	"", "<offset>", "<offset>", "", "", "",
	/* help options */
	"", "<regex>", "<section>", "<comp>", "", "", "", "<regex>",
	"<section>", "", "", "", "",
	/* misc options */
	"<time>", "", "", "", "", "", "", "", ""
};

static char *sqfstar_args[]={
	/* compression */
	"", "", "<block-size>", "<comp>",  "", "", "", "", "", "", "", "", "",
	/* build options */
	"", "", "", "", "", "", "", "", "<exclude-file>", "", "", "",
	/* time options */
	"<time>", "<time>", "<time>", "", "", "",
	/* permissions options */
	"", "<mode>", "<yser>", "<group>", "<mode>", "<mode>", "<user>",
	"<group>", "<value>", "<mode>", "<user>", "<roup>", "", "", "",
	/* pseudo options */
	"<pseudo-definition>", "<d mode uid gid>", "<D time mode u g>",
	"<pseudo-file>", "", "", "", "",
	/* xattr options */
	"", "", "<regex>", "<regex>", "<name=val>", "", "","",
	/* runtime options */
	"", "", "", "", "", "<file>", "", "", "", "<percentage>",
	"<percentage>", "<number>", "<size>", "<percent>", "", "<percentage>",
	"", "", "",
	/* expert options */
	"", "<offset>", "<offset>", "", "", "",
	/* help options */
	"", "<regex>", "<section>", "<comp>", "", "", "", "<regex>",
	"<section>", "" "", "", "",
	/* misc options */
	"<time>", "", "", "", "", "", "", ""
};

static char *mksquashfs_sections[]={
	"compression", "build", "time", "perms", "pseudo", "filter", "xattrs",
	"runtime", "append", "actions", "tar", "expert", "help", "misc",
	"pseudo-defs", "symbolic", "environment", "exit", "extra", NULL
};

static char *sqfstar_sections[]={
	"compression", "build", "time", "perms", "pseudo", "xattrs", "runtime",
	"expert", "help", "misc", "pseudo-defs", "symbolic", "environment",
	"exit", "extra", NULL
};

static char *mksquashfs_text[]={
	"Filesystem compression options:", "\n",
	"-b <block-size>\t\tset data block to <block-size>.  Default 128 "
		"Kbytes.  Optionally a suffix of K, KB, Kbytes or M, MB, "
		"Mbytes can be given to specify Kbytes or Mbytes "
		"respectively\n",
	"-comp <comp>\t\tselect <comp> compression.  Run -help-comp <comp> to "
		"get compressor options for <comp>, or <all> for all the "
		"compressors.\nCompressors available:\n"
		"\t" COMPRESSORS "\n",
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
	"\n", "Filesystem time options:", "\n",
	"-mkfs-time <time>\tset filesystem creation timestamp to <time>. "
		"<time> can be \"inode\", which means use the latest inode "
		"timestamp, an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-inode-time <time>\tset all file and directory timestamps to <time>. "
		"<time> can be an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2025\".  This option "
		"sets and overrides the -root-time option\n",
	"-root-time <time>\tset root directory time to <time>. <time> can be "
		"\"inode\", which means use the latest inode timestamp, an "
		"unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2025\"\n",
	"\n", "Filesystem permissions options:", "\n",
	"-all-root\t\tmake all files and directories owned by root\n",
	"-root-mode <mode>\tset root directory permissions to <mode>.  <Mode> "
		"can be symbolic or octal (see section Symbolic mode "
		"specification).  Default root mode is ugo=rwx or 0777 octal\n",
	"-root-uid <user>\tset root directory owner to specified <user>, "
		"<user> can be either an integer uid or user name\n",
	"-root-gid <group>\tset root directory group to specified <group>, "
		"<group> can be either an integer gid or group name\n",
	"-force-file-mode <mode>\tset all file (non-directory) permissions "
		"to <mode>.  <Mode> can be symbolic or octal (see section "
		"Symbolic mode specification)\n",
	"-force-dir-mode <mode>\tset all directory permissions to <mode>.  "
		"<Mode> can be symbolic or octal (see section Symbolic mode "
		"specification)\n",
	"-force-uid <user>\tset all file and directory uids to specified "
		"<user>, <user> can be either an integer uid or user name\n",
	"-force-gid <group>\tset all file and directory gids to specified "
		"<group>, <group> can be either an integer gid or group name\n",
	"-uid-gid-offset <value>\toffset all uid and gids by specified "
		"<value>.  <value> should be a positive integer\n",
	"\n", "Filesystem pseudo options:", "\n",
	"-p <pseudo-definition>\tadd pseudo file definition.  The definition "
		"should be quoted.  See section \"Pseudo file definition "
		"format\" for format details\n",
	"-pd <d mode uid gid>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  This also allows pseudo definitions to be "
		"specified without specifying all the directories in the "
		"pathname.  The definition should be quoted\n",
	"-pd <D time mode u g>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  The D type also allows a timestamp to be "
		"specified in addition to mode, uid and gid\n",
	"-pf <pseudo-file>\tadd list of pseudo file definitions from "
		"<pseudo-file>, use - for stdin.  Pseudo file definitions "
		"should not be quoted\n",
	"-pseudo-override\tmake pseudo file uids and gids override -all-root, "
		"-force-uid and -force-gid options\n",
	"\n", "Filesystem filter options:", "\n",
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
	"-info\t\t\tprint files written to filesystem to stdout.  This "
		"automatically disables the progress bar.  See -info-file to "
		"output to file without disabling the progress bar\n",
	"-info-file <file>\tprint files written to filesystem to file <file>.  "
		"This does not disable the progress bar\n",
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
	"-single-reader\t\tuse a single thread to read files. This "
		"reads files sequentially from the source(s)" SINGLE_STR "\n",
	"-small-readers <n>\tuse <n> threads to read small files (files "
		"less than a block size) in parallel from the source(s)" SMALL_STR "\n",
	"-block-readers <n>\tuse <n> threads to read block files (files "
		"a block or larger in size) in parallel from the source(s)" BLOCK_STR" \n",
	"-overcommit <percent>\tallow <percent> more threads to run in parallel"
	       " than available processors.  Doing this may increase CPU "
	       "utilisation.  Default is " OVERCOMMIT_STR(OVERCOMMIT_DEFAULT)
		", because normally overcommiting reduces performance due to "
		"trashing.  The percentage value is at the granularity of "
		"the number of processors, e.g. 4 processors have a percentage "
		"granularity of 25%, and 20 processors have a percentage "
		"granularity of 5%\n",
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
	"-action <action@expr>\tevaluate <expr> on every file and directory, "
		"and execute <action> if it returns TRUE\n",
	"-log-action <act@expr>\tas -action, but log expression evaluation "
		"results and actions performed\n",
	"-true-action <act@expr>\tas -action, but only log expressions which "
		"return TRUE\n",
	"-false-action <act@exp>\tas -action, but only log expressions which "
		"return FALSE\n",
	"-action-file <file>\tas action, but read actions from <file>\n",
	"-log-action-file <file>\tas -log-action, but read actions from "
		"<file>\n",
	"-true-action-file <f>\tas -true-action, but read actions from <f>\n",
	"-false-action-file <f>\tas -false-action, but read actions from <f>\n",
	"\n", "Tar file only options:", "\n",
	"-default-mode <mode>\ttar files often do not store permissions for "
		"intermediate directories.  This option sets the default "
		"directory permissions to <mode>.  <Mode> can be symbolic or "
		"octal (see section Symbolic mode specification).  Default "
		"mode is u=rwx,go=rx or 0755 octal.  This also sets the root "
		"directory mode\n",
	"-default-uid <value>\ttar files often do not store uids for "
		"intermediate directories.  This option sets the default "
		"directory owner to <value>, rather than the user running "
		"Mksquashfs.  <value> can be either an integer uid or user "
		"name.  This also sets the root directory uid\n",
	"-default-gid <value>\ttar files often do not store gids for "
		"intermediate directories.  This option sets the default "
		"directory group to <value>, rather than the group of the user "
		"running Mksquashfs.  <value> can be either an integer uid or "
		"group name.  This also sets the root directory gid\n",
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
	"-help-option <regex>\tprint the help information for options matching "
		"<regex> to pager (or stdout if not a terminal)\n",
	"-help-section <section>\tprint the help information for section "
		"<section> to pager (or stdout if not a terminal).  If "
		"<section> does not exactly match a section name, it is "
		"treated as a regular expression, and all section names that "
		"match are displayed.  Use \"list\" as section name to get a "
		"list of sections and their names\n",
	"-help-comp <comp>\tprint compressor options for compressor <comp>.  "
		"Use \"list\" to get a list of available compressors, and "
		"\"all\" to get the compressor options for all the "
		"compressors\n",
	"-help-all\t\tprint help information for all Mksquashfs options and "
		"sections to pager (or stdout if not a terminal)\n",
	"-Xhelp\t\t\tprint compressor options for selected compressor\n",
	"-h\t\t\tshorthand alternative to -help\n",
	"-ho <regex>\t\tshorthand alternative to -help-option\n",
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
	"\"filename h linkname\"\t\t\tcreate a hard-link to linkname, follows symlinks\n",
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
	"\n", "Symbolic mode specification:", "\n",
	"The symbolic mode is of the format [ugoa]*[[+-=]PERMS]+.  PERMS = "
		"[rwxXst]+ or [ugo], and the sequence can be repeated "
		"separated with commas.\n\n",
	"A combination of the letters ugoa specify which permission bits will "
		"be affected, u means user, g means group, o means other, and "
		"a means all or ugo.\n\n",
	"The next letter is +, - or =.  The letter + means add to the existing "
		"permission bits, - means remove the bits from the existing "
		"permission bits, and = means set the permission bits.\n\n",
	"The permission bits (PERMS) are a combination of [rwxXst] which "
		"sets/adds/removes those bits for the specified ugoa "
		"combination, r means read, w means write and x means execute "
		"for files or search for directories.  X has a special "
		"meaning, if the file is a directory it is equivalent to x or "
		"search, but if it is a non-directory, it only takes effect if "
		"execute is already set for user, group or other.  The s flag "
		"sets user or group ID on execution, and the t flag on a "
		"directory sets restricted deletion, or historically made the "
		"file sticky if a non-directory.\n\n",
		"The permission bits can also be u, g or o, which takes the "
			"permission bits from the user, group or other of the "
			"file respectively.\n",
	"\n", "Environment:", "\n",
	"SQFS_CMDLINE \t\tIf set, this is used as the directory to write the "
		"file sqfs_cmdline which contains the command line arguments "
		"given to Mksquashfs.  Each command line argument is wrapped "
		"in quotes to ensure there is no ambiguity when arguments "
		"contain spaces.  If the file already exists then the command "
		"line is appended to the file\n", "\n",
	"SOURCE_DATE_EPOCH\tIf set, this is used as the filesystem creation "
		"timestamp.  Also any file timestamps which are after "
		"SOURCE_DATE_EPOCH will be clamped to SOURCE_DATE_EPOCH.  "
		"See https://reproducible-builds.org/docs/source-date-epoch/"
		" for more information\n", "\n",
	"PAGER\t\t\tIf set, this is used as the name of the program used to "
		"display the help text.  The value can be a simple command or "
		"a pathname.  The default is /usr/bin/pager\n",
	"\n", "Exit status:", "\n",
	"  0\tMksquashfs successfully generated a filesystem.\n",
	"  1\tFatal errors occurred, Mksquashfs aborted and did not generate a "
		"filesystem (or update if appending).\n",
	"\n","See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.7 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/Documentation/4.7/README\n",
	"\nThe Squashfs-tools USAGE guides and other documentation can be read "
		"here https://github.com/plougher/squashfs-tools/blob/master/"
		"Documentation/4.7\n",
	NULL
};


static char *sqfstar_text[]={
	"Filesystem compression options:", "\n",
	"-b <block-size>\t\tset data block to <block-size>.  Default 128 "
		"Kbytes. Optionally a suffix of K, KB, Kbytes or M, MB, Mbytes "
		"can be given to specify Kbytes or Mbytes respectively\n",
	"-comp <comp>\t\tselect <comp> compression.  Run -help-comp <comp> to "
		"get compressor options for <comp>, or <all> for all the "
		"compressors.\nCompressors available:\n"
		"\t" COMPRESSORS "\n",
	"-noI\t\t\tdo not compress inode table\n",
	"-noId\t\t\tdo not compress the uid/gid table (implied by -noI)\n",
	"-noD\t\t\tdo not compress data blocks\n",
	"-noF\t\t\tdo not compress fragment blocks\n",
	"-noX\t\t\tdo not compress extended attributes\n",
	"-no-compression\t\tdo not compress any of the data or metadata.  This "
		"is equivalent to specifying -noI -noD -noF and -noX\n",
	"\n", "Filesystem build options:", "\n",
	"-exports\t\tmake the filesystem exportable via NFS\n",
	"-no-sparse\t\tdo not detect sparse files\n",
	"-no-fragments\t\tdo not use fragments\n",
	"-no-tailends\t\tdo not pack tail ends into fragments\n",
	"-no-duplicates\t\tdo not perform duplicate checking\n",
	"-no-hardlinks\t\tdo not hardlink files, instead store duplicates\n",
	"-regex\t\t\tallow POSIX regular expressions to be used in exclude "
		"dirs/files\n",
	"-ignore-zeros\t\tallow tar files to be concatenated together and fed "
		"to Sqfstar.  Normally a tarfile has two consecutive 512 byte "
		"blocks filled with zeros which means EOF and Sqfstar will "
		"stop reading after the first tar file on encountering them. "
		"This option makes Sqfstar ignore the zero filled blocks\n",
	"-ef <exclude-file>\tlist of exclude dirs/files.  One per line\n",
	"\n", "Filesystem time options:", "\n",
	"-mkfs-time <time>\tset filesystem creation timestamp to <time>. "
		"<time> can be \"inode\", which means use the latest inode "
		"timestamp, an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"-inode-time <time>\tset all file and directory timestamps to <time>. "
		"<time> can be an unsigned 32-bit int indicating seconds since "
		"the epoch (1970-01-01) or a string value which is passed to "
		"the \"date\" command to parse. Any string value which the "
		"date command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2025\".  This option "
		"sets and overrides the -root-time option\n",
	"-root-time <time>\tset root directory time to <time>. <time> can be "
		"\"inode\", which means use the latest inode timestamp, an "
		"unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", \"last "
		"week\", or \"Wed Feb 15 21:02:39 GMT 2025\"\n",
	"\n", "Filesystem permissions options:", "\n",
	"-all-root\t\tmake all files and directories owned by root\n",
	"-root-mode <mode>\tset root directory permissions to <mode>.  <Mode> "
		"can be symbolic or octal (see section Symbolic mode "
		"specification).  Default root mode is ugo=rwx or 0777 octal\n",
	"-root-uid <user>\tset root directory owner to specified <user>, "
		"<user> can be either an integer uid or user name\n",
	"-root-gid <group>\tset root directory group to specified <group>, "
		"<group> can be either an integer gid or group name\n",
	"-force-file-mode <mode>\tset all file (non-directory) permissions "
		"to <mode>.  <Mode> can be symbolic or octal (see section "
		"Symbolic mode specification)\n",
	"-force-dir-mode <mode>\tset all directory permissions to <mode>.  "
		"<Mode> can be symbolic or octal (see section Symbolic mode "
		"specification)\n",
	"-force-uid <user>\tset all file and directory uids to specified "
		"<user>, <user> can be either an integer uid or user name\n",
	"-force-gid <group>\tset all file and directory gids to specified "
		"<group>, <group> can be either an integer gid or group name\n",
	"-uid-gid-offset <value>\toffset all uid and gids by specified "
		"<value>.  <value> should be a positive integer\n",
	"-default-mode <mode>\ttar files often do not store permissions for "
		"intermediate directories.  This option sets the default "
		"directory permissions to <mode>.  <Mode> can be symbolic or "
		"octal (see section Symbolic mode specification).  Default "
		"mode is u=rwx,go=rx or 0755 octal.  This also sets the root "
		"directory mode\n",
	"-default-uid <user>\ttar files often do not store uids for "
		"intermediate directories.  This option sets the default "
		"directory owner to <user>, rather than the user running "
		"Sqfstar.  <user> can be either an integer uid or user name.  "
		"This also sets the root directory uid\n",
	"-default-gid <group>\ttar files often do not store gids for "
		"intermediate directories.  This option sets the default "
		"directory group to <group>, rather than the group of the "
		"user running Sqfstar.  <group> can be either an integer gid "
		"or group name.  This also sets the root directory gid\n",
	"\n", "Filesystem pseudo options:", "\n",
	"-p <pseudo-definition>\tadd pseudo file definition.  The definition "
		"should be quoted.  See section \"Pseudo file definition "
		"format\" for format details\n",
	"-pd <d mode uid gid>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  This also allows pseudo definitions to be "
		"specified without specifying all the directories in the "
		"pathname.  The definition should be quoted\n",
	"-pd <D time mode u g>\tspecify a default pseudo directory which will "
		"be used in pseudo definitions if a directory in the pathname "
		"does not exist.  The D type also allows a timestamp to be "
		"specified in addition to mode, uid and gid\n",
	"-pf <pseudo-file>\tadd list of pseudo file definitions.  Pseudo file "
		"definitions in pseudo-files should not be quoted\n",
	"-pseudo-override\tmake pseudo file uids and gids override -all-root, "
		"-force-uid and -force-gid options\n",
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
	"-info\t\t\tprint files written to filesystem to stdout.  This "
		"automatically disables the progress bar.  See -info-file to "
		"output to file without disabling the progress bar\n",
	"-info-file <file>\tprint files written to filesystem to file <file>.  "
		"This does not disable the progress bar\n",
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
	"-overcommit <percent>\tallow <percent> more threads to run in parallel"
	       " than available processors.  Doing this may increase CPU "
	       "utilisation.  Default is " OVERCOMMIT_STR(OVERCOMMIT_DEFAULT)
		", because normally overcommiting reduces performance due to "
		"trashing.  The percentage value is at the granularity of "
		"the number of processors, e.g. 4 processors have a percentage "
		"granularity of 25%, and 20 processors have a percentage "
		"granularity of 5%\n",
	"\n", "Expert options (these may make the filesystem unmountable):", "\n",
	"-nopad\t\t\tdo not pad filesystem to a multiple of 4K\n",
	"-offset <offset>\tskip <offset> bytes at the beginning of "
		"FILESYSTEM.  Optionally a suffix of K, M or G can be given to "
		"specify Kbytes, Mbytes or Gbytes respectively.  Default 0 "
		"bytes\n",
	"-o <offset>\t\tsynonym for -offset\n",
	"\n", "Help options:", "\n",
	"-help\t\t\tprint help summary information to stdout\n",
	"-help-option <regex>\tprint the help information for options matching "
		"<regex> to pager (or stdout if not a terminal)\n",
	"-help-section <section>\tprint the help information for section "
		"<section> to pager (or stdout if not a terminal).  If "
		"<section> does not exactly match a section name, it is "
		"treated as a regular expression, and all section names that "
		"match are displayed.  Use \"list\" as section name to get a "
		"list of sections and their names\n",
	"-help-comp <comp>\tprint compressor options for compressor <comp>.  "
		"Use \"list\" to get a list of available compressors, and "
		"\"all\" to get the compressor options for all the "
		"compressors\n",
	"-help-all\t\tprint help information for all Sqfstar options and "
		"sections to pager (or stdout if not a terminal)\n",
	"-Xhelp\t\t\tprint compressor options for selected compressor\n",
	"-h\t\t\tshorthand alternative to -help\n",
	"-ho <regex>\t\tshorthand alternative to -help-option\n",
	"-hs <section>\t\tshorthand alternative to -help-section\n",
	"-ha\t\t\tshorthand alternative to -help-all\n",
	"\n", "Miscellaneous options:", "\n",
	"-fstime <time>\t\talternative name for mkfs-time\n",
	"-root-owned\t\talternative name for -all-root\n",
	"-noInodeCompression\talternative name for -noI\n",
	"-noIdTableCompression\talternative name for -noId\n",
	"-noDataCompression\talternative name for -noD\n",
	"-noFragmentCompression\talternative name for -noF\n",
	"-noXattrCompression\talternative name for -noX\n",
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
	"\"filename h linkname\"\t\t\tcreate a hard-link to linkname, follows symlinks\n",
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
	"\n", "Symbolic mode specification:", "\n",
	"The symbolic mode is of the format [ugoa]*[[+-=]PERMS]+.  PERMS = "
		"[rwxXst]+ or [ugo], and the sequence can be repeated "
		"separated with commas.\n\n",
	"A combination of the letters ugoa specify which permission bits will "
		"be affected, u means user, g means group, o means other, and "
		"a means all or ugo.\n\n",
	"The next letter is +, - or =.  The letter + means add to the existing "
		"permission bits, - means remove the bits from the existing "
		"permission bits, and = means set the permission bits.\n\n",
	"The permission bits (PERMS) are a combination of [rwxXst] which "
		"sets/adds/removes those bits for the specified ugoa "
		"combination, r means read, w means write and x means execute "
		"for files or search for directories.  X has a special "
		"meaning, if the file is a directory it is equivalent to x or "
		"search, but if it is a non-directory, it only takes effect if "
		"execute is already set for user, group or other.  The s flag "
		"sets user or group ID on execution, and the t flag on a "
		"directory sets restricted deletion, or historically made the "
		"file sticky if a non-directory.\n\n",
		"The permission bits can also be u, g or o, which takes the "
			"permission bits from the user, group or other of the "
			"file respectively.\n",
	"\n", "Environment:", "\n",
	"SQFS_CMDLINE \t\tIf set, this is used as the directory to write the "
		"file sqfs_cmdline which contains the command line arguments "
		"given to Sqfstar.  Each command line argument is wrapped "
		"in quotes to ensure there is no ambiguity when arguments "
		"contain spaces.  If the file already exists then the command "
		"line is appended to the file\n", "\n",
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
	"The README for the Squashfs-tools 4.7 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/Documentation/4.7/README\n",
	"\nThe Squashfs-tools USAGE guides and other documentation can be read "
		"here https://github.com/plougher/squashfs-tools/blob/master/"
		"Documentation/4.7\n",
	NULL
};

static void print_help_all(char *name, char *syntax, char **options_text)
{
	int i, cols;
	pid_t pager_pid;
	FILE *pager;

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	autowrap_printf(pager, cols, syntax, name);

	for(i = 0; options_text[i] != NULL; i++)
		autowrap_print(pager, options_text[i], cols);

	display_compressor_usage(pager, COMP_DEFAULT, cols);

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}


static void print_option(char *prog_name, char *opt_name, char *pattern, char **options,
					char **options_args, char **options_text)
{
	int i, res, matched = FALSE;
	regex_t *preg = MALLOC(sizeof(regex_t));
	int cols = get_column_width();
	pid_t pager_pid;
	FILE *pager;

	res = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);
	if(res) {
		char str[1024]; /* overflow safe */

		regerror(res, preg, str, 1024);
		autowrap_printf(stderr, cols, "%s: %s invalid regex %s because %s\n", prog_name, opt_name, pattern, str);
		exit(1);
	}

	if(isatty(STDOUT_FILENO))
		pager = exec_pager(&pager_pid);
	else
		pager = stdout;

	for(i = 0; options[i] != NULL; i++) {
		res = regexec(preg, options[i], (size_t) 0, NULL, 0);
		if(res)
			res = regexec(preg, options_args[i], (size_t) 0, NULL, 0);
		if(!res) {
			matched = TRUE;
			autowrap_print(pager, options_text[i], cols);
		}
	}

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
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
	int i, j, secs, cols, res, matched = FALSE;
	pid_t pager_pid;
	FILE *pager;
	regex_t *preg;

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	if(strcmp(sec_name, "list") == 0) {
		autowrap_printf(pager, cols, "\nUse following section name to print %s help information for that section\n\n", prog_name);
		print_section_names(pager , "", cols, sections, options_text);
		goto finish;
	}

	for(i = 0; sections[i] != NULL; i++)
		if(strcmp(sections[i], sec_name) == 0)
			goto exact_match;

	/* match sec_name as a regex */
	preg = MALLOC(sizeof(regex_t));
	res = regcomp(preg, sec_name, REG_EXTENDED|REG_NOSUB);
	if(res) {
		char str[1024]; /* overflow safe */

		if(pager != stdout) {
			fclose(pager);
			wait_to_die(pager_pid);
		}

		regerror(res, preg, str, 1024);
		autowrap_printf(stderr, cols, "%s: %s invalid regex %s because %s\n", prog_name, opt_name, sec_name, str);
		exit(1);
	}

	for(i = j = 0; sections[i] != NULL; i++) {
		res = regexec(preg, sections[i], (size_t) 0, NULL, 0);
		if(!res) {
			autowrap_print(pager, options_text[j], cols);
			matched = TRUE;
		}

		while(options_text[++ j] != NULL && !is_header(j, options_text))
			if(!res)
				autowrap_print(pager, options_text[j], cols);
	}

	if(!matched) {
		autowrap_printf(pager, cols, "%s: %s %s does not match any section name\n", prog_name, opt_name, sec_name);
		print_section_names(pager, "", cols, sections, options_text);
	}

	goto finish;

exact_match:
	i++;

	for(j = 0, secs = 0; options_text[j] != NULL && secs <= i; j ++) {
		if(is_header(j, options_text))
			secs++;
		if(i == secs)
			autowrap_print(pager, options_text[j], cols);
	}

finish:
	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}


static void handle_invalid_option(char *prog_name, char *opt_name, char **sections, char **options_text)
{
	int cols;
	pid_t pager_pid;
	FILE *pager;

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	autowrap_printf(pager, cols, "%s: %s is an invalid option\n\n", prog_name, opt_name);
	autowrap_printf(pager, cols, "Run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	fprintf(pager, "\nOr run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(pager, "\t", cols, sections, options_text);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(1);
}


static void print_help(char *prog_name, char *message, char *syntax, char **sections, char **options_text)
{
	int cols;
	pid_t pager_pid;
	FILE *pager;

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	if(message)
		autowrap_print(pager, message, cols);
	autowrap_printf(pager, cols, syntax, prog_name);
	autowrap_printf(pager, cols, "Run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(pager, "\t", cols, sections, options_text);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(message == NULL ? 0 : 1);
}


static void print_option_help(char *prog_name, char *option, char **sections, char **options_text, const char *restrict fmt, va_list ap)
{
	int cols;
	char *string;
	pid_t pager_pid;
	FILE *pager;

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	VASPRINTF(&string, fmt, ap);
	autowrap_print(pager, string, cols);
	autowrap_printf(pager, cols, "\nRun\n  \"%s -help-option %s$\" to get help on %s option\n", prog_name, option, option);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(pager, "\t", cols, sections, options_text);
	autowrap_printf(pager, cols, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	free(string);

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(1);
}


void mksquashfs_help_all(void)
{
	print_help_all("mksquashfs", MKSQUASHFS_SYNTAX, mksquashfs_text);
}


void sqfstar_help_all(void)
{
	print_help_all("sqfstar", SQFSTAR_SYNTAX, sqfstar_text);
}


void mksquashfs_option(char *opt_name, char *pattern)
{
	print_option("mksquashfs", opt_name, pattern, mksquashfs_options, mksquashfs_args, mksquashfs_text);
}


void sqfstar_option(char *opt_name, char *pattern)
{
	print_option("sqfstar", opt_name, pattern, sqfstar_options, sqfstar_args, sqfstar_text);
}

void mksquashfs_section(char *opt_name, char *sec_name)
{
	print_section("mksquashfs", opt_name, sec_name, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_section(char *opt_name, char *sec_name)
{
	print_section("sqfstar", opt_name, sec_name, sqfstar_sections, sqfstar_text);
}

void mksquashfs_help(char *message)
{
	print_help("mksquashfs", message, MKSQUASHFS_SYNTAX, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_help(char *message)
{
	print_help("sqfstar", message, SQFSTAR_SYNTAX, sqfstar_sections, sqfstar_text);
}

void mksquashfs_invalid_option(char *opt_name)
{
	handle_invalid_option("mksquashfs", opt_name, mksquashfs_sections, mksquashfs_text);
}

void sqfstar_invalid_option(char *opt_name)
{
	handle_invalid_option("sqfstar", opt_name, sqfstar_sections, sqfstar_text);
}

void mksquashfs_option_help(char *option, const char *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	print_option_help("mksquashfs", option, mksquashfs_sections, mksquashfs_text, fmt, ap);
	va_end(ap);
}

void sqfstar_option_help(char *option, const char *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	print_option_help("sqfstar", option, sqfstar_sections, sqfstar_text, fmt, ap);
	va_end(ap);
}

void display_compressors() {
	int cols = get_column_width();

	autowrap_print(stderr, "\t" COMPRESSORS "\n", cols);
}

void print_compressor_options(char *comp_name, char *prog_name)
{
	int cols;
	pid_t pager_pid;
	FILE *pager;

	if(strcmp(comp_name, "ALL") == 0 || strcmp(comp_name, "<all>") == 0)
		comp_name = "all";

	if(strcmp(comp_name, "list") && strcmp(comp_name, "all") && !valid_compressor(comp_name)) {
		cols = get_column_width();
		autowrap_printf(stderr, cols, "%s: Compressor \"%s\" is not "
			"supported!\n", prog_name, comp_name);
		autowrap_printf(stderr, cols, "%s: Compressors available:\n",
			prog_name);
		display_compressors();
		exit(1);
	}

	if(isatty(STDOUT_FILENO)) {
		cols = get_column_width();
		pager = exec_pager(&pager_pid);
	} else {
		cols = 80;
		pager = stdout;
	}

	if(strcmp(comp_name, "list") == 0)
		autowrap_print(pager, "\t" COMPRESSORS "\n", cols);
	else
		print_comp_options(pager, cols, comp_name, prog_name);

	if(pager != stdout) {
		fclose(pager);
		wait_to_die(pager_pid);
	}

	exit(0);
}
