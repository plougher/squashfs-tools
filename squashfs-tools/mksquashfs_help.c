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

#include "mksquashfs_error.h"
#include "mksquashfs_help.h"
#include "compressor.h"

#define SYNTAX "SYNTAX:%s source1 source2 ...  FILESYSTEM [OPTIONS] [-e list of\nexclude dirs/files]\n"

static char *options[] = {
	"", "", "-b", "-comp", "-noI", "-noId", "-noD", "-noF", "-noX", "-no-compression",
	"", "", "", "-tar", "-no-strip", "-tarstyle", "-cpiostyle", "-cpiostyle0",
	"-reproducible", "-not-reproducible", "-mkfs-time", "-all-time",
	"-root-time", "-root-mode", "-root-uid", "-root-gid", "-all-root",
	"-force-uid", "-force-gid", "-pseudo-override", "-no-exports",
	"-exports", "-no-sparse", "-no-tailends", "-tailends", "-no-fragments",
	"-no-duplicates", "-no-hardlinks", "-keep-as-directory", "", "", "", "-p",
	"-pd", "-pd", "-pf", "-sort", "-ef", "-wildcards", "-regex", "-max-depth",
	"-one-file-system", "-one-file-system-x", "", "", "", "-no-xattrs", "-xattrs",
	"-xattrs-exclude", "-xattrs-include", "-xattrs-add", "", "", "", "-version",
	"-exit-on-error", "-quiet", "-info", "-no-progress", "-progress",
	"-percentage", "-throttle", "-limit", "-processors", "-mem",
	"-mem-percent", "-mem-default", "", "", "", "-noappend", "-root-becomes",
	"-no-recovery", "-recovery-path", "-recover", "", "", "", "-action",
	"-log-action", "-true-action", "-false-action", "-action-file",
	"-log-action-file", "-true-action-file", "-false-action-file", "", "", "",
	"-default-mode", "-default-uid", "-default-gid", "-ignore-zeros", "", "", "",
	"-nopad", "-offset", "-o", "", "", "", "-help", "-help-option", "-help-section",
	"help-comp", "-help-all", "-Xhelp", "-h", "-ho", "-hs", "", "", "", "-fstime", "-always-use-fragments",
	"-root-owned", "-noInodeCompression", "-noIdTableCompression", "-noDataCompression",
	"-noFragmentCompression", "-noXattrCompression", "-pseudo-dir", NULL,
};

static char *options_args[]={
	"", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"<time>", "<time>", "<time>", "<mode>", "<value>", "<value>",
	"", "<value>", "<value>", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
	"<d mode uid gid>", "<D time mode uid gid>", "<pseudo-file>", "<sort-file>", "<exclude-file>", "", "",
	"<levels>", "", "", "", "", "", "", "", "<regex>", "<regex>", "<name=val>", "", "", "", "", "", "",
	"", "", "", "", "<percentage>", "<percentage>", "<number>", "<size>", "<percent>", "", "", "", "", "",
	"<name>", "", "<name>", "<name>", "", "", "", "<action@expression>", "<action@expression>", "<action@expression>",
	"<action@expression>", "<file>", "<file>", "<file>", "<file>", "", "", "", "<mode>", "<value>", "<value>",
	"", "", "", "", "", "<offset>", "<offset>", "", "", "", "", "<regex>", "<section>", "comp", "", "", "", "<regex>", "<section>",
	"", "", "", "<time>", "", "", "", "", "", "", "", ""
};

static char *sections[]={
	"compression", "build", "filter", "xattrs", "runtime", "append", "actions", "tar", "expert", "help", "misc", "pseudo", "environment", "exit", "extra", NULL
};

static char *options_text[]={
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
	"-root-becomes <name>\twhen appending source files/directories, make the\n\t\t\toriginal root become a subdirectory in the new root\n\t\t\tcalled <name>, rather than adding the new source items\n\t\t\tto the original root\n",
	"-no-recovery\t\tdo not generate a recovery file\n",
	"-recovery-path <name>\tuse <name> as the directory to store the recovery file\n",
	"-recover <name>\t\trecover filesystem data using recovery file <name>\n",
	"\n", "Filesystem actions options:", "\n",
	"-action <action@expr>\tevaluate <expr> on every file, and execute <action>\n\t\t\tif it returns TRUE\n",
	"-log-action <act@expr>\tas above, but log expression evaluation results and\n\t\t\tactions performed\n",
	"-true-action <act@expr>\tas above, but only log expressions which return TRUE\n",
	"-false-action <act@exp>\tas above, but only log expressions which return FALSE\n",
	"-action-file <file>\tas action, but read actions from <file>\n",
	"-log-action-file <file>\tas -log-action, but read actions from <file>\n",
	"-true-action-file <f>\tas -true-action, but read actions from <f>\n",
	"-false-action-file <f>\tas -false-action, but read actions from <f>\n",
	"\n", "Tar file only options:", "\n",
	"-default-mode <mode>\ttar files often do not store permissions for\n\t\t\tintermediate directories.  This option sets the default\n\t\t\tdirectory permissions to octal <mode>, rather than 0755.\n\t\t\tThis also sets the root inode mode\n",
	"-default-uid <value>\ttar files often do not store uids for intermediate\n\t\t\tdirectories.  This option sets the default directory\n\t\t\towner to <value>, rather than the user running\n\t\t\tMksquashfs.  <value> can be either an integer uid or\n\t\t\tuser name.  This also sets the root inode uid\n",
	"-default-gid <value>\ttar files often do not store gids for intermediate\n\t\t\tdirectories.  This option sets the default directory\n\t\t\tgroup to <value>, rather than the group of the user\n\t\t\trunning Mksquashfs.  <value> can be either an integer\n\t\t\tuid or group name.  This also sets the root inode gid\n",
	"-ignore-zeros\t\tallow tar files to be concatenated together and fed to\n\t\t\tMksquashfs.  Normally a tarfile has two consecutive 512\n\t\t\tbyte blocks filled with zeros which means EOF and\n\t\t\tMksquashfs will stop reading after the first tar file on\n\t\t\tencountering them. This option makes Mksquashfs ignore\n\t\t\tthe zero filled blocks\n",
	"\n", "Expert options (these may make the filesystem unmountable):", "\n",
	"-nopad\t\t\tdo not pad filesystem to a multiple of 4K\n",
	"-offset <offset>\tskip <offset> bytes at the beginning of FILESYSTEM.\n\t\t\tOptionally a suffix of K, M or G can be given to specify\n\t\t\tKbytes, Mbytes or Gbytes respectively.\n\t\t\tDefault 0 bytes\n",
	"-o <offset>\t\tsynonym for -offset\n",
	"\n", "Help options:", "\n",
	"-help\t\t\tprint help summary information to stdout\n",
	"-help-option <regex>\tprint the help information for Mksquashfs options\n\t\t\tmatching <regex> to stdout\n",
	"-help-section <section>\tprint the help information for section <section> to\n\t\t\tstdout.  Use \"sections\" or \"h\" as section name to get a\n\t\t\tlist of sections and their names\n",
	"-help-comp <comp>\tprint compressor options for compressor <comp>\n",
	"-help-all\t\tprint help information for all Mksquashfs options and\n\t\t\tsections to stdout\n",
	"-Xhelp\t\t\tprint compressor options for selected compressor\n",
	"-h\t\t\tshorthand alternative to -help\n",
	"-ho <regex>\t\tshorthand aternative to -help-option\n",
	"-hs <section>\t\tshorthand alternative to -help-section\n",
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
	"\"filename f mode uid gid command\"\tcreate file from stdout of command\n",
	"\"filename s mode uid gid symlink\"\tcreate a symbolic link\n",
	"\"filename i mode uid gid [s|f]\"\t\tcreate a socket (s) or FIFO (f)\n",
	"\"filename x name=val\"\t\t\tcreate an extended attribute\n",
	"\"filename l linkname\"\t\t\tcreate a hard-link to linkname\n",
	"\"filename L pseudo_filename\"\t\tsame, but link to pseudo file\n",
	"\"filename D time mode uid gid\"\t\tcreate a directory with timestamp time\n",
	"\"filename M time mode uid gid\"\t\tmodify a file with timestamp time\n",
	"\"filename B time mode uid gid major minor\"\n\t\t\t\t\tcreate block device with timestamp time\n",
	"\"filename C time mode uid gid major minor\"\n\t\t\t\t\tcreate char device with timestamp time\n",
	"\"filename F time mode uid gid command\"\tcreate file with timestamp time\n",
	"\"filename S time mode uid gid symlink\"\tcreate symlink with timestamp time\n",
	"\"filename I time mode uid gid [s|f]\"\tcreate socket/fifo with timestamp time\n",
	"\n", "Environment:", "\n"
	"SOURCE_DATE_EPOCH\tIf set, this is used as the filesystem creation\n",
	"\t\t\ttimestamp.  Also any file timestamps which are\n",
	"\t\t\tafter SOURCE_DATE_EPOCH will be clamped to\n",
	"\t\t\tSOURCE_DATE_EPOCH.  See\n",
	"\t\t\thttps://reproducible-builds.org/docs/source-date-epoch/\n",
	"\t\t\tfor more information\n",
	"\n", "Exit status:", "\n",
	"  0\tMksquashfs successfully generated a filesystem.\n"
	"  1\tFatal errors occurred, Mksquashfs aborted and did not generate a\n",
	"\tfilesystem (or update if appending).\n",
	"\n","See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.6.1 release, describing the new features can be\n",
	"read here https://github.com/plougher/squashfs-tools/blob/master/README-4.6.1\n",
	"\nThe Squashfs-tools USAGE guide can be read here\n",
	"https://github.com/plougher/squashfs-tools/blob/master/USAGE-4.6\n",
	"\nThe ACTIONS-README file describing how to use the new actions feature can be\n",
	"read here https://github.com/plougher/squashfs-tools/blob/master/ACTIONS-README\n",
	NULL};


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
			cur ++;
		}

		first_line = FALSE;

		if(*cur == '\n')
			cur ++;
		else if(*cur != '\0') {
			if(eow)
				cur = eow + 1;
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


void print_help_all(char *name)
{
	int i;

	printf(SYNTAX, name);

	for(i = 0; options_text[i] != NULL; i++)
		autowrap_print(stdout, options_text[i], 80);

	autowrap_print(stdout, "\nCompressors available and compressor specific options:\n", 80);

	display_compressor_usage(stdout, COMP_DEFAULT);
	exit(0);
}


void print_option(char *prog_name, char *opt_name, char *pattern)
{
	int i, res, matched = FALSE;
	regex_t *preg = malloc(sizeof(regex_t));

	if(preg == NULL)
		MEM_ERROR();

	res = regcomp(preg, pattern, REG_EXTENDED|REG_NOSUB);

	if(res) {
		char str[1024]; /* overflow safe */

		regerror(res, preg, str, 1024);
		fprintf(stderr, "%s: %s invalid regex %s because %s\n", prog_name, opt_name, pattern, str);
		exit(1);
	}

	for(i = 0; options[i] != NULL; i++) {
		res = regexec(preg, options[i], (size_t) 0, NULL, 0);
		if(res)
			res = regexec(preg, options_args[i], (size_t) 0, NULL, 0);
		if(!res) {
			matched = TRUE;
			autowrap_print(stdout, options_text[i], 80);
		}
	}

	if(!matched) {
		fprintf(stderr, "%s: %s %s does not match any Mksquashfs option\n", prog_name, opt_name, pattern);
		exit(1);
	} else
		exit(0);
}


static int is_header(int i)
{
	int length = strlen(options_text[i]);

	return length && options_text[i][length - 1] == ':';
}


static void print_section_names(FILE *out, char *string)
{
	int i, j;

	fprintf(out, "%sSECTION NAME\t\tSECTION\n", string);

	for(i = 0, j = 0; sections[i] != NULL; j++)
		if(is_header(j)) {
			fprintf(out, "%s%s\t\t%s%s\n", string, sections[i], strlen(sections[i]) > 7 ? "" : "\t", options_text[j]);
			i++;
		}
}


void print_section(char *prog_name, char *opt_name, char *sec_name)
{
	int i, j, secs;

	if(strcmp(sec_name, "sections") == 0 || strcmp(sec_name, "h") == 0) {
		autowrap_print(stdout, "\nUse following section name to print Mksquashfs help information for that section\n\n", 80);
		print_section_names(stdout, "");
		exit(0);
	}

	for(i = 0; sections[i] != NULL; i++)
		if(strcmp(sections[i], sec_name) == 0)
			break;

	if(sections[i] == NULL) {
		fprintf(stderr, "%s: %s %s does not match any section name\n", prog_name, opt_name, sec_name);
		print_section_names(stderr, "");
		exit(1);
	}

	i++;

	for(j = 0, secs = 0; options_text[j] != NULL && secs <= i; j ++) {
		if(is_header(j))
			secs++;
		if(i == secs)
			autowrap_print(stdout, options_text[j], 80);
	}

	exit(0);
}


void handle_invalid_option(char *prog_name, char *opt_name)
{
	fprintf(stderr, "%s: %s is an invalid option\n\n", prog_name, opt_name);
	fprintf(stderr, "Run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stderr, "\t");
	fprintf(stderr, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	fprintf(stderr, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(1);
}


void print_help(int error, char *prog_name)
{
	FILE *stream = error ? stderr : stdout;

	fprintf(stream, SYNTAX "\n", prog_name);
	fprintf(stream, "Run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stream, "\t");
	fprintf(stream, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	fprintf(stream, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(error);
}


void print_option_help(char *prog_name, char *option)
{
	fprintf(stderr, "\nRun\n  \"%s -help-option %s$\" to get help on %s option\n", prog_name, option, option);
	fprintf(stderr, "Or run\n  \"%s -help-section <section-name>\" to get help on these sections\n", prog_name);
	print_section_names(stderr, "\t");
	fprintf(stderr, "\nOr run\n  \"%s -help-option <regex>\" to get help on all options matching <regex>\n", prog_name);
	fprintf(stderr, "\nOr run\n  \"%s -help-all\" to get help on all the sections\n", prog_name);
	exit(1);
}
