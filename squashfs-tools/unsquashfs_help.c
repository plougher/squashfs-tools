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
#include "alloc.h"

#define UNSQUASHFS_SYNTAX "SYNTAX: %s [OPTIONS] FILESYSTEM [files to extract " \
	"or exclude (with -excludes) or cat (with -cat )]\n\n"

#define SQFSCAT_SYNTAX "SYNTAX: %s [OPTIONS] FILESYSTEM [list of files to " \
	"cat to stdout]\n\n"

static char *unsquashfs_options[]={
	/* extraction options */
	"", "", "-dest", "-max-depth", "-excludes", "-exclude-list",
	"-extract-file", "-exclude-file", "-match", "-follow-symlinks",
	"-missing-symlinks", "-no-wildcards", "-regex", "-all-time",
	"-cat", "-force", "-pf", "", "", "",
	/* information options */
	"-stat", "-max-depth", "-info", "-linfo", "-ls", "-lls", "-llnumeric",
	"-lc", "-llc", "-full-precision", "-UTC", "-mkfs-time", "", "", "",
	/* xattrs options */
	"-no-xattrs", "-xattrs", "-xattrs-exclude", "-xattrs-include", "", "",
	"",
	/* runtime options */
	"-version", "-processors", "-mem", "-mem-percent", "-quiet",
	"-no-progress", "-percentage", "-ignore-errors", "-strict-errors",
	"-no-exit-code", "", "", "",
	/* help options */
	"-help", "-help-option", "-help-section", "-help-all", "-ho", "-hs",
	"-ha", "", "", "",
	/* misc options */
	"-offset", "-fstime", "-ef", "-excf", "-L", "-pseudo-file", "", "", "",
	NULL,
};

static char *sqfscat_options[]={
	/* runtime options */
	"", "", "-version", "-processors", "-mem", "-mem-percent", "-offset",
	"-ignore-errors", "-strict-errors", "-no-exit-code", "", "", "",
	/* filter options */
	"-no-wildcards", "-regex", "", "", "",
	/* help options */
	"-help", "-help-option", "-help-section", "-help-all", "-ho", "-hs",
	"-ha", NULL,
};

static char *unsquashfs_args[]={
	/* extraction options */
	"", "", "", "", "", "", "<file>", "<file>", "", "", "", "", "",
	"<time>", "", "", "<file>", "", "", "",
	/* information options */
	"", "<levels>", "", "", "", "", "", "", "", "", "", "", "", "", "",
	/* xattrs options */
	"", "", "<regex>", "<regex>", "", "", "",
	/* runtime options */
	"", "<number>", "<size>", "<percent>", "", "", "", "", "", "", "", "",
	"",
	/* help options */
	"", "<regex>", "<section>", "", "<regex>", "<section>", "", "", "", "",
	/* misc options */
	"<bytes>", "", "<extract file>", "<exclude file>", "", "<file>", "",
	"", "",
};

static char *sqfscat_args[]={
	/* runtime options */
	"", "", "", "<number>", "<size>", "<percent>", "<bytes>", "", "", "",
	"", "", "",
	/* filter options */
	"", "", "", "", "",
	/* help options */
	"", "<regex>", "<section>", "", "<regex>", "<section>", ""
};

static char *unsquashfs_sections[]={
	"extraction", "information", "xattrs", "runtime", "help", "misc",
	"environment", "exit", "extra", "decompressors", NULL
};

static char *sqfscat_sections[]={
	"runtime", "filter", "help", "environment", "exit", "extra",
	"decompressors", NULL
};

static char *unsquashfs_text[]={
	"Filesystem extraction (filtering) options:", "\n",
	"\t-d[est] <pathname>\textract to <pathname>, default "
		"\"squashfs-root\".  This option also sets the prefix used "
		"when listing the filesystem\n",
	"\t-max[-depth] <levels>\tdescend at most <levels> of directories when "
		"extracting\n",
	"\t-excludes\t\ttreat files on command line as exclude files\n",
	"\t-ex[clude-list]\t\tlist of files to be excluded, terminated with "
		"; e.g. file1 file2 ;\n",
	"\t-extract-file <file>\tlist of directories or files to extract.  One "
		"per line\n",
	"\t-exclude-file <file>\tlist of directories or files to exclude.  One "
		"per line\n",
	"\t-match\t\t\tabort if any extract file does not match on anything, "
		"and can not be resolved.  Implies -missing-symlinks and "
		"-no-wildcards\n",
	"\t-follow[-symlinks]\tfollow symlinks in extract files, and add all "
		"files/symlinks needed to resolve extract file.  Implies "
		"-no-wildcards\n",
	"\t-missing[-symlinks]\tUnsquashfs will abort if any symlink can't be "
		"resolved in -follow-symlinks\n",
	"\t-no-wild[cards]\t\tdo not use wildcard matching in extract and "
		"exclude names\n",
	"\t-r[egex]\t\ttreat extract names as POSIX regular expressions rather "
		"than use the default shell wildcard expansion (globbing)\n",
	"\t-all[-time] <time>\tset all file timestamps to <time>, rather than "
		"the time stored in the filesystem inode.  <time> can be an "
		"unsigned 32-bit int indicating seconds since the epoch "
		"(1970-01-01) or a string value which is passed to the "
		"\"date\" command to parse. Any string value which the date "
		"command recognises can be used such as \"now\", "
		"\"last week\", or \"Wed Feb 15 21:02:39 GMT 2023\"\n",
	"\t-cat\t\t\tcat the files on the command line to stdout\n",
	"\t-f[orce]\t\tif destination directory already exists, descend into "
		"it and any sub-directories, and unlink (delete) files if they "
		"already exist before extracting to them\n",
	"\t-pf <file>\t\toutput a pseudo file equivalent of the input Squashfs "
		"filesystem, use - for stdout\n",
	"\n", "Filesystem information and listing options:", "\n",
	"\t-s[tat]\t\t\tdisplay filesystem superblock information\n",
	"\t-max[-depth] <levels>\tdescend at most <levels> of directories when "
		"listing\n",
	"\t-i[nfo]\t\t\tprint files as they are extracted\n",
	"\t-li[nfo]\t\tprint files as they are extracted with file attributes "
		"(like ls -l output)\n",
	"\t-l[s]\t\t\tlist filesystem, but do not extract files\n",
	"\t-ll[s]\t\t\tlist filesystem with file attributes (like ls -l "
		"output), but do not extract files\n",
	"\t-lln[umeric]\t\tsame as -lls but with numeric uids and gids\n",
	"\t-lc\t\t\tlist filesystem concisely, displaying only files and empty "
		"directories.  Do not extract files\n",
	"\t-llc\t\t\tlist filesystem concisely with file attributes, "
		"displaying only files and empty directories.  Do not extract "
		"files\n",
	"\t-full[-precision]\tuse full precision when displaying times "
		"including seconds.  Use with -linfo, -lls, -lln and -llc\n",
	"\t-UTC\t\t\tuse UTC rather than local time zone when displaying "
		"time\n",
	"\t-mkfs-time\t\tdisplay filesystem superblock time, which is an "
		"unsigned 32-bit int representing the time in seconds since "
		"the epoch (1970-01-01)\n",
	"\n", "Filesystem extended attribute (xattrs) options:", "\n",
	"\t-no[-xattrs]\t\tdo not extract xattrs in file system" NOXOPT_STR "\n",
	"\t-x[attrs]\t\textract xattrs in file system" XOPT_STR "\n",
	"\t-xattrs-exclude <regex>\texclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-exclude "
		"'^user.' excludes xattrs from the user namespace\n",
	"\t-xattrs-include <regex>\tinclude any xattr names matching <regex>.  "
		"<regex> is a POSIX regular expression, e.g. -xattrs-include "
		"'^user.' includes xattrs from the user namespace\n",
	"\n", "Unsquashfs runtime options:", "\n",
	"\t-v[ersion]\t\tprint version, licence and copyright information\n",
	"\t-p[rocessors] <number>\tuse <number> processors.  By default will "
		"use the number of processors available\n",
	"\t-mem <size>\t\tuse <size> physical memory for caches.  Use K, M or "
		"G to specify Kbytes, Mbytes or Gbytes respectively.  Default "
		"512 Mbytes\n",
	"\t-mem-percent <percent>\tuse <percent> physical memory for caches.\n",
	"\t-q[uiet]\t\tno verbose output\n",
	"\t-n[o-progress]\t\tdo not display the progress bar\n",
	"\t-percentage\t\tdisplay a percentage rather than the full progress "
		"bar.  Can be used with dialog --gauge etc.\n",
	"\t-ig[nore-errors]\ttreat errors writing files to output as "
		"non-fatal\n",
	"\t-st[rict-errors]\ttreat all errors as fatal\n",
	"\t-no-exit[-code]\t\tdo not set exit code (to nonzero) on non-fatal "
		"errors\n",
	"\n", "Help options:", "\n",
	"\t-h[elp]\t\t\tprint help summary information to stdout\n",
	"\t-help-option <regex>\tprint the help information for options "
		"matching <regex> to pager (or stdout if not a terminal)\n",
	"\t-help-section <section>\tprint the help information for section "
		"<section> to pager (or stdout if not a terminal).  If "
		"<section> does not exactly match a section name, it is "
		"treated as a regular expression, and all section names that "
		"match are displayed.  Use \"list\" as section name to get a "
		"list of sections and their names\n",
	"\t-help-all\t\tprint help information for all Unsquashfs options and "
		"sections to pager (or stdout if not a terminal)\n",
	"\t-ho <regex>\t\tshorthand alternative to -help-option\n",
	"\t-hs <section>\t\tshorthand alternative to -help-section\n",
	"\t-ha\t\t\tshorthand alternative to -help-all\n",
	"\n", "Miscellaneous options:", "\n",
	"\t-o[ffset] <bytes>\tskip <bytes> at start of FILESYSTEM.  Optionally "
		"a suffix of K, M or G can be given to specify Kbytes, Mbytes "
		"or Gbytes respectively (default 0 bytes).\n",
	"\t-fstime\t\t\tsynonym for -mkfs-time\n",
	"\t-e[f] <extract file>\tsynonym for -extract-file\n",
	"\t-exc[f] <exclude file>\tsynonym for -exclude-file\n",
	"\t-L\t\t\tsynonym for -follow-symlinks\n",
	"\t-pseudo-file <file>\talternative name for -pf\n",
	"\n", "Environment:", "\n",
	"\tSQFS_CMDLINE \t\tIf set, this is used as the directory to write the "
		"file sqfs_cmdline which contains the command line arguments "
		"given to Unsquashfs.  Each command line argument is wrapped "
		"in quotes to ensure there is no ambiguity when arguments "
		"contain spaces.  If the file already exists then the command "
		"line is appended to the file\n", "\n",
	"\tPAGER\t\t\tIf set, this is used as the name of the program used to "
		"display the help text.  The value can be a simple command or "
		"a pathname.  The default is /usr/bin/pager\n",
	"\n", "Exit status:", "\n",
	"  0\tThe filesystem listed or extracted OK.\n",
	"  1\tFATAL errors occurred, e.g. filesystem corruption, I/O errors.  "
		"Unsquashfs did not continue and aborted.\n",
	"  2\tNon-fatal errors occurred, e.g. no support for XATTRs, Symbolic "
		"links in output filesystem or couldn't write permissions to "
		"output filesystem.  Unsquashfs continued and did not abort.\n",
	"\nSee -ignore-errors, -strict-errors and -no-exit-code options for "
		"how they affect the exit status.\n",
	"\n", "See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.7 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/Documentation/4.7/README\n",
	"\nThe Squashfs-tools USAGE guides and other documentation can be read "
		"here https://github.com/plougher/squashfs-tools/blob/master/"
		"Documentation/4.7\n",
	"\n", "Decompressors available:", "\n",
	"\t" DECOMPRESSORS "\n", NULL
};


static char *sqfscat_text[]={
	"Runtime options:", "\n",
	"\t-v[ersion]\t\tprint version, licence and copyright information\n",
	"\t-p[rocessors] <number>\tuse <number> processors.  By default will "
		"use the number of processors available\n",
	"\t-mem <size>\t\tuse <size> physical memory for caches.  Use K, M or "
		"G to specify Kbytes, Mbytes or Gbytes respectively.  Default "
		"512 Mbytes\n",
	"\t-mem-percent <percent>\tuse <percent> physical memory for caches.\n",
	"\t-o[ffset] <bytes>\tskip <bytes> at start of FILESYSTEM.  Optionally "
		"a suffix of K, M or G can be given to specify Kbytes, Mbytes "
		"or Gbytes respectively (default 0 bytes).\n",
	"\t-ig[nore-errors]\ttreat errors writing files to stdout as "
		"non-fatal\n",
	"\t-st[rict-errors]\ttreat all errors as fatal\n",
	"\t-no-exit[-code]\t\tdon't set exit code (to nonzero) on non-fatal "
		"errors\n",
	"\n", "Filter options:", "\n",
	"\t-no-wild[cards]\t\tdo not use wildcard matching in filenames\n",
	"\t-r[egex]\t\ttreat filenames as POSIX regular expressions rather "
		"than use the default shell wildcard expansion (globbing)\n",
	"\n", "Help options:", "\n",
	"\t-h[elp]\t\t\tprint help summary information to stdout\n",
	"\t-help-option <regex>\tprint the help information for options "
		"matching <regex> to pager (or stdout if not a terminal)\n",
	"\t-help-section <section>\tprint the help information for section "
		"<section> to pager (or stdout if not a terminal).  If "
		"<section> does not exactly match a section name, it is "
		"treated as a regular expression, and all section names that "
		"match are displayed.  Use \"list\" as section name to get a "
		"list of sections and their names\n",
	"\t-help-all\t\tprint help information for all Sqfscat options and "
		"sections to pager (or stdout if not a terminal)\n",
	"\t-ho <regex>\t\tshorthand alternative to -help-option\n",
	"\t-hs <section>\t\tshorthand alternative to -help-section\n",
	"\t-ha\t\t\tshorthand alternative to -help-all\n",
	"\n", "Environment:", "\n",
	"\tSQFS_CMDLINE \t\tIf set, this is used as the directory to write the "
		"file sqfs_cmdline which contains the command line arguments "
		"given to Sqfscat.  Each command line argument is wrapped "
		"in quotes to ensure there is no ambiguity when arguments "
		"contain spaces.  If the file already exists then the command "
		"line is appended to the file\n", "\n",
	"\tPAGER\t\t\tIf set, this is used as the name of the program used to "
		"display the help text.  The value can be a simple command or "
		"a pathname.  The default is /usr/bin/pager\n",
	"\n", "Exit status:", "\n",
	"  0\tThe file or files were output to stdout OK.\n",
	"  1\tFATAL errors occurred, e.g. filesystem corruption, I/O errors.  "
		"Sqfscat did not continue and aborted.\n",
	"  2\tNon-fatal errors occurred, e.g. not a regular file, or failed to "
		"resolve pathname.  Sqfscat continued and did not abort.\n",
	"\nSee -ignore-errors, -strict-errors and -no-exit-code options for "
		"how they affect the exit status.\n",
	"\n", "See also (extra information elsewhere):", "\n",
	"The README for the Squashfs-tools 4.7 release, describing the new "
		"features can be read here https://github.com/plougher/"
		"squashfs-tools/blob/master/Documentation/4.7/README\n",
	"\nThe Squashfs-tools USAGE guides and other documentation can be read "
		"here https://github.com/plougher/squashfs-tools/blob/master/"
		"Documentation/4.7\n",
	"\n", "Decompressors available:", "\n",
	"\t" DECOMPRESSORS "\n", NULL,
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
	else {
		cols = 80;
		pager = stdout;
	}

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


static void print_help(char *prog_name, char*message, char *syntax, char **sections, char **options_text)
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


void unsquashfs_help_all(void)
{
        print_help_all("unsquashfs", UNSQUASHFS_SYNTAX, unsquashfs_text);
}


void unsquashfs_section(char *opt_name, char *sec_name)
{
	print_section("unsquashfs", opt_name, sec_name, unsquashfs_sections, unsquashfs_text);
}


void unsquashfs_option(char *opt_name, char *pattern)
{
	print_option("unsquashfs", opt_name, pattern, unsquashfs_options, unsquashfs_args, unsquashfs_text);
}


void unsquashfs_help(char *message)
{
	print_help("unsquashfs", message, UNSQUASHFS_SYNTAX, unsquashfs_sections, unsquashfs_text);
}


void unsquashfs_invalid_option(char *opt_name)
{
	handle_invalid_option("unsquashfs", opt_name, unsquashfs_sections, unsquashfs_text);
}


void unsquashfs_option_help(char *option, const char *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	print_option_help("unsquashfs", option, unsquashfs_sections, unsquashfs_text, fmt, ap);
	va_end(ap);
}


void sqfscat_help_all(void)
{
	print_help_all("sqfscat", SQFSCAT_SYNTAX, sqfscat_text);
}


void sqfscat_section(char *opt_name, char *sec_name)
{
	print_section("sqfscat", opt_name, sec_name, sqfscat_sections, sqfscat_text);
}


void sqfscat_option(char *opt_name, char *pattern)
{
	print_option("sqfscat", opt_name, pattern, sqfscat_options, sqfscat_args, sqfscat_text);
}


void sqfscat_help(char *message)
{
	print_help("sqfscat", message, SQFSCAT_SYNTAX, sqfscat_sections, sqfscat_text);
}


void sqfscat_invalid_option(char *opt_name)
{
	handle_invalid_option("sqfscat", opt_name, sqfscat_sections, sqfscat_text);
}


void sqfscat_option_help(char *option, const char *restrict fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	print_option_help("sqfscat", option, sqfscat_sections, sqfscat_text,  fmt, ap);
	va_end(ap);
}


void display_compressors() {
	int cols = get_column_width();

	autowrap_print(stderr, "\t" DECOMPRESSORS "\n", cols);
}
