/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2012, 2014, 2017, 2019, 2021, 2022, 2023
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
 * pseudo.c
 */

#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <ctype.h>
#include <time.h>
#include <ctype.h>
#include <regex.h>
#include <dirent.h>
#include <sys/types.h>

#include "pseudo.h"
#include "mksquashfs_error.h"
#include "progressbar.h"
#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "xattr.h"

#define TRUE 1
#define FALSE 0
#define MAX_LINE 16384

struct pseudo *pseudo = NULL;

char *get_element(char *target, char **targname)
{
	char *start;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = strndup(start, target - start);

	while(*target == '/')
		target ++;

	return target;
}


/*
 * Add pseudo device target to the set of pseudo devices.  Pseudo_dev
 * describes the pseudo device attributes.
 */
static struct pseudo *add_pseudo(struct pseudo *pseudo, struct pseudo_dev *pseudo_dev,
	char *target, char *alltarget)
{
	char *targname;
	int i;

	target = get_element(target, &targname);

	if(pseudo == NULL) {
		pseudo = malloc(sizeof(struct pseudo));
		if(pseudo == NULL)
			MEM_ERROR();

		pseudo->names = 0;
		pseudo->count = 0;
		pseudo->name = NULL;
	}

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(pseudo->name[i].name, targname) == 0)
			break;

	if(i == pseudo->names) {
		/* allocate new name entry */
		pseudo->names ++;
		pseudo->name = realloc(pseudo->name, (i + 1) *
			sizeof(struct pseudo_entry));
		if(pseudo->name == NULL)
			MEM_ERROR();
		pseudo->name[i].name = targname;
		pseudo->name[i].xattr = NULL;

		if(target[0] == '\0') {
			/* at leaf pathname component */
			pseudo->name[i].pseudo = NULL;
			pseudo->name[i].pathname = strdup(alltarget);
			pseudo->name[i].dev = pseudo_dev;
		} else {
			/* recurse adding child components */
			pseudo->name[i].dev = NULL;
			pseudo->name[i].pseudo = add_pseudo(NULL, pseudo_dev,
				target, alltarget);
		}
	} else {
		/* existing matching entry */
		free(targname);

		if(pseudo->name[i].pseudo == NULL) {
			/* No sub-directory which means this is the leaf
			 * component, this may or may not be a pre-existing
			 * pseudo file.
			 */
			if(target[0] != '\0') {
				/*
				 * entry must exist as either a 'd' type or
				 * 'm' type pseudo file, or not exist at all
				 */
				if(pseudo->name[i].dev == NULL ||
					pseudo->name[i].dev->type == 'd' ||
					pseudo->name[i].dev->type == 'm')
					/* recurse adding child components */
					pseudo->name[i].pseudo =
						add_pseudo(NULL, pseudo_dev,
						target, alltarget);
				else {
					ERROR_START("%s already exists as a "
						"non directory.",
						pseudo->name[i].name);
					ERROR_EXIT(".  Ignoring %s!\n",
						alltarget);
				}
			} else if(pseudo->name[i].dev == NULL) {
				/* add this pseudo definition */
				pseudo->name[i].pathname = strdup(alltarget);
				pseudo->name[i].dev = pseudo_dev;
			} else if(memcmp(pseudo_dev, pseudo->name[i].dev,
					sizeof(struct pseudo_dev)) != 0) {
				ERROR_START("%s already exists as a different "
					"pseudo definition.", alltarget);
				ERROR_EXIT("  Ignoring!\n");
			} else {
				ERROR_START("%s already exists as an identical "
					"pseudo definition!", alltarget);
				ERROR_EXIT("  Ignoring!\n");
			}
		} else {
			if(target[0] == '\0') {
				/*
				 * sub-directory exists, which means we can only
				 * add a pseudo file of type 'd' or type 'm'
				 */
				if(pseudo->name[i].dev == NULL &&
						(pseudo_dev->type == 'd' ||
						pseudo_dev->type == 'm')) {
					pseudo->name[i].pathname =
						strdup(alltarget);
					pseudo->name[i].dev = pseudo_dev;
				} else {
					ERROR_START("%s already exists as a "
						"different pseudo definition.",
						pseudo->name[i].name);
					ERROR_EXIT("  Ignoring %s!\n",
						alltarget);
				}
			} else
				/* recurse adding child components */
				add_pseudo(pseudo->name[i].pseudo, pseudo_dev,
					target, alltarget);
		}
	}

	return pseudo;
}


static struct pseudo *add_pseudo_definition(struct pseudo *pseudo, struct pseudo_dev *pseudo_dev,
	char *target, char *alltarget)
{
	/* special case if a root pseudo definition is being added */
	if(strcmp(target, "/") == 0) {
		/* type must be 'd' */
		if(pseudo_dev->type != 'd') {
			ERROR("Pseudo definition / is not a directory.  Ignoring!\n");
			return pseudo;
		}

		/* if already have a root pseudo just replace */
		if(pseudo && pseudo->names == 1 && strcmp(pseudo->name[0].name, "/") == 0) {
			pseudo->name[0].dev = pseudo_dev;
			return pseudo;
		} else {
			struct pseudo *new = malloc(sizeof(struct pseudo));
			if(new == NULL)
				MEM_ERROR();

			new->names = 1;
			new->count = 0;
			new->name = malloc(sizeof(struct pseudo_entry));
			if(new->name == NULL)
				MEM_ERROR();

			new->name[0].name = "/";
			new->name[0].pseudo = pseudo;
			new->name[0].pathname = "/";
			new->name[0].dev = pseudo_dev;
			new->name[0].xattr = NULL;
			return new;
		}
	}

	/* if there's a root pseudo definition, skip it before walking target */
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->name[0].name, "/") == 0) {
		pseudo->name[0].pseudo = add_pseudo(pseudo->name[0].pseudo, pseudo_dev, target, alltarget);
		return pseudo;
	} else
		return add_pseudo(pseudo, pseudo_dev, target, alltarget);
}


/*
 * Find subdirectory in pseudo directory referenced by pseudo, matching
 * filename.  If filename doesn't exist or if filename is a leaf file
 * return NULL
 */
struct pseudo *pseudo_subdir(char *filename, struct pseudo *pseudo)
{
	int i;

	if(pseudo == NULL)
		return NULL;

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(filename, pseudo->name[i].name) == 0)
			return pseudo->name[i].pseudo;

	return NULL;
}


struct pseudo_entry *pseudo_readdir(struct pseudo *pseudo)
{
	if(pseudo == NULL)
		return NULL;

	while(pseudo->count < pseudo->names)
		return &pseudo->name[pseudo->count++];

	return NULL;
}


int pseudo_exec_file(struct pseudo_dev *dev, int *child)
{
	int res, pipefd[2];

	res = pipe(pipefd);
	if(res == -1) {
		ERROR("Executing dynamic pseudo file, pipe failed\n");
		return 0;
	}

	*child = fork();
	if(*child == -1) {
		ERROR("Executing dynamic pseudo file, fork failed\n");
		goto failed;
	}

	if(*child == 0) {
		close(pipefd[0]);
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if(res == -1)
			exit(EXIT_FAILURE);

		execl("/bin/sh", "sh", "-c", dev->command, (char *) NULL);
		exit(EXIT_FAILURE);
	}

	close(pipefd[1]);
	return pipefd[0];

failed:
	close(pipefd[0]);
	close(pipefd[1]);
	return 0;
}


static struct pseudo_entry *pseudo_lookup(struct pseudo *pseudo, char *target)
{
	char *targname;
	int i;

	if(pseudo == NULL)
		return NULL;

	target = get_element(target, &targname);

	for(i = 0; i < pseudo->names; i++)
		if(strcmp(pseudo->name[i].name, targname) == 0)
			break;

	free(targname);

	if(i == pseudo->names)
		return NULL;

	if(target[0] == '\0')
		return &pseudo->name[i];

	if(pseudo->name[i].pseudo == NULL)
		return NULL;

	return pseudo_lookup(pseudo->name[i].pseudo, target);
}


void print_definitions()
{
	ERROR("Pseudo definitions should be of the format\n");
	ERROR("\tfilename d mode uid gid\n");
	ERROR("\tfilename m mode uid gid\n");
	ERROR("\tfilename b mode uid gid major minor\n");
	ERROR("\tfilename c mode uid gid major minor\n");
	ERROR("\tfilename f mode uid gid command\n");
	ERROR("\tfilename s mode uid gid symlink\n");
	ERROR("\tfilename i mode uid gid [s|f]\n");
	ERROR("\tfilename x name=value\n");
	ERROR("\tfilename l filename\n");
	ERROR("\tfilename L pseudo_filename\n");
	ERROR("\tfilename D time mode uid gid\n");
	ERROR("\tfilename M time mode uid gid\n");
	ERROR("\tfilename B time mode uid gid major minor\n");
	ERROR("\tfilename C time mode uid gid major minor\n");
	ERROR("\tfilename F time mode uid gid command\n");
	ERROR("\tfilename S time mode uid gid symlink\n");
	ERROR("\tfilename I time mode uid gid [s|f]\n");
	ERROR("\tfilename R time mode uid gid length offset sparse\n");
}


static int read_pseudo_def_pseudo_link(char *orig_def, char *filename, char *name, char *def)
{
	char *linkname, *link;
	int quoted = FALSE;
	struct pseudo_entry *pseudo_ent;

	/*
	 * Scan for filename, don't use sscanf() and "%s" because
	 * that can't handle filenames with spaces.
	 *
	 * Filenames with spaces should either escape (backslash) the
	 * space or use double quotes.
	 */
	linkname = malloc(strlen(def) + 1);
	if(linkname == NULL)
		MEM_ERROR();

	for(link = linkname; (quoted || !isspace(*def)) && *def != '\0';) {
		if(*def == '"') {
			quoted = !quoted;
			def ++;
			continue;
		}

		if(*def == '\\') {
			def ++;
			if (*def == '\0')
				break;
		}
		*link ++ = *def ++;
	}
	*link = '\0';

	/* Skip any leading slashes (/) */
	for(link = linkname; *link == '/'; link ++);

	if(*link == '\0') {
		ERROR("Not enough or invalid arguments in pseudo LINK file "
			"definition \"%s\"\n", orig_def);
		goto error;
	}

	/* Lookup linkname in pseudo definition tree */
	/* if there's a root pseudo definition, skip it before walking target */
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->name[0].name, "/") == 0)
		pseudo_ent = pseudo_lookup(pseudo->name[0].pseudo, link);
	else
		pseudo_ent = pseudo_lookup(pseudo, link);

	if(pseudo_ent == NULL || pseudo_ent->dev == NULL) {
		ERROR("Pseudo LINK file %s doesn't exist\n", linkname);
		goto error;
	}

	if(pseudo_ent->dev->type == 'd' || pseudo_ent->dev->type == 'm') {
		ERROR("Cannot hardlink to a Pseudo directory or modify definition\n");
		goto error;
	}

	pseudo = add_pseudo_definition(pseudo, pseudo_ent->dev, name, name);

	free(filename);
	free(linkname);
	return TRUE;

error:
	print_definitions();
	free(filename);
	free(linkname);
	return FALSE;
}


static int read_pseudo_def_link(char *orig_def, char *filename, char *name, char *def, char *destination)
{
	char *linkname, *link;
	int quoted = FALSE;
	struct pseudo_dev *dev = NULL;
	static struct stat *dest_buf = NULL;

	/*
	 * Stat destination file.  We need to do this to prevent people
	 * from creating a circular loop, connecting the output to the
	 * input (only needed for appending, otherwise the destination
	 * file will not exist).
	 */
	if(dest_buf == NULL) {
		dest_buf = malloc(sizeof(struct stat));
		if(dest_buf == NULL)
			MEM_ERROR();

		memset(dest_buf, 0, sizeof(struct stat));
		lstat(destination, dest_buf);
	}


	/*
	 * Scan for filename, don't use sscanf() and "%s" because
	 * that can't handle filenames with spaces.
	 *
	 * Filenames with spaces should either escape (backslash) the
	 * space or use double quotes.
	 */
	linkname = malloc(strlen(def) + 1);
	if(linkname == NULL)
		MEM_ERROR();

	for(link = linkname; (quoted || !isspace(*def)) && *def != '\0';) {
		if(*def == '"') {
			quoted = !quoted;
			def ++;
			continue;
		}

		if(*def == '\\') {
			def ++;
			if (*def == '\0')
				break;
		}
		*link ++ = *def ++;
	}
	*link = '\0';

	if(*linkname == '\0') {
		ERROR("Not enough or invalid arguments in pseudo link file "
			"definition \"%s\"\n", orig_def);
		goto error;
	}

	dev = malloc(sizeof(struct pseudo_dev));
	if(dev == NULL)
		MEM_ERROR();

	memset(dev, 0, sizeof(struct pseudo_dev));

	dev->linkbuf = malloc(sizeof(struct stat));
	if(dev->linkbuf == NULL)
		MEM_ERROR();

	if(lstat(linkname, dev->linkbuf) == -1) {
		ERROR("Cannot stat pseudo link file %s because %s\n",
			linkname, strerror(errno));
		goto error;
	}

	if(S_ISDIR(dev->linkbuf->st_mode)) {
		ERROR("Pseudo link file %s is a directory, ", linkname);
		ERROR("which cannot be hardlinked to\n");
		goto error;
	}

	if(S_ISREG(dev->linkbuf->st_mode)) {
		/*
		 * Check we're not trying to create a circular loop,
		 * connecting the output destination file to the
		 * input
		 */
		if(memcmp(dev->linkbuf, dest_buf, sizeof(struct stat)) == 0) {
			ERROR("Pseudo link file %s is the ", linkname);
			ERROR("destination output file, which cannot be linked to\n");
			goto error;
		}
	}

	dev->type = 'l';
	dev->pseudo_type = PSEUDO_FILE_OTHER;
	dev->linkname = strdup(linkname);

	pseudo = add_pseudo_definition(pseudo, dev, name, name);

	free(filename);
	free(linkname);
	return TRUE;

error:
	print_definitions();
	if(dev)
		free(dev->linkbuf);
	free(dev);
	free(filename);
	free(linkname);
	return FALSE;
}


static int read_pseudo_def_extended(char type, char *orig_def, char *filename,
	char *name, char *def, char *pseudo_file, struct pseudo_file **file)
{
	int n, bytes;
	int quoted = FALSE;
	unsigned int major = 0, minor = 0, mode, mtime;
	char *ptr, *str, *string, *command = NULL, *symlink = NULL;
	char suid[100], sgid[100]; /* overflow safe */
	char ipc_type;
	long long uid, gid;
	struct pseudo_dev *dev;
	static int pseudo_ino = 1;
	long long file_length, pseudo_offset;
	int sparse;

	n = sscanf(def, "%u %o %n", &mtime, &mode, &bytes);

	if(n < 2) {
		/*
		 * Couldn't match date and mode.  Date may not be quoted
		 * and is instead using backslashed spaces (i.e. 1\ jan\ 1980)
		 * where the "1" matched for the integer, but, jan didn't for
		 * the octal number.
		 *
		 * Scan for date string, don't use sscanf() and "%s" because
		 * that can't handle strings with spaces.
		 *
		 * Strings with spaces should either escape (backslash) the
		 * space or use double quotes.
		 */
		string = malloc(strlen(def) + 1);
		if(string == NULL)
			MEM_ERROR();

		for(str = string; (quoted || !isspace(*def)) && *def != '\0';) {
			if(*def == '"') {
				quoted = !quoted;
				def ++;
				continue;
			}

			if(*def == '\\') {
				def ++;
				if (*def == '\0')
					break;
			}
			*str++ = *def ++;
		}
		*str = '\0';

		if(string[0] == '\0') {
			ERROR("Not enough or invalid arguments in pseudo file "
				"definition \"%s\"\n", orig_def);
			free(string);
			goto error;
		}

		n = exec_date(string, &mtime);
		if(n == FALSE) {
				ERROR("Couldn't parse time, date string or "
					"unsigned decimal integer "
					"expected\n");
			free(string);
			goto error;
		}

		free(string);

		n = sscanf(def, "%o %99s %99s %n", &mode, suid, sgid, &bytes);
		def += bytes;
		if(n < 3) {
			ERROR("Not enough or invalid arguments in pseudo file "
				"definition \"%s\"\n", orig_def);
			switch(n) {
			case -1:
			/* FALLTHROUGH */
			case 0:
				ERROR("Couldn't parse mode, octal integer expected\n");
				break;
			case 1:
				ERROR("Read filename, type, time and mode, but failed to "
					"read or match uid\n");
				break;
			default:
				ERROR("Read filename, type, time, mode and uid, but failed "
					"to read or match gid\n");
				break;
			}
			goto error;
		}
	} else {
		def += bytes;
		n = sscanf(def, "%99s %99s %n", suid, sgid, &bytes);
		def += bytes;

		if(n < 2) {
			ERROR("Not enough or invalid arguments in pseudo file "
				"definition \"%s\"\n", orig_def);
			switch(n) {
			case -1:
				/* FALLTHROUGH */
			case 0:
				ERROR("Read filename, type, time and mode, but failed to "
					"read or match uid\n");
				break;
			default:
				ERROR("Read filename, type, time, mode and uid, but failed "
					"to read or match gid\n");
				break;
			}
			goto error;
		}
	}

	switch(type) {
	case 'B':
		/* FALLTHROUGH */
	case 'C':
		n = sscanf(def, "%u %u %n", &major, &minor, &bytes);
		def += bytes;

		if(n < 2) {
			ERROR("Not enough or invalid arguments in %s device "
				"pseudo file definition \"%s\"\n", type == 'B' ?
				"block" : "character", orig_def);
			if(n < 1)
				ERROR("Read filename, type, time, mode, uid and "
					"gid, but failed to read or match major\n");
			else
				ERROR("Read filename, type, time, mode, uid, gid "
					"and major, but failed to read  or "
					"match minor\n");
			goto error;
		}

		if(major > 0xfff) {
			ERROR("Major %d out of range\n", major);
			goto error;
		}

		if(minor > 0xfffff) {
			ERROR("Minor %d out of range\n", minor);
			goto error;
		}
		break;
	case 'I':
		n = sscanf(def, "%c %n", &ipc_type, &bytes);
		def += bytes;

		if(n < 1) {
			ERROR("Not enough or invalid arguments in ipc "
				"pseudo file definition \"%s\"\n", orig_def);
			ERROR("Read filename, type, mode, uid and gid, "
				"but failed to read or match ipc_type\n");
			goto error;
		}

		if(ipc_type != 's' && ipc_type != 'f') {
			ERROR("Ipc_type should be s or f\n");
			goto error;
		}
		break;
	case 'R':
		if(pseudo_file == NULL) {
			ERROR("'R' definition can only be used in a Pseudo file\n");
			goto error;
		}

		n = sscanf(def, "%lld %lld %d %n", &file_length, &pseudo_offset,
						&sparse, &bytes);
		def += bytes;

		if(n < 3) {
			ERROR("Not enough or invalid arguments in inline read "
				"pseudo file definition \"%s\"\n", orig_def);
			ERROR("Read filename, type, time, mode, uid and gid, "
				"but failed to read or match file length, "
						"offset or sparse\n");
			goto error;
		}
		break;
	case 'D':
	case 'M':
		break;
	case 'F':
		if(def[0] == '\0') {
			ERROR("Not enough arguments in dynamic file pseudo "
				"definition \"%s\"\n", orig_def);
			ERROR("Expected command, which can be an executable "
				"or a piece of shell script\n");
			goto error;
		}
		command = def;
		def += strlen(def);
		break;
	case 'S':
		if(def[0] == '\0') {
			ERROR("Not enough arguments in symlink pseudo "
				"definition \"%s\"\n", orig_def);
			ERROR("Expected symlink\n");
			goto error;
		}

		if(strlen(def) > 65535) {
			ERROR("Symlink pseudo definition %s is greater than 65535"
								" bytes!\n", def);
			goto error;
		}
		symlink = def;
		def += strlen(def);
		break;
	default:
		ERROR("Unsupported type %c\n", type);
		goto error;
	}

	/*
	 * Check for trailing junk after expected arguments
	 */
	if(def[0] != '\0') {
		ERROR("Unexpected tailing characters in pseudo file "
			"definition \"%s\"\n", orig_def);
		goto error;
	}

	if(mode > 07777) {
		ERROR("Mode %o out of range\n", mode);
		goto error;
	}

	uid = strtoll(suid, &ptr, 10);
	if(*ptr == '\0') {
		if(uid < 0 || uid > ((1LL << 32) - 1)) {
			ERROR("Uid %s out of range\n", suid);
			goto error;
		}
	} else {
		struct passwd *pwuid = getpwnam(suid);
		if(pwuid)
			uid = pwuid->pw_uid;
		else {
			ERROR("Uid %s invalid uid or unknown user\n", suid);
			goto error;
		}
	}

	gid = strtoll(sgid, &ptr, 10);
	if(*ptr == '\0') {
		if(gid < 0 || gid > ((1LL << 32) - 1)) {
			ERROR("Gid %s out of range\n", sgid);
			goto error;
		}
	} else {
		struct group *grgid = getgrnam(sgid);
		if(grgid)
			gid = grgid->gr_gid;
		else {
			ERROR("Gid %s invalid uid or unknown user\n", sgid);
			goto error;
		}
	}

	switch(type) {
	case 'B':
		mode |= S_IFBLK;
		break;
	case 'C':
		mode |= S_IFCHR;
		break;
	case 'I':
		if(ipc_type == 's')
			mode |= S_IFSOCK;
		else
			mode |= S_IFIFO;
		break;
	case 'D':
		mode |= S_IFDIR;
		break;
	case 'F':
	case 'R':
		mode |= S_IFREG;
		break;
	case 'S':
		/* permissions on symlinks are always rwxrwxrwx */
		mode = 0777 | S_IFLNK;
		break;
	}

	dev = malloc(sizeof(struct pseudo_dev));
	if(dev == NULL)
		MEM_ERROR();

	dev->buf = malloc(sizeof(struct pseudo_stat));
	if(dev->buf == NULL)
		MEM_ERROR();

	dev->type = type == 'M' ? 'M' : tolower(type);
	dev->buf->mode = mode;
	dev->buf->uid = uid;
	dev->buf->gid = gid;
	dev->buf->major = major;
	dev->buf->minor = minor;
	dev->buf->mtime = mtime;
	dev->buf->ino = pseudo_ino ++;

	if(type == 'R') {
		if(*file == NULL) {
			*file = malloc(sizeof(struct pseudo_file));
			if(*file == NULL)
				MEM_ERROR();

			(*file)->filename = strdup(pseudo_file);
			(*file)->fd = -1;
		}

		dev->data = malloc(sizeof(struct pseudo_data));
		if(dev->data == NULL)
			MEM_ERROR();

		dev->pseudo_type = PSEUDO_FILE_DATA;
		dev->data->file = *file;
		dev->data->length = file_length;
		dev->data->offset = pseudo_offset;
		dev->data->sparse = sparse;
	} else if(type == 'F') {
		dev->pseudo_type = PSEUDO_FILE_PROCESS;
		dev->command = strdup(command);
	} else
		dev->pseudo_type = PSEUDO_FILE_OTHER;

	if(type == 'S')
		dev->symlink = strdup(symlink);

	pseudo = add_pseudo_definition(pseudo, dev, name, name);

	free(filename);
	return TRUE;

error:
	print_definitions();
	free(filename);
	return FALSE;
}


static int read_pseudo_def_original(char type, char *orig_def, char *filename, char *name, char *def)
{
	int n, bytes;
	unsigned int major = 0, minor = 0, mode;
	char *ptr, *command = NULL, *symlink = NULL;
	char suid[100], sgid[100]; /* overflow safe */
	char ipc_type;
	long long uid, gid;
	struct pseudo_dev *dev;
	static int pseudo_ino = 1;

	n = sscanf(def, "%o %99s %99s %n", &mode, suid, sgid, &bytes);
	def += bytes;

	if(n < 3) {
		ERROR("Not enough or invalid arguments in pseudo file "
			"definition \"%s\"\n", orig_def);
		switch(n) {
		case -1:
			/* FALLTHROUGH */
		case 0:
			/* FALLTHROUGH */
		case 1:
			ERROR("Couldn't parse filename, type or octal mode\n");
			ERROR("If the filename has spaces, either quote it, or "
				"backslash the spaces\n");
			break;
		case 2:
			ERROR("Read filename, type and mode, but failed to "
				"read or match uid\n");
			break;
		default:
			ERROR("Read filename, type, mode and uid, but failed "
				"to read or match gid\n");
			break; 
		}
		goto error;
	}

	switch(type) {
	case 'b':
		/* FALLTHROUGH */
	case 'c':
		n = sscanf(def, "%u %u %n", &major, &minor, &bytes);
		def += bytes;

		if(n < 2) {
			ERROR("Not enough or invalid arguments in %s device "
				"pseudo file definition \"%s\"\n", type == 'b' ?
				"block" : "character", orig_def);
			if(n < 1)
				ERROR("Read filename, type, mode, uid and gid, "
					"but failed to read or match major\n");
			else
				ERROR("Read filename, type, mode, uid, gid "
					"and major, but failed to read  or "
					"match minor\n");
			goto error;
		}	
		
		if(major > 0xfff) {
			ERROR("Major %d out of range\n", major);
			goto error;
		}

		if(minor > 0xfffff) {
			ERROR("Minor %d out of range\n", minor);
			goto error;
		}
		break;
	case 'i':
		n = sscanf(def, "%c %n", &ipc_type, &bytes);
		def += bytes;

		if(n < 1) {
			ERROR("Not enough or invalid arguments in ipc "
				"pseudo file definition \"%s\"\n", orig_def);
			ERROR("Read filename, type, mode, uid and gid, "
				"but failed to read or match ipc_type\n");
			goto error;
		}

		if(ipc_type != 's' && ipc_type != 'f') {
			ERROR("Ipc_type should be s or f\n");
			goto error;
		}
		break;
	case 'd':
	case 'm':
		break;
	case 'f':
		if(def[0] == '\0') {
			ERROR("Not enough arguments in dynamic file pseudo "
				"definition \"%s\"\n", orig_def);
			ERROR("Expected command, which can be an executable "
				"or a piece of shell script\n");
			goto error;
		}	
		command = def;
		def += strlen(def);
		break;
	case 's':
		if(def[0] == '\0') {
			ERROR("Not enough arguments in symlink pseudo "
				"definition \"%s\"\n", orig_def);
			ERROR("Expected symlink\n");
			goto error;
		}

		if(strlen(def) > 65535) {
			ERROR("Symlink pseudo definition %s is greater than 65535"
								" bytes!\n", def);
			goto error;
		}
		symlink = def;
		def += strlen(def);
		break;
	default:
		ERROR("Unsupported type %c\n", type);
		goto error;
	}

	/*
	 * Check for trailing junk after expected arguments
	 */
	if(def[0] != '\0') {
		ERROR("Unexpected tailing characters in pseudo file "
			"definition \"%s\"\n", orig_def);
		goto error;
	}

	if(mode > 07777) {
		ERROR("Mode %o out of range\n", mode);
		goto error;
	}

	uid = strtoll(suid, &ptr, 10);
	if(*ptr == '\0') {
		if(uid < 0 || uid > ((1LL << 32) - 1)) {
			ERROR("Uid %s out of range\n", suid);
			goto error;
		}
	} else {
		struct passwd *pwuid = getpwnam(suid);
		if(pwuid)
			uid = pwuid->pw_uid;
		else {
			ERROR("Uid %s invalid uid or unknown user\n", suid);
			goto error;
		}
	}
		
	gid = strtoll(sgid, &ptr, 10);
	if(*ptr == '\0') {
		if(gid < 0 || gid > ((1LL << 32) - 1)) {
			ERROR("Gid %s out of range\n", sgid);
			goto error;
		}
	} else {
		struct group *grgid = getgrnam(sgid);
		if(grgid)
			gid = grgid->gr_gid;
		else {
			ERROR("Gid %s invalid uid or unknown user\n", sgid);
			goto error;
		}
	}

	switch(type) {
	case 'b':
		mode |= S_IFBLK;
		break;
	case 'c':
		mode |= S_IFCHR;
		break;
	case 'i':
		if(ipc_type == 's')
			mode |= S_IFSOCK;
		else
			mode |= S_IFIFO;
		break;
	case 'd':
		mode |= S_IFDIR;
		break;
	case 'f':
		mode |= S_IFREG;
		break;
	case 's':
		/* permissions on symlinks are always rwxrwxrwx */
		mode = 0777 | S_IFLNK;
		break;
	}

	dev = malloc(sizeof(struct pseudo_dev));
	if(dev == NULL)
		MEM_ERROR();

	dev->buf = malloc(sizeof(struct pseudo_stat));
	if(dev->buf == NULL)
		MEM_ERROR();

	dev->type = type;
	dev->buf->mode = mode;
	dev->buf->uid = uid;
	dev->buf->gid = gid;
	dev->buf->major = major;
	dev->buf->minor = minor;
	dev->buf->mtime = time(NULL);
	dev->buf->ino = pseudo_ino ++;

	if(type == 'f') {
		dev->pseudo_type = PSEUDO_FILE_PROCESS;
		dev->command = strdup(command);
	} else
		dev->pseudo_type = PSEUDO_FILE_OTHER;

	if(type == 's')
		dev->symlink = strdup(symlink);

	pseudo = add_pseudo_definition(pseudo, dev, name, name);

	free(filename);
	return TRUE;

error:
	print_definitions();
	free(filename);
	return FALSE;
}


static int read_pseudo_def(char *def, char *destination, char *pseudo_file, struct pseudo_file **file)
{
	int n, bytes;
	int quoted = 0;
	char type;
	char *filename, *name;
	char *orig_def = def;

	/*
	 * Scan for filename, don't use sscanf() and "%s" because
	 * that can't handle filenames with spaces.
	 *
	 * Filenames with spaces should either escape (backslash) the
	 * space or use double quotes.
	 */
	filename = malloc(strlen(def) + 1);
	if(filename == NULL)
		MEM_ERROR();

	for(name = filename; (quoted || !isspace(*def)) && *def != '\0';) {
		if(*def == '"') {
			quoted = !quoted;
			def ++;
			continue;
		}

		if(*def == '\\') {
			def ++;
			if (*def == '\0')
				break;
		}
		*name ++ = *def ++;
	}
	*name = '\0';

	/* Skip any leading slashes (/) */
	for(name = filename; *name == '/'; name ++);

	if(*name == '\0') {
		strcpy(filename, "/");
		name = filename;
	}

	n = sscanf(def, " %c %n", &type, &bytes);
	def += bytes;

	if(n < 1) {
		ERROR("Not enough or invalid arguments in pseudo file "
			"definition \"%s\"\n", orig_def);
		goto error;
	}

	if(type == 'x')
		return read_pseudo_xattr(orig_def, filename, name, def);
	else if(type == 'l')
		return read_pseudo_def_link(orig_def, filename, name, def, destination);
	else if(type == 'L')
		return read_pseudo_def_pseudo_link(orig_def, filename, name, def);
	else if(isupper(type))
		return read_pseudo_def_extended(type, orig_def, filename, name, def, pseudo_file, file);
	else
		return read_pseudo_def_original(type, orig_def, filename, name, def);

error:
	print_definitions();
	free(filename);
	return FALSE;
}


int read_pseudo_definition(char *filename, char *destination)
{
	return read_pseudo_def(filename, destination, NULL, NULL);
}


int read_pseudo_file(char *filename, char *destination)
{
	FILE *fd;
	char *def, *err, *line = NULL;
	int res, size = 0;
	struct pseudo_file *file = NULL;
	long long bytes = 0;
	int pseudo_stdin = strcmp(filename, "-") == 0;

	if(pseudo_stdin)
		fd = stdin;
	else {
		fd = fopen(filename, "r");
		if(fd == NULL) {
			ERROR("Could not open pseudo device file \"%s\" "
				"because %s\n", filename, strerror(errno));
			return FALSE;
		}
	}

	while(1) {
		int total = 0;

		while(1) {
			int len;

			if(total + (MAX_LINE + 1) > size) {
				line = realloc(line, size += (MAX_LINE + 1));
				if(line == NULL)
					MEM_ERROR();
			}

			err = fgets(line + total, MAX_LINE + 1, fd);
			if(err == NULL)
				break;

			len = strlen(line + total);
			total += len;
			bytes += len;

			if(len == MAX_LINE && line[total - 1] != '\n') {
				/* line too large */
				ERROR("Line too long when reading "
					"pseudo file \"%s\", larger than "
					"%d bytes\n", filename, MAX_LINE);
				goto failed;
			}

			/*
			 * Remove '\n' terminator if it exists (the last line
			 * in the file may not be '\n' terminated)
			 */
			if(len && line[total - 1] == '\n') {
				line[-- total] = '\0';
				len --;
			}

			/*
			 * If no line continuation then jump out to
			 * process line.  Note, we have to be careful to
			 * check for "\\" (backslashed backslash) and to
			 * ensure we don't look at the previous line
			 */
			if(len == 0 || line[total - 1] != '\\' || (len >= 2 &&
					strcmp(line + total - 2, "\\\\") == 0))
				break;
			else
				total --;
		}

		if(err == NULL) {
			if(ferror(fd)) {
				ERROR("Reading pseudo file \"%s\" failed "
					"because %s\n", filename,
					strerror(errno));
				goto failed;
			}

			/*
			 * At EOF, normally we'll be finished, but, have to
			 * check for special case where we had "\" line
			 * continuation and then hit EOF immediately afterwards
			 */
			if(total == 0)
				break;
			else
				line[total] = '\0';
		}

		/* Skip any leading whitespace */
		for(def = line; isspace(*def); def ++);

		/* if line is now empty after skipping characters, skip it */
		if(*def == '\0')
			continue;

		/* if comment line, skip it.  But, we also have to check if
		 * it is the data demarker */
		if(*def == '#') {
			if(strcmp(def, "# START OF DATA - DO NOT MODIFY") == 0) {
				if(file) {
					file->start = bytes + 2;
					file->current = 0;
					file->fd = pseudo_stdin ? 0 : -1;
					fgetc(fd);
					fgetc(fd);
				}
				if(!pseudo_stdin)
					fclose(fd);
				free(line);
				return TRUE;
			} else
				continue;
		}

		res = read_pseudo_def(def, destination, filename, &file);
		if(res == FALSE)
			goto failed;
	}

	if(file) {
		/* No Data demarker found */
		ERROR("No START OF DATA demarker found in pseudo file %s\n", filename);
		goto failed;
	}

	if(!pseudo_stdin)
		fclose(fd);
	free(line);
	return TRUE;

failed:
	if(!pseudo_stdin)
		fclose(fd);
	free(line);
	return FALSE;
}


struct pseudo *get_pseudo()
{
	return pseudo;
}


#ifdef SQUASHFS_TRACE
static void dump_pseudo(struct pseudo *pseudo, char *string)
{
	int i, res;
	char *path;

	for(i = 0; i < pseudo->names; i++) {
		struct pseudo_entry *entry = &pseudo->name[i];
		if(string) {
			res = asprintf(&path, "%s/%s", string, entry->name);
			if(res == -1)
				BAD_ERROR("asprintf failed in dump_pseudo\n");
		} else
			path = entry->name;
		if(entry->dev)
			ERROR("%s %c 0%o %d %d %d %d\n", path, entry->dev->type,
				entry->dev->buf->mode & ~S_IFMT, entry->dev->buf->uid,
				entry->dev->buf->gid, entry->dev->buf->major,
				entry->dev->buf->minor);
		if(entry->pseudo)
			dump_pseudo(entry->pseudo, path);
		if(string)
			free(path);
	}
}


void dump_pseudos()
{
    if (pseudo)
        dump_pseudo(pseudo, NULL);
}
#else
void dump_pseudos()
{
}
#endif
