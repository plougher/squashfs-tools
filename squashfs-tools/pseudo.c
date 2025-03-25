/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009, 2010, 2012, 2013, 2014, 2017, 2019, 2021, 2022, 2023,
 * 2024, 2025
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
#include "alloc.h"

#define TRUE 1
#define FALSE 0
#define MAX_LINE 16384

struct pseudo *pseudo = NULL;
extern int force_single_threaded;

char *pseudo_definitions[] = {
	"d mode uid gid",
	"m mode uid gid",
	"b mode uid gid major minor",
	"c mode uid gid major minor",
	"f mode uid gid command",
	"s mode uid gid symlink",
	"i mode uid gid [s|f]",
	"x name=value",
	"h filename",
	"l filename",
	"L pseudo_filename",
	"D time mode uid gid",
	"M time mode uid gid",
	"B time mode uid gid major minor",
	"C time mode uid gid major minor",
	"F time mode uid gid command",
	"S time mode uid gid symlink",
	"I time mode uid gid [s|f]",
	"R time mode uid gid length offset sparse",
	NULL
};

char *get_element(char *target, char **targname, char **subpathend)
{
	char *start;

	start = target;
	while(*target != '/' && *target != '\0')
		target ++;

	*targname = STRNDUP(start, target - start);
	*subpathend = target;

	while(*target == '/')
		target ++;

	return target;
}


struct pseudo_entry *pseudo_search(struct pseudo *pseudo, char *targname,
				char *alltarget, char *subpathend, int *new)
{
	struct pseudo_entry *cur, *ent, *prev;

	for(cur = pseudo->head, prev = NULL; cur; prev = cur, cur = cur->next) {
		int res = strcmp(cur->name, targname);

		if(res == 0) {
			*new = FALSE;
			return cur;
		} else if(res < 0)
			break;
	}

	ent = MALLOC(sizeof(struct pseudo_entry));
	ent->name = targname;
	ent->pathname = STRNDUP(alltarget, subpathend - alltarget);
	ent->dev = NULL;
	ent->pseudo = NULL;
	ent->xattr = NULL;

	if(prev)
		prev->next = ent;
	else
		pseudo->head = ent;

	ent->next = cur;

	pseudo->names ++;
	*new = TRUE;

	return ent;
}


/*
 * Add pseudo device target to the set of pseudo devices.  Pseudo_dev
 * describes the pseudo device attributes.
 */
static struct pseudo *add_pseudo(struct pseudo *pseudo, struct pseudo_dev *pseudo_dev,
	char *target, char *alltarget)
{
	char *targname, *subpathend;
	int new;
	struct pseudo_entry *ent;

	target = get_element(target, &targname, &subpathend);

	if(pseudo == NULL) {
		pseudo = MALLOC(sizeof(struct pseudo));
		pseudo->names = 0;
		pseudo->current = NULL;
		pseudo->head = NULL;
	}

	ent = pseudo_search(pseudo, targname, alltarget, subpathend, &new);

	if(new) {
		if(target[0] == '\0') {
			/* at leaf pathname component */
			ent->dev = pseudo_dev;
		} else {
			/* recurse adding child components */
			ent->pseudo = add_pseudo(NULL, pseudo_dev,
				target, alltarget);
		}
	} else {
		/* existing matching entry */
		free(targname);

		if(ent->pseudo == NULL) {
			/* No sub-directory which means this is the leaf
			 * component, this may or may not be a pre-existing
			 * pseudo file.
			 */
			if(target[0] != '\0') {
				/*
				 * entry must exist as either a 'd' type or
				 * 'm' type pseudo file, or not exist at all
				 */
				if(ent->dev == NULL ||
					ent->dev->type == 'd' ||
					ent->dev->type == 'm')
					/* recurse adding child components */
					ent->pseudo = add_pseudo(NULL,
						pseudo_dev, target, alltarget);
				else {
					ERROR_START("%s already exists as a "
						"non directory.", ent->name);
					ERROR_EXIT(".  Ignoring %s!\n",
						alltarget);
				}
			} else if(ent->dev == NULL) {
				/* add this pseudo definition */
				ent->dev = pseudo_dev;
			} else if(memcmp(pseudo_dev, ent->dev,
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
				if(ent->dev == NULL &&
						(pseudo_dev->type == 'd' ||
						pseudo_dev->type == 'm')) {
					ent->dev = pseudo_dev;
				} else {
					ERROR_START("%s already exists as a "
						"different pseudo definition.",
						ent->name);
					ERROR_EXIT("  Ignoring %s!\n",
						alltarget);
				}
			} else
				/* recurse adding child components */
				add_pseudo(ent->pseudo, pseudo_dev,
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
		if(pseudo && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0) {
			pseudo->head->dev = pseudo_dev;
			return pseudo;
		} else {
			struct pseudo *new = MALLOC(sizeof(struct pseudo));

			new->names = 1;
			new->current = NULL;
			new->head = MALLOC(sizeof(struct pseudo_entry));
			new->head->name = "/";
			new->head->pseudo = pseudo;
			new->head->pathname = "/";
			new->head->dev = pseudo_dev;
			new->head->xattr = NULL;
			new->head->next = NULL;
			return new;
		}
	}

	/* if there's a root pseudo definition, skip it before walking target */
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0) {
		pseudo->head->pseudo = add_pseudo(pseudo->head->pseudo, pseudo_dev, target, alltarget);
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
	struct pseudo_entry *ent;

	if(pseudo == NULL)
		return NULL;

	for(ent = pseudo->head; ent; ent = ent->next)
		if(strcmp(filename, ent->name) == 0)
			return ent->pseudo;

	return NULL;
}


struct pseudo_entry *pseudo_readdir(struct pseudo *pseudo)
{
	if(pseudo == NULL)
		return NULL;

	if(pseudo->current == NULL)
		pseudo->current = pseudo->head;
	else
		pseudo->current = pseudo->current->next;

	return pseudo->current;
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
	char *targname, *subpathend;
	struct pseudo_entry *ent;

	if(pseudo == NULL)
		return NULL;

	target = get_element(target, &targname, &subpathend);

	for(ent = pseudo->head; ent; ent = ent->next)
		if(strcmp(ent->name, targname) == 0)
			break;

	free(targname);

	if(ent == NULL)
		return NULL;

	if(target[0] == '\0')
		return ent;

	if(ent->pseudo == NULL)
		return NULL;

	return pseudo_lookup(ent->pseudo, target);
}


static void print_definitions()
{
	int i;

	ERROR("Pseudo definitions should be of the format\n");

	for(i = 0; pseudo_definitions[i] != NULL; i++)
		ERROR("\tfilename %s\n", pseudo_definitions[i]);
}


static void print_definition(char type)
{
	int i;

	ERROR("Pseudo definition should be of the format\n");

	for(i = 0; pseudo_definitions[i] != NULL; i++)
		if(pseudo_definitions[i][0] == type)
			ERROR("\tfilename %s\n", pseudo_definitions[i]);
}


static struct pseudo_dev *read_pseudo_def_pseudo_link(char *orig_def, char *def)
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
	linkname = MALLOC(strlen(def) + 1);

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
	if(pseudo && pseudo->names == 1 && strcmp(pseudo->head->name, "/") == 0)
		pseudo_ent = pseudo_lookup(pseudo->head->pseudo, link);
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

	free(linkname);
	return pseudo_ent->dev;

error:
	free(linkname);
	return NULL;
}


static struct pseudo_dev *read_pseudo_def_link(char *orig_def, char *def, char *destination, int follow)
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
		dest_buf = MALLOC(sizeof(struct stat));
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
	linkname = MALLOC(strlen(def) + 1);

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

	if(follow) {
		char *resolved_linkname = realpath(linkname, NULL);

		if (resolved_linkname == NULL) {
			ERROR("Cannot resolve pseudo link file %s because %s\n", linkname, strerror(errno));
			goto error;
		}

		free(linkname);
		linkname = resolved_linkname;
	}

	dev = MALLOC(sizeof(struct pseudo_dev));
	memset(dev, 0, sizeof(struct pseudo_dev));
	dev->linkbuf = MALLOC(sizeof(struct stat));

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
	dev->linkname = STRDUP(linkname);

	free(linkname);
	return dev;

error:
	if(dev)
		free(dev->linkbuf);
	free(dev);
	free(linkname);
	return NULL;
}


static struct pseudo_dev *read_pseudo_def_extended(char type, char *orig_def,
	char *def, char *pseudo_file, struct pseudo_file **file)
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
		string = MALLOC(strlen(def) + 1);

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
			return NULL;
		}

		n = exec_date(string, &mtime);
		if(n == FALSE) {
				ERROR("Couldn't parse time, date string or "
					"unsigned decimal integer "
					"expected\n");
			free(string);
			return NULL;
		}

		free(string);

		n = sscanf(def, "%o %99s %99s %n", &mode, suid, sgid, &bytes);
		def += bytes;
		if(n < 3) {
			switch(n) {
			case -1:
				/* FALLTHROUGH */
			case 0:
				ERROR("Failed to read octal mode in pseudo file definition \"%s\"\n",
					orig_def);
				break;
			case 1:
				ERROR("Failed to read uid or user name in pseudo file definition \"%s\"\n",
					orig_def);
				break;
			default:
				ERROR("Failed to read gid or group name in pseudo file definition \"%s\"\n",
					orig_def);
				break;
			}
			return NULL;
		}
	} else {
		def += bytes;
		n = sscanf(def, "%99s %99s %n", suid, sgid, &bytes);
		def += bytes;

		if(n < 2) {
			switch(n) {
			case -1:
				/* FALLTHROUGH */
			case 0:
				ERROR("Failed to read uid or user name in pseudo file definition \"%s\"\n",
					orig_def);
				break;
			default:
				ERROR("Failed to read gid or group name in pseudo file definition \"%s\"\n",
					orig_def);
				break;
			}
			return NULL;
		}
	}

	switch(type) {
	case 'B':
		/* FALLTHROUGH */
	case 'C':
		n = sscanf(def, "%u %u %n", &major, &minor, &bytes);
		def += bytes;

		if(n < 2) {
			if(n < 1)
				ERROR("Failed to read major number in pseudo file definition \"%s\"\n", orig_def);
			else
				ERROR("Failed to read minor number in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(major > 0xfff) {
			ERROR("Major %u out of range in pseudo file definition \"%s\"\n", major, orig_def);
			return NULL;
		}

		if(minor > 0xfffff) {
			ERROR("Minor %u out of range in pseudo file definition \"%s\"\n", minor, orig_def);
			return NULL;
		}
		break;
	case 'I':
		n = sscanf(def, "%c %n", &ipc_type, &bytes);
		def += bytes;

		if(n < 1) {
			ERROR("Failed to read ipc_type in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(ipc_type != 's' && ipc_type != 'f') {
			ERROR("Ipc_type should be \"s\" or \"f\" in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}
		break;
	case 'R':
		if(pseudo_file == NULL) {
			ERROR("\"R\" definition can only be used in a Pseudo file\n");
			return NULL;
		}

		n = sscanf(def, "%lld %lld %d %n", &file_length, &pseudo_offset,
						&sparse, &bytes);
		def += bytes;

		if(n < 3) {
			ERROR("Failed to read file length, offset or sparse in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
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
			return NULL;
		}
		command = def;
		def += strlen(def);
		break;
	case 'S':
		if(def[0] == '\0') {
			ERROR("Expected symlink in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(strlen(def) > 65535) {
			ERROR("Symlink pseudo definition %s is greater than 65535"
								" bytes!\n", def);
			return NULL;
		}
		symlink = def;
		def += strlen(def);
		break;
	default:
		ERROR("Unsupported type %c\n", type);
		return NULL;
	}

	/*
	 * Check for trailing junk after expected arguments
	 */
	if(def[0] != '\0') {
		ERROR("Unexpected tailing characters in pseudo file "
			"definition \"%s\"\n", orig_def);
		return NULL;
	}

	if(mode > 07777) {
		ERROR("Mode %o out of range in pseudo file definition \"%s\"\n", mode, orig_def);
		return NULL;
	}

	uid = strtoll(suid, &ptr, 10);
	if(*ptr == '\0') {
		if(uid < 0 || uid > ((1LL << 32) - 1)) {
			ERROR("Uid %s out of range in pseudo file definition \"%s\"\n", suid, orig_def);
			return NULL;
		}
	} else {
		struct passwd *pwuid = getpwnam(suid);
		if(pwuid)
			uid = pwuid->pw_uid;
		else {
			ERROR("%s is an invalid uid or unknown user in pseudo file definition \"%s\"\n", suid, orig_def);
			return NULL;
		}
	}

	gid = strtoll(sgid, &ptr, 10);
	if(*ptr == '\0') {
		if(gid < 0 || gid > ((1LL << 32) - 1)) {
			ERROR("Gid %s out of range in pseudo file definition \"%s\"\n", sgid, orig_def);
			return NULL;
		}
	} else {
		struct group *grgid = getgrnam(sgid);
		if(grgid)
			gid = grgid->gr_gid;
		else {
			ERROR("%s is an invalid gid or unknown group in pseudo file definition \"%s\"\n", sgid, orig_def);
			return NULL;
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

	dev = MALLOC(sizeof(struct pseudo_dev));
	dev->buf = MALLOC(sizeof(struct pseudo_stat));
	dev->type = type == 'M' ? 'M' : tolower(type);
	dev->buf->mode = mode;
	dev->buf->uid = uid;
	dev->buf->gid = gid;
	dev->buf->major = major;
	dev->buf->minor = minor;
	dev->buf->mtime = mtime;
	dev->buf->ino = pseudo_ino ++;

	if(type == 'R') {
		/*
		 * The file's data is in a Unsquashfs generated pseudo file,
		 * where the data for all files is in the same file.  It is
		 * better to use single readed reader in this case
		 */
		force_single_threaded = TRUE;

		if(*file == NULL) {
			*file = MALLOC(sizeof(struct pseudo_file));
			(*file)->filename = STRDUP(pseudo_file);
			(*file)->fd = -1;
		}

		dev->data = MALLOC(sizeof(struct pseudo_data));
		dev->pseudo_type = PSEUDO_FILE_DATA;
		dev->data->file = *file;
		dev->data->length = file_length;
		dev->data->offset = pseudo_offset;
		dev->data->sparse = sparse;
	} else if(type == 'F') {
		dev->pseudo_type = PSEUDO_FILE_PROCESS;
		dev->command = STRDUP(command);
	} else
		dev->pseudo_type = PSEUDO_FILE_OTHER;

	if(type == 'S')
		dev->symlink = STRDUP(symlink);

	return dev;
}


static struct pseudo_dev *read_pseudo_def_original(char type, char *orig_def, char *def)
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
		switch(n) {
		case -1:
			/* FALLTHROUGH */
		case 0:
			ERROR("Failed to read octal mode in pseudo file definition \"%s\"\n",
				orig_def);
			break;
		case 1:
			ERROR("Failed to read uid or user name in pseudo file definition \"%s\"\n",
				orig_def);
			break;
		default:
			ERROR("Failed to read gid or group name in pseudo file definition \"%s\"\n",
				orig_def);
			break;
		}
		return NULL;
	}

	switch(type) {
	case 'b':
		/* FALLTHROUGH */
	case 'c':
		n = sscanf(def, "%u %u %n", &major, &minor, &bytes);
		def += bytes;

		if(n < 2) {
			if(n < 1)
				ERROR("Failed to read major number in pseudo file definition \"%s\"\n", orig_def);
			else
				ERROR("Failed to read minor number in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(major > 0xfff) {
			ERROR("Major %u out of range in pseudo file definition \"%s\"\n", major, orig_def);
			return NULL;
		}

		if(minor > 0xfffff) {
			ERROR("Minor %u out of range in pseudo file definition \"%s\"\n", minor, orig_def);
			return NULL;
		}
		break;
	case 'i':
		n = sscanf(def, "%c %n", &ipc_type, &bytes);
		def += bytes;

		if(n < 1) {
			ERROR("Failed to read ipc_type in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(ipc_type != 's' && ipc_type != 'f') {
			ERROR("Ipc_type should be \"s\" or \"f\" in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
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
			return NULL;
		}	
		command = def;
		def += strlen(def);
		break;
	case 's':
		if(def[0] == '\0') {
			ERROR("Expected symlink in pseudo file definition \"%s\"\n", orig_def);
			return NULL;
		}

		if(strlen(def) > 65535) {
			ERROR("Symlink pseudo definition %s is greater than 65535"
								" bytes!\n", def);
			return NULL;
		}
		symlink = def;
		def += strlen(def);
		break;
	default:
		ERROR("Unsupported type %c\n", type);
		return NULL;
	}

	/*
	 * Check for trailing junk after expected arguments
	 */
	if(def[0] != '\0') {
		ERROR("Unexpected tailing characters in pseudo file "
			"definition \"%s\"\n", orig_def);
		return NULL;
	}

	if(mode > 07777) {
		ERROR("Mode %o out of range in pseudo file definition \"%s\"\n", mode, orig_def);
		return NULL;
	}

	uid = strtoll(suid, &ptr, 10);
	if(*ptr == '\0') {
		if(uid < 0 || uid > ((1LL << 32) - 1)) {
			ERROR("Uid %s out of range in pseudo file definition \"%s\"\n", suid, orig_def);
			return NULL;
		}
	} else {
		struct passwd *pwuid = getpwnam(suid);
		if(pwuid)
			uid = pwuid->pw_uid;
		else {
			ERROR("%s is an invalid uid or unknown user in pseudo file definition \"%s\"\n", suid, orig_def);
			return NULL;
		}
	}
		
	gid = strtoll(sgid, &ptr, 10);
	if(*ptr == '\0') {
		if(gid < 0 || gid > ((1LL << 32) - 1)) {
			ERROR("Gid %s out of range in pseudo file definition \"%s\"\n", sgid, orig_def);
			return NULL;
		}
	} else {
		struct group *grgid = getgrnam(sgid);
		if(grgid)
			gid = grgid->gr_gid;
		else {
			ERROR("%s is an invalid gid or unknown group in pseudo file definition \"%s\"\n", sgid, orig_def);
			return NULL;
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

	dev = MALLOC(sizeof(struct pseudo_dev));
	dev->buf = MALLOC(sizeof(struct pseudo_stat));
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
		dev->command = STRDUP(command);
	} else
		dev->pseudo_type = PSEUDO_FILE_OTHER;

	if(type == 's')
		dev->symlink = STRDUP(symlink);

	return dev;
}


static int is_original_def(char type)
{
	int i;
	char valid_type[] = "bcdfims";

	for(i = 0; i < sizeof(valid_type); i++)
		if(type == valid_type[i])
			return TRUE;

	return FALSE;
}


static int is_extended_def(char type)
{
	int i;
	char valid_type[] = "BCDFIMRS";

	for(i = 0; i < sizeof(valid_type); i++)
		if(type == valid_type[i])
			return TRUE;

	return FALSE;
}


static int read_pseudo_def(char *def, char *destination, char *pseudo_file, struct pseudo_file **file)
{
	int n, bytes;
	int quoted = 0;
	char type;
	char *filename, *name;
	char *orig_def = def;
	struct pseudo_dev *dev = NULL;
	struct xattr_add *xattr = NULL;

	/*
	 * Scan for filename, don't use sscanf() and "%s" because
	 * that can't handle filenames with spaces.
	 *
	 * Filenames with spaces should either escape (backslash) the
	 * space or use double quotes.
	 */
	filename = MALLOC(strlen(def) + 1);

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
		xattr = read_pseudo_xattr(def);
	else if(type == 'l')
		dev = read_pseudo_def_link(orig_def, def, destination, 0);
	else if(type == 'h')
		dev = read_pseudo_def_link(orig_def, def, destination, 1);
	else if(type == 'L')
		dev = read_pseudo_def_pseudo_link(orig_def, def);
	else if(is_original_def(type))
		dev = read_pseudo_def_original(type, orig_def, def);
	else if(is_extended_def(type))
		dev = read_pseudo_def_extended(type, orig_def, def, pseudo_file, file);
	else {
		ERROR("Pseudo definition type \"%c\" is invalid in pseudo file definition \"%s\"\n",
			 type, orig_def);
		ERROR("If the filename has spaces, either quote it, or backslash the spaces\n");
		goto error;
	}

	if(dev)
		pseudo = add_pseudo_definition(pseudo, dev, name, name);
	else if(xattr)
		pseudo = add_pseudo_xattr_definition(pseudo, xattr, name, name);
	else
		print_definition(type);

	free(filename);
	return dev != NULL || xattr != NULL;

error:
	print_definitions();
	free(filename);
	return FALSE;
}


struct pseudo_dev *read_pseudo_dir(char *def)
{
	int n, bytes;
	char type;

	n = sscanf(def, " %c %n", &type, &bytes);

	if(n < 1) {
		ERROR("Not enough arguments in pseudo file definition \"%s\"\n", def);
		goto error;
	}

	if(type == 'd')
		return read_pseudo_def_original(type, def, def + bytes);
	else if(type == 'D')
		return read_pseudo_def_extended(type, def, def + bytes, NULL, NULL);

	ERROR("Invalid type %c in pseudo file definition \"%s\"\n", type, def);

error:
	ERROR("Pseudo file definition should be of the form:\n");
	ERROR("\td mode uid gid\n");
	ERROR("\tD time mode uid gid\n");
	return NULL;
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

			if(total + (MAX_LINE + 1) > size)
				line = REALLOC(line, size += (MAX_LINE + 1));

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
	char *path;
	struct pseudo_entry *entry;

	for(entry = pseudo->head; entry; entry = entry->next) {
		if(string)
			ASPRINTF(&path, "%s/%s", string, entry->name);
		else
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
