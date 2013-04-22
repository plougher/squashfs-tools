/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2013
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
 * info.c
 */

#include <pthread.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <stdio.h>
#include <math.h>
#include <stdarg.h>
#include <errno.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "error.h"

static int silent = 0;
static struct dir_ent *dir_ent = NULL;

pthread_t info_thread;


void disable_info()
{
	dir_ent = NULL;
}


void update_info(struct dir_ent *ent)
{
	dir_ent = ent;
}


void print_filename()
{
	int res;
	char *subpath;

	if(dir_ent == NULL)
		return;

	if(dir_ent->our_dir->subpath[0] != '\0')
		res = asprintf(&subpath, "%s/%s",
			dir_ent->our_dir->subpath, dir_ent->name);
	else
		res = asprintf(&subpath, "/%s", dir_ent->name);

	if(res < 0)
		printf("asprintf failed in info_thrd\n");

	INFO("%s\n", subpath);

	free(subpath);
}


void *info_thrd(void *arg)
{
	sigset_t sigmask;
	int sig;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGQUIT);

	while(1) {
		sigwait(&sigmask, &sig);

		print_filename();
	}
}


void init_info()
{
	pthread_create(&info_thread, NULL, info_thrd, NULL);
}
