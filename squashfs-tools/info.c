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
#include <string.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "error.h"
#include "progressbar.h"
#include "caches-queues-lists.h"

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

	if(res < 0) {
		ERROR("asprintf failed in info_thrd\n");
		return;
	}

	INFO("%s\n", subpath);

	free(subpath);
}


void dump_state()
{
	disable_progress_bar();

	printf("Queue and Cache status dump\n");
	printf("===========================\n");

	printf("from_reader queue (reader thread -> deflate thread(s))\n");
	dump_queue(from_reader);

	//printf("\nfrom_deflate queue (deflate thread(s) -> main thread)\n");
	//dump_queue(from_deflate);

	printf("\nto_frag queue (main thread -> fragment deflate thread(s))\n");
	dump_queue(to_frag);

	printf("\nto_writer queue (main thread & fragment deflate threads(s)"
		" -> writer thread)\n");
	dump_queue(to_writer);

	printf("\nread cache (uncompressed blocks read by reader thread)\n");
	dump_cache(reader_buffer);

	printf("\nwrite cache (compressed blocks waiting to be written by the"
		" writer thread)\n");
	dump_cache(writer_buffer);

	printf("\nfragment cache (frags waiting to be compressed by fragment"
		" deflate thread(s))\n");
	dump_cache(fragment_buffer);

	enable_progress_bar();
}


void *info_thrd(void *arg)
{
	sigset_t sigmask;
	struct timespec timespec = { .tv_sec = 1, .tv_nsec = 0 };
	int sig, waiting = 0;

	sigemptyset(&sigmask);
	sigaddset(&sigmask, SIGQUIT);
	sigaddset(&sigmask, SIGHUP);

	while(1) {
		if(waiting)
			sig = sigtimedwait(&sigmask, NULL, &timespec);
		else
			sig = sigwaitinfo(&sigmask, NULL);

		if(sig == -1) {
			switch(errno) {
			case EAGAIN:
				/* interval timed out */
				waiting = 0;
				/* FALLTHROUGH */
			case EINTR:
				/* if waiting, the wait will be longer, but
				   that's OK */
				continue;
			default:
				BAD_ERROR("sigtimedwait/sigwaitinfo failed "
					"because %s\n", strerror(errno));
			}
		}

		if(sig == SIGQUIT && !waiting) {
			print_filename();

			/* set one second interval period, if ^\ received
			   within then, dump queue and cache status */
			waiting = 1;
		} else
			dump_state();
	}
}


void init_info()
{
	pthread_create(&info_thread, NULL, info_thrd, NULL);
}
