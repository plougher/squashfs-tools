/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2012, 2013, 2014, 2021, 2022
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
 * progressbar.c
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

#include "mksquashfs_error.h"

#define FALSE 0
#define TRUE 1

/* flag whether progressbar display is enabled or not */
static int display_progress_bar = FALSE;

/* flag whether the progress bar is temporarily disbled */
static int temp_disabled = FALSE;

/* flag whether to display full progress bar or just a percentage */
static int percent = FALSE;

/* flag whether we need to output a newline before printing
 * a line - this is because progressbar printing does *not*
 * output a newline */
static int need_nl = FALSE;

static int rotate = 0;
static long long cur_uncompressed = 0, estimated_uncompressed = 0;
static int columns;

static pthread_t progress_thread;
static pthread_mutex_t progress_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t size_mutex = PTHREAD_MUTEX_INITIALIZER;


static void sigwinch_handler(int arg)
{
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
}


void progressbar_percentage()
{
	percent = TRUE;
}


void inc_progress_bar()
{
	cur_uncompressed ++;
}


void dec_progress_bar(int count)
{
	cur_uncompressed -= count;
}


void progress_bar_size(int count)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &size_mutex);
	pthread_mutex_lock(&size_mutex);
	estimated_uncompressed += count;
	pthread_cleanup_pop(1);
}


static void progressbar(long long current, long long max, int columns)
{
	char rotate_list[] = { '|', '/', '-', '\\' };
	int max_digits, used, hashes, spaces, percentage;
	static int tty = -1;

	if(max == 0) {
		max_digits = 1;
		used = 13;
		hashes = 0;
		spaces = columns - 13;
		percentage = 100;
	} else {
		max_digits = floor(log10(max)) + 1;
		used = max_digits * 2 + 11;
		hashes = (current * (columns - used)) / max;
		spaces = columns - used - hashes;
		percentage = current * 100 / max;
	}

	if((current > max) || (columns - used < 0))
		return;

	if(tty == -1)
		tty = isatty(STDOUT_FILENO);
	if(!tty) {
		static long long previous = -1;

		/* Updating much more frequently than this results in huge
		 * log files. */
		if((current % 100) != 0 && current != max)
			return;
		/* Don't update just to rotate the spinner. */
		if(current == previous)
			return;
		previous = current;
	}

	printf("\r[");

	while (hashes --)
		putchar('=');

	putchar(rotate_list[rotate]);

	while(spaces --)
		putchar(' ');

	printf("] %*lld/%*lld", max_digits, current, max_digits, max);
	printf(" %3d%%", percentage);
	fflush(stdout);
}


static void display_percentage(long long current, long long max)
{
	int percentage = max == 0 ? 100 : current * 100 / max;
	static int previous = -1;

	if(percentage != previous) {
		printf("%d\n", percentage);
		fflush(stdout);
		previous = percentage;
	}
}


static void progress_bar(long long current, long long max, int columns)
{
	if(percent)
		display_percentage(current, max);
	else
		progressbar(current, max, columns);
}


void enable_progress_bar()
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &progress_mutex);
	pthread_mutex_lock(&progress_mutex);
	if(display_progress_bar)
		progress_bar(cur_uncompressed, estimated_uncompressed, columns);
	temp_disabled = FALSE;
	pthread_cleanup_pop(1);
}


void disable_progress_bar()
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &progress_mutex);
	pthread_mutex_lock(&progress_mutex);
	if(need_nl) {
		printf("\n");
		need_nl = FALSE;
	}
	temp_disabled = TRUE;
	pthread_cleanup_pop(1);
}


void set_progressbar_state(int state)
{
	pthread_cleanup_push((void *) pthread_mutex_unlock, &progress_mutex);
	pthread_mutex_lock(&progress_mutex);
	if(display_progress_bar != state) {
		if(display_progress_bar && !temp_disabled) {
			progress_bar(cur_uncompressed, estimated_uncompressed,
				columns);
			printf("\n");
			need_nl = FALSE;
		}
		display_progress_bar = state;
	}
	pthread_cleanup_pop(1);
}


static void *progress_thrd(void *arg)
{
	struct timespec requested_time, remaining;
	struct winsize winsize;

	if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		columns = 80;
	} else
		columns = winsize.ws_col;
	signal(SIGWINCH, sigwinch_handler);

	requested_time.tv_sec = 0;
	requested_time.tv_nsec = 250000000;

	while(1) {
		int res = nanosleep(&requested_time, &remaining);

		if(res == -1 && errno != EINTR)
			BAD_ERROR("nanosleep failed in progress thread\n");

		pthread_mutex_lock(&progress_mutex);
		rotate = (rotate + 1) % 4;
		if(display_progress_bar && !temp_disabled) {
			progress_bar(cur_uncompressed, estimated_uncompressed, columns);
			need_nl = TRUE;
		}
		pthread_mutex_unlock(&progress_mutex);
	}
}


void init_progress_bar()
{
	pthread_create(&progress_thread, NULL, progress_thrd, NULL);
}


void progressbar_error(char *fmt, ...)
{
	va_list ap;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &progress_mutex);
	pthread_mutex_lock(&progress_mutex);

	if(need_nl) {
		printf("\n");
		need_nl = FALSE;
	}

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	pthread_cleanup_pop(1);
}


void progressbar_info(char *fmt, ...)
{
	va_list ap;

	pthread_cleanup_push((void *) pthread_mutex_unlock, &progress_mutex);
	pthread_mutex_lock(&progress_mutex);

	if(need_nl) {
		printf("\n");
		need_nl = FALSE;
	}

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);

	pthread_cleanup_pop(1);
}

