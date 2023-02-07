#ifndef SIGNALS_H
#define SIGNALS_H
/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2023
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
 * signals.h
 */

static inline int wait_for_signal(sigset_t *sigmask, int *waiting)
{
	int sig;

#if defined(__APPLE__) && defined(__MACH__)
	sigwait(sigmask, &sig);
	*waiting = 0;
#else
	struct timespec timespec = { .tv_sec = 1, .tv_nsec = 0 };

	while(1) {
		if(*waiting)
			sig = sigtimedwait(sigmask, NULL, &timespec);
		else
			sig = sigwaitinfo(sigmask, NULL);

		if(sig != -1)
			break;

		if(errno == EAGAIN)
			*waiting = 0;
		else if(errno != EINTR)
			BAD_ERROR("sigtimedwait/sigwaitinfo failed because %s\n", strerror(errno));
	}
#endif
	return sig;
}
#endif
