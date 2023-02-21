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
 * date.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>

#include "date.h"
#include "error.h"

int exec_date(char *string, unsigned int *mtime)
{
	int res, pipefd[2], child, status;
	int bytes = 0;
	long long time;
	char buffer[11];

	res = pipe(pipefd);
	if(res == -1) {
		ERROR("Error executing date, pipe failed\n");
		return FALSE;
	}

	child = fork();
	if(child == -1) {
		ERROR("Error executing date, fork failed\n");
		goto failed;
	}

	if(child == 0) {
		close(pipefd[0]);
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if(res == -1)
			exit(EXIT_FAILURE);

		execl("/usr/bin/date", "date", "-d", string, "+%s", (char *) NULL);
		exit(EXIT_FAILURE);
	}

	close(pipefd[1]);

	while(1) {
		res = read_bytes(pipefd[0], buffer, 11);
		if(res == -1) {
			ERROR("Error executing date\n");
			goto failed2;
		} else if(res == 0)
			break;

		bytes += res;
	}

	while(1) {
		res = waitpid(child, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR) {
			ERROR("Error executing data, waitpid failed\n");
			goto failed2;
		}
	}

	close(pipefd[0]);

	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		ERROR("Error executing date, failed to parse date string\n");
		return FALSE;
	}

	if(bytes == 0 || bytes > 11) {
		ERROR("Error executing date, unexpected result\n");
		return FALSE;
	}

	/* replace trailing newline with string terminator */
	buffer[bytes - 1] = '\0';

	res = sscanf(buffer, "%lld", &time);

	if(res < 1) {
		ERROR("Error, unexpected result from date\n");
		return FALSE;
	}

	if(time < 0) {
		ERROR("Error, negative number returned from date, dates should be on or after the epoch of 1970-01-01 00:00 UTC\n");
		return FALSE;
	}

	if(time > UINT_MAX) {
		ERROR("Error, number returned from date >= 2^32, dates should be before 2106-02-07 06:28:16 UTC\n");
		return FALSE;
	}

	*mtime = (unsigned int) time;

	return TRUE;

failed:
	close(pipefd[1]);
failed2:
	close(pipefd[0]);
	return FALSE;
}
