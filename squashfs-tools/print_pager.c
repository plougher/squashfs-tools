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
 * print_pager.c
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include "error.h"
#include "print_pager.h"
#include "alloc.h"

extern long long read_bytes(int, void *, long long);

static char **pager_argv = NULL;
static char *pager_command = NULL;
static int pager_from_env_var = FALSE;
int no_pager = FALSE;
int user_cols = -1;

static char *get_base(char *pathname)
{
	char *cur = pathname, *sow = NULL, *eow = NULL;

	while(*cur != '\0') {
		if(*cur == '/')
			cur ++;
		else if(strcmp(cur, ".") == 0)
			cur ++;
		else if(strcmp(cur, "..") == 0)
			cur += 2;
		else if(strncmp(cur, "./", 2) == 0)
			cur +=2;
		else if(strncmp(cur, "../", 3) == 0)
			cur += 3;
		else {
			sow = cur;

			do {
				cur ++;
			} while(*cur != '/' && *cur != '\0');

			eow = cur;
		}
	}

	if(sow == NULL || eow != cur)
		return NULL;
	else
		return sow;
}


static inline int quoted_bs_char(char cur)
{
	/*
	 * Within double quoted strings Bash allows the characters $, `, ",\ and
	 * newline to be backslashed.  Backslashes that are followed by one of
	 * those characters are removed.  Backslashes preceeding other
	 * characters are left unmodified.
	 *
	 * Following the principle of least surprise copy this behaviour.
	 */
	return cur == '$' || cur == '`' || cur == '"' || cur == '\\' || cur == '\n';
}


int next_arg_count(char *cur)
{
	int count = 0;
	char sq = FALSE, dq = FALSE;

	/* skip whitespace */
	while(*cur == '\t' || *cur == ' ')
		cur ++;

	if(*cur == '\0')
		return -1;

	for(; *cur != '\0'; cur ++) {
		if(!sq && !dq) {
			/* Check string doesn't contain pipes, command separators or file
			 * redirects.
			 *
			 * Note: this isn't an exhaustive check of what can't be in the
			 *	 pager name, as the execlp() will do this.  It is more
			 *	 intended to check for common shell metacharacters and
			 *	 warn users this isn't supported in a friendlier way.
			 */
			if(*cur == '|' || *cur == ';')
				return -2;
			else if(*cur == '<' || *cur == '>' || *cur == '&')
				return -3;
			else if(*cur == '\'')
				sq = TRUE;
			else if(*cur == '"')
				dq = TRUE;
			else if(*cur == '\t' || *cur == ' ')
			       break;
			else if(*cur == '\\' && *(cur + 1) != '\0') {
				count ++;
				cur ++;
			} else
				count ++;
		} else if(dq) {
			if(*cur == '"')
				dq = FALSE;
			else if(*cur == '\\' && quoted_bs_char(*(cur + 1))) {
				count ++;
				cur ++;
			} else
				count ++;
		} else if(sq) {
			if(*cur == '\'')
				sq = FALSE;
			else
				count ++;
		}
	}

	return (sq || dq) ? -4 : count;
}


char *next_arg_copy(char **pos, int count)
{
	char sq = FALSE, dq = FALSE;
	char *arg = MALLOC(count + 1), *copy = arg;
	char *cur = *pos;

	/* skip whitespace */
	while(*cur == '\t' || *cur == ' ')
		cur ++;

	for(; *cur != '\0'; cur ++) {
		if(!sq && !dq) {
			if(*cur == '\'')
				sq = TRUE;
			else if(*cur == '"')
				dq = TRUE;
			else if(*cur == '\t' || *cur == ' ')
			       break;
			else if(*cur == '\\' && *(cur + 1) != '\0')
				*copy ++ = *++ cur;
			else
				*copy ++ = *cur;
		} else if(dq) {
			if(*cur == '"')
				dq = FALSE;
			else if(*cur == '\\' && quoted_bs_char(*(cur + 1)))
				*copy ++ = *++ cur;
			else
				*copy ++ = *cur;
		} else if(sq) {
			if(*cur == '\'')
				sq = FALSE;
			else
				*copy ++ = *cur;
		}
	}

	*copy = '\0';
	*pos = cur;
	return arg;
}


char *next_arg(char **pos, int *result)
{
	*result = next_arg_count(*pos);

	return (*result < 0) ? NULL : next_arg_copy(pos, *result);
}


int check_and_set_pager(char *pager)
{
	int args = 0, result;
	char *base, *cur = pager;

	 /* split PAGER into arguments */
	while(*cur != '\0') {
		char *arg = next_arg(&cur, &result);

		if(result == -1)
			break;
		else if(result == -2) {
			ERROR("PAGER cannot have shell special characters '|' or ';'!  Quote or backslash them to pass to pager command\n");
			goto failed;
		} else if(result == -3) {
			ERROR("PAGER cannot have shell special characters '<', '>' or '&'!  Quote or backslash them to pass to pager command\n");
			goto failed;
		} else if(result == -4) {
			ERROR("PAGER has unterminated single or double quoted string\n");
			goto failed;
		} else {
			pager_argv = REALLOC(pager_argv, (args + 2) * sizeof(char *));
			pager_argv[args++] = arg;
		}
	}

	if(args == 0) {
		no_pager = TRUE;
		return TRUE;
	}

	base = get_base(pager_argv[0]);
	if(base == NULL) {
		ERROR("PAGER doesn't have a command name in it or it has trailing '/', '.' or '..' characters!\n");
		goto failed;
	}

	pager_command = pager_argv[0];
	pager_argv[0] = base;
	pager_from_env_var = TRUE;
	return TRUE;

failed:
	for(int i = 0; i < args; i++)
		free(pager_argv[i]);
	free(pager_argv);
	return FALSE;
}


static int determine_pager(char *name, char *path1, char *path2)
{
	int bytes, status, res, pipefd[2];
	pid_t child;
	char buffer[1024];

	res = pipe(pipefd);
	if(res == -1)
		BAD_ERROR("Error determining pager, pipe failed\n");

	child = fork();
	if(child == -1)
		BAD_ERROR("Error determining pager, fork failed\n");

	if(child == 0) { /* child */
		close(pipefd[0]);
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if(res == -1)
			exit(EXIT_FAILURE);

		execlp(path1, name, "--version", (char *) NULL);
		if(path2)
			execl(path2, name, "--version", (char *) NULL);
		close(pipefd[1]);
		exit(EXIT_FAILURE);
	}

	/* parent */
	close(pipefd[1]);

	bytes = read_bytes(pipefd[0], buffer, 1024);

	if(bytes == -1)
		BAD_ERROR("Error determining pager, read failed\n");

	if(res == 1024)
		BAD_ERROR("Pager (%s) returned unexpectedly large amount of data for --version\n", pager_command);

	while(1) {
		res = waitpid(child, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR)
			BAD_ERROR("Error determining pager, waitpid failed\n");
	}

	close(pipefd[0]);

	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		/* Pager didn't understand --version?  Return unknown pager */
		return UNKNOWN_PAGER;
	}

	if(strncmp(buffer, "less", strlen("less")) == 0)
		return LESS_PAGER;
	else if(strncmp(buffer, "more", strlen("more")) == 0 ||
				strncmp(buffer, "pager", strlen("pager")) == 0)
		return MORE_PAGER;
	else
		return UNKNOWN_PAGER;
}


static void wait_to_die(pid_t process)
{
	int res, status;

	while(1) {
		res = waitpid(process, &status, 0);
		if(res != -1)
			break;
		else if(errno != EINTR) {
			ERROR("Error executing pager, waitpid failed\n");
			return;
		}
	}

	if(!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		ERROR("Pager failed to run or failed with an error status\n");
		ERROR("Set PAGER to empty or use -no-pager to not use a pager\n");
	}
}


static void run_cmd(char *name, char *path1, char*path2, int no_arg)
{
	int pager = determine_pager(name, path1, path2);

	if(pager == LESS_PAGER) {
		execlp(path1, name, "--quit-if-one-screen", (char *) NULL);
		if(path2)
			execl(path2, name, "--quit-if-one-screen", (char *) NULL);
	} else if(pager == MORE_PAGER) {
		execlp(path1, name, "--exit-on-eof", (char *) NULL);
		if(path2)
			execl(path2, name, "--exit-on-eof", (char *) NULL);
	} else if(no_arg) {
		execlp(path1, name, (char *) NULL);
		if(path2)
			execl(path2, name, (char *) NULL);
	}
}


void simple_cat()
{
	int c;

	while((c = getchar()) != EOF)
		putchar(c);
}


static FILE *exec_pager(pid_t *process)
{
	FILE *file;
	int res, pipefd[2];
	pid_t child;

	res = pipe(pipefd);
	if(res == -1)
		BAD_ERROR("Error executing pager, pipe failed\n");

	child = fork();
	if(child == -1)
		BAD_ERROR("Error executing pager, fork failed\n");

	if(child == 0) { /* child */
		close(pipefd[1]);
		close(STDIN_FILENO);
		res = dup(pipefd[0]);
		if(res == -1)
			exit(EXIT_FAILURE);

		if(pager_from_env_var) {
			if(pager_argv[1] == NULL)
				run_cmd(pager_argv[0], pager_command, NULL, TRUE);
			else {
				execvp(pager_command, pager_argv);
				execv(pager_command, pager_argv);
			}
		} else
			run_cmd("pager", "pager", "/usr/bin/pager", TRUE);

		run_cmd("less", "less", "/usr/bin/less", FALSE);
		run_cmd("more", "more", "/usr/bin/more", FALSE);
		execlp("less", "less",  (char *) NULL);
		execl("/usr/bin/less", "less", (char *) NULL);
		execlp("more", "more",  (char *) NULL);
		execl("/usr/bin/more", "more", (char *) NULL);
		execlp("cat", "cat", (char *) NULL);
		execl("/usr/bin/cat", "cat", (char *) NULL);
		simple_cat();

		close(pipefd[0]);
		exit(0);
	}

	/* parent */
	close(pipefd[0]);

	file = fdopen(pipefd[1], "w");
	if(file == NULL)
		BAD_ERROR("Error executing pager, fdopen failed\n");

	*process = child;
	return file;
}


FILE *launch_pager(pid_t *process, int *cols)
{
	if(no_pager) {
		*cols = get_column_width();
		*process = 0;
		return stdout;
	} else if(isatty(STDOUT_FILENO)) {
		*cols = get_column_width();
		return exec_pager(process);
	} else {
		*cols = user_cols != -1 ? user_cols : 80;
		*process = 0;
		return stdout;
	}
}


void delete_pager(FILE *pager, pid_t process)
{
	if(pager != stdout) {
		fclose(pager);
		wait_to_die(process);
	}
}


int get_column_width()
{
	struct winsize winsize;

	if(user_cols != -1)
		return user_cols;
	else if(ioctl(1, TIOCGWINSZ, &winsize) == -1) {
		if(isatty(STDOUT_FILENO))
			ERROR("TIOCGWINSZ ioctl failed, defaulting to 80 "
				"columns\n");
		return 80;
	} else
		return winsize.ws_col;
}


void autowrap_print(FILE *stream, char *text, int maxl)
{
	char *cur = text;
	int tab_out = 0, length;

	while(*cur != '\0') {
		char *sol = cur, *lw = NULL, *eow = NULL;
		int wrapped = FALSE;

		for(length = 0; length < tab_out; length += 8)
			fputc('\t', stream);

		while((!maxl || length <= maxl) && *cur != '\n' && *cur != '\0') {
			if(*cur == '\t')
				tab_out = length = (length + 8) & ~7;
			else
				length ++;

			if(*cur == '\t' || *cur == ' ')
				eow = lw;
			else
				lw = cur;

			if(!maxl || length <= maxl)
				cur ++;
		}

		if(*cur == '\n')
			cur ++;
		else if(*cur != '\0') {
			if(eow)
				cur = eow + 1;
			else if(cur - sol == 0)
				cur ++;

			if(maxl && tab_out >= maxl)
				tab_out = 0;

			wrapped = TRUE;
		}

		while(sol < cur)
			fputc(*sol ++, stream);

		if(wrapped) {
			fputc('\n', stream);

			while(*cur == ' ')
				cur ++;
		}
	}
}


void autowrap_printf(FILE *stream, int maxl, char *fmt, ...)
{
	va_list ap;
	char *text;

	va_start(ap, fmt);
	VASPRINTF(&text, fmt, ap);
	va_end(ap);

	autowrap_print(stream, text, maxl);
	free(text);
}
