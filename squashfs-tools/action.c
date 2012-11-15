/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2011, 2012
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
 * action.c
 */

#include <dirent.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fnmatch.h>
#include <pwd.h>
#include <grp.h>
#include <sys/wait.h>
#include <regex.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "action.h"
#include "error.h"

/*
 * code to parse actions
 */

static char *cur_ptr, *source;
static struct action *spec_list = NULL;
static int spec_count = 0;
static int fragment_count = 0;
static int exclude_count = 0;
static int empty_count = 0;
static int move_count = 0;
static int other_count = 0;

static struct file_buffer *def_fragment = NULL;

static struct token_entry token_table[] = {
	{ " ", 	TOK_WHITE_SPACE, 1 },
	{ "(", TOK_OPEN_BRACKET, 1, },
	{ ")", TOK_CLOSE_BRACKET, 1 },
	{ "&&", TOK_AND, 2 },
	{ "||", TOK_OR, 2 },
	{ "!", TOK_NOT, 1 },
	{ ",", TOK_COMMA, 1 },
	{ "@", TOK_AT, 1},
	{ "", -1, 0 }
};


static struct test_entry test_table[];

static struct action_entry action_table[];

static struct expr *parse_expr(int subexp);

extern char *pathname(struct dir_ent *);

extern char *subpathname(struct dir_ent *);

/*
 * Lexical analyser
 */
static int get_token(char **string)
{
	int i;

	while (1) {
		if (*cur_ptr == '\0')
			return TOK_EOF;
		for (i = 0; token_table[i].token != -1; i++)
			if (strncmp(cur_ptr, token_table[i].string,
						token_table[i].size) == 0)
				break;
		if (token_table[i].token != TOK_WHITE_SPACE)
			break;
		cur_ptr ++;
	}

	if (token_table[i].token == -1) { /* string */
		char *start = cur_ptr ++;
		while (1) {
			if (*cur_ptr == '\0')
				break;
			for(i = 0; token_table[i].token != -1; i++)
				if (strncmp(cur_ptr, token_table[i].string,
						token_table[i].size) == 0)
					break;
			if (token_table[i].token != -1)
				break;
			cur_ptr ++;
		}
		
         	*string = strndup(start, cur_ptr - start);
		return TOK_STRING;
	}

	cur_ptr += token_table[i].size;
	return token_table[i].token;
}


static int peek_token(char **string)
{
	char *saved = cur_ptr;
	int token = get_token(string);

	cur_ptr = saved;

	return token;
}


/*
 * Expression parser
 */
static struct expr *create_expr(struct expr *lhs, int op, struct expr *rhs)
{
	struct expr *expr;

	if (rhs == NULL)
		return NULL;

	expr = malloc(sizeof(*expr));
	if (expr == NULL)
		BAD_ERROR("Out of memory in create_expr\n");

	expr->type = OP_TYPE;
	expr->expr_op.lhs = lhs;
	expr->expr_op.rhs = rhs;
	expr->expr_op.op = op;

	return expr;
}


static struct expr *create_unary_op(struct expr *lhs, int op)
{
	struct expr *expr;

	if (lhs == NULL)
		return NULL;

	expr = malloc(sizeof(*expr));
	if (expr == NULL)
		BAD_ERROR("Out of memory in create_unary_op\n");

	expr->type = UNARY_TYPE;
	expr->unary_op.expr = lhs;
	expr->unary_op.op = op;

	return expr;
}


static struct expr *parse_test(char *name)
{
	char *string;
	int token;
	int i;
	struct test_entry *test;
	struct expr *expr;

	for (i = 0; test_table[i].args != -1; i++)
		if (strcmp(name, test_table[i].name) == 0)
			break;

	if (test_table[i].args == -1) {
		SYNTAX_ERROR("Non-existent test \"%s\"\n", name);
		return NULL;
	}

	test = &test_table[i];

	expr = malloc(sizeof(*expr));
	if (expr == NULL)
		BAD_ERROR("Out of memory in parse_test\n");

	expr->type = ATOM_TYPE;

	expr->atom.argv = malloc(test->args * sizeof(char *));
	if (expr->atom.argv == NULL)
		BAD_ERROR("Out of memory in parse_test\n");

	expr->atom.test = test;
	expr->atom.data = NULL;

	/*
	 * If the test has no arguments, allow it to be typed
	 *  without brackets
	 */
	if (test->args == 0) {
		token = peek_token(&string);

		if (token != TOK_OPEN_BRACKET)
			goto skip_args;
	}

	token = get_token(&string);

	if (token != TOK_OPEN_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \"(\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

	for (i = 0; i < test->args; i++) {
		token = get_token(&string);

		if (token != TOK_STRING) {
			SYNTAX_ERROR("Unexpected token \"%s\", expected "
				"argument\n", TOK_TO_STR(token, string));
			goto failed;
		}

		expr->atom.argv[i] = string;

		if (i + 1 < test->args) {
			token = get_token(&string);

			if (token != TOK_COMMA) {
				SYNTAX_ERROR("Unexpected token \"%s\", "
					"expected \",\"\n",
					TOK_TO_STR(token, string));
			goto failed;
			}
		}
	}

	if (test->parse_args) {
		int res = test->parse_args(test, &expr->atom);

		if (res == 0)		
			goto failed;
	}

	token = get_token(&string);

	if (token != TOK_CLOSE_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \")\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

skip_args:
	return expr;

failed:
	free(expr->atom.argv);
	free(expr);
	return NULL;
}


static struct expr *get_atom()
{
	char *string;
	int token = get_token(&string);

	switch(token) {
	case TOK_NOT:
		return create_unary_op(get_atom(), token);
	case TOK_OPEN_BRACKET:
		return parse_expr(1);
	case TOK_STRING:
		return parse_test(string);
	default:
		SYNTAX_ERROR("Unexpected token \"%s\", expected test "
					"operation, \"!\", or \"(\"\n",
					TOK_TO_STR(token, string));
		return NULL;
	}
}


static struct expr *parse_expr(int subexp)
{
	struct expr *expr = get_atom();

	while (expr) {
		char *string;
		int op = get_token(&string);

		if (op == TOK_EOF) {
			if (subexp) {
				SYNTAX_ERROR("Expected \"&&\", \"||\" or "
						"\")\", got EOF\n");
				return NULL;
			}
			break;
		}

		if (op == TOK_CLOSE_BRACKET) {
			if (!subexp) {
				SYNTAX_ERROR("Unexpected \")\", expected "
						"\"&&\", \"!!\" or EOF\n");
				return NULL;
			}
			break;
		}
		
		if (op != TOK_AND && op != TOK_OR) {
			SYNTAX_ERROR("Unexpected token \"(%s\"), expected "
				"\"&&\" or \"||\"\n", TOK_TO_STR(op, string));
			return NULL;
		}

		expr = create_expr(expr, op, get_atom());
	}

	return expr;
}


/*
 * Action parser
 */
int parse_action(char *s)
{
	char *string, **argv = NULL;
	int i, token, args = 0;
	struct expr *expr;
	struct action_entry *action;
	void *data = NULL;

	cur_ptr = source = s;
	token = get_token(&string);

	if (token != TOK_STRING) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected name\n",
						TOK_TO_STR(token, string));
		return 0;
	}

	for (i = 0; action_table[i].args != -1; i++)
		if (strcmp(string, action_table[i].name) == 0)
			break;

	if (action_table[i].args == -1) {
		SYNTAX_ERROR("Non-existent action \"%s\"\n", string);
		return 0;
	}

	action = &action_table[i];

	token = get_token(&string);

	if (token == TOK_AT)
		goto skip_args;

	if (token != TOK_OPEN_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \"(\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

	/*
	 * speculatively read all the arguments, and then see if the
	 * number of arguments read is the number expected, this handles
	 * actions with a variable number of arguments
	 */
	token = get_token(&string);
	if (token == TOK_CLOSE_BRACKET)
		goto skip_args;

	while (1) {
		if (token != TOK_STRING) {
			SYNTAX_ERROR("Unexpected token \"%s\", expected "
				"argument\n", TOK_TO_STR(token, string));
			goto failed;
		}

		argv = realloc(argv, (args + 1) * sizeof(char *));
		if (argv == NULL)
			BAD_ERROR("Realloc failed in parse_action\n");

		argv[args ++] = string;

		token = get_token(&string);

		if (token == TOK_CLOSE_BRACKET)
			break;

		if (token != TOK_COMMA) {
			SYNTAX_ERROR("Unexpected token \"%s\", expected "
				"\",\" or \")\"\n", TOK_TO_STR(token, string));
			goto failed;
		}
		token = get_token(&string);
	}

skip_args:
	/*
	 * expected number of arguments?
	 */
	if(action->args != -2 && args != action->args) {
		SYNTAX_ERROR("Unexpected number of arguments, expected %d, "
			"got %d\n", action->args, args);
		goto failed;
	}

	if (action->parse_args) {
		int res = action->parse_args(action, args, argv, &data);

		if (res == 0)
			goto failed;
	}

	if (token == TOK_CLOSE_BRACKET)
		token = get_token(&string);

	if (token != TOK_AT) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \"@\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}
	
	expr = parse_expr(0);

	if (expr == NULL)
		goto failed;

	spec_list = realloc(spec_list, (spec_count + 1) *
					sizeof(struct action));
	if (spec_list == NULL)
		BAD_ERROR("Out of memory in parse_action\n");

	spec_list[spec_count].type = action->type;
	spec_list[spec_count].action = action;
	spec_list[spec_count].args = args;
	spec_list[spec_count].argv = argv;
	spec_list[spec_count].expr = expr;
	spec_list[spec_count ++].data = data;

	/* increment action specific counters */
	switch(action->type) {
	case FRAGMENT_ACTION:
		fragment_count ++;
		break;
	case EXCLUDE_ACTION:
		exclude_count ++;
		break;
	case EMPTY_ACTION:
		empty_count ++;
		break;
	case MOVE_ACTION:
		move_count ++;
		break;
	default:
		other_count ++;
	}
	
	return 1;

failed:
	free(argv);
	return 0;
}


static void dump_parse_tree(struct expr *expr)
{
	if(expr->type == ATOM_TYPE) {
		int i;

		printf("%s(", expr->atom.test->name);
		for(i = 0; i < expr->atom.test->args; i++) {
			printf("%s", expr->atom.argv[i]);
			if (i + 1 < expr->atom.test->args)
				printf(",");
		}
		printf(")");
	} else if (expr->type == UNARY_TYPE) {
		printf("%s", token_table[expr->unary_op.op].string);
		dump_parse_tree(expr->unary_op.expr);
	} else {
		printf("(");
		dump_parse_tree(expr->expr_op.lhs);
		printf("%s", token_table[expr->expr_op.op].string);
		dump_parse_tree(expr->expr_op.rhs);
		printf(")");
	}
}


void dump_actions()
{
	int i;

	for (i = 0; i < spec_count; i++) {
		printf("%s", spec_list[i].action->name);
		if (spec_list[i].action->args) {
			int n;

			printf("(");
			for (n = 0; n < spec_list[i].action->args; n++) {
				printf("%s", spec_list[i].argv[n]);
				if (n + 1 < spec_list[i].action->args)
					printf(",");
			}
			printf(")");
		}
		printf("=");
		dump_parse_tree(spec_list[i].expr);
		printf("\n");
	}
}


/*
 * Evaluate expressions
 */
int eval_expr(struct expr *expr, struct action_data *action_data)
{
	int match;

	switch (expr->type) {
	case ATOM_TYPE:
		match = expr->atom.test->fn(&expr->atom, action_data);
		break;
	case UNARY_TYPE:
		match = !eval_expr(expr->unary_op.expr, action_data);
		break;
	default:
		match = eval_expr(expr->expr_op.lhs, action_data);

		if ((expr->expr_op.op == TOK_AND && match) ||
					(expr->expr_op.op == TOK_OR && !match))
			match = eval_expr(expr->expr_op.rhs, action_data);
		break;
	}

	return match;
}


/*
 * General action evaluation code
 */
int actions()
{
	return other_count;
}


void eval_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;
	int file_type = dir_ent->inode->buf.st_mode & S_IFMT;

	action_data.name = dir_ent->name;
	action_data.pathname = pathname(dir_ent);
	action_data.subpath = subpathname(dir_ent);
	action_data.buf = &dir_ent->inode->buf;
	action_data.depth = dir_ent->our_dir->depth;

	for (i = 0; i < spec_count; i++) {
		struct action *action = &spec_list[i];

		if (action->action->run_action == NULL)
			/* specialised action handler exists */
			continue;

		if ((action->action->file_types & file_type) == 0)
			/* action does not operate on this file type */
			continue;

		match = eval_expr(action->expr, &action_data);

		if (match)
			action->action->run_action(action, dir_ent);
	}
}


/*
 * Fragment specific action code
 */
void *eval_frag_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;

	action_data.name = dir_ent->name;
	action_data.pathname = pathname(dir_ent);
	action_data.subpath = subpathname(dir_ent);
	action_data.buf = &dir_ent->inode->buf;
	action_data.depth = dir_ent->our_dir->depth;

	for (i = 0; i < spec_count; i++) {
		if (spec_list[i].type != FRAGMENT_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &action_data);

		if (match)
			return &spec_list[i].data;
	}

	return &def_fragment;
}


void *get_frag_action(void *fragment)
{
	struct action *spec_list_end = &spec_list[spec_count];
	struct action *action;

	if (fragment == NULL)
		return &def_fragment;

	if (spec_count == 0)
		return NULL;

	if (fragment == &def_fragment)
		action = &spec_list[0] - 1;
	else 
		action = fragment - offsetof(struct action, data);

	do {
		if (++action == spec_list_end)
			return NULL;
	} while (action->type != FRAGMENT_ACTION);

	return &action->data;
}


/*
 * Exclude specific action code
 */
int eval_exclude_actions(char *name, char *pathname, char *subpath,
	struct stat *buf, int depth)
{
	int i, match = 0;
	struct action_data action_data;

	action_data.name = name;
	action_data.pathname = pathname;
	action_data.subpath = subpath;
	action_data.buf = buf;
	action_data.depth = depth;

	for (i = 0; i < spec_count && !match; i++) {
		if (spec_list[i].type != EXCLUDE_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &action_data);
	}

	return match;
}


/*
 * Fragment specific action code
 */
void frag_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->no_fragments = 0;
}

void no_frag_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->no_fragments = 1;
}

void always_frag_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->always_use_fragments = 1;
}

void no_always_frag_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->always_use_fragments = 0;
}


/*
 * Compression specific action code
 */
void comp_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->noD = inode->noF = 0;
}

void uncomp_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;

	inode->noD = inode->noF = 1;
}


/*
 * Uid/gid specific action code
 */
static long long parse_uid(char *arg) {
	char *b;
	long long uid = strtoll(arg, &b, 10);

	if (*b == '\0') {
		if (uid < 0 || uid >= (1LL < 32)) {
			SYNTAX_ERROR("action: uid out of range\n");
			return -1;
		}
	} else {
		struct passwd *passwd = getpwnam(arg);

		if (passwd)
			uid = passwd->pw_uid;
		else {
			SYNTAX_ERROR("action: invalid uid or unknown user\n");
			return -1;
		}
	}

	return uid;
}


static long long parse_gid(char *arg) {
	char *b;
	long long gid = strtoll(arg, &b, 10);

	if (*b == '\0') {
		if (gid < 0 || gid >= (1LL < 32)) {
			SYNTAX_ERROR("action: gid out of range\n");
			return -1;
		}
	} else {
		struct group *group = getgrnam(arg);

		if (group)
			gid = group->gr_gid;
		else {
			SYNTAX_ERROR("action: invalid gid or unknown user\n");
			return -1;
		}
	}

	return gid;
}


int parse_uid_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	long long uid;
	struct uid_info *uid_info;

	uid = parse_uid(argv[0]);
	if (uid == -1)
		return 0;

	uid_info = malloc(sizeof(struct uid_info));
	if (uid_info == NULL)
		BAD_ERROR("Out of memory in action uid\n");

	uid_info->uid = uid;
	*data = uid_info;

	return 1;
}


int parse_gid_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	long long gid;
	struct gid_info *gid_info;

	gid = parse_gid(argv[0]);
	if (gid == -1)
		return 0;

	gid_info = malloc(sizeof(struct gid_info));
	if (gid_info == NULL)
		BAD_ERROR("Out of memory in action gid\n");

	gid_info->gid = gid;
	*data = gid_info;

	return 1;
}


int parse_guid_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	long long uid, gid;
	struct guid_info *guid_info;

	uid = parse_uid(argv[0]);
	if (uid == -1)
		return 0;

	gid = parse_gid(argv[1]);
	if (gid == -1)
		return 0;

	guid_info = malloc(sizeof(struct guid_info));
	if (guid_info == NULL)
		BAD_ERROR("Out of memory in action guid\n");

	guid_info->uid = uid;
	guid_info->gid = gid;
	*data = guid_info;

	return 1;
}


void uid_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;
	struct uid_info *uid_info = action->data;

	inode->buf.st_uid = uid_info->uid;
}

void gid_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;
	struct gid_info *gid_info = action->data;

	inode->buf.st_gid = gid_info->gid;
}

void guid_action(struct action *action, struct dir_ent *dir_ent)
{
	struct inode_info *inode = dir_ent->inode;
	struct guid_info *guid_info = action->data;

	inode->buf.st_uid = guid_info->uid;
	inode->buf.st_gid = guid_info->gid;

}


/*
 * Mode specific action code
 */
int parse_octal_mode_args(unsigned int mode, int bytes, int args, char **argv,
								void **data)
{
	struct mode_data *mode_data;

	/* check there's no trailing junk */
	if (argv[0][bytes] != '\0') {
		SYNTAX_ERROR("Unexpected trailing bytes after octal "
			"mode number\n");
		return 0;
	}

	/* check there's only one argument */
	if (args > 1) {
		SYNTAX_ERROR("Octal mode number is first argument, "
			"expected one argument, got %d\n", args);
		return 0;
	}

	/*  check mode is within range */
	if (mode > 07777) {
		SYNTAX_ERROR("Octal mode %o is out of range\n", mode);
		return 0;
	}

	mode_data = malloc(sizeof(struct mode_data));
	if (mode_data == NULL)
		BAD_ERROR("Out of memory in action mode\n");

	mode_data->operation = ACTION_MODE_OCT;
	mode_data->mode = mode;
	mode_data->next = NULL;
	*data = mode_data;

	return 1;
}


/*
 * Parse symbolic mode of format [ugoa]+[+-=]PERMS
 * PERMS = [rwxXst]+ or [ugo]
 */
struct mode_data *parse_sym_mode_arg(char *arg)
{
	struct mode_data *mode_data = malloc(sizeof(*mode_data));
	int mode = 0;
	int mask = 0;
	int op;
	char X = 0;

	if (mode_data == NULL)
		BAD_ERROR("Out of memory in action mode\n");

	if (arg[0] != 'u' && arg[0] != 'g' && arg[0] != 'o' && arg[0] != 'a') {
		/* no ownership specifiers, default to a */
		mask = 0777;
		goto parse_operation;
	}

	/* parse ownership specifiers */
	while(1) {
		switch(*arg) {
		case 'u':
			mask |= 04700;
			break;
		case 'g':
			mask |= 02070;
			break;
		case 'o':
			mask |= 01007;
			break;
		case 'a':
			mask = 07777;
			break;
		default:
			goto parse_operation;
		}
		arg ++;
	}

parse_operation:
	switch(*arg) {
	case '+':
		op = ACTION_MODE_ADD;
		break;
	case '-':
		op = ACTION_MODE_REM;
		break;
	case '=':
		op = ACTION_MODE_SET;
		break;
	default:
		SYNTAX_ERROR("Action mode: Expected one of '+', '-' or '=', "
			"got '%c'\n", *arg);
		goto failed;
	}

	arg ++;

	/* Parse PERMS */
	if (*arg == 'u' || *arg == 'g' || *arg == 'o') {
 		/* PERMS = [ugo] */
		mode = - *arg;
		if (*++arg != '\0') {
			SYNTAX_ERROR("Action mode: permission 'u', 'g' or 'o' "
				"has trailing characters\n");
			goto failed;
		}
	} else {
 		/* PERMS = [rwxXst]+ */
		while(*arg != '\0') {
			switch(*arg) {
			case 'r':
				mode |= 0444;
				break;
			case 'w':
				mode |= 0222;
				break;
			case 'x':
				mode |= 0111;
				break;
			case 's':
				mode |= 06000;
				break;
			case 't':
				mode |= 01000;
				break;
			case 'X':
				X = 1;
				break;
			default:
				SYNTAX_ERROR("Action mode: unrecognised "
						"permission '%c'\n", *arg);
				goto failed;
			}

			arg ++;
		}
		mode &= mask;
	}

	mode_data->operation = op;
	mode_data->mode = mode;
	mode_data->mask = mask;
	mode_data->X = X;
	mode_data->next = NULL;

	return mode_data;

failed:
	free(mode_data);
	return NULL;
}


int parse_sym_mode_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	int i;
	struct mode_data *head = NULL, *cur = NULL;

	for (i = 0; i < args; i++) {
		struct mode_data *entry = parse_sym_mode_arg(argv[i]);

		if (entry == NULL)
			return 0;

		if (cur) {
			cur->next = entry;
			cur = entry;
		} else
			head = cur = entry;
	}

	*data = head;

	return 1;
}


int parse_mode_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	int n, bytes;
	unsigned int mode;

	if (args == 0) {
		SYNTAX_ERROR("Mode action expects one or more arguments\n");
		return 0;
	}

	/* octal mode number? */
	n = sscanf(argv[0], "%o%n", &mode, &bytes);

	if(n >= 1)
		return parse_octal_mode_args(mode, bytes, args, argv, data);
	else
		return parse_sym_mode_args(action, args, argv, data);
}


void mode_action(struct action *action, struct dir_ent *dir_ent)
{
	struct stat *buf = &dir_ent->inode->buf;
	struct mode_data *mode_data = action->data;
	int mode = 0;

	for (;mode_data; mode_data = mode_data->next) {
		if (mode_data->mode < 0) {
			/* 'u', 'g' or 'o' */
			switch(-mode_data->mode) {
			case 'u':
				mode = (buf->st_mode >> 6) & 07;
				break;
			case 'g':
				mode = (buf->st_mode >> 3) & 07;
				break;
			case 'o':
				mode = buf->st_mode & 07;
				break;
			}
			mode = ((mode << 6) | (mode << 3) | mode) &
				mode_data->mask;
		} else if (mode_data->X &&
				((buf->st_mode & S_IFMT) == S_IFDIR ||
				(buf->st_mode & 0111)))
			/* X permission, only takes effect if inode is a
			 * directory or x is set for some owner */
			mode = mode_data->mode | (0111 & mode_data->mask);
		else
			mode = mode_data->mode;

		switch(mode_data->operation) {
		case ACTION_MODE_OCT:
			buf->st_mode = (buf->st_mode & ~S_IFMT) | mode;
			break;
		case ACTION_MODE_SET:
			buf->st_mode = (buf->st_mode & ~mode_data->mask) | mode;
			break;
		case ACTION_MODE_ADD:
			buf->st_mode |= mode;
			break;
		case ACTION_MODE_REM:
			buf->st_mode &= ~mode;
		}
	}
}


/*
 *  Empty specific action code
 */
int empty_actions()
{
	return empty_count;
}


int parse_empty_args(struct action_entry *action, int args, char **argv,
								void **data)
{
	struct empty_data *empty_data;
	int val;

	if (args >= 2) {
		SYNTAX_ERROR("Empty action expects zero or one argument\n");
		return 0;
	}

	if (args == 0 || strcmp(argv[0], "all") == 0)
		val = EMPTY_ALL;
	else if (strcmp(argv[0], "source") == 0)
		val = EMPTY_SOURCE;
	else if (strcmp(argv[0], "excluded") == 0)
		val = EMPTY_EXCLUDED;
	else {
		SYNTAX_ERROR("Empty action expects zero arguments, or one"
			"argument containing \"all\", \"source\", or \"excluded\""
			"\n");
		return 0;
	}

	empty_data = malloc(sizeof(*empty_data));
	if (empty_data == NULL)
		BAD_ERROR("Out of memory in action empty\n");

	empty_data->val = val;
	*data = empty_data;

	return 1;
}


int eval_empty_actions(struct dir_ent *dir_ent)
{
	int i, match = 0;
	struct action_data action_data;
	struct empty_data *data;
	struct dir_info *dir = dir_ent->dir;

	/*
	 * Empty action only works on empty directories
	 */
	if (dir->count != 0)
		return 0;

	action_data.name = dir_ent->name;
	action_data.pathname = pathname(dir_ent);
	action_data.subpath = subpathname(dir_ent);
	action_data.buf = &dir_ent->inode->buf;
	action_data.depth = dir_ent->our_dir->depth;

	for (i = 0; i < spec_count && !match; i++) {
		if (spec_list[i].type != EMPTY_ACTION)
			continue;

		data = spec_list[i].data;

		/*
		 * determine the cause of the empty directory and evaluate
		 * the empty action specified.  Three empty actions:
		 * - EMPTY_SOURCE: empty action triggers only if the directory
		 *	was originally empty, i.e directories that are empty
		 *	only due to excluding are ignored.
		 * - EMPTY_EXCLUDED: empty action triggers only if the directory
		 *	is empty because of excluding, i.e. directories that
		 *	were originally empty are ignored.
		 * - EMPTY_ALL (the default): empty action triggers if the
		 *	directory is empty, irrespective of the reason, i.e.
		 *	the directory could have been originally empty or could
		 *	be empty due to excluding.
		 */
		if ((data->val == EMPTY_EXCLUDED && !dir->excluded) ||
				(data->val == EMPTY_SOURCE && dir->excluded))
			continue;
		
		match = eval_expr(spec_list[i].expr, &action_data);
	}

	return match;
}


/*
 *  Move specific action code
 */
static struct move_ent *move_list = NULL;


int move_actions()
{
	return move_count;
}


char *move_pathname(struct move_ent *move)
{
	struct dir_info *dest;
	char *name, *pathname;
	int res;

	dest = (move->ops & ACTION_MOVE_MOVE) ?
		move->dest : move->dir_ent->our_dir;
	name = (move->ops & ACTION_MOVE_RENAME) ?
		move->name : move->dir_ent->name;

	if(dest->subpath[0] != '\0')
		res = asprintf(&pathname, "%s/%s", dest->subpath, name);
	else
		res = asprintf(&pathname, "/%s", name);

	if(res == -1)
		BAD_ERROR("asprintf failed in move_pathname\n");

	return pathname;
}


char *get_comp(char **pathname)
{
	char *path = *pathname, *start;

	while(*path == '/')
		path ++;

	if(*path == '\0')
		return NULL;

	start = path;
	while(*path != '/' && *path != '\0')
		path ++;

	*pathname = path;
	return strndup(start, path - start);
}


struct dir_ent *lookup_comp(char *comp, struct dir_info *dest)
{
	struct dir_ent *dir_ent;

	for(dir_ent = dest->list; dir_ent; dir_ent = dir_ent->next)
		if(strcmp(comp, dir_ent->name) == 0)
			break;

	return dir_ent;
}


void eval_move(struct action_data *action_data, struct move_ent *move,
		struct dir_info *root, struct dir_ent *dir_ent, char *pathname)
{
	struct dir_info *dest, *source = dir_ent->our_dir;
	struct dir_ent *comp_ent;
	char *comp, *path = pathname;

	/*
	 * Walk pathname to get the destination directory
	 *
	 * Like the mv command, if the last component exists and it
	 * is a directory, then move the file into that directory,
	 * otherwise, move the file into parent directory of the last
	 * component and rename to the last component.
	 */
	if (pathname[0] == '/')
		/* absolute pathname, walk from root directory */
		dest = root;
	else
		/* relative pathname, walk from current directory */
		dest = source;

	for(comp = get_comp(&pathname); comp; free(comp),
						comp = get_comp(&pathname)) {

		if (strcmp(comp, ".") == 0)
			continue;

		if (strcmp(comp, "..") == 0) {
			dest = dest->dir_ent->our_dir;
			continue;
		}

		/*
		 * Look up comp in current directory, if it exists and it is a
		 * directory continue walking the pathname, otherwise exit,
		 * we've walked as far as we can go, normally this is because
		 * we've arrived at the leaf component which we are going to
		 * rename source to
		 */
		comp_ent = lookup_comp(comp, dest);
		if (comp_ent == NULL || (comp_ent->inode->buf.st_mode & S_IFMT)
							!= S_IFDIR)
			break;

		dest = comp_ent->dir;
	}

	if(comp) {
		/* Leaf component? If so we're renaming to this  */
		char *remainder = get_comp(&pathname);
		free(remainder);

		if(remainder) {
			/*
			 * trying to move source to a subdirectory of
			 * comp, but comp either doesn't exist, or it isn't
			 * a directory, which is impossible
			 */
			if (comp_ent == NULL)
				ERROR("Move action: cannot move %s to %s, no "
					"such directory %s\n",
					action_data->subpath, path, comp);
			else
				ERROR("Move action: cannot move %s to %s, %s "
					"is not a directory\n",
					action_data->subpath, path, comp);
			free(comp);
			return;
		}

		/*
		 * Multiple move actions triggering on one file can be merged
		 * if one is a RENAME and the other is a MOVE.  Multiple RENAMEs
		 * can only merge if they're doing the same thing
	 	 */
		if(move->ops & ACTION_MOVE_RENAME) {
			if(strcmp(comp, move->name) != 0) {
				char *conf_path = move_pathname(move);
				ERROR("Move action: Cannot move %s to %s, "
					"conflicting move, already moving "
					"to %s via another move action!\n",
					action_data->subpath, path, conf_path);
				free(conf_path);
				free(comp);
				return;
			}
			free(comp);
		} else {
			move->name = comp;
			move->ops |= ACTION_MOVE_RENAME;
		}
	}

	if(dest != source) {
		/*
		 * Multiple move actions triggering on one file can be merged
		 * if one is a RENAME and the other is a MOVE.  Multiple MOVEs
		 * can only merge if they're doing the same thing
	 	 */
		if(move->ops & ACTION_MOVE_MOVE) {
			if(dest != move->dest) {
				char *conf_path = move_pathname(move);
				ERROR("Move action: Cannot move %s to %s, "
					"conflicting move, already moving "
					"to %s via another move action!\n",
					action_data->subpath, path, conf_path);
				free(conf_path);
				return;
			}
		} else {
			move->dest = dest;
			move->ops |= ACTION_MOVE_MOVE;
		}
	}
}


int subdirectory(struct dir_info *source, struct dir_info *dest)
{
	if(source == NULL)
		return 0;

	return strlen(source->subpath) <= strlen(dest->subpath) &&
		(dest->subpath[strlen(source->subpath)] == '/' ||
		dest->subpath[strlen(source->subpath)] == '\0') &&
		strncmp(source->subpath, dest->subpath,
		strlen(source->subpath)) == 0;
}


void eval_move_actions(struct dir_info *root, struct dir_ent *dir_ent)
{
	int i;
	struct action_data action_data;
	struct move_ent *move = NULL;

	action_data.name = dir_ent->name;
	action_data.pathname = pathname(dir_ent);
	action_data.subpath = subpathname(dir_ent);
	action_data.buf = &dir_ent->inode->buf;
	action_data.depth = dir_ent->our_dir->depth;

	/*
	 * Evaluate each move action against the current file.  For any
	 * move actions that match don't actually perform the move now, but,
	 * store it, and execute all the stored move actions together once the
	 * directory scan is complete.  This is done to ensure each separate
	 * move action does not nondeterministically interfere with other move
	 * actions.  Each move action is considered to act independently, and
	 * each move action sees the directory tree in the same state.
	 */
	for (i = 0; i < spec_count; i++) {
		struct action *action = &spec_list[i];
		int match;

		if (action->type != MOVE_ACTION)
			continue;

		match = eval_expr(action->expr, &action_data);

		if(match) {
			if(move == NULL) {
				move = malloc(sizeof(*move));
				if(move == NULL)
					BAD_ERROR("Out of memory in "
						"eval_move_actions\n");

				move->ops = 0;
				move->dir_ent = dir_ent;
			}
			eval_move(&action_data, move, root, dir_ent,
				action->argv[0]);
		}
	}

	if(move) {
		struct dir_ent *comp_ent;
		struct dir_info *dest;
		char *name;

		/*
		 * Move contains the result of all triggered move actions.
		 * Check the destination doesn't already exist
		 */
		if(move->ops == 0) {
			free(move);
			return;
		}

		dest = (move->ops & ACTION_MOVE_MOVE) ?
			move->dest : dir_ent->our_dir;
		name = (move->ops & ACTION_MOVE_RENAME) ?
			move->name : dir_ent->name;
		comp_ent = lookup_comp(name, dest);
		if(comp_ent) {
			char *conf_path = move_pathname(move);
			ERROR("Move action: Cannot move %s to %s, "
				"destination already exists\n",
				action_data.subpath, conf_path);
			free(conf_path);
			free(move);
			return;
		}

		/*
		 * If we're moving a directory, check we're not moving it to a
		 * subdirectory of itself
		 */
		if(subdirectory(dir_ent->dir, dest)) {
			char *conf_path = move_pathname(move);
			ERROR("Move action: Cannot move %s to %s, this is a "
				"subdirectory of itself\n",
				action_data.subpath, conf_path);
			free(conf_path);
			free(move);
			return;
		}
		move->next = move_list;
		move_list = move;
	}
}


void move_dir(struct dir_ent *dir_ent)
{
	struct dir_info *dir = dir_ent->dir;
	struct dir_ent *comp_ent;

	/* update our directory's subpath name */
	dir->subpath = strdup(subpathname(dir_ent));

	/* recursively update the subpaths of any sub-directories */
	for(comp_ent = dir->list; comp_ent; comp_ent = comp_ent->next)
		if(comp_ent->dir)
			move_dir(comp_ent);
}


void move_file(struct move_ent *move_ent)
{
	struct dir_ent *dir_ent = move_ent ->dir_ent;

	if(move_ent->ops & ACTION_MOVE_MOVE) {
		struct dir_ent *comp_ent, *prev = NULL;
		struct dir_info *source = dir_ent->our_dir,
							*dest = move_ent->dest;
		char *filename = pathname(dir_ent);

		/*
		 * If we're moving a directory, check we're not moving it to a
		 * subdirectory of itself
		 */
		if(subdirectory(dir_ent->dir, dest)) {
			char *conf_path = move_pathname(move_ent);
			ERROR("Move action: Cannot move %s to %s, this is a "
				"subdirectory of itself\n",
				subpathname(dir_ent), conf_path);
			free(conf_path);
			return;
		}

		/* Remove the file from source directory */
		for(comp_ent = source->list; comp_ent != dir_ent;
				prev = comp_ent, comp_ent = comp_ent->next);

		if(prev)
			prev->next = comp_ent->next;
		else
			source->list = comp_ent->next;

		source->count --;
		if((comp_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			source->directory_count --;

		/* Add the file to dest directory */
		comp_ent->next = dest->list;
		dest->list = comp_ent;
		comp_ent->our_dir = dest;

		dest->count ++;
		if((comp_ent->inode->buf.st_mode & S_IFMT) == S_IFDIR)
			dest->directory_count ++;

		/*
		 * We've moved the file, and so we can't now use the
		 * parent directory's pathname to calculate the pathname
		 */
		if(dir_ent->nonstandard_pathname == NULL) {
			dir_ent->nonstandard_pathname = strdup(filename);
			if(dir_ent->source_name) {
				free(dir_ent->source_name);
				dir_ent->source_name = NULL;
			}
		}
	}

	if(move_ent->ops & ACTION_MOVE_RENAME) {
		/*
		 * If we're using name in conjunction with the parent
		 * directory's pathname to calculate the pathname, we need
		 * to use source_name to override.  Otherwise it's already being
		 * over-ridden
		 */
		if(dir_ent->nonstandard_pathname == NULL &&
						dir_ent->source_name == NULL)
			dir_ent->source_name = dir_ent->name;
		else
			free(dir_ent->name);

		dir_ent->name = move_ent->name;
	}

	if(dir_ent->dir)
		/*
		 * dir_ent is a directory, and we have to recursively fix-up
		 * its subpath, and the subpaths of all of its sub-directories
		 */
		move_dir(dir_ent);
}


void do_move_actions()
{
	while(move_list) {
		struct move_ent *temp = move_list;
		struct dir_info *dest = (move_list->ops & ACTION_MOVE_MOVE) ?
			move_list->dest : move_list->dir_ent->our_dir;
		char *name = (move_list->ops & ACTION_MOVE_RENAME) ?
			move_list->name : move_list->dir_ent->name;
		struct dir_ent *comp_ent = lookup_comp(name, dest);
		if(comp_ent) {
			char *conf_path = move_pathname(move_list);
			ERROR("Move action: Cannot move %s to %s, "
				"destination already exists\n",
				subpathname(move_list->dir_ent), conf_path);
			free(conf_path);
		} else
			move_file(move_list);

		move_list = move_list->next;
		free(temp);
	}
}


/*
 * General test evaluation code
 */

/*
 * A number can be of the form [range]number[size]
 * [range] is either:
 *	'<' or '-', match on less than number
 *	'>' or '+', match on greater than number
 *	'' (nothing), match on exactly number
 * [size] is either:
 *	'k' or 'K', number * 2^10
 * 	'm' or 'M', number * 2^20
 *	'g' or 'G', number * 2^30
 */
int parse_number(char *arg, long long *size, int *range, char **error)
{
	char *b;

	if (*arg == '>' || *arg == '+') {
		*range = NUM_GREATER;
		arg ++;
	} else if (*arg == '<' || *arg == '-') {
		*range = NUM_LESS;
		arg ++;
	} else
		*range = NUM_EQ;

	*size = strtoll(arg, &b, 10);

	if (b == arg) {
		/* Couldn't read any number  */
		*error = "Number expected";
		return 0;
	}

	switch (*b) {
	case 'g':
	case 'G':
		*size *= 1024;
	case 'm':
	case 'M':
		*size *= 1024;
	case 'k':
	case 'K':
		*size *= 1024;

		b ++;

		if (*b != '\0') {
			*error = "Trailing junk after size specifier";
			return 0;
		}

		break;
	case '\0':
		break;
	default:
		*error = "Trailing junk after number";
		return 0;
	}

	return 1;
}


int parse_number_arg(struct test_entry *test, struct atom *atom)
{
	struct test_number_arg *number;
	long long size;
	int range;
	char *error;
	int res = parse_number(atom->argv[0], &size, &range, &error);

	if (res == 0) {
		TEST_SYNTAX_ERROR(test, 0, "%s\n", error);
		return 0;
	}

	number = malloc(sizeof(*number));
	if (number == NULL)
		BAD_ERROR("Out of memory in parse test\n");

	number->range = range;
	number->size = size;

	atom->data = number;

	return 1;
}


int parse_range_args(struct test_entry *test, struct atom *atom)
{
	struct test_range_args *range;
	long long start, end;
	int type;
	int res;
	char *error;

	res = parse_number(atom->argv[0], &start, &type, &error);
	if (res == 0) {
		TEST_SYNTAX_ERROR(test, 0, "%s\n", error);
		return 0;
	}

	if (type != NUM_EQ) {
		TEST_SYNTAX_ERROR(test, 0, "Range specifier (<, >, -, +) not "
			"expected\n");
		return 0;
	}
 
	res = parse_number(atom->argv[1], &end, &type, &error);
	if (res == 0) {
		TEST_SYNTAX_ERROR(test, 1, "%s\n", error);
		return 0;
	}

	if (type != NUM_EQ) {
		TEST_SYNTAX_ERROR(test, 1, "Range specifier (<, >, -, +) not "
			"expected\n");
		return 0;
	}
 
	range = malloc(sizeof(*range));
	if (range == NULL)
		BAD_ERROR("Out of memory in parse test\n");

	range->start = start;
	range->end = end;

	atom->data = range;

	return 1;
}


/*
 * Generic test code macro
 */
#define TEST_FN(NAME, MATCH, CODE) \
int NAME##_fn(struct atom *atom, struct action_data *action_data) \
{ \
	/* test operates on MATCH file types only */ \
	if (!(action_data->buf->st_mode & MATCH)) \
		return 0; \
 \
	CODE \
}

/*
 * Generic test code macro testing VAR for size (eq, less than, greater than)
 */
#define TEST_VAR_FN(NAME, MATCH, VAR) TEST_FN(NAME, MATCH, \
	{ \
	int match = 0; \
	struct test_number_arg *number = atom->data; \
	\
	switch (number->range) { \
	case NUM_EQ: \
		match = VAR == number->size; \
		break; \
	case NUM_LESS: \
		match = VAR < number->size; \
		break; \
	case NUM_GREATER: \
		match = VAR > number->size; \
		break; \
	} \
	\
	return match; \
	})	


/*
 * Generic test code macro testing VAR for range [x, y] (value between x and y
 * inclusive).
 */	
#define TEST_VAR_RANGE_FN(NAME, MATCH, VAR) TEST_FN(NAME##_range, MATCH, \
	{ \
	struct test_range_args *range = atom->data; \
	\
	return range->start <= VAR && VAR <= range->end; \
	})	


/*
 * Name, Pathname and Subpathname test specific code
 */

/*
 * Add a leading "/" if subpathname and pathname lacks it
 */
int check_pathname(struct test_entry *test, struct atom *atom)
{
	int res;
	char *name;

	if(atom->argv[0][0] != '/') {
		res = asprintf(&name, "/%s", atom->argv[0]);
		if(res == -1)
			BAD_ERROR("asprintf failed in check_pathname\n");

		free(atom->argv[0]);
		atom->argv[0] = name;
	}

	return 1;
}


TEST_FN(name, ACTION_ALL_LNK, \
	return fnmatch(atom->argv[0], action_data->name,
				FNM_PATHNAME|FNM_PERIOD|FNM_EXTMATCH) == 0;)

TEST_FN(pathname, ACTION_ALL_LNK, \
	return fnmatch(atom->argv[0], action_data->subpath,
				FNM_PATHNAME|FNM_PERIOD|FNM_EXTMATCH) == 0;)


int count_components(char *path)
{
	int count;

	for (count = 0; *path != '\0'; count ++) {
		while (*path == '/')
			path ++;

		while (*path != '\0' && *path != '/')
			path ++;
	}

	return count;
}


char *get_start(char *s, int n)
{
	int count;
	char *path = s;

	for (count = 0; *path != '\0' && count < n; count ++) {
		while (*path == '/')
			path ++;

		while (*path != '\0' && *path != '/')
			path ++;
	}

	if (count == n)
		*path = '\0';

	return s;
}
	

int subpathname_fn(struct atom *atom, struct action_data *action_data)
{
	return fnmatch(atom->argv[0], get_start(strdupa(action_data->subpath),
		count_components(atom->argv[0])),
		FNM_PATHNAME|FNM_PERIOD|FNM_EXTMATCH) == 0;
}

TEST_VAR_FN(filesize, ACTION_REG, action_data->buf->st_size)

TEST_VAR_FN(dirsize, ACTION_DIR, action_data->buf->st_size)

TEST_VAR_FN(size, ACTION_ALL_LNK, action_data->buf->st_size)

TEST_VAR_FN(inode, ACTION_ALL_LNK, action_data->buf->st_ino)

TEST_VAR_FN(nlink, ACTION_ALL_LNK, action_data->buf->st_nlink)

TEST_VAR_FN(fileblocks, ACTION_REG, action_data->buf->st_blocks)

TEST_VAR_FN(dirblocks, ACTION_DIR, action_data->buf->st_blocks)

TEST_VAR_FN(blocks, ACTION_ALL_LNK, action_data->buf->st_blocks)

TEST_VAR_FN(gid, ACTION_ALL_LNK, action_data->buf->st_gid)

TEST_VAR_FN(uid, ACTION_ALL_LNK, action_data->buf->st_uid)

TEST_VAR_FN(depth, ACTION_ALL_LNK, action_data->depth)

TEST_VAR_RANGE_FN(filesize, ACTION_REG, action_data->buf->st_size)

TEST_VAR_RANGE_FN(dirsize, ACTION_DIR, action_data->buf->st_size)

TEST_VAR_RANGE_FN(size, ACTION_ALL_LNK, action_data->buf->st_size)

TEST_VAR_RANGE_FN(inode, ACTION_ALL_LNK, action_data->buf->st_ino)

TEST_VAR_RANGE_FN(nlink, ACTION_ALL_LNK, action_data->buf->st_nlink)

TEST_VAR_RANGE_FN(fileblocks, ACTION_REG, action_data->buf->st_blocks)

TEST_VAR_RANGE_FN(dirblocks, ACTION_DIR, action_data->buf->st_blocks)

TEST_VAR_RANGE_FN(blocks, ACTION_ALL_LNK, action_data->buf->st_blocks)

TEST_VAR_RANGE_FN(gid, ACTION_ALL_LNK, action_data->buf->st_gid)

TEST_VAR_RANGE_FN(uid, ACTION_ALL_LNK, action_data->buf->st_uid)

TEST_VAR_RANGE_FN(depth, ACTION_ALL_LNK, action_data->depth)

/*
 * Type test specific code
 */
struct type_entry type_table[] = {
	{ S_IFSOCK, 's' },
	{ S_IFLNK, 'l' },
	{ S_IFREG, 'f' },
	{ S_IFBLK, 'b' },
	{ S_IFDIR, 'd' },
	{ S_IFCHR, 'c' },
	{ S_IFIFO, 'p' },
	{ 0, 0 },
};


int parse_type_arg(struct test_entry *test, struct atom *atom)
{
	int i;

	if (strlen(atom->argv[0]) != 1)
		goto failed;

	for(i = 0; type_table[i].type != 0; i++)
		if (type_table[i].type == atom->argv[0][0])
			break;

	atom->data = &type_table[i];

	if(type_table[i].type != 0)
		return 1;

failed:
	TEST_SYNTAX_ERROR(test, 0, "Unexpected file type, expected 'f', 'd', "
		"'c', 'b', 'l', 's' or 'p'\n");
	return 0;
}
	

int type_fn(struct atom *atom, struct action_data *action_data)
{
	struct type_entry *type = atom->data;

	return (action_data->buf->st_mode & S_IFMT) == type->value;
}


/*
 * True test specific code
 */
int true_fn(struct atom *atom, struct action_data *action_data)
{
	return 1;
}


/*
 *  False test specific code
 */
int false_fn(struct atom *atom, struct action_data *action_data)
{
	return 0;
}


/*
 *  File test specific code
 */
int parse_file_arg(struct test_entry *test, struct atom *atom)
{
	int res;
	regex_t *preg = malloc(sizeof(regex_t));

	if (preg == NULL)
		BAD_ERROR("parse file arg malloc failed\n");

	res = regcomp(preg, atom->argv[0], REG_EXTENDED);
	if (res) {
		char str[1024];

		regerror(res, preg, str, 1024);
		TEST_SYNTAX_ERROR(test, 0, "invalid regex \"%s\" because "
			"\"%s\"\n", atom->argv[0], str);
		return 0;
	}

	atom->data = preg;

	return 1;
}


int file_fn(struct atom *atom, struct action_data *action_data)
{
	int child, res, size = 0, status;
	int pipefd[2];
	char *buffer = NULL;
	regex_t *preg = atom->data;

	res = pipe(pipefd);
	if (res == -1)
		BAD_ERROR("file_fn pipe failed\n");

	child = fork();
	if (child == -1)
		BAD_ERROR("file_fn fork_failed\n");

	if (child == 0) {
		/*
		 * Child process
		 * Connect stdout to pipefd[1] and execute file command
		 */
		close(STDOUT_FILENO);
		res = dup(pipefd[1]);
		if (res == -1) {
			ERROR("file_fn dup failed\n");
			exit(EXIT_FAILURE);
		}
		execlp("file", "file", "-b", action_data->pathname,
			(char *) NULL);
		ERROR("file_fn execlp failed\n");
		exit(EXIT_FAILURE);
	}

	/*
	 * Parent process.  Read stdout from file command
 	 */
	close(pipefd[1]);

	do {
		buffer = realloc(buffer, size + 512);
		if (buffer == NULL)
			BAD_ERROR("file_fn malloc failed\n");

		res = read_bytes(pipefd[0], buffer + size, 512);

		if (res == -1)
			BAD_ERROR("file_fn pipe read error\n");

		size += 512;

	} while (res == 512);

	size = size + res - 512;

	buffer[size] = '\0';

	res = waitpid(child,  &status, 0);

	if (res == -1)
		BAD_ERROR("file_fn waitpid failed\n");
 
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		BAD_ERROR("file_fn file returned error\n");

	close(pipefd[0]);

	res = regexec(preg, buffer, (size_t) 0, NULL, 0);

	free(buffer);

	return res == 0;
}


static struct test_entry test_table[] = {
	{ "name", 1, name_fn},
	{ "pathname", 1, pathname_fn, check_pathname},
	{ "subpathname", 1, subpathname_fn, check_pathname},
	{ "filesize", 1, filesize_fn, parse_number_arg},
	{ "dirsize", 1, dirsize_fn, parse_number_arg},
	{ "size", 1, size_fn, parse_number_arg},
	{ "inode", 1, inode_fn, parse_number_arg},
	{ "nlink", 1, nlink_fn, parse_number_arg},
	{ "fileblocks", 1, fileblocks_fn, parse_number_arg},
	{ "dirblocks", 1, dirblocks_fn, parse_number_arg},
	{ "blocks", 1, blocks_fn, parse_number_arg},
	{ "gid", 1, gid_fn, parse_number_arg},
	{ "uid", 1, uid_fn, parse_number_arg},
	{ "depth", 1, depth_fn, parse_number_arg},
	{ "filesize_range", 2, filesize_range_fn, parse_range_args},
	{ "dirsize_range", 2, dirsize_range_fn, parse_range_args},
	{ "size_range", 2, size_range_fn, parse_range_args},
	{ "inode_range", 2, inode_range_fn, parse_range_args},
	{ "nlink_range", 2, nlink_range_fn, parse_range_args},
	{ "fileblocks_range", 2, fileblocks_range_fn, parse_range_args},
	{ "dirblocks_range", 2, dirblocks_range_fn, parse_range_args},
	{ "blocks_range", 2, blocks_range_fn, parse_range_args},
	{ "gid_range", 2, gid_range_fn, parse_range_args},
	{ "uid_range", 2, uid_range_fn, parse_range_args},
	{ "depth_range", 2, depth_range_fn, parse_range_args},
	{ "type", 1, type_fn, parse_type_arg},
	{ "true", 0, true_fn, NULL},
	{ "false", 0, false_fn, NULL},
	{ "file", 1, file_fn, parse_file_arg},
	{ "", -1 }
};


static struct action_entry action_table[] = {
	{ "fragment", FRAGMENT_ACTION, 1, ACTION_REG, NULL, NULL},
	{ "exclude", EXCLUDE_ACTION, 0, ACTION_ALL_LNK, NULL, NULL},
	{ "fragments", FRAGMENTS_ACTION, 0, ACTION_REG, NULL, frag_action},
	{ "no-fragments", NO_FRAGMENTS_ACTION, 0, ACTION_REG, NULL,
						no_frag_action},
	{ "always-use-fragments", ALWAYS_FRAGS_ACTION, 0, ACTION_REG, NULL,
						always_frag_action},
	{ "dont-always-use-fragments", NO_ALWAYS_FRAGS_ACTION, 0, ACTION_REG,	
						NULL, no_always_frag_action},
	{ "compressed", COMPRESSED_ACTION, 0, ACTION_REG, NULL, comp_action},
	{ "uncompressed", UNCOMPRESSED_ACTION, 0, ACTION_REG, NULL,
						uncomp_action},
	{ "uid", UID_ACTION, 1, ACTION_ALL_LNK, parse_uid_args, uid_action},
	{ "gid", GID_ACTION, 1, ACTION_ALL_LNK, parse_gid_args, gid_action},
	{ "guid", GUID_ACTION, 2, ACTION_ALL_LNK, parse_guid_args, guid_action},
	{ "mode", MODE_ACTION, -2, ACTION_ALL, parse_mode_args, mode_action },
	{ "empty", EMPTY_ACTION, -2, ACTION_DIR, parse_empty_args, NULL},
	{ "move", MOVE_ACTION, -2, ACTION_ALL_LNK, NULL, NULL},
	{ "", 0, -1, 0, NULL, NULL}
};
