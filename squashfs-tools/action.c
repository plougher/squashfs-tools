/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2011
 * Phillip Lougher <phillip@lougher.demon.co.uk>
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

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "action.h"

/*
 * code to parse actions
 */

static char *cur_ptr, *source;
static struct action *spec_list = NULL;
static int spec_count = 0;
static struct file_buffer *def_fragment = NULL;

static struct token_entry token_table[] = {
	{ " ", 	TOK_WHITE_SPACE, 1 },
	{ "(", TOK_OPEN_BRACKET, 1, },
	{ ")", TOK_CLOSE_BRACKET, 1 },
	{ "&&", TOK_AND, 2 },
	{ "||", TOK_OR, 2 },
	{ "!", TOK_NOT, 1 },
	{ ",", TOK_COMMA, 1 },
	{ "=", TOK_EQUALS, 1},
	{ "", -1, 0 }
};


static struct test_entry test_table[];

static struct action_entry action_table[];

static struct expr *parse_expr(int subexp);


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
		return NULL;

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
		return NULL;

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
	expr->type = ATOM_TYPE;
	expr->atom.argv = malloc(test->args * sizeof(char *));
	expr->atom.test = test;

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

	token = get_token(&string);

	if (token != TOK_CLOSE_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \")\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

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
	int i, token;
	struct expr *expr;
	struct action_entry *action;

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

	if (action->args == 0)
		goto skip_args;

	argv = malloc(action->args * sizeof(char *));

	token = get_token(&string);

	if (token != TOK_OPEN_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \"(\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

	for (i = 0; i < action->args; i++) {
		token = get_token(&string);

		if (token != TOK_STRING) {
			SYNTAX_ERROR("Unexpected token \"%s\", expected "
				"argument\n", TOK_TO_STR(token, string));
			goto failed;
		}

		argv[i] = string;

		if (i + 1 < action->args) {
			token = get_token(&string);

			if (token != TOK_COMMA) {
				SYNTAX_ERROR("Unexpected token \"%s\", "
					"expected \",\"\n",
					TOK_TO_STR(token, string));
			goto failed;
			}
		}
	}

	token = get_token(&string);

	if (token != TOK_CLOSE_BRACKET) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \")\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}

skip_args:
	token = get_token(&string);

	if (token != TOK_EQUALS) {
		SYNTAX_ERROR("Unexpected token \"%s\", expected \"=\"\n",
						TOK_TO_STR(token, string));
		goto failed;
	}
	
	expr = parse_expr(0);

	if (expr == NULL)
		goto failed;

	if (action->parse_args) {
		int res = action->parse_args(action->args, argv);

		if (res == 0)
			goto failed;
	}

	spec_list = realloc(spec_list, (spec_count + 1) *
					sizeof(struct action));

	spec_list[spec_count].type = action->type;
	spec_list[spec_count].action = action;
	spec_list[spec_count].argv = argv;
	spec_list[spec_count].expr = expr;
	spec_list[spec_count ++].data = NULL;

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
int eval_expr(struct expr *expr, struct action *action,
					struct action_data *action_data)
{
	int match;

	switch (expr->type) {
	case ATOM_TYPE:
		match = expr->atom.test->fn(action, expr->atom.test->args,
					expr->atom.argv, action_data);
		break;
	case UNARY_TYPE:
		match = !eval_expr(expr->unary_op.expr, action, action_data);
		break;
	default:
		match = eval_expr(expr->expr_op.lhs, action, action_data);

		if ((expr->expr_op.op == TOK_AND && match) ||
					(expr->expr_op.op == TOK_OR && !match))
			match = eval_expr(expr->expr_op.rhs, action,
					action_data);
		break;
	}

	return match;
}


/*
 * Fragment specific action code
 */
void *eval_frag_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;

	action_data.name = dir_ent->name;
	action_data.pathname = dir_ent->pathname;
	action_data.buf = &dir_ent->inode->buf;

	for (i = 0; i < spec_count; i++) {
		if (spec_list[i].type != FRAGMENT_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &spec_list[i],
			&action_data);

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
int eval_exclude_actions(char *name, char *pathname, struct stat *buf)
{
	int i, match = 0;
	struct action_data action_data;

	action_data.name = name;
	action_data.pathname = pathname;
	action_data.buf = buf;

	for (i = 0; i < spec_count && !match; i++) {
		if (spec_list[i].type != EXCLUDE_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &spec_list[i],
			&action_data);
	}

	return match;
}


/*
 * Fragment specific action code
 */
void eval_fragment_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;
	struct inode_info *inode = dir_ent->inode;

	action_data.name = dir_ent->name;
	action_data.pathname = dir_ent->pathname;
	action_data.buf = &dir_ent->inode->buf;

	for (i = 0; i < spec_count; i++) {
		if (spec_list[i].type != FRAGMENTS_ACTION &&
				spec_list[i].type != NO_FRAGMENTS_ACTION &&
				spec_list[i].type != ALWAYS_FRAGS_ACTION &&
				spec_list[i].type != NO_ALWAYS_FRAGS_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &spec_list[i],
			&action_data);

		if (match)
			switch(spec_list[i].type) {
			case FRAGMENTS_ACTION:
				inode->no_fragments = 0;
				break;
			case NO_FRAGMENTS_ACTION:
				inode->no_fragments = 1;
				break;
			case ALWAYS_FRAGS_ACTION:
				inode->always_use_fragments = 1;
				break;
			case NO_ALWAYS_FRAGS_ACTION:
				inode->always_use_fragments = 0;
				break;
			}
	}
}


/*
 * Compression specific action code
 */
void eval_compression_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;
	struct inode_info *inode = dir_ent->inode;

	action_data.name = dir_ent->name;
	action_data.pathname = dir_ent->pathname;
	action_data.buf = &dir_ent->inode->buf;

	for (i = 0; i < spec_count; i++) {
		if (spec_list[i].type != COMPRESSED_ACTION &&
				spec_list[i].type != UNCOMPRESSED_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &spec_list[i],
			&action_data);

		if (match)
			switch(spec_list[i].type) {
			case COMPRESSED_ACTION:
				inode->noD = inode->noF = 0;
				break;
			case UNCOMPRESSED_ACTION:
				inode->noD = inode->noF = 1;
				inode->no_fragments = 1;
				break;
			}
	}
}


/*
 * Uid/gid specific action code
 */
void eval_uid_actions(struct dir_ent *dir_ent)
{
	int i, match;
	struct action_data action_data;
	struct inode_info *inode = dir_ent->inode;
	struct uid_info *uid_info;
	struct gid_info *gid_info;

	action_data.name = dir_ent->name;
	action_data.pathname = dir_ent->pathname;
	action_data.buf = &dir_ent->inode->buf;

	for (i = 0; i < spec_count; i++) {
		if (spec_list[i].type != UID_ACTION &&
				spec_list[i].type != GID_ACTION)
			continue;

		match = eval_expr(spec_list[i].expr, &spec_list[i],
			&action_data);

		if(!match)
			continue;

		switch(spec_list[i].type) {
		case UID_ACTION:
			uid_info = spec_list[i].data;

			if (uid_info == NULL) {
				char *b;
				long long uid = strtoll(spec_list[i].argv[0],
					&b, 10);

				uid_info = malloc(sizeof(struct uid_info));
				if (uid_info == NULL) {
					printf("Out of memory in action uid\n");
					continue;
				}

				if (*b == '\0') {
					if (uid < 0 || uid >= (1LL < 32)) {
						printf("action: uid out of "
							"range\n");
						continue;
					}
					uid_info->uid = uid;
				} else {
					struct passwd *uid =
						getpwnam(spec_list[i].argv[0]);
					if (uid)
						uid_info->uid = uid->pw_uid;
					else {
						printf("action: invalid uid or "
							"unknown user\n");
						continue;
					}
				}
				spec_list[i].data = uid_info;
			}

			inode->buf.st_uid = uid_info->uid;
			break;
		case GID_ACTION:
			gid_info = spec_list[i].data;

			if (gid_info == NULL) {
				char *b;
				long long gid = strtoll(spec_list[i].argv[0],
					&b, 10);

				gid_info = malloc(sizeof(struct gid_info));
				if (gid_info == NULL) {
					printf("Out of memory in action gid\n");
					continue;
				}

				if (*b == '\0') {
					if (gid < 0 || gid >= (1LL < 32)) {
						printf("action: gid out of "
							"range\n");
						continue;
					}
					gid_info->gid = gid;
				} else {
					struct group *gid =
						getgrnam(spec_list[i].argv[0]);
					if (gid)
						gid_info->gid = gid->gr_gid;
					else {
						printf("action: invalid gid or "
							"unknown user\n");
						continue;
					}
				}
				spec_list[i].data = gid_info;
			}

			inode->buf.st_gid = gid_info->gid;
			break;
		}
	}
}


/*
 * Test operation functions
 */
int name_fn(struct action *action, int argc, char **argv,
	struct action_data *action_data)
{
	return fnmatch(argv[0], action_data->name,
				FNM_PATHNAME|FNM_PERIOD|FNM_EXTMATCH) == 0;
}


int size_fn(struct action *action, int argc, char **argv,
	struct action_data *action_data)
{
	return 1;
}


static struct test_entry test_table[] = {
	{ "name", 1, name_fn},
	{ "size", 2, size_fn},
	{ "", -1 }
};


static struct action_entry action_table[] = {
	{ "fragment", FRAGMENT_ACTION, 1, NULL},
	{ "exclude", EXCLUDE_ACTION, 0, NULL},
	{ "fragments", FRAGMENTS_ACTION, 0, NULL},
	{ "no-fragments", NO_FRAGMENTS_ACTION, 0, NULL},
	{ "always-use-fragments", ALWAYS_FRAGS_ACTION, 0, NULL},
	{ "dont-always-use-fragments", NO_ALWAYS_FRAGS_ACTION, 0, NULL},
	{ "compressed", COMPRESSED_ACTION, 0, NULL},
	{ "uncompressed", UNCOMPRESSED_ACTION, 0, NULL},
	{ "uid", UID_ACTION, 1, NULL},
	{ "gid", GID_ACTION, 1, NULL},
	{ "", 0, -1, NULL}
};
