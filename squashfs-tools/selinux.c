/* Copyright 2015 The Android Open Source Project */

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <selinux/label.h>

#include "error.h"
#include "selinux.h"
#include "xattr.h"


#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))


squashfs_selinux_handle *get_sehnd(const char *context_file) {
	struct selinux_opt seopts[] = {
		{
			.type = SELABEL_OPT_PATH,
			.value = context_file
		}
	};
	struct selabel_handle *sehnd =
		selabel_open(SELABEL_CTX_FILE, seopts, ARRAY_SIZE(seopts));

	if(sehnd == NULL)
		BAD_ERROR("Failure calling selabel_open: %s\n", strerror(errno));

	return sehnd;
}

static char *set_selabel(const char *path, unsigned int mode, struct selabel_handle *sehnd) {
	char *secontext;
	if(sehnd == NULL)
		BAD_ERROR("selabel handle is NULL\n");

	int full_name_size = strlen(path) + 2;
	char* full_name = (char*) malloc(full_name_size);
	if(full_name == NULL)
		MEM_ERROR();

	full_name[0] = '/';
	strncpy(full_name + 1, path, full_name_size - 1);

	if(selabel_lookup(sehnd, &secontext, full_name, mode))
		secontext = strdup("u:object_r:unlabeled:s0");

	free(full_name);
	return secontext;
}

void read_selinux_xattr_from_context_file(char *filename, int mode,
	squashfs_selinux_handle *sehnd, struct xattr_list *xattrs) {
	char *attr_val;

	xattrs->type = get_prefix(xattrs, "security.selinux");
	attr_val = set_selabel(filename, mode, sehnd);
	xattrs->value = (void *)attr_val;
	xattrs->vsize = strlen(attr_val);
}

