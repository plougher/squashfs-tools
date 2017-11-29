/* Copyright 2015 The Android Open Source Project */

#ifndef SELINUX_H
#define SELINUX_H

#include "xattr.h"

#ifdef SELINUX_SUPPORT
typedef struct selabel_handle squashfs_selinux_handle;
extern squashfs_selinux_handle *get_sehnd(const char *context_file);
extern void read_selinux_xattr_from_context_file(char *filename, int mode,
	struct selabel_handle *sehnd, struct xattr_list *xattrs);
#else
typedef void squashfs_selinux_handle;


static squashfs_selinux_handle *get_sehnd(const char *context_file) {
	return NULL;
}


static void read_selinux_xattr_from_context_file(char *filename, int mode,
	squashfs_selinux_handle *sehnd, struct xattr_list *xattrs) {
}
#endif

#endif
