#ifndef SQUASHFS_FAKEROOTDB_H
#define SQUASHFS_FAKEROOTDB_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

struct fakerootdb {
	struct stat *db;
	size_t count;
};

int fakeroot_read_db(FILE *fakedata, struct fakerootdb *db);

void fakeroot_override_stat(struct stat *st, const struct fakerootdb *fakerootdb);

#endif /* SQUASHFS_FAKEROOTDB_H */
