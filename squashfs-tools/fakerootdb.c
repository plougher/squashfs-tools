#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "fakerootdb.h"

#define FAKEROOT_ENTRY_FIELDS	7
#define FAKEROOT_ENTRY_FMT "dev=%lx,ino=%lu,mode=%o,uid=%u,gid=%u,nlink=%lu,rdev=%lu"

static int compare_by_dev_ino(const void *px, const void *py)
{
	struct stat const* const x = px;
	struct stat const* const y = py;

	if (x->st_dev < y->st_dev)
		return -1;
	else if (x->st_dev > y->st_dev)
		return 1;
	else if (x->st_ino < y->st_ino)
		return -1;
	else if (x->st_ino > y->st_ino)
		return 1;
	else
		return 0;
}

int fakeroot_read_db(FILE *fakedata, struct fakerootdb *db)
{
	struct stat elt, *d;
	int n;
	if (!db)
		return -EINVAL;
	if (db->db) {
		free(db->db);
		db->db = NULL;
		db->count = 0;
	}
	while (!feof(fakedata)) {
		if (ferror(fakedata))
			return -EIO;
		memset(&elt, 0, sizeof(elt));
		n = fscanf(fakedata,
			   FAKEROOT_ENTRY_FMT "\n",
			   &elt.st_dev,
			   &elt.st_ino,
			   &elt.st_mode,
			   &elt.st_uid,
			   &elt.st_gid,
			   &elt.st_nlink,
			   &elt.st_rdev);
		if (n != FAKEROOT_ENTRY_FIELDS)
			return -EINVAL;

		/* skip uid = gid = 0 entries, unless they are device nodes.
		 * fakeroot assumes uid = gid = 0 by default */
		if (elt.st_uid == 0 && elt.st_gid == 0 && elt.st_rdev == 0)
			continue;

		d = realloc(db->db, (db->count + 1)*sizeof(elt));
		if (!d)
			return -ENOMEM;
		memcpy(&d[db->count], &elt, sizeof(elt));
		db->db = d;
		db->count += 1;
	}
	qsort(db->db, db->count, sizeof(elt), compare_by_dev_ino);
	return 0;
}

void fakeroot_override_stat(struct stat *st, const struct fakerootdb *db)
{
	struct stat key;
	struct stat const* o = NULL;
	if (!db|| !db->db || db->count == 0)
		return;
	memset(&key, 0, sizeof(key));
	key.st_dev = st->st_dev;
	key.st_ino = st->st_ino;
	o = bsearch(&key, db->db, db->count, sizeof(key), compare_by_dev_ino);
	if (o) {
		st->st_mode = o->st_mode;
		st->st_uid = o->st_uid;
		st->st_gid = o->st_gid;
		st->st_rdev = o->st_rdev;
	} else {
		/* fakeroot sets uid=gid=0 if the object is not in the DB */
		st->st_uid = 0;
		st->st_gid = 0;
	}
}
