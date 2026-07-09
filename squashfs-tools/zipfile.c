/*
 * Squashfs
 *
 * Copyright (c) 2026
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
 * zipfile.c
 */

#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <regex.h>
#include <errno.h>
#include <zlib.h>

#include "squashfs_fs.h"
#include "mksquashfs.h"
#include "mksquashfs_error.h"
#include "xattr.h"
#include "tar.h"
#include "zipfile.h"
#include "progressbar.h"
#include "info.h"
#include "symbolic_mode.h"
#include "reader.h"
#include "caches-queues-lists.h"
#include "alloc.h"
#include "archive.h"

#define TRUE 1
#define FALSE 0

/* Size of the compressed-input read chunk used when inflating */
#define ZIP_IN_CHUNK 65536

/* Command-line source archives, defined in mksquashfs.c */
extern int source;
extern char **source_path;

/*
 * A single surviving entry from the merged set of all input archives.  The
 * staging metadata (pathname, stat, symlink target, xattrs) lives in a
 * struct tar_file, which is reused verbatim from the tar reader so that the
 * generic tree-building, write_file() and xattr machinery can be shared.
 */
struct zip_entry {
	struct tar_file	*file;		/* parsed metadata (reused from tar) */
	int		zip;		/* index into zip_fd[] / zip_name[] */
	long long	offset;		/* local file header offset */
	long long	comp_size;	/* compressed size */
	long long	uncomp_size;	/* uncompressed size */
	long long	data_seq;	/* pre-assigned file_count of first block */
	int		method;		/* ZIP_STORED or ZIP_DEFLATE */
	int		excluded;	/* matched an -e/-ef pattern, drop it */
};

/* Populated by the central-directory parse, consumed by the reader threads */
static struct zip_entry *entries = NULL;
static int nentries = 0;

static int *zip_fd = NULL;
static char **zip_name = NULL;
static int nzips = 0;

/* Total number of data buffers (== total file_count span) */
static long long total_seq = 0;

/* Shared work counter handed out to the parallel reader threads */
static int next_entry = 0;
static pthread_mutex_t entry_mutex = PTHREAD_MUTEX_INITIALIZER;


/*
 * Little-endian accessors for the (untrusted) archive bytes.
 */
static unsigned int get16(unsigned char *p)
{
	return p[0] | (p[1] << 8);
}


static unsigned int get32(unsigned char *p)
{
	return (unsigned int) p[0] | (p[1] << 8) | (p[2] << 16) |
		((unsigned int) p[3] << 24);
}


static unsigned long long get64(unsigned char *p)
{
	return (unsigned long long) get32(p) |
		((unsigned long long) get32(p + 4) << 32);
}


/*
 * pread() wrapper that reads exactly count bytes, handling short reads and
 * EINTR.  Returns TRUE on success, FALSE if EOF or error is hit first.
 */
static int pread_exact(int fd, void *buf, long long count, long long offset)
{
	char *ptr = buf;

	while(count) {
		ssize_t res = pread(fd, ptr, count, offset);

		if(res == 0)
			return FALSE;
		if(res == -1) {
			if(errno == EINTR)
				continue;
			return FALSE;
		}

		ptr += res;
		offset += res;
		count -= res;
	}

	return TRUE;
}


/*
 * Strip any leading "/", "./" or "../" components from a pathname, matching
 * the behaviour of the tar reader.  Returns a newly allocated string.
 */
static char *normalise_pathname(char *name, int size)
{
	int length = size;
	char *filename = name;

	while(1) {
		if(length >= 3 && strncmp(filename, "../", 3) == 0) {
			filename += 3;
			length -= 3;
		} else if(length >= 2 && strncmp(filename, "./", 2) == 0) {
			filename += 2;
			length -= 2;
		} else if(length >= 1 && *filename == '/') {
			filename++;
			length--;
		} else
			break;
	}

	/* Drop a single trailing '/' (directory marker) */
	if(length && filename[length - 1] == '/')
		length--;

	return STRNDUP(filename, length);
}


/*
 * Convert an MS-DOS date/time pair into a Unix time (interpreted as UTC for
 * reproducibility).  DOS times have two-second resolution and a 1980 epoch.
 */
static time_t dos_to_unix(unsigned int dostime, unsigned int dosdate)
{
	struct tm tm;

	memset(&tm, 0, sizeof(tm));
	tm.tm_sec = (dostime & 0x1f) * 2;
	tm.tm_min = (dostime >> 5) & 0x3f;
	tm.tm_hour = (dostime >> 11) & 0x1f;
	tm.tm_mday = dosdate & 0x1f;
	tm.tm_mon = ((dosdate >> 5) & 0xf) - 1;
	tm.tm_year = ((dosdate >> 9) & 0x7f) + 80;
	tm.tm_isdst = 0;

	return timegm(&tm);
}


/*
 * Streaming decompressor for a single entry's data.
 */
struct unz {
	int		fd;
	long long	in_off;		/* next compressed byte in the file */
	long long	remaining;	/* compressed bytes left to read */
	int		method;
	z_stream	strm;
	int		strm_init;
	unsigned char	inbuf[ZIP_IN_CHUNK];
};


static int unz_init(struct unz *unz, struct zip_entry *entry)
{
	unsigned char lh[ZIP_LOCAL_SIZE];
	unsigned int name_len, extra_len;
	int fd = zip_fd[entry->zip];

	if(pread_exact(fd, lh, ZIP_LOCAL_SIZE, entry->offset) == FALSE)
		return FALSE;

	if(get32(lh) != ZIP_LOCAL_MAGIC)
		return FALSE;

	name_len = get16(lh + 26);
	extra_len = get16(lh + 28);

	unz->fd = fd;
	unz->in_off = entry->offset + ZIP_LOCAL_SIZE + name_len + extra_len;
	unz->remaining = entry->comp_size;
	unz->method = entry->method;
	unz->strm_init = FALSE;

	if(unz->method == ZIP_DEFLATE) {
		unz->strm.zalloc = Z_NULL;
		unz->strm.zfree = Z_NULL;
		unz->strm.opaque = Z_NULL;
		unz->strm.next_in = Z_NULL;
		unz->strm.avail_in = 0;

		/* Negative window bits selects raw deflate (no zlib header) */
		if(inflateInit2(&unz->strm, -15) != Z_OK)
			return FALSE;
		unz->strm_init = TRUE;
	} else if(unz->method != ZIP_STORED)
		return FALSE;

	return TRUE;
}


static void unz_end(struct unz *unz)
{
	if(unz->strm_init)
		inflateEnd(&unz->strm);
}


/*
 * Produce exactly want bytes of uncompressed data into dest.  Returns the
 * number of bytes produced (less than want only at end of the entry).
 */
static int unz_read(struct unz *unz, char *dest, int want)
{
	if(want == 0)
		return 0;

	if(unz->method == ZIP_STORED) {
		int n = want;

		if(n > unz->remaining)
			n = unz->remaining;
		if(n == 0)
			return 0;
		if(pread_exact(unz->fd, dest, n, unz->in_off) == FALSE)
			return -1;

		unz->in_off += n;
		unz->remaining -= n;
		return n;
	}

	unz->strm.next_out = (unsigned char *) dest;
	unz->strm.avail_out = want;

	while(unz->strm.avail_out) {
		int ret;

		if(unz->strm.avail_in == 0 && unz->remaining > 0) {
			int chunk = unz->remaining > ZIP_IN_CHUNK ?
				ZIP_IN_CHUNK : (int) unz->remaining;

			if(pread_exact(unz->fd, unz->inbuf, chunk,
							unz->in_off) == FALSE)
				return -1;

			unz->in_off += chunk;
			unz->remaining -= chunk;
			unz->strm.next_in = unz->inbuf;
			unz->strm.avail_in = chunk;
		}

		ret = inflate(&unz->strm, Z_NO_FLUSH);

		if(ret == Z_STREAM_END)
			break;
		if(ret != Z_OK && ret != Z_BUF_ERROR)
			return -1;
		if(ret == Z_BUF_ERROR && unz->strm.avail_in == 0 &&
							unz->remaining == 0)
			break;
	}

	return want - unz->strm.avail_out;
}


/*
 * Read and decompress one regular file's data, feeding it into the compression
 * pipeline.  Data buffers use the pre-assigned dense file_count so that the
 * sequenced to_main queue reassembles them in order regardless of which reader
 * thread produced them, or in what order.
 */
static void read_zip_data(struct reader *reader, struct zip_entry *entry)
{
	struct tar_file *file = entry->file;
	struct file_buffer *file_buffer;
	long long read_size = entry->uncomp_size;
	long long bytes = 0, seq = entry->data_seq;
	int blocks = (read_size + block_size - 1) >> block_log, block = 0;
	struct unz unz;

	if(unz_init(&unz, entry) == FALSE)
		BAD_ERROR("Failed to read zip entry %s from %s, the archive "
			"appears to be corrupt\n", file->pathname,
			zip_name[entry->zip]);

	do {
		file_buffer = cache_get_nohash(reader->buffer);
		file_buffer->file_size = read_size;
		file_buffer->tar_file = file;
		file_buffer->file_count = seq++;
		file_buffer->block = 0;
		file_buffer->version = 0;
		file_buffer->noD = noD;
		file_buffer->error = FALSE;
		file_buffer->next_state = NEXT_FILE;
		file_buffer->alignment = 0;
		file_buffer->thread = reader->id;

		if((block + 1) < blocks) {
			/* non-tail block should be exactly block_size */
			file_buffer->size = unz_read(&unz, file_buffer->data,
								block_size);
			if(file_buffer->size != block_size)
				BAD_ERROR("Failed to read zip entry %s from %s,"
					" the archive appears to be corrupt\n",
					file->pathname, zip_name[entry->zip]);

			bytes += file_buffer->size;
			file_buffer->fragment = FALSE;
			put_file_buffer(file_buffer, reader->id);
		} else {
			int expected = read_size - bytes;
			int size = unz_read(&unz, file_buffer->data, expected);

			if(size != expected)
				BAD_ERROR("Failed to read zip entry %s from %s,"
					" the archive appears to be corrupt\n",
					file->pathname, zip_name[entry->zip]);

			file_buffer->size = read_size - bytes;
		}
	} while(++block < blocks);

	file_buffer->fragment = is_fragment(read_size);
	put_file_buffer(file_buffer, reader->id);

	unz_end(&unz);
}


static int next_work()
{
	int idx;

	pthread_mutex_lock(&entry_mutex);
	idx = next_entry++;
	pthread_mutex_unlock(&entry_mutex);

	return idx;
}


static void *zip_worker(void *arg)
{
	struct reader *reader = arg;

	while(1) {
		int idx = next_work();
		struct zip_entry *entry;

		if(idx >= nentries)
			break;

		entry = &entries[idx];
		if(S_ISREG(entry->file->buf.st_mode) && !entry->excluded)
			read_zip_data(reader, entry);
	}

	return NULL;
}


/*
 * Reader-thread entry point.  The central directories have already been parsed
 * by process_zip_file() (running on the main thread), so all we do here is fan
 * out the entry list over the available reader threads.
 */
long long read_zip_file()
{
	int nreaders, i;
	struct reader *reader = get_readers(&nreaders);
	pthread_t *threads;

	if(nreaders < 1)
		nreaders = 1;

	threads = MALLOC(nreaders * sizeof(pthread_t));

	for(i = 1; i < nreaders; i++)
		pthread_create(&threads[i], NULL, zip_worker, &reader[i]);

	/* Use the current (reader) thread as worker 0 */
	zip_worker(&reader[0]);

	for(i = 1; i < nreaders; i++)
		pthread_join(threads[i], NULL);

	free(threads);

	return total_seq;
}


/*
 * Read (and decompress) the whole of a small entry's data into a freshly
 * allocated buffer.  Used for symbolic link targets, whose content is the link
 * destination.
 */
static char *read_entry_content(struct zip_entry *entry)
{
	struct unz unz;
	char *data;
	long long size = entry->uncomp_size, done = 0;

	if(unz_init(&unz, entry) == FALSE)
		return NULL;

	data = MALLOC(size + 1);

	while(done < size) {
		int want = size - done > INT_MAX ? INT_MAX : (int) (size - done);
		int res = unz_read(&unz, data + done, want);

		if(res <= 0) {
			free(data);
			unz_end(&unz);
			return NULL;
		}
		done += res;
	}

	data[size] = '\0';
	unz_end(&unz);

	return data;
}


/*
 * Parse a single extra field, extracting anything we understand (uid/gid,
 * timestamps, xattrs and the ZIP64 sizes).
 */
static void parse_extra(struct zip_entry *entry, unsigned char *extra,
	int extra_len, int size32, int csize32, int off32)
{
	struct tar_file *file = entry->file;

	while(extra_len >= 4) {
		unsigned int id = get16(extra);
		unsigned int len = get16(extra + 2);
		unsigned char *data = extra + 4;

		if(len > extra_len - 4)
			break;

		switch(id) {
		case ZIP_EXTRA_ZIP64: {
			/* Present in the order: uncomp, comp, offset - but only
			 * for those fields that were 0xffffffff */
			unsigned char *p = data;
			int left = len;

			if(size32 && left >= 8) {
				entry->uncomp_size = get64(p);
				file->buf.st_size = entry->uncomp_size;
				p += 8; left -= 8;
			}
			if(csize32 && left >= 8) {
				entry->comp_size = get64(p);
				p += 8; left -= 8;
			}
			if(off32 && left >= 8) {
				entry->offset = get64(p);
				p += 8; left -= 8;
			}
			break;
		}
		case ZIP_EXTRA_UT:
			/* flags byte, then mtime (if bit 0 set) */
			if(len >= 5 && (data[0] & 1))
				file->buf.st_mtime = (int) get32(data + 1);
			break;
		case ZIP_EXTRA_NEW_UNIX:
			/* version(1), uidsize(1), uid, gidsize(1), gid */
			if(len >= 3 && data[0] == 1) {
				int uidsize = data[1];

				if(len >= 2 + uidsize + 1) {
					int gidsize = data[2 + uidsize];

					if(uidsize == 4)
						file->buf.st_uid = get32(data + 2);
					if(len >= 2 + uidsize + 1 + gidsize &&
								gidsize == 4)
						file->buf.st_gid =
							get32(data + 3 + uidsize);
				}
			}
			break;
		case ZIP_EXTRA_XATTR: {
			unsigned char *p = data;
			int left = len;

			while(left >= 2) {
				int nl = get16(p);
				char *xname, *xval;

				p += 2; left -= 2;
				if(nl > left - 4)
					break;
				xname = STRNDUP((char *) p, nl);
				p += nl; left -= nl;

				if(left < 4) {
					free(xname);
					break;
				}
				int vl = get32(p);
				p += 4; left -= 4;
				if(vl > left) {
					free(xname);
					break;
				}
				xval = MALLOC(vl ? vl : 1);
				memcpy(xval, p, vl);
				p += vl; left -= vl;

				read_tar_xattr(xname, xval, vl, ENCODING_BINARY,
					file);
				free(xname);
				free(xval);
			}
			break;
		}
		default:
			break;
		}

		extra += 4 + len;
		extra_len -= 4 + len;
	}
}


/*
 * Parse one central-directory record at cd[0..].  Returns the number of bytes
 * consumed, or -1 on error.  On success *entryp points at the appended entry.
 */
static long long parse_central_record(unsigned char *cd, long long avail,
	int zip, struct zip_entry *entry)
{
	struct tar_file *file;
	unsigned int made_by, flags, method, name_len, extra_len, comment_len;
	unsigned int ext_attr, mode, host;
	long long comp_size, uncomp_size, offset;
	int size32, csize32, off32, type;
	char *name;

	if(avail < ZIP_CENTRAL_SIZE || get32(cd) != ZIP_CENTRAL_MAGIC)
		return -1;

	made_by = get16(cd + 4);
	host = made_by >> 8;
	flags = get16(cd + 8);
	method = get16(cd + 10);
	comp_size = get32(cd + 20);
	uncomp_size = get32(cd + 24);
	name_len = get16(cd + 28);
	extra_len = get16(cd + 30);
	comment_len = get16(cd + 32);
	ext_attr = get32(cd + 38);
	offset = get32(cd + 42);

	if(avail < (long long) ZIP_CENTRAL_SIZE + name_len + extra_len +
								comment_len)
		return -1;

	(void) flags;

	file = MALLOC(sizeof(struct tar_file));
	memset(file, 0, sizeof(struct tar_file));

	name = normalise_pathname((char *) (cd + ZIP_CENTRAL_SIZE), name_len);

	entry->file = file;
	entry->zip = zip;
	entry->offset = offset;
	entry->comp_size = comp_size;
	entry->uncomp_size = uncomp_size;
	entry->method = method;
	entry->data_seq = 0;

	size32 = uncomp_size == 0xffffffff;
	csize32 = comp_size == 0xffffffff;
	off32 = offset == 0xffffffff;

	/*
	 * Determine the file type and mode.  Unix-produced archives store the
	 * mode in the upper 16 bits of the external attributes; otherwise fall
	 * back to sensible defaults.
	 */
	mode = ext_attr >> 16;

	if(host == ZIP_HOST_UNIX && (mode & S_IFMT)) {
		file->buf.st_mode = mode;
		type = mode & S_IFMT;
	} else {
		/* No unix mode - infer directory from a trailing slash on the
		 * original name, everything else is a regular file */
		if(name_len && cd[ZIP_CENTRAL_SIZE + name_len - 1] == '/') {
			type = S_IFDIR;
			file->buf.st_mode = S_IFDIR | 0755;
		} else {
			type = S_IFREG;
			file->buf.st_mode = S_IFREG | 0644;
		}
		if(default_mode_opt)
			file->buf.st_mode = mode_execute(default_mode,
				file->buf.st_mode) | type;
	}

	/* A trailing slash always denotes a directory */
	if(name_len && cd[ZIP_CENTRAL_SIZE + name_len - 1] == '/') {
		type = S_IFDIR;
		file->buf.st_mode = (file->buf.st_mode & ~S_IFMT) | S_IFDIR;
	}

	file->pathname = name;
	file->buf.st_size = uncomp_size;
	file->buf.st_mtime = dos_to_unix(get16(cd + 12), get16(cd + 14));

	if(default_uid_opt)
		file->buf.st_uid = default_uid;
	else if(host != ZIP_HOST_UNIX)
		file->buf.st_uid = getuid();
	if(default_gid_opt)
		file->buf.st_gid = default_gid;
	else if(host != ZIP_HOST_UNIX)
		file->buf.st_gid = getgid();

	parse_extra(entry, cd + ZIP_CENTRAL_SIZE + name_len, extra_len,
		size32, csize32, off32);

	if(strlen(file->pathname) == 0) {
		/* Empty name after normalisation (e.g. the archive root) */
		free(file->pathname);
		free(file);
		entry->file = NULL;
		return ZIP_CENTRAL_SIZE + name_len + extra_len + comment_len;
	}

	if(S_ISLNK(file->buf.st_mode)) {
		char *link = read_entry_content(entry);

		if(link == NULL)
			BAD_ERROR("Failed to read symlink target for %s in %s\n",
				file->pathname, zip_name[zip]);
		file->link = link;
		/* Symlink permissions are always rwxrwxrwx */
		file->buf.st_mode = S_IFLNK | 0777;
	}

	return ZIP_CENTRAL_SIZE + name_len + extra_len + comment_len;
}


/*
 * Locate and read the central directory of one archive, appending every record
 * to the global entries[] array.
 */
static void parse_one_zip(int zip)
{
	int fd = zip_fd[zip];
	struct stat st;
	long long fsize, tail, cd_off, cd_size, i;
	long long cd_entries, scan;
	unsigned char *buffer, *eocd = NULL, *cd, *p;

	if(fstat(fd, &st) == -1)
		BAD_ERROR("Failed to stat zip file %s\n", zip_name[zip]);
	fsize = st.st_size;

	if(fsize < ZIP_EOCD_SIZE)
		BAD_ERROR("%s is too small to be a zip file\n", zip_name[zip]);

	/* The EOCD lies within the last 64KiB + 22 bytes (max comment) */
	tail = fsize < (65535 + ZIP_EOCD_SIZE) ? fsize : (65535 + ZIP_EOCD_SIZE);
	buffer = MALLOC(tail);
	if(pread_exact(fd, buffer, tail, fsize - tail) == FALSE)
		BAD_ERROR("Failed to read end of zip file %s\n", zip_name[zip]);

	for(scan = tail - ZIP_EOCD_SIZE; scan >= 0; scan--) {
		if(get32(buffer + scan) == ZIP_EOCD_MAGIC) {
			eocd = buffer + scan;
			break;
		}
	}

	if(eocd == NULL)
		BAD_ERROR("Could not find end-of-central-directory record in "
			"%s; is it a zip file?\n", zip_name[zip]);

	cd_entries = get16(eocd + 10);
	cd_size = get32(eocd + 12);
	cd_off = get32(eocd + 16);

	/* ZIP64: if any field is saturated, consult the ZIP64 EOCD record */
	if(cd_entries == 0xffff || cd_size == 0xffffffff ||
						cd_off == 0xffffffff) {
		long long loc_pos = (eocd - buffer) - ZIP_ZIP64_LOC_SIZE;

		if(loc_pos >= 0 && get32(buffer + loc_pos) ==
						ZIP_ZIP64_LOC_MAGIC) {
			long long z64_off = get64(buffer + loc_pos + 8);
			unsigned char z64[56];

			if(pread_exact(fd, z64, sizeof(z64), z64_off) == TRUE &&
					get32(z64) == ZIP_ZIP64_EOCD_MAGIC) {
				cd_entries = get64(z64 + 32);
				cd_size = get64(z64 + 40);
				cd_off = get64(z64 + 48);
			}
		}
	}

	free(buffer);

	if(cd_off + cd_size > fsize)
		BAD_ERROR("Central directory of %s extends past end of file\n",
			zip_name[zip]);

	cd = MALLOC(cd_size);
	if(pread_exact(fd, cd, cd_size, cd_off) == FALSE)
		BAD_ERROR("Failed to read central directory of %s\n",
			zip_name[zip]);

	p = cd;
	for(i = 0; i < cd_entries; i++) {
		long long consumed;
		struct zip_entry entry;

		memset(&entry, 0, sizeof(entry));
		consumed = parse_central_record(p, cd_size - (p - cd), zip,
			&entry);
		if(consumed == -1)
			BAD_ERROR("Corrupt central directory record in %s\n",
				zip_name[zip]);

		if(entry.file) {
			entries = REALLOC(entries, (nentries + 1) *
				sizeof(struct zip_entry));
			entries[nentries++] = entry;
		}

		p += consumed;
	}

	free(cd);
}


/*
 * A simple chained hash set keyed on pathname, used to detect entries that
 * share a path across (or within) archives.
 */
struct name_hash {
	char		*name;
	int		index;		/* index into entries[] */
	struct name_hash *next;
};

static struct name_hash **name_table = NULL;
static int name_table_size = 0;


static unsigned int name_hash(char *name)
{
	unsigned int hash = 5381;

	while(*name)
		hash = ((hash << 5) + hash) + (unsigned char) *name++;

	return hash & (name_table_size - 1);
}


/*
 * Resolve path collisions with last-wins semantics: when a later entry has the
 * same path as an earlier one, the earlier one is dropped and a warning is
 * emitted.  Returns a compacted list preserving archive order.
 */
static void resolve_collisions()
{
	int i, dropped = 0, out = 0;
	char *dropped_flag;

	if(nentries == 0)
		return;

	/* Table sized to the next power of two above nentries */
	name_table_size = 1;
	while(name_table_size < nentries)
		name_table_size <<= 1;

	name_table = MALLOC(name_table_size * sizeof(struct name_hash *));
	memset(name_table, 0, name_table_size * sizeof(struct name_hash *));

	dropped_flag = MALLOC(nentries);
	memset(dropped_flag, 0, nentries);

	for(i = 0; i < nentries; i++) {
		char *name = entries[i].file->pathname;
		unsigned int h = name_hash(name);
		struct name_hash *n;

		for(n = name_table[h]; n; n = n->next)
			if(strcmp(n->name, name) == 0)
				break;

		if(n) {
			/* An earlier entry has the same path - it loses.
			 * Directories appearing in more than one archive are a
			 * normal consequence of overlaying, so only warn when a
			 * real file is being overridden (or a type changes) */
			mode_t old_mode = entries[n->index].file->buf.st_mode;
			mode_t new_mode = entries[i].file->buf.st_mode;

			if(!(S_ISDIR(old_mode) && S_ISDIR(new_mode))) {
				ERROR("WARNING: '%s' in %s overrides earlier copy"
					" in %s\n", name,
					zip_name[entries[i].zip],
					zip_name[entries[n->index].zip]);
				dropped++;
			}
			dropped_flag[n->index] = TRUE;
			n->index = i;
		} else {
			n = MALLOC(sizeof(struct name_hash));
			n->name = name;
			n->index = i;
			n->next = name_table[h];
			name_table[h] = n;
		}
	}

	/* Compact, freeing the metadata of dropped entries */
	for(i = 0; i < nentries; i++) {
		if(dropped_flag[i]) {
			free_tar_xattrs(entries[i].file);
			free(entries[i].file->pathname);
			free(entries[i].file->link);
			free(entries[i].file);
		} else
			entries[out++] = entries[i];
	}
	nentries = out;

	for(i = 0; i < name_table_size; i++) {
		struct name_hash *n = name_table[i], *next;

		for(; n; n = next) {
			next = n->next;
			free(n);
		}
	}
	free(name_table);
	free(dropped_flag);

	if(dropped)
		INFO("%d duplicate path%s overridden across the input "
			"archives\n", dropped, dropped == 1 ? "" : "s");
}


/*
 * Determine up front whether an entry's pathname is excluded by the -e/-ef
 * patterns, walking the path components through excluded() exactly as
 * add_zipfile() does when it builds the tree.  excluded() is a pure function of
 * (component name, search set), independent of tree state, so the verdict here
 * matches what add_zipfile() would decide.  Because the central directory gives
 * us every pathname before any data is read, excluded entries can be dropped
 * from the sequence entirely - they are never inflated, sequenced or drained.
 */
static int zip_excluded(char *source)
{
	struct pathnames *cur = paths;
	struct pathnames *new, *prev = NULL;
	char *name;
	int res;

	/* The legacy dev/inode exclude code cannot be used with zip files, and
	 * option parsing forbids that combination, so there is nothing to test
	 * unless the wildcard/regex matcher is active */
	if(old_exclude)
		return FALSE;

	while(1) {
		source = get_component(source, &name);
		new = NULL;
		res = excluded(name, cur, &new);
		free(name);
		free(prev);		/* container from the previous level */
		if(res) {
			free(new);
			return TRUE;
		}
		if(source[0] == '\0') {
			free(new);
			return FALSE;
		}
		prev = cur = new;	/* search set for the next component */
	}
}


/*
 * Assign each regular file a dense range of file_count values, matching the
 * order in which the main thread will consume the data via write_file().
 * Excluded entries are marked here and left out of the sequence.
 */
static void assign_sequence()
{
	int i;
	long long seq = 0;

	for(i = 0; i < nentries; i++) {
		struct zip_entry *entry = &entries[i];

		entry->excluded = zip_excluded(entry->file->pathname);

		if(!S_ISREG(entry->file->buf.st_mode) || entry->excluded)
			continue;

		entry->data_seq = seq;

		if(entry->uncomp_size == 0)
			seq += 1;
		else
			seq += (entry->uncomp_size + block_size - 1) >> block_log;

		progress_bar_size((entry->uncomp_size + block_size - 1)
								>> block_log);
	}

	total_seq = seq;
}


static void parse_all_zips()
{
	int i;

	if(source == 0)
		BAD_ERROR("No zip files specified on the command line\n");

	nzips = source;
	zip_fd = MALLOC(nzips * sizeof(int));
	zip_name = MALLOC(nzips * sizeof(char *));

	for(i = 0; i < nzips; i++) {
		zip_name[i] = source_path[i];
		while((zip_fd[i] = open(source_path[i], O_RDONLY)) == -1 &&
								errno == EINTR);
		if(zip_fd[i] == -1)
			BAD_ERROR("Could not open zip file %s\n", source_path[i]);
	}

	for(i = 0; i < nzips; i++)
		parse_one_zip(i);

	resolve_collisions();
	assign_sequence();
}


squashfs_inode process_zip_file(int progress)
{
	struct dir_info *new;
	struct dir_ent *dir_ent;
	struct zip_entry *entry;
	int i;

	/* Parse every archive's central directory before starting the readers */
	parse_all_zips();

	/* Release the reader thread, which now fans out over entries[] */
	queue_put(to_reader, NULL);
	set_progressbar_state(progress);

	for(i = 0; i < nentries; i++) {
		struct tar_file *file;

		entry = &entries[i];
		file = entry->file;

		/* Excluded entries were never inflated or sequenced, so there is
		 * no data to consume - skip them without touching the pipeline */
		if(entry->excluded)
			continue;

		new = add_archive_file(root_dir, file->pathname, "", file,
			paths, 1, &dir_ent, NULL, "zipfile");

		if(new) {
			int duplicate_file;
			root_dir = new;

			if(S_ISREG(file->buf.st_mode) &&
						dir_ent->inode->read == FALSE) {
				update_info(dir_ent);
				file->file = write_file(dir_ent, &duplicate_file);
				dir_ent->inode->read = TRUE;
				INFO("file %s, uncompressed size %lld bytes %s\n",
					file->pathname,
					(long long) file->buf.st_size,
					duplicate_file ? "DUPLICATE" : "");
			}
		} else if(S_ISREG(file->buf.st_mode))
			/* Path collisions are resolved before sequencing, so the
			 * only reason add_zipfile() drops a regular file is
			 * exclusion, which is handled above.  Reaching here means
			 * a file's data was inflated but never written, which
			 * would desync the sequenced pipeline */
			BAD_ERROR("Internal error: zip entry %s was inflated but "
				"not added to the filesystem tree\n",
				file->pathname);
	}

	return create_root_scan(progress);
}
