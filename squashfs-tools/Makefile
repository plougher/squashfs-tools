INSTALL_DIR = /usr/local/bin

INCLUDEDIR = .

CFLAGS := -I$(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -O2

all: mksquashfs unsquashfs

mksquashfs: mksquashfs.o read_fs.o sort.o swap.o
	$(CC) mksquashfs.o read_fs.o sort.o swap.o -lz -lpthread -lm -o $@

mksquashfs.o: mksquashfs.c squashfs_fs.h mksquashfs.h global.h sort.h squashfs_swap.h

read_fs.o: read_fs.c squashfs_fs.h read_fs.h global.h squashfs_swap.h Makefile

sort.o: sort.c squashfs_fs.h global.h sort.h Makefile

swap.o: swap.c Makefile

unsquashfs: unsquashfs.o
	$(CC) unsquashfs.o -lz -lpthread -lm -o $@

unsquashfs.o: unsquashfs.c squashfs_fs.h read_fs.h global.h Makefile

clean:
	-rm -f *.o mksquashfs unsquashfs

install: mksquashfs
	mkdir -p $(INSTALL_DIR)
	cp mksquashfs $(INSTALL_DIR)
