INSTALL_DIR = /usr/local/bin

INCLUDEDIR = .

CFLAGS := -I$(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -D_GNU_SOURCE -O2

all: mksquashfs unsquashfs

mksquashfs: mksquashfs.o read_fs.o sort.o swap.o pseudo.o
	$(CC) mksquashfs.o read_fs.o sort.o swap.o pseudo.o -lz -lpthread -lm -o $@

mksquashfs.o: mksquashfs.c squashfs_fs.h mksquashfs.h global.h sort.h squashfs_swap.h Makefile

read_fs.o: read_fs.c squashfs_fs.h read_fs.h global.h squashfs_swap.h Makefile

sort.o: sort.c squashfs_fs.h global.h sort.h Makefile

swap.o: swap.c Makefile

pseudo.o: pseudo.c pseudo.h Makefile

unsquashfs: unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o unsquash-4.o swap.o
	$(CC) unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o unsquash-4.o swap.o -lz -lpthread -lm -o $@

unsquashfs.o: unsquashfs.h unsquashfs.c squashfs_fs.h squashfs_swap.h squashfs_compat.h global.h Makefile

unsquash-1.o: unsquashfs.h unsquash-1.c squashfs_fs.h squashfs_compat.h global.h Makefile

unsquash-2.o: unsquashfs.h unsquash-2.c unsquashfs.h squashfs_fs.h squashfs_compat.h global.h Makefile

unsquash-3.o: unsquashfs.h unsquash-3.c squashfs_fs.h squashfs_compat.h global.h Makefile

unsquash-4.o: unsquashfs.h unsquash-4.c squashfs_fs.h squashfs_swap.h global.h Makefile

clean:
	-rm -f *.o mksquashfs unsquashfs

install: mksquashfs unsquashfs
	mkdir -p $(INSTALL_DIR)
	cp mksquashfs $(INSTALL_DIR)
	cp unsquashfs $(INSTALL_DIR)
