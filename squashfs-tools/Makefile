#
# Building LZMA support
#
# Both XZ Utils liblzma  (http://tukaani.org/xz/) and LZMA SDK
# (http://www.7-zip.org/sdk.html) are supported
#
# To build using XZ Utils liblzma - install the library and uncomment
# the XZ_SUPPORT line below.
#
# To build using the LZMA SDK (4.65 used in development, other versions may
# work) - download and unpack it, uncomment and set LZMA_DIR to unpacked source,
# and uncomment the LZMA_SUPPORT line below.

#XZ_SUPPORT = 1
#LZMA_SUPPORT = 1
#LZMA_DIR = ../../../LZMA/lzma465

#Compression default.
COMP_DEFAULT = gzip

INCLUDEDIR = -I.
INSTALL_DIR = /usr/local/bin

MKSQUASHFS_OBJS = mksquashfs.o read_fs.o sort.o swap.o pseudo.o compressor.o \
	gzip_wrapper.o xattr.o read_xattrs.o

UNSQUASHFS_OBJS = unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o \
	unsquash-4.o swap.o compressor.o gzip_wrapper.o

CFLAGS = $(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE \
	-D_GNU_SOURCE -DCOMP_DEFAULT=\"$(COMP_DEFAULT)\" -O2 -Wall

LIBS =
ifdef LZMA_SUPPORT
LZMA_OBJS = $(LZMA_DIR)/C/Alloc.o $(LZMA_DIR)/C/LzFind.o \
	$(LZMA_DIR)/C/LzmaDec.o $(LZMA_DIR)/C/LzmaEnc.o $(LZMA_DIR)/C/LzmaLib.o
INCLUDEDIR += -I$(LZMA_DIR)/C
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
UNSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
endif

ifdef XZ_SUPPORT
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += xz_wrapper.o
UNSQUASHFS_OBJS += xz_wrapper.o
LIBS += -llzma
endif

.PHONY: all
all: mksquashfs unsquashfs

mksquashfs: $(MKSQUASHFS_OBJS)
	$(CC) $(MKSQUASHFS_OBJS) -lz -lpthread -lm $(LIBS) -o $@

mksquashfs.o: mksquashfs.c squashfs_fs.h mksquashfs.h global.h sort.h \
	squashfs_swap.h

read_fs.o: read_fs.c squashfs_fs.h read_fs.h global.h squashfs_swap.h

sort.o: sort.c squashfs_fs.h global.h sort.h

swap.o: swap.c

pseudo.o: pseudo.c pseudo.h

compressor.o: compressor.c compressor.h

xattr.o: xattr.h

read_xattrs.o: xattr.h

unsquashfs: $(UNSQUASHFS_OBJS)
	$(CC) $(UNSQUASHFS_OBJS) -lz -lpthread -lm $(LIBS) -o $@

unsquashfs.o: unsquashfs.h unsquashfs.c squashfs_fs.h squashfs_swap.h \
	squashfs_compat.h global.h

unsquash-1.o: unsquashfs.h unsquash-1.c squashfs_fs.h squashfs_compat.h \
	global.h

unsquash-2.o: unsquashfs.h unsquash-2.c unsquashfs.h squashfs_fs.h \
	squashfs_compat.h global.h

unsquash-3.o: unsquashfs.h unsquash-3.c squashfs_fs.h squashfs_compat.h \
	global.h

unsquash-4.o: unsquashfs.h unsquash-4.c squashfs_fs.h squashfs_swap.h \
	global.h

.PHONY: clean
clean:
	-rm -f *.o mksquashfs unsquashfs

.PHONY: install
install: mksquashfs unsquashfs
	mkdir -p $(INSTALL_DIR)
	cp mksquashfs $(INSTALL_DIR)
	cp unsquashfs $(INSTALL_DIR)
