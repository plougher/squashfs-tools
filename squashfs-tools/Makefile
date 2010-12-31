###############################################
#          Compression build options          #
###############################################
#
#
############# Building gzip support ###########
#
# Gzip support is by default enabled, and the compression type default
# (COMP_DEFAULT) is gzip.
#
# If you don't want/need gzip support then comment out the GZIP SUPPORT line
# below, and change COMP_DEFAULT to one of the compression types you have
# selected.
#
# Obviously, you must select at least one of the available gzip, lzma, lzo
# compression types.
#
GZIP_SUPPORT = 1


########### Building LZMA support #############
#
# LZMA1 compression.
#
# Both XZ Utils liblzma (http://tukaani.org/xz/) and LZMA SDK
# (http://www.7-zip.org/sdk.html) are supported
#
# To build using XZ Utils liblzma - install the library and uncomment
# the LZMA_XZ_SUPPORT line below.
#
# To build using the LZMA SDK (4.65 used in development, other versions may
# work) - download and unpack it, uncomment and set LZMA_DIR to unpacked source,
# and uncomment the LZMA_SUPPORT line below.
#
#LZMA_XZ_SUPPORT = 1
#LZMA_SUPPORT = 1
#LZMA_DIR = ../../../../LZMA/lzma465

########### Building XZ support #############
#
# LZMA2 compression.
#
# XZ Utils liblzma (http://tukaani.org/xz/) is supported
#
# To build using XZ Utils liblzma - install the library and uncomment
# the XZ_SUPPORT line below.
#
#XZ_SUPPORT = 1


############ Building LZO support ##############
#
# The LZO library (http://www.oberhumer.com/opensource/lzo/) is supported.
#
# To build using the LZO library - install the library and uncomment the
# LZO_SUPPORT line below. If needed, uncomment and set LZO_DIR to the
# installation prefix.
#
#LZO_SUPPORT = 1
#LZO_DIR = /usr/local


######## Specifying default compression ########
#
# The next line specifies which compression algorithm is used by default
# in Mksquashfs.  Obviously the compression algorithm must have been
# selected to be built
#
COMP_DEFAULT = gzip

###############################################
#  Extended attribute (XATTRs) build options  #
###############################################
#
# Building XATTR support for Mksquashfs and Unsquashfs
#
# If your C library or build/target environment doesn't support XATTRs then
# comment out the next line to build Mksquashfs and Unsquashfs without XATTR
# support
XATTR_SUPPORT = 1

# Select whether you wish xattrs to be stored by Mksquashfs and extracted
# by Unsquashfs by default.  If selected users can disable xattr support by
# using the -no-xattrs option
#
# If unselected, Mksquashfs/Unsquashfs won't store and extract xattrs by
# default.  Users can enable xattrs by using the -xattrs option.
XATTR_DEFAULT = 1


###############################################
#        End of BUILD options section         #
###############################################

INCLUDEDIR = -I.
INSTALL_DIR = /usr/local/bin

MKSQUASHFS_OBJS = mksquashfs.o read_fs.o sort.o swap.o pseudo.o compressor.o

UNSQUASHFS_OBJS = unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o \
	unsquash-4.o swap.o compressor.o

CFLAGS = $(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE \
	-D_GNU_SOURCE -DCOMP_DEFAULT=\"$(COMP_DEFAULT)\"  -O2 -Wall

LIBS = -lpthread -lm
ifdef GZIP_SUPPORT
CFLAGS += -DGZIP_SUPPORT
MKSQUASHFS_OBJS += gzip_wrapper.o
UNSQUASHFS_OBJS += gzip_wrapper.o
LIBS += -lz
COMPRESSORS += gzip
endif

ifdef LZMA_SUPPORT
LZMA_OBJS = $(LZMA_DIR)/C/Alloc.o $(LZMA_DIR)/C/LzFind.o \
	$(LZMA_DIR)/C/LzmaDec.o $(LZMA_DIR)/C/LzmaEnc.o $(LZMA_DIR)/C/LzmaLib.o
INCLUDEDIR += -I$(LZMA_DIR)/C
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
UNSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
COMPRESSORS += lzma
endif

ifdef LZMA_XZ_SUPPORT
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += lzma_xz_wrapper.o
UNSQUASHFS_OBJS += lzma_xz_wrapper.o
LIBS += -llzma
COMPRESSORS += lzma
endif

ifdef XZ_SUPPORT
CFLAGS += -DXZ_SUPPORT
MKSQUASHFS_OBJS += xz_wrapper.o
UNSQUASHFS_OBJS += xz_wrapper.o
LIBS += -llzma
COMPRESSORS += xz
endif

ifdef LZO_SUPPORT
CFLAGS += -DLZO_SUPPORT
ifdef LZO_DIR
INCLUDEDIR += -I$(LZO_DIR)/include
LZO_LIBDIR = -L$(LZO_DIR)/lib
endif
MKSQUASHFS_OBJS += lzo_wrapper.o
UNSQUASHFS_OBJS += lzo_wrapper.o
LIBS += $(LZO_LIBDIR) -llzo2
COMPRESSORS += lzo
endif

ifdef XATTR_SUPPORT
ifdef XATTR_DEFAULT
CFLAGS += -DXATTR_SUPPORT -DXATTR_DEFAULT
else
CFLAGS += -DXATTR_SUPPORT
endif
MKSQUASHFS_OBJS += xattr.o read_xattrs.o
UNSQUASHFS_OBJS += read_xattrs.o unsquashfs_xattr.o
endif

#
# If LZMA_SUPPORT is specified then LZMA_DIR must be specified too
#
ifdef LZMA_SUPPORT
ifndef LZMA_DIR
$(error "LZMA_SUPPORT requires LZMA_DIR to be also defined")
endif
endif

#
# Both LZMA_XZ_SUPPORT and LZMA_SUPPORT cannot be specified
#
ifdef LZMA_XZ_SUPPORT
ifdef LZMA_SUPPORT
$(error "Both LZMA_XZ_SUPPORT and LZMA_SUPPORT cannot be specified")
endif
endif

#
# At least one compressor must have been selected
#
ifndef COMPRESSORS
$(error "No compressor selected! Select one or more of GZIP, LZMA, XZ or LZO!")
endif

#
# COMP_DEFAULT must be a selected compressor
#
ifeq (, $(findstring $(COMP_DEFAULT), $(COMPRESSORS)))
$(error "COMP_DEFAULT isn't selected to be built!")
endif

.PHONY: all
all: mksquashfs unsquashfs

mksquashfs: $(MKSQUASHFS_OBJS)
	$(CC) $(MKSQUASHFS_OBJS) $(LIBS) -o $@

mksquashfs.o: mksquashfs.c squashfs_fs.h mksquashfs.h global.h sort.h \
	squashfs_swap.h xattr.h pseudo.h compressor.h

read_fs.o: read_fs.c squashfs_fs.h read_fs.h global.h squashfs_swap.h \
	compressor.h xattr.h

sort.o: sort.c squashfs_fs.h global.h sort.h mksquashfs.h

swap.o: swap.c

pseudo.o: pseudo.c pseudo.h

compressor.o: compressor.c compressor.h squashfs_fs.h

xattr.o: xattr.c xattr.h squashfs_fs.h global.h squashfs_swap.h mksquashfs.h

read_xattrs.o: read_xattrs.c xattr.h squashfs_fs.h global.h squashfs_swap.h \
	read_fs.h

gzip_wrapper.o: gzip_wrapper.c compressor.h squashfs_fs.h

lzma_wrapper.o: lzma_wrapper.c compressor.h squashfs_fs.h

lzma_xz_wrapper.o: lzma_xz_wrapper.c compressor.h squashfs_fs.h

lzo_wrapper.o: lzo_wrapper.c compressor.h squashfs_fs.h

xz_wrapper.o: xz_wrapper.c compressor.h squashfs_fs.h

unsquashfs: $(UNSQUASHFS_OBJS)
	$(CC) $(UNSQUASHFS_OBJS) $(LIBS) -o $@

unsquashfs.o: unsquashfs.h unsquashfs.c squashfs_fs.h squashfs_swap.h \
	squashfs_compat.h global.h xattr.h read_fs.h compressor.h

unsquash-1.o: unsquashfs.h unsquash-1.c squashfs_fs.h squashfs_compat.h \
	global.h

unsquash-2.o: unsquashfs.h unsquash-2.c squashfs_fs.h squashfs_compat.h \
	global.h

unsquash-3.o: unsquashfs.h unsquash-3.c squashfs_fs.h squashfs_compat.h \
	global.h

unsquash-4.o: unsquashfs.h unsquash-4.c squashfs_fs.h squashfs_swap.h \
	global.h read_fs.h

unsquashfs_xattr.o: unsquashfs_xattr.c unsquashfs.h squashfs_fs.h global.h \
	xattr.h
	

.PHONY: clean
clean:
	-rm -f *.o mksquashfs unsquashfs

.PHONY: install
install: mksquashfs unsquashfs
	mkdir -p $(INSTALL_DIR)
	cp mksquashfs $(INSTALL_DIR)
	cp unsquashfs $(INSTALL_DIR)
