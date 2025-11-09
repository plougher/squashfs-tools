# Squashfs-tools 4.7.4 release
RELEASE_VERSION = 4.7.4
RELEASE_DATE = 2025/11/09
###############################################
#                Build options                #
###############################################
#
# Edit the following definitions to customise the build, or run
# "CONFIG=1 make" with the build options below to customise the build on
# the command line.
#
ifndef CONFIG
###############################################
#            Compression algorithms           #
###############################################
#
# All of the compression algorithms (gzip, lzo, lz4, xz and zstd) are
# by default selected to be built.
#
# To unselect an algorithm comment out the XXX_SUPPORT = 1 line.
#
# Obviously you may need to install the compression algorithm devel
# packages, otherwise the build will fail.
#
############# Building gzip support ###########
#
# The compression type default (COMP_DEFAULT) is gzip.
#
# If you don't want/need gzip support then comment out the GZIP SUPPORT line
# below, and change COMP_DEFAULT to one of the compression types you have
# selected.
#
# Obviously at least one of the compression types must be built and selected
# as the default compression type.
#
GZIP_SUPPORT = 1

########### Building XZ support #############
#
# LZMA2 compression.
#
# XZ Utils liblzma (https://tukaani.org/xz/) is supported
#
# Development packages (libraries and header files) should be
# supported by most modern distributions.  Please refer to
# your distribution package manager.
#
# To skip building ZX support comment out the line below.
XZ_SUPPORT = 1

# Enable support for OpenWrt extended compression options by uncommenting
# next line.  Do not do this unless you understand the implications.
#XZ_EXTENDED_OPTIONS = 1


############ Building LZO support ##############
#
# The LZO library (http://www.oberhumer.com/opensource/lzo/) is supported.
#
# Development packages (libraries and header files) should be
# supported by most modern distributions.  Please refer to
# your distribution package manager.
#
# To skip building LZO support comment out the line below.
LZO_SUPPORT = 1


########### Building LZ4 support #############
#
# Yann Collet's LZ4 tools are supported
# LZ4 homepage: https://lz4.github.io/lz4/
# LZ4 source repository: https://github.com/lz4/lz4/
#
# Development packages (libraries and header files) should be
# supported by most modern distributions.  Please refer to
# your distribution package manager.
#
# To skip building LZ4 support comment out the line below.
LZ4_SUPPORT = 1


########### Building ZSTD support ############
#
# The ZSTD library is supported
# ZSTD homepage: https://facebook.github.io/zstd/
# ZSTD source repository: https://github.com/facebook/zstd
#
# Development packages (libraries and header files) should be
# supported by most modern distributions.  Please refer to
# your distribution package manager.
#
# To skip building ZSTD support comment out the line below.
ZSTD_SUPPORT = 1


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
# Building XATTR support for Squashfs tools.
#
# If you don't want to read, write or store XATTRs in Squashfs
# filesystems, then comment out the next definition.  Generally
# speaking you want to define this option even if your C library
# or operating system doesn't support XATTRs, because this option
# contains support to add XATTRs to the Squashfs filesystem
# on the command line, via actions and input and output them via
# pseudo-files etc. which is independent of library/OS support.
XATTR_SUPPORT = 1

# If your C library or operating system doesn't support XATTRs then
# this definition is the one you should comment out.  Commenting
# this out will not build code to read XATTRs from the source filesystem
# or write XATTRs to the target filesystem.
XATTR_OS_SUPPORT = 1

# Select whether you wish xattrs to be stored by Mksquashfs and extracted
# by Unsquashfs by default.  If selected users can disable xattr support by
# using the -no-xattrs option
#
# If unselected, Mksquashfs/Unsquashfs won't store and extract xattrs by
# default.  Users can enable xattrs by using the -xattrs option.
XATTR_DEFAULT = 1


###############################################
#       Parallel reader thread options        #
###############################################
#
# Select how many reader threads are enabled by default.  The options are:
#
# 1. A single reader thread, as was traditionally used in Mksquashfs.  This
#    is the lowest performing and most conservative option.
#
# 2. The default number of small reader threads and block reader threads given
#    here.  These values are intended to give a peformance boost on media
#    that will benefit from parallel reads (e.g. modern SSD drives), but not
#    affect performance on other media that won't benefit from parallel reads.
#
# 3. A custom default setting of small reader threads and block reader threads.
#    The higher the number of threads the greater the performance boost on
#    filesystems with lots of small files, and/or media that benefits from
#    a high amount of parallelism such as network filesystems.
#
# Uncomment next line to use a single reader thread
#SINGLE_READER_THREAD = 1
SMALL_READER_THREADS = 4
BLOCK_READER_THREADS = 4

###############################################
#               Manpage generation            #
###############################################
#
# If help2man is available on the system, on installation, the Makefile
# will try to generate "custom" manpages from the built squashfs-tools.
#
# If the squashfs-tools have been cross-compiled, or for any other
# reason they're not executable, this will generate errors at
# installation and the install script will fall back to using
# pre-built manpages.
#
# Change next variable to "y" to use the pre-built manpages by default,
# and not attempt to generate "custom" manpages.  This will eliminate
# errors and warnings at install time.
USE_PREBUILT_MANPAGES = n

###############################################
#              INSTALL PATHS                  #
###############################################
#
# Alter INSTALL_* to install binaries and manpages
# elsewhere.
#
# To skip building and installing manpages,
# unset INSTALL_MANPAGES_DIR or set to ""
#
INSTALL_PREFIX = /usr/local
INSTALL_DIR = $(INSTALL_PREFIX)/bin
INSTALL_MANPAGES_DIR = $(INSTALL_PREFIX)/man/man1

###############################################
#             __ATOMIC_EXCHANGE_N             #
###############################################
#
# Mksquashfs uses a GCC builtin (also supported by Clang)
# __atomic_exchange_n() to do lockless thread synchronisation.
# If this is unavailable on your compiler, uncomment
# the line below to use a (slower) Pthread mutex.
#DONT_USE_ATOMIC_EXCHANGE_N = 1

###############################################
#              Obsolete options               #
###############################################

########### Building LZMA support #############
#
# LZMA1 compression.
#
# LZMA1 compression is obsolete, and the newer and better XZ (LZMA2)
# compression should be used in preference.
#
# Both XZ Utils liblzma (https://tukaani.org/xz/) and LZMA SDK
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
else
GZIP_SUPPORT ?= 1
XZ_SUPPORT ?= 1
LZO_SUPPORT ?= 1
LZ4_SUPPORT ?= 1
ZSTD_SUPPORT ?= 1
COMP_DEFAULT ?= gzip
XATTR_SUPPORT ?= 1
XATTR_OS_SUPPORT ?= 1
XATTR_DEFAULT ?= 1
USE_PREBUILT_MANPAGES ?= n
INSTALL_PREFIX ?= /usr/local
INSTALL_DIR ?= $(INSTALL_PREFIX)/bin
INSTALL_MANPAGES_DIR ?= $(INSTALL_PREFIX)/man/man1
LZMA_XZ_SUPPORT ?= 0
LZMA_SUPPORT ?= 0
LZMA_DIR ?= ../../../../LZMA/lzma465
XZ_EXTENDED_OPTIONS ?= 0
DONT_USE_ATOMIC_EXCHANGE_N ?= 0
SINGLE_READER_THREAD ?= 0
SMALL_READER_THREADS ?= 8
BLOCK_READER_THREADS ?= 3
endif


###############################################
#        End of BUILD options section         #
###############################################
#
INCLUDEDIR = -I.

MKSQUASHFS_OBJS = mksquashfs.o read_fs.o action.o swap.o pseudo.o compressor.o \
	sort.o progressbar.o info.o restore.o process_fragments.o \
	caches-queues-lists.o reader.o tar.o date.o memory.o mksquashfs_help.o \
	print_pager.o symbolic_mode.o thread.o nprocessors_compat.o limit.o \
	virt_disk_pos.o

UNSQUASHFS_OBJS = unsquashfs.o unsquash-1.o unsquash-2.o unsquash-3.o \
	unsquash-4.o unsquash-123.o unsquash-34.o unsquash-1234.o unsquash-12.o \
	swap.o compressor.o unsquashfs_info.o date.o memory.o print_pager.o \
	unsquashfs_help.o nprocessors_compat.o limit.o

CFLAGS ?= -O2
CFLAGS += $(EXTRA_CFLAGS) $(INCLUDEDIR) -D_FILE_OFFSET_BITS=64 \
	-D_LARGEFILE_SOURCE -D_GNU_SOURCE -DCOMP_DEFAULT=\"$(COMP_DEFAULT)\" \
	-Wall

LIBS = -lpthread -lm
ifeq ($(GZIP_SUPPORT),1)
CFLAGS += -DGZIP_SUPPORT
MKSQUASHFS_OBJS += gzip_wrapper.o
UNSQUASHFS_OBJS += gzip_wrapper.o
LIBS += -lz
ifeq ($(COMP_DEFAULT),gzip)
COMPRESSORS += gzip@(default)
else
COMPRESSORS += gzip
endif
endif

ifeq ($(LZO_SUPPORT),1)
CFLAGS += -DLZO_SUPPORT
MKSQUASHFS_OBJS += lzo_wrapper.o
UNSQUASHFS_OBJS += lzo_wrapper.o
LIBS += -llzo2
ifeq ($(COMP_DEFAULT),lzo)
COMPRESSORS += lzo@(default)
else
COMPRESSORS += lzo
endif
endif

ifeq ($(LZ4_SUPPORT),1)
CFLAGS += -DLZ4_SUPPORT
MKSQUASHFS_OBJS += lz4_wrapper.o
UNSQUASHFS_OBJS += lz4_wrapper.o
LIBS += -llz4
ifeq ($(COMP_DEFAULT),lz4)
COMPRESSORS += lz4@(default)
else
COMPRESSORS += lz4
endif
endif

ifeq ($(XZ_SUPPORT),1)
CFLAGS += -DXZ_SUPPORT
ifeq ($(XZ_EXTENDED_OPTIONS),1)
MKSQUASHFS_OBJS += xz_wrapper_extended.o
UNSQUASHFS_OBJS += xz_wrapper_extended.o
else
MKSQUASHFS_OBJS += xz_wrapper.o
UNSQUASHFS_OBJS += xz_wrapper.o
endif
LIBS += -llzma
ifeq ($(COMP_DEFAULT),xz)
COMPRESSORS += xz@(default)
else
COMPRESSORS +=xz
endif
endif

ifeq ($(ZSTD_SUPPORT),1)
CFLAGS += -DZSTD_SUPPORT
MKSQUASHFS_OBJS += zstd_wrapper.o
UNSQUASHFS_OBJS += zstd_wrapper.o
LIBS += -lzstd
ifeq ($(COMP_DEFAULT),zstd)
COMPRESSORS += zstd@(default)
else
COMPRESSORS += zstd
endif
endif

ifeq ($(LZMA_SUPPORT),1)
LZMA_OBJS = $(LZMA_DIR)/C/Alloc.o $(LZMA_DIR)/C/LzFind.o \
	$(LZMA_DIR)/C/LzmaDec.o $(LZMA_DIR)/C/LzmaEnc.o $(LZMA_DIR)/C/LzmaLib.o
INCLUDEDIR += -I$(LZMA_DIR)/C
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
UNSQUASHFS_OBJS += lzma_wrapper.o $(LZMA_OBJS)
ifeq ($(COMP_DEFAULT),lzma)
COMPRESSORS += lzma@(default)
else
COMPRESSORS += lzma
endif
endif

ifeq ($(LZMA_XZ_SUPPORT),1)
CFLAGS += -DLZMA_SUPPORT
MKSQUASHFS_OBJS += lzma_xz_wrapper.o
UNSQUASHFS_OBJS += lzma_xz_wrapper.o
LIBS += -llzma
ifeq ($(COMP_DEFAULT),lzma)
COMPRESSORS += lzma@(default)
else
COMPRESSORS += lzma
endif
endif

ifeq ($(XATTR_SUPPORT),1)
ifeq ($(XATTR_DEFAULT),1)
CFLAGS += -DXATTR_SUPPORT -DXATTR_DEFAULT
else
CFLAGS += -DXATTR_SUPPORT
endif
ifeq ($(XATTR_OS_SUPPORT),1)
CFLAGS += -DXATTR_OS_SUPPORT
MKSQUASHFS_OBJS += xattr.o read_xattrs.o tar_xattr.o pseudo_xattr.o xattr_system.o
UNSQUASHFS_OBJS += read_xattrs.o unsquashfs_xattr.o unsquashfs_xattr_system.o
else
MKSQUASHFS_OBJS += xattr.o read_xattrs.o tar_xattr.o pseudo_xattr.o
UNSQUASHFS_OBJS += read_xattrs.o unsquashfs_xattr.o
endif
endif

ifeq ($(DONT_USE_ATOMIC_EXCHANGE_N),1)
CFLAGS += -DDONT_USE_ATOMIC_EXCHANGE_N
endif

MAX_READER_THREADS=1024
CFLAGS+= -DMAX_READER_THREADS=$(MAX_READER_THREADS)

ifeq ($(SINGLE_READER_THREAD),1)
CFLAGS += -DSINGLE_READER_THREAD
else
ifeq ($(shell [ $(SMALL_READER_THREADS) -gt $(MAX_READER_THREADS) ] && echo Y),Y)
$(error SMALL_READER_THREADS is too large, it must be $(MAX_READER_THREADS) \
	or less and not 0)
endif
ifeq ($(shell [ $(SMALL_READER_THREADS) -le 0 ] && echo Y),Y)
$(error SMALL_READER_THREADS should not be negative or 0!)
endif
ifeq ($(shell [ $(BLOCK_READER_THREADS) -gt $(MAX_READER_THREADS) ] && echo Y),Y)
$(error BLOCK_READER_THREADS is too large, it must be $(MAX_READER_THREADS) \
	or less and not 0)
endif
ifeq ($(shell [ $(BLOCK_READER_THREADS) -le 0 ] && echo Y),Y)
$(error BLOCK_READER_THREADS should not be negative or 0!)
endif
CFLAGS += -DSMALL_READER_THREADS=$(SMALL_READER_THREADS) -DBLOCK_READER_THREADS=$(BLOCK_READER_THREADS)
endif

# If LZMA_SUPPORT is specified then LZMA_DIR must be specified too
#
ifeq ($(LZMA_SUPPORT),1)
ifndef LZMA_DIR
$(error "LZMA_SUPPORT requires LZMA_DIR to be also defined")
endif
endif

#
# Both LZMA_XZ_SUPPORT and LZMA_SUPPORT cannot be specified
#
ifeq ($(LZMA_XZ_SUPPORT),1)
ifeq ($(LZMA_SUPPORT),1)
$(error "Both LZMA_XZ_SUPPORT and LZMA_SUPPORT cannot be specified")
endif
endif

#
# At least one compressor must have been selected
#
ifndef COMPRESSORS
$(error "No compressor selected! Select one or more of GZIP, LZMA, XZ, LZO, \
	LZ4 or ZSTD!")
endif

#
# COMP_DEFAULT should be defined
#
ifndef COMP_DEFAULT
$(error "COMP_DEFAULT must be set to a compressor!")
endif

#
# COMP_DEFAULT must be a selected compressor
#
ifeq (, $(findstring $(COMP_DEFAULT), $(COMPRESSORS)))
$(error "COMP_DEFAULT is set to ${COMP_DEFAULT}, which isn't selected to be \
	built!")
endif

space := $(subst ,, )

#
# Get VERSION and DATE for Mksquashfs/Unsquashfs version strings.
#
# If RELEASE_VERSION/RELEASE_DATE set, use them.
#
# If not set, this is a development version, therefore
#
# If this source has been exported by "git archive" use automatically
# expanded strings.
#
# Otherwise ask git for the details from current HEAD.
#
include version.mk

ifdef RELEASE_VERSION
VERSION := $(RELEASE_VERSION)
DATE := $(RELEASE_DATE)
else
ifeq ($(HASH),$Format:%h$)
VERSION := 4.7.4-$(shell git show -s --pretty=format:%h)
DATE := $(firstword $(subst -,/,$(shell git show -s --pretty=format:%ci)))
else
VERSION := 4.7.4-$(HASH)
DATE := $(firstword $(subst -,/,$(FULLDATE)))
endif
endif

YEAR := $(firstword $(subst /, , $(DATE)))

CFLAGS += -DVERSION=\"$(VERSION)\" -DDATE=\"$(DATE)\" -DYEAR=\"$(YEAR)\"

.PHONY: all
all: mksquashfs unsquashfs

mksquashfs: $(MKSQUASHFS_OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) $(MKSQUASHFS_OBJS) $(LIBS) -o $@
	ln -sf mksquashfs sqfstar

mksquashfs.o: Makefile mksquashfs.c squashfs_fs.h squashfs_swap.h mksquashfs.h \
	sort.h pseudo.h compressor.h xattr.h action.h mksquashfs_error.h progressbar.h \
	info.h caches-queues-lists.h read_fs.h restore.h process_fragments.h

reader.o: squashfs_fs.h mksquashfs.h caches-queues-lists.h progressbar.h \
	mksquashfs_error.h pseudo.h sort.h

read_fs.o: read_fs.c squashfs_fs.h squashfs_swap.h compressor.h xattr.h \
	mksquashfs_error.h mksquashfs.h

sort.o: sort.c squashfs_fs.h mksquashfs.h sort.h mksquashfs_error.h progressbar.h

swap.o: swap.c

pseudo.o: pseudo.c pseudo.h mksquashfs_error.h progressbar.h

pseudo_xattr.o: pseudo_xattr.c xattr.h mksquashfs_error.h progressbar.h

compressor.o: Makefile compressor.c compressor.h squashfs_fs.h

xattr.o: xattr.c squashfs_fs.h squashfs_swap.h mksquashfs.h xattr.h mksquashfs_error.h \
	progressbar.h

read_xattrs.o: read_xattrs.c squashfs_fs.h squashfs_swap.h xattr.h error.h

action.o: action.c squashfs_fs.h mksquashfs.h action.h mksquashfs_error.h

progressbar.o: progressbar.c mksquashfs_error.h

info.o: info.c squashfs_fs.h mksquashfs.h mksquashfs_error.h progressbar.h \
	caches-queues-lists.h

restore.o: restore.c caches-queues-lists.h squashfs_fs.h mksquashfs.h mksquashfs_error.h \
	progressbar.h info.h

process_fragments.o: process_fragments.c process_fragments.h

caches-queues-lists.o: caches-queues-lists.c mksquashfs_error.h caches-queues-lists.h

tar.o: tar.h

tar_xattr.o: tar.h xattr.h

date.o: date.h error.h

memory.o: error.h memory_compat.h memory.h

symbolic_mode.o: symbolic_mode.h symbolic_mode.c

gzip_wrapper.o: gzip_wrapper.c squashfs_fs.h gzip_wrapper.h compressor.h

lzma_wrapper.o: lzma_wrapper.c compressor.h squashfs_fs.h

lzma_xz_wrapper.o: lzma_xz_wrapper.c compressor.h squashfs_fs.h

lzo_wrapper.o: lzo_wrapper.c squashfs_fs.h lzo_wrapper.h compressor.h

lz4_wrapper.o: lz4_wrapper.c squashfs_fs.h lz4_wrapper.h compressor.h

xz_wrapper.o: xz_wrapper.c squashfs_fs.h xz_wrapper.h compressor.h

xz_wrapper_extended.o: xz_wrapper_extended.c squashfs_fs.h xz_wrapper.h compressor.h

mksquashfs_help.o: mksquashfs_help.c mksquashfs_help.h Makefile
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -DCOMPRESSORS="\"$(subst @, ,$(subst $(space),\n,$(COMPRESSORS)))\"" $<

print_pager.o: print_pager.c print_pager.h

thread.o: thread.c thread.h

nprocessors_compat.o: nprocessors_compat.c nprocessors_compat.h

virt_disk_pos.o: virt_disk_pos.c virt_disk_pos.h

unsquashfs_help.o: unsquashfs_help.c unsquashfs_help.h
	$(CC) -c $(CFLAGS) $(CPPFLAGS) -DDECOMPRESSORS="\"$(subst @(default),,$(subst $(space),\n,$(COMPRESSORS)))\"" $<

limit.o: limit.h error.h

unsquashfs: $(UNSQUASHFS_OBJS)
	$(CC) $(LDFLAGS) $(EXTRA_LDFLAGS) $(UNSQUASHFS_OBJS) $(LIBS) -o $@
	ln -sf unsquashfs sqfscat

unsquashfs.o: unsquashfs.h unsquashfs.c squashfs_fs.h squashfs_swap.h \
	squashfs_compat.h xattr.h read_fs.h compressor.h unsquashfs_error.h

unsquash-1.o: unsquashfs.h unsquash-1.c squashfs_fs.h squashfs_compat.h unsquashfs_error.h

unsquash-2.o: unsquashfs.h unsquash-2.c squashfs_fs.h squashfs_compat.h unsquashfs_error.h

unsquash-3.o: unsquashfs.h unsquash-3.c squashfs_fs.h squashfs_compat.h unsquashfs_error.h

unsquash-4.o: unsquashfs.h unsquash-4.c squashfs_fs.h squashfs_swap.h \
	read_fs.h unsquashfs_error.h

unsquash-123.o: unsquashfs.h unsquash-123.c squashfs_fs.h squashfs_compat.h unsquashfs_error.h

unsquash-34.o: unsquashfs.h unsquash-34.c unsquashfs_error.h

unsquash-1234.o: unsquash-1234.c unsquashfs_error.h

unsquash-12.o: unsquash-12.c unsquashfs.h

unsquashfs_xattr.o: unsquashfs_xattr.c unsquashfs.h squashfs_fs.h xattr.h unsquashfs_error.h

unsquashfs_info.o: unsquashfs.h squashfs_fs.h unsquashfs_error.h

.PHONY: clean
clean:
	-rm -f *.o mksquashfs unsquashfs sqfstar sqfscat *.1

.PHONY: install
install: mksquashfs unsquashfs
	mkdir -p $(INSTALL_DIR)
	cp mksquashfs $(INSTALL_DIR)
	cp unsquashfs $(INSTALL_DIR)
	ln -fs unsquashfs $(INSTALL_DIR)/sqfscat
	ln -fs mksquashfs $(INSTALL_DIR)/sqfstar
	generate-manpages/install-manpages.sh $(shell pwd)/.. "$(INSTALL_MANPAGES_DIR)" "$(USE_PREBUILT_MANPAGES)"
