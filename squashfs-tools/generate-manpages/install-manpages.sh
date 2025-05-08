#!/bin/sh


if [ $# -lt 3 ]; then
	echo "$0: Insufficient arguments." >&2
	echo "$0: <path to git-root OR source-root> <path to install manpages> <use prebuilt manpages=y/n>" >&2
	exit 1;
fi

if [ ! -f $1/squashfs-tools/generate-manpages/functions.sh ]; then
	echo "$0: <arg1> doesn't seem to contain the path to the git-root OR source-root" >&2
	exit 1
fi

. $1/squashfs-tools/generate-manpages/functions.sh

if [ -z "$2" ]; then
	error "$0: Install path for manpages empty.  Skipping manpage install"
	exit 0
fi

# Sanity check, check that the utilities this script depends on, are in PATH
for i in gzip; do
	if ! which $i > /dev/null 2>&1; then
		error "$0: This script needs $i, which is not in your PATH."
		error "$0: Fix PATH or install before running this script!"
		exit 1
	fi
done

cd $1/squashfs-tools/generate-manpages

# We must have help2man to generate "custom" manpages for the
# built squashfs-tools, incorporating build choices (the
# compressors built, default compressors, XATTR support etc).
#
# Use the pre-built manpages if we've been told to use them ($3 = y), or
# if help2man doesn't exist, or the manpage generation fails.

source=../../Documentation/manpages

if [ $3 = "y" ]; then
	print "$0: Using pre-built manpages"
elif which help2man > /dev/null 2>&1; then
	for i in mksquashfs unsquashfs sqfstar sqfscat; do
		if ! ./$i-manpage.sh ../ ../$i.1; then
			error "$0: Failed to generate manpage.  Falling back to using pre-built manpages"
			failed="y"
			break
		fi
	done

	[ -z "$failed" ] && source=../
else
	error "$0: ERROR - No help2man in PATH.  Cannot generate manpages."
	failed="y"
fi

if [ "$failed" = "y" ]; then
	error "$0: WARNING: Installing pre-built manpages."
	error "$0: WARNING: These pages are built with the Makefile defaults, and all"
	error "$0: WARNING: the compressors configured (except the deprecated lzma).  This may not"
	error "$0: WARNING: match your build configuration."
	error
	error "$0: Set USE_PREBUILT_MANPAGES to "y" in Makefile, to avoid these errors/warnings"
fi

if ! mkdir -p $2; then
	error "$0: Creating manpage install directory failed.  Aborting"
	exit 1
fi

for i in mksquashfs unsquashfs sqfstar sqfscat; do
	if ! cp $source/$i.1 $2/$i.1; then
		error "$0: Copying manpage to install directory failed.  Aborting"
		exit 1
	fi

	if ! gzip -n -f9 $2/$i.1; then
		error "$0: Compressing installed manpage failed.  Aborting"
		exit 1
	fi
done
