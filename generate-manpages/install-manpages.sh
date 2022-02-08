#!/bin/sh

if [ $# -lt 2 ]; then
	echo "$0: Insufficient arguments." >&2
	echo "$0: <path to git-root/source-root> <path to install manpages>" >&2
	exit 1;
fi

if [ -z "$2" ]; then
	echo "$0: Install path for manpages empty.  Skipping manpage install" >&2
	exit 0
fi

cd $1/generate-manpages

# We must have help2man to generate "custom" manpages for the
# built squashfs-tools, incorporating build choices (the
# compressors built, default compressors, XATTR support etc).
#
# If help2man doesn't exist, use the pre-built manpages.

if ! which help2man > /dev/null 2>&1; then
	echo "$0: ERROR - No help2man in PATH.  Cannot generate manpages." >&2
	echo "WARNING: Installing pre-built manpages." >&2
	echo "WARNING: These pages are built with the Makefile defaults, and all" >&2
	echo "WARNING: the compressors configured (except the deprecated lzma).  This may not" >&2
	echo "WARNING: match your build configuation." >&2
	source=../manpages
else
	for i in mksquashfs unsquashfs; do
		if ! ./$i-manpage.sh ../squashfs-tools ../squashfs-tools/$i.1; then
			echo "$0: Failed to generate manpage.  Aborting" >&2
			exit 1
		fi
	done

	source=../squashfs-tools
fi

if ! mkdir -p $2; then
	echo "$0: Creating manpage install directory failed.  Aborting" >&2
	exit 1
fi

for i in mksquashfs unsquashfs; do
	if ! cp $source/$i.1 $2/$i.1; then
		echo "$0: Copying manpage to install directory failed.  Aborting" >&2
		exit 1
	fi

	if ! gzip -f9 $2/$i.1; then
		echo "$0: Compressing installed manpage failed.  Aborting" >&2
		exit 1
	fi
done
