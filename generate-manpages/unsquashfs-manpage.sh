#!/bin/sh

# This script generates a manpage from the unsquashfs -help and -version
# output, using help2man.  The script does various modfications to the
# output from -help and -version, before passing it to help2man, to allow
# it be successfully processed into a manpage by help2man.

if [ $# -lt 2 ]; then
	echo "$0: Insufficient arguments" >&2
	echo "$0: <path to unsquashfs> <output file>" >&2
	exit 1
fi

# Sanity check, ensure $1 points to a directory with a runnable Unsquashfs
if [ ! -x $1/unsquashfs ]; then
	echo "\$arg1 doesn\'t point to a directory with Unsquashfs in it!" 2>&1
	echo "\$arg1 should point to the directory with the Unsquashfs" 2>&1
	echo "you want to generate a manpage for." 2>&1
	exit 1
fi

# Sanity check, check that the utilities this script depends on, are in PATH
for i in sed help2man; do
	if ! which $i > /dev/null 2>&1; then
		echo "This script needs $i, which is not in your PATH." 2>&1
		echo "Fix PATH or install before running this script!" 2>&1
		exit 1
	fi
done

tmp=$(mktemp -d)

# Run unsquashfs -help, and output the help text to
# $tmp/unsquashfs.help.  This is to allow it to be modified before
# passing to help2man.

$1/unsquashfs -help > $tmp/unsquashfs.help

# Run unsquashfs -version, and output the version text to
# $tmp/unsquashfs.version.  This is to allow it to be modified before
# passing to help2man.

$1/unsquashfs -version > $tmp/unsquashfs.version

# Create a dummy executable in $tmp, which outputs $tmp/unsquashfs.help
# and $tmp/unsquashfs.version.  This gets around the fact help2man wants
# to pass --help and --version directly to unsquashfs, rather than take the
# (modified) output from $tmp/unsquashfs.help and $tmp/unsquashfs.version

echo "#!/bin/sh
if [ \$1 = \"--help\" ]; then
	cat $tmp/unsquashfs.help
else
	cat $tmp/unsquashfs.version
fi" > $tmp/unsquashfs.sh

chmod u+x $tmp/unsquashfs.sh

# help2man gets confused by the version date returned by -version,
# and includes it in the version string

sed -i "s/ (.*)$//" $tmp/unsquashfs.version

# help2man expects copyright to have an upper-case C ...

sed -i "s/^copyright/Copyright/" $tmp/unsquashfs.version

# help2man doesn't pick up the author from the version.  Easiest to add
# it here.

echo -e "\nWritten by Phillip Lougher <phillip@squashfs.org.uk>" >> $tmp/unsquashfs.version

# help2man expects "Usage: ", and so rename "SYNTAX:" to "Usage: "

sed -i "s/^SYNTAX:/Usage: /" $tmp/unsquashfs.help

# Man pages expect the options to be in the "Options" section.  So insert
# Options section after Usage

sed -i "/^Usage/a *OPTIONS*" $tmp/unsquashfs.help

# help2man expects options to start in the 2nd column

sed -i "s/^\t-/  -/" $tmp/unsquashfs.help

# Split combined short-form/long-form options into separate short-form,
# and long form, i.e.
# -da[ta-queue] <size> becomes
# -da <size>, -data-queue <size>

sed -i "s/\([^ ][^ \[]*\)\[\([a-z-]*\)\] \(<[a-z-]*>\)/\1 \3, \1\2 \3/" $tmp/unsquashfs.help
sed -i "s/\([^ ][^ \[]*\)\[\([a-z-]*\)\]/\1, \1\2/" $tmp/unsquashfs.help

# help2man expects the options usage to be separated from the
# option and operands text by at least 2 spaces.

sed -i "s/\t/  /g" $tmp/unsquashfs.help

# Uppercase the options operands (between < and > ) to make it conform
# more to man page standards

sed -i "s/<[^>]*>/\U&/g" $tmp/unsquashfs.help

# Remove the "<" and ">" around options operands to make it conform
# more to man page standards

sed -i -e "s/<//g" -e "s/>//g" $tmp/unsquashfs.help

# help2man doesn't deal well with the list of supported compressors.
# So concatenate them onto one line with commas

sed -i "/^Decompressors available:/ {
n
s/^  //

: again
N
/\n$/b

s/\n */, /
b again
}" $tmp/unsquashfs.help

# Concatenate the options text on to one line.  Add a full stop to the end of
# the options text

sed -i "/^  -/ {
:again
N
/\n$/b print
/\n  -/b print
s/\n */ /
b again

:print
s/\([^.]\)\n/\1.\n/
P
s/^.*\n//
/^  -/b again
}" $tmp/unsquashfs.help

# Concatenate the exit status text on to one line.

sed -i "/^  [012]/ {
:again
N
/\n$/b print
/\n  [012]/b print
s/\n */ /
b again

:print
P
s/^.*\n//
/^  [012]/b again
}" $tmp/unsquashfs.help

# Make Decompressors available header into a manpage section

sed -i "s/\(Decompressors available\):/*\1*/" $tmp/unsquashfs.help

# Make Exit status header into a manpage section

sed -i "s/\(Exit status\):/*\1*/" $tmp/unsquashfs.help

# Add reference to manpages for other squashfs-tools programs
sed -i "s/See also:/See also:\nmksquashfs(1), sqfstar(1), sqfscat(1)\n/" $tmp/unsquashfs.help

# Make See also header into a manpage section

sed -i "s/\(See also\):/*\1*/" $tmp/unsquashfs.help

if ! help2man -Ni unsquashfs.h2m -o $2 $tmp/unsquashfs.sh; then
	echo "$0: help2man returned error.  Aborting" >&2
	exit 1
fi

rm -rf $tmp
