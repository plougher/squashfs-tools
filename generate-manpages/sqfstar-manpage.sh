#!/bin/sh

# This script generates a manpage from the sqfstar -help and -version
# output, using help2man.  The script does various modfications to the
# output from -help and -version, before passing it to help2man, to allow
# it be successfully processed into a manpage by help2man.

if [ $# -lt 2 ]; then
	echo "$0: Insufficient arguments" >&2
	echo "$0: <path to sqfstar> <output file>" >&2
	exit 1
fi

# Sanity check, ensure $1 points to a directory with a runnable Sqfstar
if [ ! -x $1/sqfstar ]; then
	echo "<arg1> doesn't point to a directory with Sqfstar in it!" 2>&1
	echo "<arg1> should point to the directory with the Sqfstar" \
		"you want to generate a manpage for." 2>&1
	exit 1
fi

# Sanity check, check that the utilities this script depends on, are in PATH
for i in expand sed help2man; do
	if ! which $i > /dev/null 2>&1; then
		echo "This script needs $i, which is not in your PATH." 2>&1
		echo "Fix PATH or install before running this script!" 2>&1
		exit 1
	fi
done

tmp=$(mktemp -d)

# Run sqfstar -help, expand TABS to spaces, and output the help text to
# $tmp/sqfstar.help.  This is to allow it to be modified before
# passing to help2man.

if ! $1/sqfstar -help > $tmp/sqfstar.help2; then
	echo "$0: Running Sqfstar failed.  Cross-compiled or incompatible binary?" 2>&1
	exit 1
fi

expand $tmp/sqfstar.help2 > $tmp/sqfstar.help


# Run sqfstar -version, and output the version text to
# $tmp/sqfstar.version.  This is to allow it to be modified before
# passing to help2man.

$1/sqfstar -version > $tmp/sqfstar.version

# Create a dummy executable in $tmp, which outputs $tmp/sqfstar.help
# and $tmp/sqfstar.version.  This gets around the fact help2man wants
# to pass --help and --version directly to sqfstar, rather than take the
# (modified) output from $tmp/sqfstar.help and $tmp/sqfstar.version

echo "#!/bin/sh
if [ \$1 = \"--help\" ]; then
	cat $tmp/sqfstar.help
else
	cat $tmp/sqfstar.version
fi" > $tmp/sqfstar.sh

chmod u+x $tmp/sqfstar.sh

# help2man gets confused by the version date returned by -version,
# and includes it in the version string

sed -i "s/ (.*)$//" $tmp/sqfstar.version

# help2man expects copyright to have an upper-case C ...

sed -i "s/^copyright/Copyright/" $tmp/sqfstar.version

# help2man doesn't pick up the author from the version.  Easiest to add
# it here.

echo >> $tmp/sqfstar.version
echo "Written by Phillip Lougher <phillip@squashfs.org.uk>" >> $tmp/sqfstar.version

# Man pages expect the options to be in the "Options" section.  So insert
# Options section after first line

sed -i "1a *OPTIONS*" $tmp/sqfstar.help

# Delete the first line, as this is being replaced by a section included
# from sqfstar.h2m

sed -i "1d" $tmp/sqfstar.help

# help2man expects options to start in the 2nd column

sed -i "s/^-/  -/" $tmp/sqfstar.help
sed -i "s/^ *-X/  -X/" $tmp/sqfstar.help

# Uppercase the options operands (between < and > ) to make it conform
# more to man page standards

sed -i "s/<[^>]*>/\U&/g" $tmp/sqfstar.help

# Remove the "<" and ">" around options operands to make it conform
# more to man page standards

sed -i -e "s/<//g" -e "s/>//g" $tmp/sqfstar.help

# The help text reports the amount of physical RAM that Sqfstar
# will use on the machine.  This is't much use for a man page as that
# will change on different machines

sed -i "s/  Currently set to [0-9]*M//" $tmp/sqfstar.help

# help2man doesn't deal well with the list of supported compressors.
# So concatenate them onto one line with commas

sed -i "/^  -comp/ {
N
s/\n */. /
s/:/: /

N
s/\n *\([^ ]*$\)/\1/
s/\n *\([^ ]* (default)$\)/\1/

: again
N
/\n  -b/b

s/\n *\([^ ]*$\)/, \1/
s/\n *\([^ ]* (default)$\)/, \1/
b again
}" $tmp/sqfstar.help

# help2man doesn't deal well with the list of lzo1* algorithms.
# So concatenate them onto one line with commas

sed -i "/^ *lzo1x_1/ {
s/\n *\([^ ]*$\)/\1/
s/\n *\([^ ]* (default)$\)/\1/

: again
N
/\n *lzo/!b

s/\n *\([^ ]*$\)/, \1/
s/\n *\([^ ]* (default)$\)/, \1/
b again
}" $tmp/sqfstar.help

# Make each compressor entry in the compressors available section, a subsection
# First, have to deal with the deprecated lzma compressor separately, because
# it doesn't have any options (i.e. text prefixed with -).

sed -i "/^ *lzma/ {
s/^ *\(lzma.*$\)/\1:/
n
s/^ */  /
} " $tmp/sqfstar.help

# Now deal with the others

sed -i -e "s/^ *\(gzip.*$\)/\1:/" -e "s/^ *\(lzo$\)/\1:/" \
	-e "s/^ *\(lzo (default)$\)/\1:/" -e "s/^ *\(lz4.*$\)/\1:/" \
	-e "s/^ *\(xz.*$\)/\1:/" -e "s/^ *\(zstd.*$\)/\1:/" \
	$tmp/sqfstar.help

# Concatenate the options text (normal options and compressor options) on to one
# line.  Add a full stop to the end of the options text

sed -i "/^  -/ {
:option
s/^ *-/  -/

/  -.*  /!s/.$/& /

:again
N
/\n$/b print
/\n[^ ]/b print
/\n *-/b print
s/\n */ /
b again

:print
s/ \n/.\n/
s/\([^.]\)\n/\1.\n/
P
s/^.*\n//
/^ *-/b option
}" $tmp/sqfstar.help

# Concatenate the SOURCE_DATE_EPOCH text on to one line.  Indent the line by
# two and add a full stop to the end of the line

sed -i " /SOURCE_DATE_EPOCH/ {
s/SOURCE_DATE_EPOCH/  SOURCE_DATE_EPOCH/

:again
N
/\n$/b print
s/\n */ /
b again

:print
s/\([^.]\)\n/\1.\n/
}" $tmp/sqfstar.help

# Make Compressors available header into a manpage section

sed -i "s/\(Compressors available and compressor specific options\):/*\1*/" $tmp/sqfstar.help

# Add reference to manpages for other squashfs-tools programs
sed -i "s/See also:/See also:\nmksquashfs(1), unsquashfs(1), sqfscat(1)\n/" $tmp/sqfstar.help

# Make See also header into a manpage section

sed -i "s/\(See also\):/*\1*/" $tmp/sqfstar.help

# Make Environment header into a manpage section

sed -i "s/\(Environment\):/*\1*/" $tmp/sqfstar.help

if ! help2man -Ni sqfstar.h2m -o $2 $tmp/sqfstar.sh; then
	echo "$0: help2man returned error.  Aborting" >&2
	exit 1
fi

rm -rf $tmp
