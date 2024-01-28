#!/bin/sh

print() {
	${ECHO} "$@"
}

error() {
	${ECHO} "$@" >&2
}

check_sed () {
	if ! which $1 > /dev/null 2>&1; then
		return 1;
	fi

	# Check how sed handles the -i option ...
	file=$(mktemp)

	if ! $1 -i -e p ${file}; then
		rm ${file}
		return 1
	fi

	# FreeBSD sed's handling of -i will have produced a file named ${file}-e
	if [ -e ${file}-e ]; then
		rm ${file}
		rm ${file}-e
		return 1
	fi

	# Now check if sed handles the \U replacement flag in substitute command
	echo test > ${file}

	if ! $1 -i "s/.*/\U&/g" ${file}; then
		return 1;
	fi

	if grep -q TEST ${file}; then
		# Yes it uppercased it
		rm ${file}
		return 0
	fi

	rm ${file}
	return 1
}


# Sanity check, check that the non-builtin echo exists and is in PATH
if ! which echo > /dev/null 2>&1; then
	echo "$0: This script needs the non-builtin echo, which is not in your PATH." >&2
	echo "$0: Fix PATH or install before running this script!" >&2
	exit 1
fi

ECHO=$(which echo)

# The manpage generation scripts rely on sed being GNU sed.  Check whether
# 'sed' looks like GNU sed, and if not try gsed which is often what GNU sed is
# named on BSD systems.
if check_sed sed; then
	SED=sed;
elif check_sed gsed; then
	SED=gsed
else
	error "$0: You don't seem to have GNU sed installed, either as sed or gsed."
	error "$0: Fix PATH or install before running this script!"
	exit 1
fi
