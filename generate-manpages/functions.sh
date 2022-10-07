#!/bin/sh

# Sanity check, check that the non-builtin echo exists and is in PATH
if ! which echo > /dev/null 2>&1; then
	echo "$0: This script needs the non-builtin echo, which is not in your PATH." >&2
	echo "$0: Fix PATH or install before running this script!" >&2
	exit 1
fi

ECHO=$(which echo)

print() {
	${ECHO} "$@"
}

error() {
	${ECHO} "$@" >&2
}
