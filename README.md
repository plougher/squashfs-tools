# Welcome to Squashfs-tools!

This is the official Squashfs-tools repository.

To build and install the tools please read the [Documentation/4.7.2/INSTALL file](Documentation/4.7.2/INSTALL)

To find out how use the latest release please start by reading [Documentation/4.7.2/README](Documentation/4.7.2/README)

The latest **4.7.2** release may have already been packaged for you distribution, please see "Packaging status" to the below right.

Thanks

## Contents of the repository

<a href="https://repology.org/project/squashfs-tools/versions">
    <img src="https://repology.org/badge/vertical-allrepos/squashfs-tools.svg" alt="Packaging status" align="right">
</a>

The top-level directory contains the following files:

* **ACKNOWLEDGEMENTS** - This contains some historical acknowlegements, this file has mostly been replaced by the Github issues tracker.
* **CHANGES** - a reverse chronological list of changes from the latest release to the earliest release.
* **INSTALL** - where to get the INSTALL file for your version of squashfs-tools.
* **MIMALLOC.md** - documentation on using the optional mimalloc high-performance memory allocator.
* **README** - where to get the README for you version of squashfs-tools.
* **USAGE** - where to get the USAGE files for your version of squashfs-tools.

The top-level directory has the following directories:

* **Documentation** - this directory contains documentation for various versions of squashfs-tools, and it is split into subdirectories for versions 4.5, 4.5.1, 4.6, 4.6.1, 4.7, 4.7.1 and the latest version 4.7.2.  It also has a directory containing prebuilt manpages for latest version of squashfs-tools.
* **squashfs-tools** - the source code directory, enter this directory and type `make` to build, or `sudo make install` to install.  Edit the Makefile to change the compression algorithms built and other defaults including install PATH, XATTR support, and number of parallel reader threads.
