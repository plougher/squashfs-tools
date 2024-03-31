# Welcome to Squashfs-tools!

This is the official Squashfs-tools repository.

To build and install the tools please read the **INSTALL** file.

To find out how use the latest release please start by reading **README-4.6.1**.

Thanks

## Contents of the repository

The top-level directory contains the following information files:

* **README-4.6.1** - description of the changes in the latest Squashfs-tools release.
* **USAGE-4.6** - general description of the four tools Mksquashfs, Unsquashfs, Sqfstar and Sqfscat.
* **USAGE-MKSQUASHFS-4.6** - how to use the Mksquashfs program to create Squashfs images.
* **USAGE-UNSQUASHFS-4.6** - how to use the Unsquashfs program to extract and list Squashfs images.
* **USAGE-SQFSTAR-4.6** - how to use the Sqfstar program to convert tarfiles to Squashfs images.
* **USAGE-SQFSCAT-4.6** - how to use the Sqfscat program to cat (print) one or more files to stdout from Squashfs images.
* **INSTALL** - installation instructions.
* **CHANGES** - a chronological list of changes from the earliest release to the latest release.
* **ACTION-README** - instructions on how to use the Actions feature of Mksquashfs.
* **TECHNICAL-INFO** - some technical information on Reproducible builds, Extended Attributes and the filesystem layout.

The top-level directory has the following directories:

* **squashfs-tools** - the source code directory, enter this directory and type `make` to build, or `make install` to install.
* **manpages** - pre-generated manpages, these can be viewed using `man -l`.
* **generate-manpages** - shell scripts etc used to generate the manpages.
* **examples** - an old example file on how to use pseudo-file definitions.
* **RELEASE-READMEs** - README files from previous releases.
* **kernel** - directory containing Squashfs kernel source code.  This directory has been unused since mainlining Squashfs into the kernel in 2009.  The files are obsolete and not updated and are preserved for historical reasons.

