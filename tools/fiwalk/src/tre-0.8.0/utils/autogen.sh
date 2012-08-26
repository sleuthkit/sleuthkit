#! /bin/sh

set -e

# Clear the cache to get a clean rebuild.
rm -rf autom4te.cache

# Generate the ChangeLog file.
darcs changes --summary > ChangeLog

# Replace variables here and there to get a consistent tree.
./utils/replace-vars.sh

# Set up the standard gettext infrastructure.
autopoint

# Set up libtool stuff for use with Automake.
libtoolize --automake

# Update aclocal.m4, using the macros from the m4 directories.
aclocal -I m4

# Run autoheader to generate config.h.in.
autoheader

# Create Makefile.in's.
automake --foreign --add-missing

# Create the configure script.
autoconf
