# configure.ac  -*- Autoconf -*-
# Process this file with autoconf, to generate a configure script.
#
# $Id: configure.ac,v 1.2 2007/05/03 22:46:09 keithmarshall Exp $
#
# Copyright (C) 2007, MinGW Project
# Written by Keith Marshall <keithmarshall@users.sourceforge.net>
#
# Package identification.
#
# This is configure.ac for the MinGW `libgnurx' package.
# BASENAME, VERSION_MAJOR and VERSION_MINOR are required tags;
# complete `Value' fields as appropriate.
#
#                            Tag              Value
#                            ---------------  ----------
  MINGW_AC_DEFINE_PACKAGE_ID([BASENAME],      [libgnurx])
  MINGW_AC_DEFINE_PACKAGE_ID([VERSION_MAJOR], [2])
  MINGW_AC_DEFINE_PACKAGE_ID([VERSION_MINOR], [5])
#
# PATCHLEVEL is optional; comment/uncomment and adjust as required.
#
  MINGW_AC_DEFINE_PACKAGE_ID([PATCHLEVEL],    [1])
#
# DLL_VERSION is required; installed DLLs will be versioned, by
# appending a hyphen, the specified tag value, and then the `.dll'
# file name extension, to the base name of each generated DLL.
#
  MINGW_AC_DEFINE_PACKAGE_ID([DLL_VERSION],   [0])
#
#
# libgnurx is an adaptation of Tor Lillqvist's original port of the
# regex functions from GNU libc, for use on native Woe32 platforms.
#
# The original sources, on which this port is based, remain copyright
# of their respective authors, or of the Free Software Foundation Inc.,
# as indicated in individual file headers; all are redistributed with
# permission, as granted by the GNU Lesser General Public License.
#
# This is free software.  It is provided AS IS, in the hope that it may
# be useful, but WITHOUT WARRANTY OF ANY KIND, not even an IMPLIED WARRANTY
# of MERCHANTABILITY, nor of FITNESS FOR ANY PARTICULAR PURPOSE.
#
# Permission is granted to redistribute this software, either "as is" or
# in modified form, under the terms of the GNU Lesser General Public License,
# as published by the Free Software Foundation; either version 2.1, or (at
# your option) any later version.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software; see the file COPYING.LIB.  If not, write to the
# Free Software Foundation, 51 Franklin St - Fifth Floor, Boston,
# MA 02110-1301, USA.

# Autoconf initialisation.
#
  AC_PREREQ([2.59])
  AC_INIT(__MINGW_AC_PACKAGE_IDENTIFICATION__)

# Compiler and build tool checks.
#
  AC_PROG_CC
  MINGW_AC_PROG_CC_OPTIONS([CC_QUALIFIED], [-m], [threads tune=pentium3])

# Set the release version for the resultant DLL.
#
  AC_SUBST([DLLVERSION], [__MINGW_AC_PACKAGE_DLL_VERSION__])

# User configuration options.
#
  MINGW_AC_DISTRIBUTION_TYPE([tar])
  MINGW_AC_MSVC_IMPORT_LIBS([GNURX_LIB], [gnurx.lib])
  MINGW_AC_DEV_INSTALL_OPTION

# Configuration output.
#
  AC_SUBST([GNURX_LIB])
  AC_SUBST([CC_QUALIFIED], ["$CC $CC_QUALIFIED"])
  LDFLAGS="$LDFLAGS -Wl,--enable-auto-image-base -Wl,--out-implib,libgnurx.dll.a"
  test -n "${GNURX_LIB}" && LDFLAGS="$LDFLAGS -Wl,--output-def,libgnurx.def"
  AC_CONFIG_FILES([Makefile])
  AC_OUTPUT
#
# $RCSfile: configure.ac,v $Revision: 1.2 $: end of file
