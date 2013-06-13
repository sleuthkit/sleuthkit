## pkgid.m4  -*- Autoconf -*- vim: filetype=config
## Generate a package identification argument list for AC_INIT.
## (MinGW Project specific version).
##
## $Id: pkgid.m4,v 1.1 2007/04/30 22:46:38 keithmarshall Exp $
##
## Written by Keith Marshall <keithmarshall@users.sourceforge.net>
##
## Hereby assigned to the public domain.
## This file is provided `as is', in the hope that it may be useful,
## but WITHOUT WARRANTY OF ANY KIND, not even any implied warranty of
## MERCHANTABILITY, nor of FITNESS FOR ANY PARTICULAR PURPOSE.
##
##
## m4_include this file in aclocal.m4, and invoke AC_INIT as:--
##
##   AC_INIT(__MINGW_AC_PACKAGE_IDENTIFICATION__)
##
## to automatically define PACKAGE_NAME, PACKAGE_VERSION, PACKAGE_TARNAME
## and PACKAGE_BUG_REPORT, deriving them from tags specified in configure.ac,
## using the MINGW_AC_DEFINE_PACKAGE_ID( TAGNAME, VALUE ) macro to define
## the tag values, *before* invoking AC_INIT.
##

# MINGW_AC_DEFINE_PACKAGE_ID( TAGNAME, VALUE )
# --------------------------------------------
# Define VALUE for a tag, selected from the following TAGNAME list,
# and used to compose arguments for AC_INIT.
#
#   PROVIDER         optional; default is `MinGW'
#   BASENAME         required; the base name for the package
#   TARNAME_PREFIX   optional; default is `mingw'
#   VERSION_MAJOR    required; major version number for package
#   VERSION_MINOR    required; minor version number for package
#   PATCHLEVEL       optional; default is an empty string
#   BUG_REPORT_URI   predefined to URI for the MinGW bug tracker
#
# These are assigned to AC_INIT arguments as follows:--
#
#   PACKAGE_NAME        =  [PROVIDER ]BASENAME
#   PACKAGE_VERSION     =  VERSION_MAJOR.VERSION_MINOR[.PATCHLEVEL]
#   PACKAGE_TARNAME     =  [TARNAME_PREFIX-]NAME
#   PACKAGE_BUG_REPORT  =  BUG_REPORT_URI
#
m4_define([MINGW_AC_DEFINE_PACKAGE_ID],
[m4_define([__MINGW_AC_PACKAGE_][$1][__],[$2])dnl
])# MINGW_AC_DEFINE_PACKAGE_ID

# Define default values for the optional tags.
#
MINGW_AC_DEFINE_PACKAGE_ID([PROVIDER],        [MinGW])
MINGW_AC_DEFINE_PACKAGE_ID([TARNAME_PREFIX],  [mingw])
MINGW_AC_DEFINE_PACKAGE_ID([BUG_TRACKER_URI],
[https://sourceforge.net/tracker/?group_id=2435&atid=102435])

# __MINGW_AC_PACKAGE_IDENTIFICATION__
# -----------------------------------
# Construct an argument list for AC_INIT.
#
m4_define([__MINGW_AC_PACKAGE_IDENTIFICATION__],
[__MINGW_AC_PACKAGE_OPTION__([__MINGW_AC_PACKAGE_PROVIDER__],[ ])]dnl
[__MINGW_AC_PACKAGE_BASENAME__][,]dnl
[__MINGW_AC_PACKAGE_VERSION_MAJOR__[.][__MINGW_AC_PACKAGE_VERSION_MINOR__]]dnl
[__MINGW_AC_PACKAGE_OPTION__([__MINGW_AC_PACKAGE_PATCHLEVEL__],[],[.])][,]dnl
[__MINGW_AC_PACKAGE_BUG_TRACKER_URI__][,]dnl
[__MINGW_AC_PACKAGE_OPTION__([__MINGW_AC_PACKAGE_TARNAME_PREFIX__],[-])dnl
[__MINGW_AC_PACKAGE_BASENAME__]dnl
])#__MINGW_AC_PACKAGE_IDENTIFICATION__

# __MINGW_AC_PACKAGE_OPTION__( TAG, [SUFFIX], [PREFIX] )
# ------------------------------------------------------
# Insert optional package ID tags in the generated AC_INIT arglist,
# in the form `[PREFIX]TAG[SUFFIX]'; emits nothing, if TAG is either
# undefined, or is an empty string.
#
m4_define([__MINGW_AC_PACKAGE_OPTION__],[m4_ifdef([$1],[$3]$1[$2])dnl
])#__MINGW_AC_PACKAGE_OPTION__

# $RCSfile: pkgid.m4,v $Revision: 1.1 $: end of file
