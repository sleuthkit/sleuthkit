# ===========================================================================
#    http://www.gnu.org/software/autoconf-archive/ax_jni_include_dir.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_JNI_INCLUDE_DIR
#
# DESCRIPTION
#
#   AX_JNI_INCLUDE_DIR finds include directories needed for compiling
#   programs using the JNI interface.
#
#   JNI include directories are usually in the java distribution This is
#   deduced from the value of JAVAC. When this macro completes, a list of
#   directories is left in the variable JNI_INCLUDE_DIRS.
#
#   Example usage follows:
#
#     AX_JNI_INCLUDE_DIR
#
#     for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
#     do
#             CPPFLAGS="$CPPFLAGS -I$JNI_INCLUDE_DIR"
#     done
#
#   If you want to force a specific compiler:
#
#   - at the configure.in level, set JAVAC=yourcompiler before calling
#   AX_JNI_INCLUDE_DIR
#
#   - at the configure level, setenv JAVAC
#
#   Note: This macro can work with the autoconf M4 macros for Java programs.
#   This particular macro is not part of the original set of macros.
#
# LICENSE
#
#   Copyright (c) 2008 Don Anderson <dda@sleepycat.com>
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.


# TSK: This has been modifed to not error out if JNI things cannot be resolved
# and to support scenarios whereby JAVAC is set to a location, but it is not
# on the path. 

#serial 7

AU_ALIAS([AC_JNI_INCLUDE_DIR], [AX_JNI_INCLUDE_DIR])
AC_DEFUN([AX_JNI_INCLUDE_DIR],[

JNI_INCLUDE_DIRS=""

test "x$JAVAC" = x && AC_MSG_ERROR(['\$JAVAC' undefined])
AC_PATH_PROG([_ACJNI_JAVAC], [$JAVAC], [no])

if test "x$_ACJNI_JAVAC" = xno; then
  AC_MSG_NOTICE(["$JAVAC could not be found in path -- cannot resolve to JNI headers"])
else
  _ACJNI_FOLLOW_SYMLINKS("$_ACJNI_JAVAC")
  _JTOPDIR=`echo "$_ACJNI_FOLLOWED" | sed -e 's://*:/:g' -e 's:/[[^/]]*$::'`
  case "$host_os" in
        darwin*)        _JTOPDIR=`echo "$_JTOPDIR" | sed -e 's:/[[^/]]*$::'`
                        if test -d "$_JTOPDIR/Headers" 
			then
				_JINC="$_JTOPDIR/Headers"
			elif test -d "$_JTOPDIR/include" 
			then 
			     _JINC="$_JTOPDIR/include"
			fi;;
        *)              _JINC="$_JTOPDIR/include";;
  esac
  _AS_ECHO_LOG([_JTOPDIR=$_JTOPDIR])
  _AS_ECHO_LOG([_JINC=$_JINC])

  # On Mac OS X 10.6.4, jni.h is a symlink:
  # /System/Library/Frameworks/JavaVM.framework/Versions/Current/Headers/jni.h
  # -> ../../CurrentJDK/Headers/jni.h.
  if test -f "$_JINC/jni.h" || test -L "$_JINC/jni.h"; then
        JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JINC"
  else
        _JTOPDIR=`echo "$_JTOPDIR" | sed -e 's:/[[^/]]*$::'`
        if test -f "$_JTOPDIR/include/jni.h"; then
                JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JTOPDIR/include"
        else
                AC_MSG_NOTICE(["cannot find java include files"])
        fi
  fi

  if test "x$JNI_INCLUDE_DIRS" != x; then
    # get the likely subdirectories for system specific java includes
    case "$host_os" in
    bsdi*)          _JNI_INC_SUBDIRS="bsdos";;
    linux*)         _JNI_INC_SUBDIRS="linux genunix";;
    darwin*)	    _JNI_INC_SUBDIRS="darwin";;
    osf*)           _JNI_INC_SUBDIRS="alpha";;
    solaris*)       _JNI_INC_SUBDIRS="solaris";;
    mingw*)		_JNI_INC_SUBDIRS="win32";;
    cygwin*)	_JNI_INC_SUBDIRS="win32";;
    *)              _JNI_INC_SUBDIRS="genunix";;
    esac

    # add any subdirectories that are present
    for JINCSUBDIR in $_JNI_INC_SUBDIRS
    do
      if test -d "$_JTOPDIR/include/$JINCSUBDIR"; then
         JNI_INCLUDE_DIRS="$JNI_INCLUDE_DIRS $_JTOPDIR/include/$JINCSUBDIR"
      fi
    done
  fi
fi
])

# _ACJNI_FOLLOW_SYMLINKS <path>
# Follows symbolic links on <path>,
# finally setting variable _ACJNI_FOLLOWED
# ----------------------------------------
AC_DEFUN([_ACJNI_FOLLOW_SYMLINKS],[
# find the include directory relative to the javac executable
_cur="$1"
while ls -ld "$_cur" 2>/dev/null | grep " -> " >/dev/null; do
        AC_MSG_CHECKING([symlink for $_cur])
        _slink=`ls -ld "$_cur" | sed 's/.* -> //'`
        case "$_slink" in
        /*) _cur="$_slink";;
        # 'X' avoids triggering unwanted echo options.
        *) _cur=`echo "X$_cur" | sed -e 's/^X//' -e 's:[[^/]]*$::'`"$_slink";;
        esac
        AC_MSG_RESULT([$_cur])
done
_ACJNI_FOLLOWED="$_cur"
])# _ACJNI
