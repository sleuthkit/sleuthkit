#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])

AC_INIT(sleuthkitframework, 4.0.0)
AC_CONFIG_SRCDIR([framework.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset strtoul strtoull])

AC_CONFIG_FILES([Makefile Utilities/Makefile])

AC_OUTPUT
