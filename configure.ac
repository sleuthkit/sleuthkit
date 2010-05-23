#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ(2.59)

AC_INIT(sleuthkit, 3.1.2)
AC_CONFIG_SRCDIR([tsk3/base/tsk_base.h])
AM_CONFIG_HEADER([tsk3/tsk_config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PATH_PROG(PERL, perl)


# Checks for header files.
AC_HEADER_STDC
#AC_HEADER_MAJOR
#AC_HEADER_SYS_WAIT
#AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h locale.h memory.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/time.h unistd.h utime.h wchar.h wctype.h])
AC_CHECK_HEADERS([inttypes.h unistd.h sys/param.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
#AC_CHECK_MEMBERS([struct stat.st_rdev])
#AC_HEADER_TIME
#AC_STRUCT_TM

# check for large file support
AC_SYS_LARGEFILE

# Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE
#AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
#AC_FUNC_MALLOC
#AC_FUNC_MBRTOWC
#AC_FUNC_MEMCMP
#AC_FUNC_MKTIME
#AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
#AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([dup2 gethostname isascii iswprint memset munmap regcomp select setlocale strcasecmp strchr strdup strerror strndup strrchr strtol strtoul strtoull utime wcwidth])

# Not all compilers include /usr/local in the include and link path
if test -d /usr/local/include; then
    CFLAGS="$CFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

# Checks for libraries.

# Check if we should link afflib.  
AC_ARG_WITH([afflib],
    [AS_HELP_STRING([--without-afflib],[Do not use AFFLIB even if it is installed])]
    [AS_HELP_STRING([--with-afflib=dir],[Specify that AFFLIB is installed in directory 'dir'])],
    # If --with-afflib or --without-afflib is given
    [],
    # if nothing was specified, default to a test
    [with_afflib=yes])

# check for the lib if they did not specify no
AS_IF([test "x$with_afflib" != "xno"],
    # Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_afflib" != "xyes"],
        [AS_IF([test -d ${with_afflib}/include],
            [CFLAGS="$CFLAGS -I${with_afflib}/include"
                LDFLAGS="$LDFLAGS -L${with_afflib}/lib"],
            # Dir given was not correct
            [AC_MSG_FAILURE([AFFLIB directory not found at ${with_afflib}])])
        ]
    )]
    # Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([afflib/afflib.h], 
      [AC_CHECK_LIB([afflib], [af_open])]
    )]
)


# Check if we should link libewf.  
AC_ARG_WITH([libewf],
    [AS_HELP_STRING([--without-libewf],[Do not use libewf even if it is installed])]
    [AS_HELP_STRING([--with-libewf=dir],[Specify that libewf is installed in directory 'dir'])],
    # If --with-libewf or --without-libewf is given
    [],
    # if nothing was specified, default to a test
    [with_libewf=yes])

# check for the lib if they did not specify no
AS_IF([test "x$with_libewf" != "xno"],
    # Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_libewf" != "xyes"],
        [AS_IF([test -d ${with_libewf}/include],
            [CFLAGS="$CFLAGS -I${with_libewf}/include"
                LDFLAGS="$LDFLAGS -L${with_libewf}/lib"],
            # Dir given was not correct
            [AC_MSG_FAILURE([libewf directory not found at ${with_libewf}])])
        ]
    )]
    # Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([libewf.h], 
      [AC_CHECK_LIB([ewf], [libewf_open])]
    )]
)


AC_CONFIG_COMMANDS([tsk3/tsk_incs.h],
        [
          echo "#ifndef _TSK_INCS_H" > tsk3/tsk_incs.h
          echo "#define _TSK_INCS_H" >> tsk3/tsk_incs.h
          echo "// automatically by ./configure" >> tsk3/tsk_incs.h
          echo "// Contains the config.h data needed by programs that use libtsk" >> tsk3/tsk_incs.h
          echo "" >> tsk3/tsk_incs.h
          if test x$ac_cv_header_unistd_h = xyes; then
            echo "#include <unistd.h>" >> tsk3/tsk_incs.h
          fi
          if test x$ac_cv_header_inttypes_h = xyes; then
            echo "#define  __STDC_FORMAT_MACROS" >> tsk3/tsk_incs.h
            echo "#include <inttypes.h>" >> tsk3/tsk_incs.h
          fi
          if test x$ac_cv_header_sys_param_h = xyes; then
            echo "#include <sys/param.h>" >> tsk3/tsk_incs.h
          fi
          echo "" >> tsk3/tsk_incs.h
          echo "#endif" >> tsk3/tsk_incs.h
        ],
        [
          ac_cv_header_unistd_h=$ac_cv_header_unistd_h
          ac_cv_header_inttypes_h=$ac_cv_header_inttypes_h
          ac_cv_header_sys_param_h=$ac_cv_header_sys_param_h
        ])

AC_CONFIG_FILES([Makefile
                 tsk3/Makefile
                 tsk3/base/Makefile
                 tsk3/img/Makefile
                 tsk3/vs/Makefile
                 tsk3/fs/Makefile
                 tsk3/hashdb/Makefile
                 tools/Makefile
                 tools/imgtools/Makefile
                 tools/vstools/Makefile
                 tools/fstools/Makefile
                 tools/hashtools/Makefile
                 tools/srchtools/Makefile
                 tools/sorter/Makefile
                 tools/timeline/Makefile
                 tests/Makefile
                 samples/Makefile
                 man/Makefile])
AC_OUTPUT


