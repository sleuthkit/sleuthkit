#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ(2.59)

AC_INIT(sleuthkit, 4.1.0)
m4_include([m4/ax_pthread.m4])
# include the version from 1.12.1. This will work for 
m4_include([m4/cppunit.m4])
m4_include([m4/ax_jni_include_dir.m4])
m4_include([m4/ac_prog_javac_works.m4])
m4_include([m4/ac_prog_javac.m4])


AC_CONFIG_SRCDIR([tsk/base/tsk_base.h])
AC_CONFIG_HEADERS([tsk/tsk_config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AM_PATH_CPPUNIT(1.12.1)
AM_CONDITIONAL([CPPUNIT],[test "x$no_cppunit" = x])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CONFIG_MACRO_DIR([m4])

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
AC_CHECK_HEADERS([err.h inttypes.h unistd.h stdint.h sys/param.h])

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
#AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
#AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([dup2 gethostname isascii iswprint memset munmap regcomp select setlocale strcasecmp strchr strdup strerror strndup strrchr strtol strtoul strtoull utime wcwidth])
AC_CHECK_FUNCS([ishexnumber err errx warn warnx vasprintf])
AX_PTHREAD( [
            AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
            CLIBS="$PTHREAD_LIBS $LIBS"
            CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
            LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"
            CC="$PTHREAD_CC"],[])
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



# Check if we should link zlib
AC_ARG_WITH([zlib],
    [AS_HELP_STRING([--without-zlib],[Do not use ZLIB even if it is installed])]
    [AS_HELP_STRING([--with-zlib=dir],[Specify that ZLIB is installed in directory 'dir'])],
    # If --with-zlib or --without-zlib is given
    [],
    # if nothing was specified, default to a test
    [with_zlib=yes])


# check for the lib if they did not specify no
AS_IF(
   [test "x$with_zlib" != "xno"],
   [AC_MSG_NOTICE([checking for zlib])]
   # Test the dir if they specified something beyond yes/no
   [AS_IF([test "x$with_zlib" != "xyes"],
       [AC_MSG_NOTICE([LOOKING for zlib in ${with_zlib}])]
       [AS_IF([test -d ${with_zlib}],
           [CFLAGS="$CFLAGS -I${with_zlib}/include"
                LDFLAGS="$LDFLAGS -L${with_zlib}/lib"],
           # Dir given was not correct
           [AC_MSG_FAILURE([ZLIB directory not found at ${with_zlib}])]
       )]
    )]
    # Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([zlib.h],
      [AC_CHECK_LIB([z], [inflate],
         [],
         [AC_MSG_WARN([Found zlib headers, but could not link to zlib library.  Will build without zlib.])]
         [with_zlib=no]
      )],
      [AC_MSG_WARN([Could not find usable zlib headers.  Will build without zlib.])]
      [with_zlib=no]
    )],
    [AC_MSG_NOTICE([NOT checking for zlib because with_zlib is no])]
)


#needed for sqllite
AC_CHECK_LIB(dl, dlopen) 



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
      [AC_CHECK_LIB([ewf], [libewf_get_version])]
    )]
)

# sqlite requires pthread libraries - this was copied from its configure.ac
# AC_SEARCH_LIBS(pthread_create, pthread)
AC_SEARCH_LIBS(dlopen, dl)

# Test for java/jni so that we can compile the java bindings
AC_PROG_JAVAC
if test "x$JAVAC" != x; then
    AX_JNI_INCLUDE_DIR
    for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
    do
        JNI_CPPFLAGS="$JNI_CPPFLAGS -I$JNI_INCLUDE_DIR"
    done
    # Export the paths so that the makefile gets them
    AC_SUBST(JNI_CPPFLAGS, $JNI_CPPFLAGS)
fi
AM_CONDITIONAL([X_JNI],[test "x$JNI_CPPFLAGS" != x])

AC_CONFIG_COMMANDS([tsk/tsk_incs.h],
        [
          echo "#ifndef _TSK_INCS_H" > tsk/tsk_incs.h
          echo "#define _TSK_INCS_H" >> tsk/tsk_incs.h
          echo "// automatically by ./configure" >> tsk/tsk_incs.h
          echo "// Contains the config.h data needed by programs that use libtsk" >> tsk/tsk_incs.h
          echo "" >> tsk/tsk_incs.h
          if test x$ac_cv_header_unistd_h = xyes; then
            echo "#include <unistd.h>" >> tsk/tsk_incs.h
          fi
          if test x$ac_cv_header_inttypes_h = xyes; then
            echo "#ifndef __STDC_FORMAT_MACROS" >> tsk/tsk_incs.h
            echo "#define  __STDC_FORMAT_MACROS" >> tsk/tsk_incs.h
            echo "#endif" >> tsk/tsk_incs.h
            echo "#include <inttypes.h>" >> tsk/tsk_incs.h
          fi
          if test x$ac_cv_header_sys_param_h = xyes; then
            echo "#include <sys/param.h>" >> tsk/tsk_incs.h
          fi

          if test x$ax_pthread_ok = xyes; then
            echo "#define TSK_MULTITHREAD_LIB // set because we have pthreads" >> tsk/tsk_incs.h
          fi

          echo "" >> tsk/tsk_incs.h
          echo "#endif" >> tsk/tsk_incs.h
        ],
        [
          ac_cv_header_unistd_h=$ac_cv_header_unistd_h
          ac_cv_header_inttypes_h=$ac_cv_header_inttypes_h
          ac_cv_header_sys_param_h=$ac_cv_header_sys_param_h
          ax_pthread_ok=$ax_pthread_ok
        ])


AC_CONFIG_FILES([Makefile
                 tsk/Makefile
                 tsk/base/Makefile
                 tsk/img/Makefile
                 tsk/vs/Makefile
                 tsk/fs/Makefile
                 tsk/hashdb/Makefile
                 tsk/auto/Makefile
                 tools/Makefile
                 tools/imgtools/Makefile
                 tools/vstools/Makefile
                 tools/fstools/Makefile
                 tools/hashtools/Makefile
                 tools/srchtools/Makefile
                 tools/autotools/Makefile
                 tools/sorter/Makefile
                 tools/timeline/Makefile
                 tools/fiwalk/Makefile
                 tools/fiwalk/src/Makefile
                 tools/fiwalk/plugins/Makefile
                 tests/Makefile
                 samples/Makefile
                 man/Makefile
                 bindings/java/jni/Makefile
                 unit_tests/Makefile
                 unit_tests/base/Makefile])
AC_OUTPUT


