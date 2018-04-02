dnl -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.59)

AC_INIT(sleuthkit, 4.6.0)
m4_include([m4/ax_pthread.m4])
dnl include the version from 1.12.1. This will work for
m4_include([m4/cppunit.m4])
m4_include([m4/ax_jni_include_dir.m4])
m4_include([m4/ac_prog_javac_works.m4])
m4_include([m4/ac_prog_javac.m4])
m4_include([m4/ac_prog_java_works.m4])
m4_include([m4/ac_prog_java.m4])

AC_CONFIG_SRCDIR([tsk/base/tsk_base.h])
AC_CONFIG_HEADERS([tsk/tsk_config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AM_PATH_CPPUNIT(1.12.1)
AM_CONDITIONAL([CPPUNIT],[test "x$no_cppunit" = x])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CONFIG_MACRO_DIR([m4])

dnl Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PATH_PROG(PERL, perl)

dnl Checks for header files.
AC_HEADER_STDC
dnl AC_HEADER_MAJOR
dnl AC_HEADER_SYS_WAIT
dnl AC_CHECK_HEADERS([fcntl.h inttypes.h limits.h locale.h memory.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/time.h unistd.h utime.h wchar.h wctype.h])
AC_CHECK_HEADERS([err.h inttypes.h unistd.h stdint.h sys/param.h sys/resource.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_MODE_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
dnl AC_CHECK_MEMBERS([struct stat.st_rdev])
dnl AC_HEADER_TIME
dnl AC_STRUCT_TM

dnl check for large file support
AC_SYS_LARGEFILE

dnl Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_ERROR_AT_LINE
dnl AC_FUNC_FORK
AC_FUNC_FSEEKO
AC_PROG_GCC_TRADITIONAL
AC_FUNC_LSTAT
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
dnl AC_FUNC_MALLOC
dnl AC_FUNC_MBRTOWC
dnl AC_FUNC_MEMCMP
dnl AC_FUNC_MKTIME
dnl AC_FUNC_MMAP
dnl AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
dnl AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
dnl AC_CHECK_FUNCS([dup2 gethostname isascii iswprint memset munmap regcomp select setlocale strcasecmp strchr strdup strerror strndup strrchr strtol strtoul strtoull utime wcwidth])
AC_CHECK_FUNCS([ishexnumber err errx warn warnx vasprintf getrusage])
AC_CHECK_FUNCS([strlcpy strlcat])

AX_PTHREAD([
    AC_DEFINE(HAVE_PTHREAD,1,[Define if you have POSIX threads libraries and header files.])
    CLIBS="$PTHREAD_LIBS $LIBS"
    CPPFLAGS="$CPPFLAGS $PTHREAD_CFLAGS"
    LDFLAGS="$LDFLAGS $PTHREAD_CFLAGS"
    CC="$PTHREAD_CC"],[])

dnl Permit single-threaded builds
AC_ARG_ENABLE([multithreading],
    [AS_HELP_STRING([--disable-multithreading], [Build without multithreading support])])

dnl Enable multithreading by default in the presence of pthread
AS_IF([test "x$ax_pthread_ok" = "xyes" && test "x$enable_multithreading" != "xno"], [ax_multithread=yes], [ax_multithread=no])

case "$host" in
*-*-mingw*)
  dnl Adding the native /usr/local is wrong for cross-compiling
  ;;
*)
  dnl Not all compilers include /usr/local in the include and link path
  if test -d /usr/local/include; then
    CPPFLAGS="$CPPFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
  fi
  ;;
esac

dnl Add enable/disable option
AC_ARG_ENABLE([java],
    [AS_HELP_STRING([--disable-java], [Do not build the java bindings or jar file])])

dnl Checks for libraries.


dnl Some platforms will complain about missing included functions if libstdc++ is not included.
AC_CHECK_LIB(stdc++, main, , AC_MSG_ERROR([missing libstdc++]))
AC_CHECK_HEADERS(list, , , AC_MSG_ERROR([missing STL list class header]))
AC_CHECK_HEADERS(map, , , AC_MSG_ERROR([missing STL map class header]))
AC_CHECK_HEADERS(queue, , , AC_MSG_ERROR([missing STL queue class header]))
AC_CHECK_HEADERS(set, , , AC_MSG_ERROR([missing STL set class header]))
AC_CHECK_HEADERS(stack, , , AC_MSG_ERROR([missing STL stack class header]))
AC_CHECK_HEADERS(streambuf, , , AC_MSG_ERROR([missing STL streambuf class header]))
AC_CHECK_HEADERS(string, , , AC_MSG_ERROR([missing STL string class header]))
AC_CHECK_HEADERS(vector, , , AC_MSG_ERROR([missing STL vector class header]))

dnl Check for sqlite and its dependencies
AC_CHECK_HEADERS([sqlite3.h],
                 [AC_CHECK_LIB(dl, dlopen)
                  AC_CHECK_LIB(sqlite3, sqlite3_open)])
dnl Compile the bundled sqlite if there is no system one installed
AC_MSG_CHECKING(which sqlite3 to use)
AS_IF([test "x$ac_cv_lib_sqlite3_sqlite3_open" = "xyes"],
      [AC_MSG_RESULT([system])],
      [AC_MSG_RESULT([bundled])])
AM_CONDITIONAL([HAVE_LIBSQLITE3],
               [test "x$ac_cv_lib_sqlite3_sqlite3_open" = "xyes"])
dnl check for postgresql
AC_CHECK_HEADERS([postgresql/libpq-fe.h],AC_CHECK_LIB([pq],[PQlibVersion]))
AM_CONDITIONAL([HAVE_POSTGRESQL],[test "x$ac_cv_lib_pq_PQlibVersion" = "xyes"])
AM_COND_IF([HAVE_POSTGRESQL],[ax_libpq=yes],[ax_libpq=no])
AM_COND_IF([HAVE_POSTGRESQL], [AC_DEFINE([HAVE_LIBPQ_], [1], [Define if using libpq.])])

# Check if we should link afflib.
AC_ARG_WITH([afflib],
    [AS_HELP_STRING([--without-afflib],[Do not use AFFLIB even if it is installed])]
    [AS_HELP_STRING([--with-afflib=dir],[Specify that AFFLIB is installed in directory 'dir'])],
    dnl If --with-afflib or --without-afflib is given
    [],
    dnl If --with-afflib or --without-afflib is given
    [with_afflib=yes])

dnl check for the lib if they did not specify no
AS_IF([test "x$with_afflib" != "xno"],
    dnl Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_afflib" != "xyes"],
        [AS_IF([test -d ${with_afflib}/include],
            [CPPFLAGS="$CPPFLAGS -I${with_afflib}/include"
                LDFLAGS="$LDFLAGS -L${with_afflib}/lib"],
            dnl Dir given was not correct
            [AC_MSG_FAILURE([AFFLIB directory not found at ${with_afflib}])])
        ]
    )]
    dnl Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([afflib/afflib.h],
      [AC_CHECK_LIB([afflib], [af_open])]
    )]
)
AS_IF([test "x$ac_cv_lib_afflib_af_open" = "xyes"], [ax_afflib=yes], [ax_afflib=no])


dnl Check if we should link zlib
AC_ARG_WITH([zlib],
    [AS_HELP_STRING([--without-zlib],[Do not use ZLIB even if it is installed])]
    [AS_HELP_STRING([--with-zlib=dir],[Specify that ZLIB is installed in directory 'dir'])],
    dnl If --with-zlib or --without-zlib is given
    [],
    dnl if nothing was specified, default to a test
    [with_zlib=yes])

dnl check for the lib if they did not specify no
AS_IF(
   [test "x$with_zlib" != "xno"],
   [AC_MSG_NOTICE([checking for zlib])]
   dnl Test the dir if they specified something beyond yes/no
   [AS_IF([test "x$with_zlib" != "xyes"],
       [AC_MSG_NOTICE([LOOKING for zlib in ${with_zlib}])]
       [AS_IF([test -d ${with_zlib}],
           [CPPFLAGS="$CPPFLAGS -I${with_zlib}/include"
                LDFLAGS="$LDFLAGS -L${with_zlib}/lib"],
           dnl Dir given was not correct
           [AC_MSG_FAILURE([ZLIB directory not found at ${with_zlib}])]
       )]
    )]
    dnl Check for the header file first to make sure they have the dev install
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
AS_IF([test "x$ac_cv_lib_z_inflate" = "xyes"], [ax_zlib=yes], [ax_zlib=no])

AM_CONDITIONAL([X_ZLIB],[test "x$with_zlib" != "xno" && test "x$with_zlib" != "xyes"])
AS_IF([test "x$with_zlib" != "xno"],
   [Z_PATH="${with_zlib}/lib"],
   [AC_MSG_NOTICE([failed to make Z_PATH])]
)
AC_SUBST(Z_PATH, $Z_PATH)

dnl needed for sqllite
AC_CHECK_LIB(dl, dlopen)

dnl check for user online input

AC_ARG_ENABLE([offline],
    [ AS_HELP_STRING([--enable-offline],[Turn on offline mode])],
    [case "${enableval}" in
	yes) offline=true ;;
	no) offline=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-online]) ;;
     esac],[offline=false])

AM_CONDITIONAL([OFFLINE], [test "x$offline" = xtrue])


dnl Check if we should link libewf.
AC_ARG_WITH([libewf],
    [AS_HELP_STRING([--without-libewf],[Do not use libewf even if it is installed])]
    [AS_HELP_STRING([--with-libewf=dir],[Specify that libewf is installed in directory 'dir'])],
    dnl If --with-libewf or --without-libewf is given
    [],
    dnl if nothing was specified, default to a test
    [with_libewf=yes])

dnl check for the lib if they did not specify no
AS_IF([test "x$with_libewf" != "xno"],
    dnl Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_libewf" != "xyes"],
        [AS_IF([test -d ${with_libewf}/include],
            [CPPFLAGS="$CPPFLAGS -I${with_libewf}/include"
                LDFLAGS="$LDFLAGS -L${with_libewf}/lib"],
            dnl Dir given was not correct
            [AC_MSG_FAILURE([libewf directory not found at ${with_libewf}])])
        ]
    )]
    dnl Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([libewf.h],
      [AC_CHECK_LIB([ewf], [libewf_get_version], [], [NO_LIBEWF=true])]
    )]
)
AS_IF([test "x$ac_cv_lib_ewf_libewf_get_version" = "xyes"], [ax_libewf=yes], [ax_libewf=no])

dnl Check if we should link libvhdi.
AC_ARG_WITH([libvhdi],
    [AS_HELP_STRING([--without-libvhdi],[Do not use libvhdi even if it is installed])]
    [AS_HELP_STRING([--with-libvhdi=dir],[Specify that libvhdi is installed in directory 'dir'])],
    dnl If --with-libvhdi or --without-libvhdi is given
    [],
    dnl if nothing was specified, default to a test
    [with_libvhdi=yes])

dnl check for the lib if they did not specify no
AS_IF([test "x$with_libvhdi" != "xno"],
    dnl Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_libvhdi" != "xyes"],
        [AS_IF([test -d ${with_libvhdi}/include],
            [CPPFLAGS="$CPPFLAGS -I${with_libvhdi}/include"
                LDFLAGS="$LDFLAGS -L${with_libvhdi}/lib"],
            dnl Dir given was not correct
            [AC_MSG_FAILURE([libvhdi directory not found at ${with_libvhdi}])])
        ]
    )]
    dnl Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([libvhdi.h],
      [AC_CHECK_LIB([vhdi], [libvhdi_get_version], [], [NO_libvhdi=true])]
    )]
)
AS_IF([test "x$ac_cv_lib_vhdi_libvhdi_get_version" = "xyes"], [ax_libvhdi=yes], [ax_libvhdi=no])

dnl Check if we should link libvmdk.
AC_ARG_WITH([libvmdk],
    [AS_HELP_STRING([--without-libvmdk],[Do not use libvmdk even if it is installed])]
    [AS_HELP_STRING([--with-libvmdk=dir],[Specify that libvmdk is installed in directory 'dir'])],
    dnl If --with-libvmdk or --without-libvmdk is given
    [],
    dnl if nothing was specified, default to a test
    [with_libvmdk=yes])

dnl check for the lib if they did not specify no
AS_IF([test "x$with_libvmdk" != "xno"],
    dnl Test the dir if they specified something beyond yes/no
    [AS_IF([test "x$with_libvmdk" != "xyes"],
        [AS_IF([test -d ${with_libvmdk}/include],
            [CPPFLAGS="$CPPFLAGS -I${with_libvmdk}/include"
                LDFLAGS="$LDFLAGS -L${with_libvmdk}/lib"],
            dnl Dir given was not correct
            [AC_MSG_FAILURE([libvmdk directory not found at ${with_libvmdk}])])
        ]
    )]
    dnl Check for the header file first to make sure they have the dev install
    [AC_CHECK_HEADERS([libvmdk.h],
      [AC_CHECK_LIB([vmdk], [libvmdk_get_version], [], [NO_libvmdk=true])]
    )]
)
AS_IF([test "x$ac_cv_lib_vmdk_libvmdk_get_version" = "xyes"], [ax_libvmdk=yes], [ax_libvmdk=no])

dnl Test for the various java things that we need for bindings
AS_IF([test "x$enable_java" != "xno"], [
    dnl javac is needed to compile the JAR file
    AC_PROG_JAVAC
    if test "x$JAVAC" != x; then
        AX_JNI_INCLUDE_DIR
        for JNI_INCLUDE_DIR in $JNI_INCLUDE_DIRS
        do
            JNI_CPPFLAGS="$JNI_CPPFLAGS -I$JNI_INCLUDE_DIR"
        done
        dnl Export the paths so that the makefile gets them
        AC_SUBST(JNI_CPPFLAGS, $JNI_CPPFLAGS)
    fi

    dnl java is needed by ant
    dnl we had one report of a system with javac and not java
    AC_PROG_JAVA

    dnl Test is ant is available
    AC_PATH_PROG([ANT_FOUND], [ant], [])

]) dnl test enable_java

dnl if we found everything we need, set ax_java_support for the
dnl status message and set X_JNI for use in Makefile
AS_IF([test "x$JNI_CPPFLAGS" != x && test "x$ANT_FOUND" != x && test "x$JAVA" != x], [ax_java_support=yes], [ax_java_support=no])
AM_CONDITIONAL([X_JNI],[test "x$ax_java_support" == "xyes"])

AC_CONFIG_COMMANDS([tsk/tsk_incs.h],
    [echo "#ifndef _TSK_INCS_H" > tsk/tsk_incs.h
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

    if test x$ax_multithread = xyes; then
        echo "#define TSK_MULTITHREAD_LIB // enable multithreading" >> tsk/tsk_incs.h
    fi

    echo "" >> tsk/tsk_incs.h
    echo "#endif" >> tsk/tsk_incs.h],

    [ac_cv_header_unistd_h=$ac_cv_header_unistd_h
    ac_cv_header_inttypes_h=$ac_cv_header_inttypes_h
    ac_cv_header_sys_param_h=$ac_cv_header_sys_param_h
    ax_multithread=$ax_multithread])

AC_MSG_CHECKING([if libtool needs -no-undefined flag to build shared libraries])
case "$host" in
*-*-mingw*)
  dnl Add -no-undefined flag to LDFLAGS to let libtool build DLLs.
  AC_MSG_RESULT([yes])
  LIBTSK_LDFLAGS="-no-undefined"
  AC_SUBST([LIBTSK_LDFLAGS])
  ;;
  *)
  dnl No additional flags needed.
  AC_MSG_RESULT([no])
  ;;
esac

dnl Dependencies for fiwalk
AC_CHECK_FUNCS([getline])
AC_SEARCH_LIBS(regexec, [regex], , AC_MSG_ERROR([missing regex]))

AC_CONFIG_FILES([
    Makefile
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
    bindings/java/Makefile
    bindings/java/jni/Makefile
    unit_tests/Makefile
    unit_tests/base/Makefile])

AC_OUTPUT

dnl Print a summary
AC_MSG_NOTICE([
Building:
   afflib support:                        $ax_afflib
   libewf support:                        $ax_libewf
   zlib support:                          $ax_zlib
   libvhdi support:                       $ax_libvhdi
   libvmdk support:                       $ax_libvmdk
   postgresql support:                    $ax_libpq
Features:
   Java/JNI support:                      $ax_java_support
   Multithreading:                        $ax_multithread
]);
