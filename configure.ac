dnl -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.


AC_PREREQ(2.59)

AC_INIT(sleuthkit, 4.12.1)
m4_include([m4/ax_pthread.m4])
dnl include the version from 1.12.1. This will work for
m4_include([m4/cppunit.m4])
m4_include([m4/ax_jni_include_dir.m4])
m4_include([m4/ac_prog_javac_works.m4])
m4_include([m4/ac_prog_javac.m4])
m4_include([m4/ac_prog_java_works.m4])
m4_include([m4/ac_prog_java.m4])
m4_include([m4/ax_cxx_compile_stdcxx.m4])

AC_CONFIG_SRCDIR([tsk/base/tsk_base.h])
AC_CONFIG_HEADERS([tsk/tsk_config.h])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign tar-ustar])
AM_PATH_CPPUNIT(1.12.1)
AM_CONDITIONAL([CPPUNIT],[test "x$no_cppunit" = x])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CONFIG_MACRO_DIR([m4])

dnl Checks for programs.
AC_PROG_CXX
AX_CXX_COMPILE_STDCXX([14], [noext], [mandatory])
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PATH_PROG(PERL, perl)

TSK_CHECK_PROG_PKGCONFIG

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
AS_IF([test "x$ac_cv_prog_PKGCONFIG" = "xyes"],
  [
    SAVED_AX_PACKAGE_REQUIRES_PRIVATE="$AX_PACKAGE_REQUIRES_PRIVATE"
    TSK_PKG_CHECK_MODULES([SQLITE3], [], [sqlite3],
    [
      CFLAGS="$CFLAGS $SQLITE3_CFLAGS"
      CXXFLAGS="$CXXFLAGS $SQLITE3_CFLAGS"
      LIBS="$LIBS $SQLITE3_LIBS"
    ],
    [
      AX_PACKAGE_REQUIRES_PRIVATE="$SAVED_AX_PACKAGE_REQUIRES_PRIVATE"
      ax_sqlite3=no
    ]
  )]
)

dnl needed for sqllite
AC_CHECK_LIB(dl, dlopen)

AC_CHECK_HEADERS([sqlite3.h], [AC_CHECK_LIB([sqlite3], [sqlite3_open])])
AS_IF([test "x$ac_cv_lib_sqlite3_sqlite3_open" = "xyes"], [ax_sqlite3=yes])

dnl Compile the bundled sqlite if there is no system one installed
AC_MSG_CHECKING(which sqlite3 to use)
AS_IF([test "x$ax_sqlite3" = "xyes"],
      [AC_MSG_RESULT([system])
       PACKAGE_LIBS_PRIVATE="$PACKAGE_LIBS_PRIVATE -lsqlite3"],
      [AC_MSG_RESULT([bundled])])
AM_CONDITIONAL([HAVE_LIBSQLITE3], [test "x$ax_sqlite3" = "xyes"])

dnl Check if we should link with afflib
TSK_OPT_DEP_CHECK([afflib], [], [], [afflib/afflib.h], [afflib], [af_open])
dnl Check if we should link with zlib
TSK_OPT_DEP_CHECK([zlib], [ZLIB], [zlib], [zlib.h], [z], [inflate])
dnl Check if we should link with libbfio
TSK_OPT_DEP_CHECK([libbfio], [], [libbfio], [libbfio.h], [bfio], [libbfio_get_version])
dnl Check if we should link with libewf
TSK_OPT_DEP_CHECK([libewf], [EWF], [libewf], [libewf.h], [ewf], [libewf_get_version])
dnl Check if we should link with libvhdi
TSK_OPT_DEP_CHECK([libvhdi], [VHDI], [libvhdi], [libvhdi.h], [vhdi], [libvhdi_get_version])
dnl Check if we should link with libvmdk
TSK_OPT_DEP_CHECK([libvmdk], [VMDK], [libvmdk], [libvmdk.h], [vmdk], [libvmdk_get_version])
dnl Check if we should link with libvslvm
AS_IF([test "x$ax_libbfio" = "xyes"],
      [TSK_OPT_DEP_CHECK([libvslvm], [LVM], [libvslvm], [libvslvm.h], [vslvm], [libvslvm_get_version])],
      [ax_libvslvm=no])

dnl check for cppunit
AC_ARG_ENABLE([cppunit],
    [AS_HELP_STRING([--disable-cppunit], [Build without cppunit tests])])

ac_cv_cppunit=no
AS_IF([test "x$enable_cppunit" != "xno"], [
  AS_IF([test "x$ac_cv_prog_PKGCONFIG" = "xyes"],
    [
      dnl IGNOREs keep cppunit out of .pc file, as it's for testing only
      TSK_PKG_CHECK_MODULES([CPPUNIT], [], [cppunit >= 1.12.1], [ac_cv_cppunit=yes], [ac_cv_cppunit=no], [IGNORE], [IGNORE])
    ]
  )

  AS_IF([test "x$ac_cv_cppunit" != "xyes"],
    [AM_PATH_CPPUNIT(1.12.1)
     AS_IF([test "x$no_cppunit" = x], [ac_cv_cppunit=yes])]
  )

  AC_MSG_CHECKING([for TestRunner in -lcppunit])

  SAVED_CFLAGS="$CFLAGS"
  SAVED_LDFLAGS="$LDFLAGS"
  CFLAGS="$CPPUNIT_CLFAGS"
  LDFLAGS="$CPPUNIT_LIBS"

  AC_LANG_PUSH([C++])
  AC_LINK_IFELSE([AC_LANG_PROGRAM(
    [[#include <cppunit/ui/text/TestRunner.h>]],
    [[CppUnit::TextUi::TestRunner();]])],
    [ax_cv_cppunit=yes],
    [ax_cv_cppunit=no])
  AC_LANG_POP([C++])

  CFLAGS="$SAVED_CFLAGS"
  LDFLAGS="$SAVED_LDFLAGS"

  AC_MSG_RESULT([$ax_cv_cppunit])
])

AM_CONDITIONAL([HAVE_CPPUNIT],[test "x$ac_cv_cppunit" = xyes])

dnl check for user online input

AC_ARG_ENABLE([offline],
    [ AS_HELP_STRING([--enable-offline],[Turn on offline mode])],
    [case "${enableval}" in
	yes) offline=true ;;
	no) offline=false ;;
	*) AC_MSG_ERROR([bad value ${enableval} for --enable-online]) ;;
     esac],[offline=false])

AM_CONDITIONAL([OFFLINE], [test "x$offline" = xtrue])

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


dnl OpenSSL support for encryption - currently disabled due to automatic test failures
dnl AX_CHECK_OPENSSL(
dnl  [ax_openssl=yes]
dnl  LIBTSK_LDFLAGS="$LIBTSK_LDFLAGS $OPENSSL_LDFLAGS $OPENSSL_LIBS",
dnl  AC_SUBST([LIBTSK_LDFLAGS])
[ax_openssl=no]
dnl  [AC_MSG_ERROR([OpenSSL headers cannot be located. Consider using the --with-openssl option to specify an appropriate path.])]
dnl )
dnl For the moment, disable the openssl library so the Travis test will pass
dnl AS_IF([test "x$ax_openssl" = xyes], AC_DEFINE(HAVE_LIBOPENSSL,1, [Define if using opensll]), [])


dnl Enable compliation warnings
WARNINGS='-Wall -Wextra -Wno-unused-parameter'

AC_SUBST(AM_CFLAGS, $WARNINGS)
AC_SUBST(AM_CXXFLAGS, $WARNINGS)

AC_CONFIG_FILES([
    Makefile
    tsk/Makefile
    tsk/base/Makefile
    tsk/img/Makefile
    tsk/vs/Makefile
    tsk/fs/Makefile
    tsk/hashdb/Makefile
    tsk/auto/Makefile
    tsk/pool/Makefile
    tsk/util/Makefile
    tools/Makefile
    tools/imgtools/Makefile
    tools/vstools/Makefile
    tools/fstools/Makefile
    tools/hashtools/Makefile
    tools/srchtools/Makefile
    tools/autotools/Makefile
    tools/pooltools/Makefile
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
    case-uco/java/Makefile
    unit_tests/Makefile
    unit_tests/base/Makefile])

AC_OUTPUT

dnl Print a summary
dnl openssl is disabled, so removed line openssl support: $ax_openssl
AC_MSG_NOTICE([
Building:
   afflib support:                        $ax_afflib
   libewf support:                        $ax_libewf
   zlib support:                          $ax_zlib

   libbfio support:                       $ax_libbfio
   libvhdi support:                       $ax_libvhdi
   libvmdk support:                       $ax_libvmdk
   libvslvm support:                      $ax_libvslvm
Features:
   Java/JNI support:                      $ax_java_support
   Multithreading:                        $ax_multithread
]);
