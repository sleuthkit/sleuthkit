#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.


AC_PREREQ(2.59)

AC_INIT(sleuthkit, 4.0.0b1)
m4_include([m4/ax_pthread.m4])
# include the version from 1.12.1. This will work for 
m4_include([m4/cppunit.m4])
m4_include([m4/ax_jni_include_dir.m4])
m4_include([m4/ac_prog_javac_works.m4])
m4_include([m4/ac_prog_javac.m4])


AC_CONFIG_SRCDIR([tsk3/base/tsk_base.h])
AM_CONFIG_HEADER([tsk3/tsk_config.h])
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
#AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
#AC_FUNC_STAT
AC_FUNC_UTIME_NULL
AC_FUNC_VPRINTF
#AC_CHECK_FUNCS([dup2 gethostname isascii iswprint memset munmap regcomp select setlocale strcasecmp strchr strdup strerror strndup strrchr strtol strtoul strtoull utime wcwidth])
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
      [AC_CHECK_LIB([ewf], [libewf_open])]
    )]
)

# Check if we should build fiwalk.
AC_ARG_ENABLE(fiwalk,
    [AS_HELP_STRING([--disable-fiwalk],[Disable fiwalk build])],
    #if --diable-fiwalk
#   [echo option provided:fiwalk" | "$fiwalk" | "$enable_fiwalk]
    [],
    #Default to fiwalk build enabled
#    [echo "option not provided: "fiwalk" | "$fiwalk" | "$enable_fiwalk]
    [enable_fiwalk=yes]
#    [echo fiwalk $fiwalk $enable_fiwalk]
    )

AS_IF([test "x$enable_fiwalk" = "xyes"], [AC_DEFINE([BUILD_FIWALK],[1],[Define if fiwalk will be built])],
    [test "x$enable_fiwalk" = "xno"], [AC_DEFINE([BUILD_FIWALK],[0],[Define if fiwalk will not be built])],
    [AC_MSG_FAILURE([unsupported fiwalk build option: ${enable_fiwalk}])]
)

AM_CONDITIONAL([BUILD_FIWALK], [test x$enable_fiwalk = xyes])
if test "x$enable_fiwalk" == xyes; then
   ## These will be removed after complete integration
   ## At that point fiwalk will just be part of TSK not a separate package
   AC_DEFINE([FIWALK_VERSION], ["0.6.18"], [version of fiwalk subpackage])
   AC_DEFINE([FIWALK_PACKAGE], ["FIWALK"], [name of fiwalk subpackage])

   ################################################################
   ##
   ## Bloom support
   AC_TYPE_INT64_T
   AC_CHECK_HEADERS([err.h sys/mman.h sys/resource.h unistd.h])
   #AC_CHECK_HEADERS([openssl/hmac.h openssl/pem.h err.h sys/mman.h sys/resource.h unistd.h])
   AC_CHECK_FUNCS([printf getrusage err errx warn warnx mmap])
   
   ################################################################
   ##
   ## utils.h/utils.c support:
   AC_CHECK_HEADERS([err.h sys/mman.h sys/resource.h unistd.h])
   #AC_CHECK_HEADERS([err.h openssl/hmac.h openssl/pem.h err.h sys/mman.h sys/resource.h unistd.h])
   AC_CHECK_FUNCS([ishexnumber unistd.h err errx warn warnx ishexnumber pread64 pread _lseeki64 ])
   
   ################################################################
   ##
   ## xml.cpp support
   AC_CHECK_FUNCS([vasprintf])
   
   ################################################################
   
   ################################################################
   ### pthread support 
   ###
   AC_CHECK_HEADERS([pthread.h])
   #m4_include([ax_pthread.m4])			#Redundant
   #AX_PTHREAD()				#Redundant
   #LIBS="$PTHREAD_LIBS $LIBS"			#Redundant
   #CFLAGS="$CFLAGS $PTHREAD_CFLAGS"		#Redundant
   #CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"	#Redundant
   #CC="$PTHREAD_CC"				#Redundant
   ################################################################
   
   # Specific headers that I plan to use
   #AC_HEADER_STDC				#Redundant
   AC_HEADER_DIRENT
   AC_CHECK_HEADERS([ctype.h err.h stdio.h strings.h string.h stdlib.h stdint.h sys/mman.h sys/types.h sys/time.h sys/resource.h sys/signal.h inttypes.h sys/resource.h sys/utsname.h])
   #AC_CHECK_HEADERS([openssl/evp.h openssl/hmac.h openssl/x509.h openssl/pem.h])
   #AC_CHECK_HEADERS([CommonCrypto/CommonDigest.h])
   AC_CHECK_HEADERS([magic.h])
   AC_CHECK_MEMBERS([struct glob_t.gl_matchc],,,[[#include <glob.h>]])
   AC_CHECK_MEMBERS([struct dirent.d_name],,,[[#include <dirent.h>]])
   AC_CHECK_MEMBERS([struct dirent.d_namlen],,,[[#include <dirent.h>]])
   
   # Specific functions that we want to know about
   AC_CHECK_FUNCS([printf getrusage strcasestr err ishexnumber])
   
   AC_CHECK_LIB([regex],[regcomp])		    # see if we need -lregex
   
   
   # Special features that can be enabled or disabled
   AC_ARG_ENABLE(opt,
   	       AC_HELP_STRING([--enable-opt],
   	       [Drop -O C flags]))
   if test "x$with_afflib" != "xno"; then
      AC_CHECK_LIB([z],[uncompress],,AC_MSG_WARN([zlib not installed; required for AFFLIB and libewf]))
      AC_CHECK_LIB([afflib],[af_open],,AC_MSG_WARN([AFFLIB not found]))
   fi
   #AC_CHECK_LIB([ssl],[ssl3_new])
   #AC_CHECK_LIB([system],[CC_MD2_Init])
   #AC_CHECK_LIB([crypto],[EVP_md5])
   if test "x$with_libewf" != "xno"; then
      AC_CHECK_LIB([ewf],[libewf_get_version],,AC_MSG_WARN([libewf not found; no E01 support]))
   else
      AC_MSG_WARN([libewf support disabled: no E01 support])
   fi
   AC_CHECK_LIB([magic],[magic_open])
   AC_DEFINE_UNQUOTED([UNAMES],"`(uname -s)`",[Host operating system])
   
   if test "x$with_afflib" != "xno"; then
      # Check to see if we have the modern AFFLIB
      AC_MSG_NOTICE([Checking for modern AFFLIB])
      AC_TRY_COMPILE([
      #include <afflib/afflib.h>
      #include <afflib/afflib_i.h>
      int	af_get_seg(AFFILE *af,const char *name,uint32_t *arg,
      		   unsigned char *data,size_t *datalen);
      ],
                     [AFFILE *af=0;const char *segname="";uint32_t arg;u_char *data = 0;size_t datalen=0;
      	       af_get_seg(af,segname,&arg,data,&datalen);],
      	       [AC_MSG_NOTICE([AFFLIB is not obsolete])
       	        afflib_obsolete=no],
      	       [AC_MSG_NOTICE([AFFLIB is obsolete; disabling AFFLIB support.])
                      afflib_obsolete=yes])
      
      if test $afflib_obsolete = yes ; then
         AC_DEFINE(AFFLIB_OBSOLETE, 1,[AFFLIB rejects uint32_t])
      else
         AC_CHECK_FUNCS([af_display_as_quad af_display_as_hex])
      fi   
   fi
   
   
   ################################################################
   ## Sleuthkit support
   ## Notice that SleuthKit now requires C++ due to autotools
   ## This needs to come last, because once we -ltsk3, everything needs
   ## to be C++ includes
   ##
   AC_LANG_PUSH([C++])
   #  AC_CHECK_LIB([tsk3],[tsk_fs_open_img],,AC_MSG_ERROR([Requires TSK 3.2.1 or above library]))
   #  AC_CHECK_HEADER([tsk3/libtsk.h],,AC_MSG_ERROR([Requires TSK 3.2.1 or above include files]))
     AC_CHECK_MEMBER([struct TSK_IMG_INFO.sector_size],
     AC_DEFINE([HAVE_TSK_IMG_INFO_SECTOR_SIZE], 
     	[1 /* Released in TSK 3.0.1 */], [Description]),
   	[],
   	[[#include "tsk3/libtsk.h"]])
     AC_CHECK_FUNCS([tsk_fs_meta_make_ls])
   AC_LANG_POP([C++])
fi

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
            echo "#ifndef __STDC_FORMAT_MACROS" >> tsk3/tsk_incs.h
            echo "#define  __STDC_FORMAT_MACROS" >> tsk3/tsk_incs.h
            echo "#endif" >> tsk3/tsk_incs.h
            echo "#include <inttypes.h>" >> tsk3/tsk_incs.h
          fi
          if test x$ac_cv_header_sys_param_h = xyes; then
            echo "#include <sys/param.h>" >> tsk3/tsk_incs.h
          fi

          if test x$ax_pthread_ok = xyes; then
            echo "#define TSK_MULTITHREAD_LIB" >> tsk3/tsk_incs.h
          fi

          echo "" >> tsk3/tsk_incs.h
          echo "#endif" >> tsk3/tsk_incs.h
        ],
        [
          ac_cv_header_unistd_h=$ac_cv_header_unistd_h
          ac_cv_header_inttypes_h=$ac_cv_header_inttypes_h
          ac_cv_header_sys_param_h=$ac_cv_header_sys_param_h
          ax_pthread_ok=$ax_pthread_ok
        ])

AC_CONFIG_FILES([Makefile
                 tsk3/Makefile
                 tsk3/base/Makefile
                 tsk3/img/Makefile
                 tsk3/vs/Makefile
                 tsk3/fs/Makefile
                 tsk3/hashdb/Makefile
                 tsk3/auto/Makefile
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


