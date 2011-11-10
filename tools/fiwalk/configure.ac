#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
# Order is largely irrevellant, although it must start with AC_INIT and end with AC_OUTPUT
# See http://autotoolset.sourceforge.net/tutorial.html
# and http://www.openismus.com/documents/linux/automake/automake.shtml

AC_INIT(FIWALK, 0.6.15, bugs@afflib.org)
AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])

# Programs that we will be using
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL

AC_CONFIG_FILES([Makefile src/Makefile plugins/Makefile python/Makefile])
AM_CONFIG_HEADER([config.h])

CPPFLAGS="-D_FILE_OFFSET_BITS=64 $CPPFLAGS"
CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -Wall"
CXXFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -Wall "


if test x"${cross_compiling}" = "xno" ; then
  # Bring additional directories where things might be found into our
  # search path. I don't know why autoconf doesn't do this by default
  for spfx in /opt/local /sw /usr/local ${prefix} ; do
      echo checking ${spfx}/include
      if test -d ${spfx}/include; then
          CPPFLAGS="-I${spfx}/include $CPPFLAGS"
          LDFLAGS="-L${spfx}/lib $LDFLAGS"
      fi
  done
else
  AC_MSG_NOTICE([Cross Compiling --- will not update CPPFALGS or LDFLAGS with /usr/local, /opt/local or /sw])
  LIBS="$LIBS -lws2_32 -lgdi32"
fi


################################################################
##
## Bloom support
AC_TYPE_INT64_T
AC_CHECK_HEADERS([openssl/hmac.h openssl/pem.h err.h sys/mman.h sys/resource.h unistd.h])
AC_CHECK_FUNCS([printf getrusage err errx warn warnx mmap])

################################################################
##
## utils.h/utils.c support:
AC_CHECK_HEADERS([err.h openssl/hmac.h openssl/pem.h err.h sys/mman.h sys/resource.h unistd.h])
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
m4_include([ax_pthread.m4])
AX_PTHREAD()
LIBS="$PTHREAD_LIBS $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"
CXXFLAGS="$CXXFLAGS $PTHREAD_CFLAGS"
CC="$PTHREAD_CC"
################################################################

# Specific headers that I plan to use
AC_HEADER_STDC
AC_HEADER_DIRENT
AC_CHECK_HEADERS([ctype.h err.h stdio.h strings.h string.h stdlib.h stdint.h sys/mman.h sys/types.h sys/time.h sys/resource.h sys/signal.h inttypes.h sys/resource.h sys/utsname.h])
AC_CHECK_HEADERS([openssl/evp.h openssl/hmac.h openssl/x509.h openssl/pem.h])
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

AC_CHECK_LIB([z],[uncompress],,AC_MSG_WARN([zlib not installed; required for AFFLIB and libewf]))
AC_CHECK_LIB([ssl],[ssl3_new])
AC_CHECK_LIB([crypto],[EVP_md5])
AC_CHECK_LIB([afflib],[af_open],,AC_MSG_WARN([AFFLIB not found]))
AC_CHECK_LIB([ewf],[libewf_get_version],,AC_MSG_WARN([libewf not found; no E01 support]))
AC_CHECK_LIB([magic],[magic_open])
AC_DEFINE_UNQUOTED([UNAMES],"`(uname -s)`",[Host operating system])

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



################################################################
## Sleuthkit support
## Notice that SleuthKit now requires C++ due to autotools
## This needs to come last, because once we -ltsk3, everything needs
## to be C++ includes
##
AC_LANG_PUSH([C++])
  AC_CHECK_LIB([tsk3],[tsk_fs_open_img],,AC_MSG_ERROR([Requires TSK 3.2.1 or above library]))
  AC_CHECK_HEADER([tsk3/libtsk.h],,AC_MSG_ERROR([Requires TSK 3.2.1 or above include files]))
  AC_CHECK_MEMBER([struct TSK_IMG_INFO.sector_size],
  AC_DEFINE([HAVE_TSK_IMG_INFO_SECTOR_SIZE], 
  	[1 /* Released in TSK 3.0.1 */], [Description]),
	[],
	[[#include <tsk3/libtsk.h>]])
  AC_CHECK_FUNCS([tsk_fs_meta_make_ls])
AC_LANG_POP([C++])

			


#LIBS="$LIBS -lewf -lz"	# for luck

############## drop optimization flags ################
if test x"${AFF_NOOPT}" != "x" ; then
   with_noopt="yes";
fi

if test "${with_noopt}" = "yes" ; then
  CFLAGS=`echo "$CFLAGS" | sed s/-O[[0-9]]//`             # note the double quoting! 
  CXXFLAGS=`echo "$CXXFLAGS" | sed s/-O[[0-9]]//`
fi

AC_OUTPUT


