#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT(c_RegRipperModule, 1.0.0)
AC_CONFIG_SRCDIR([RegRipperModule.cpp])
AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AM_PROG_LIBTOOL
AM_MAINTAINER_MODE
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_LANG([C++])
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP

# Not all compilers include /usr/local in the include and link path
if test -e /usr/local/include; then
    CFLAGS="$CFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
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

# Check for methods in library and check for header files
AC_CHECK_HEADERS([Poco/Foundation.h Poco/Net/HTTPCookie.h Poco/DOM/Entity.h Poco/Util/Timer.h],
  [],
  AC_MSG_ERROR([Poco include files not found.])
)

AC_CHECK_LIB([PocoFoundation],[main],[HAVE_POCOFOUNDATION=1],AC_MSG_ERROR([PocoFoundation library not found.]))
if test "$HAVE_POCOFOUNDATION"; then
    save_libs="${LIBS}"
    LIBS="-lPocoFoundation"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include "Poco/UnicodeConverter.h"],
            [std::wstring wstr; Poco::UnicodeConverter::toUTF16("hello", wstr);]
        )],
        [LIBS="$LIBS $save_libs"],
        [AC_MSG_ERROR([linking with PocoFoundation failed.])]
    )
fi

AC_CHECK_LIB([PocoUtil],[main],[HAVE_POCOUTIL=1],AC_MSG_ERROR([PocoUtil library not found.]))
if test "$HAVE_POCOUTIL"; then
    save_libs="${LIBS}"
    LIBS="-lPocoUtil"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include "Poco/Util/Option.h"],
            [Poco::Util::Option();]
        )],
        [LIBS="$LIBS $save_libs"],
        [AC_MSG_ERROR([linking with PocoUtil failed.])]
    )
fi

AC_CHECK_LIB([PocoXML],[main],[HAVE_POCOXML=1],AC_MSG_ERROR([PocoXML library not found.]))
if test "$HAVE_POCOXML"; then
    save_libs="${LIBS}"
    LIBS="-lPocoXML"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include "Poco/DOM/DOMParser.h"],
            [Poco::XML::DOMParser().parse("http://www.google.com");]
        )],
        [LIBS="$LIBS $save_libs"],
        [AC_MSG_ERROR([linking with PocoXML failed.])]
    )
fi

AC_CHECK_LIB([PocoNet],[main],[HAVE_POCONET=1],AC_MSG_ERROR([PocoNet library not found.]))
if test "$HAVE_POCONET"; then
    save_libs="${LIBS}"
    LIBS="-lPocoNet"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include "Poco/Net/HTTPClientSession.h"],
            [Poco::Net::HTTPClientSession();]
        )],
        [LIBS="$LIBS $save_libs"],
        [AC_MSG_ERROR([linking with PocoNET failed.])]
    )
fi

AC_CHECK_LIB([PocoZip],[main],[HAVE_POCOZIP=1],AC_MSG_ERROR([PocoZip library not found.]))
if test "$HAVE_POCOZIP"; then
    save_libs="${LIBS}"
    LIBS="-lPocoZip"
    AC_LINK_IFELSE(
        [AC_LANG_PROGRAM(
            [#include "Poco/Zip/ZipArchive.h"],
            [Poco::Zip::ZipArchive::FileHeaders::const_iterator fh;]
        )],
        [LIBS="$LIBS $save_libs"],
        [AC_MSG_ERROR([linking with PocoZip failed.])]
    )
fi

# Check if the module is under tsk/framework/modules
if test -f ../../modules/Makefile.am; then
   AC_SUBST(FW_LIBS, "../../tsk/framework/libtskframework.la ../../../tsk/libtsk.la")
   AC_SUBST(TSK_INCLUDE, "-I../../..")
   AC_SUBST(FW_INCLUDE,  "-I../..")
else
   # Not part of tsk/framework/modules, check if Tsk and Framework has been installed
   AC_SUBST(FW_LIBS, "")
   AC_SUBST(TSK_INCLUDE, "")
   AC_SUBST(FW_INCLUDE,  "")
   AC_CHECK_HEADERS([tsk/libtsk.h],[],AC_MSG_ERROR([Tsk include files not found.]))
   AC_CHECK_LIB([tsk],[main],[],AC_MSG_ERROR([Tsk library not found.]))
   AC_CHECK_HEADERS([tsk/framework/framework.h],[],AC_MSG_ERROR([Framework include files not found.]))
   AC_CHECK_LIB([tskframework],[main],[],AC_MSG_ERROR([tskframework library not found.]))
fi

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
