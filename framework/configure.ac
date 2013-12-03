#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.59])

AC_INIT(sleuthkitframework, 4.0.0)
AC_CONFIG_SRCDIR([tsk/framework/framework.h])
AC_CONFIG_HEADERS([config.h])
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

# Check for OS
AC_CANONICAL_HOST
AM_CONDITIONAL([DARWIN],false)
case $host_os in
    darwin*)
        # Mac
        AM_CONDITIONAL([DARWIN],true)
        ;;
    linux*)
        # Linux
        # nothing special to do for now
        ;;
    *)
        # Default Case
        AC_MSG_ERROR([Your platform is not currently supported])
        ;;
esac

# Not all compilers include /usr/local in the include and link path
if test -e /usr/local/include; then
    CFLAGS="$CFLAGS -I/usr/local/include"
    LDFLAGS="$LDFLAGS -L/usr/local/lib"
fi

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
# AC_CHECK_HEADER_STDBOOL
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
AC_CHECK_HEADERS([Poco/Foundation.h Poco/Net/HTTPCookie.h Poco/DOM/Entity.h Poco/Util/Timer.h],[],AC_MSG_ERROR([Poco include files not found.]))

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

# Standard values for modules in the modules folder
AC_SUBST(AM_CXXFLAGS_MOD, "-I../.. -I../../.. -Wall")
AC_SUBST(AM_LIBADD_MOD, "../../tsk/framework/libtskframework.la ../../../tsk/libtsk.la")

# REMOVE THESE
AC_SUBST(TSK_INCLUDE, "-I../../..")
AC_SUBST(FW_INCLUDE,  "-I../..")
AC_SUBST(FW_LIBS, "../../tsk/framework/libtskframework.la ../../../tsk/libtsk.la")

# RUNTIME_MODULES_CONFIG_DIR
AC_SUBST(RUNTIME_MODULES_CONFIG_DIR, "../../runtime/modules_config")

# MODULES_ROOT_DIR is the tsk/framework/modules directory
# MODULES_ROOT_DIR is relative to RUNTIME_MODULES_CONFIG_DIR/<module_name>
# so that each module can do the following to populate config files to the runtime directory.
#   mkdir -p $(RUNTIME_MODULES_CONFIG_DIR)/<module_name>
#   (cd $(RUNTIME_MODULES_CONFIG_DIR)/<module_name>; ln -s $(MODULES_ROOT_DIR)/c_foobarModule/foobar_config.xml .)
AC_SUBST(MODULES_ROOT_DIR, "../../../modules")

[rm -f modules/*/missing_libs.txt]
for i in `ls modules/`
do
  if test -d "modules/${i}"; then
    case ${i} in
      c_FileTypeSigModule)          AC_CONFIG_SUBDIRS([modules/c_FileTypeSigModule]) ;;
      c_LibExifModule)              AC_CONFIG_SUBDIRS([modules/c_LibExifModule]) ;;
# NOTE: There is a small amount of code in the ZIP configure.ac to list out
# all modules that missed dependencies.  If one gets added after it, then 
# besure to move that code to that module so that it is shown at the end
# of a "./configure" run
    esac
  fi
done

AC_CONFIG_FILES([Makefile
        tsk/framework/Makefile
        tsk/framework/extraction/Makefile
        tsk/framework/file/Makefile
        tsk/framework/pipeline/Makefile
        tsk/framework/services/Makefile
        tsk/framework/utilities/Makefile
        modules/Makefile
        modules/c_EntropyModule/Makefile
        modules/c_HashCalcModule/Makefile
        modules/c_InterestingFilesModule/Makefile
        modules/c_RegRipperModule/Makefile
        modules/c_SaveInterestingFilesModule/Makefile
        modules/c_SummaryReportModule/Makefile
        modules/c_TskHashLookupModule/Makefile
        modules/c_ZIPExtractionModule/Makefile
        tools/Makefile
        tools/tsk_analyzeimg/Makefile
        tools/tsk_validatepipeline/Makefile
])

AC_OUTPUT
