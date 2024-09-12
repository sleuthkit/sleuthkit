# Compile the sub directories
SUBDIRS = img vs fs hashdb auto pool util util/Bitlocker

AM_CPPFLAGS = -I..

noinst_LTLIBRARIES = base/libtskbase.la

base_libtskbase_la_SOURCES = \
	base/crc.c \
	base/crc.h \
	base/md5c.c \
	base/mymalloc.c \
	base/sha1c.c \
	base/tsk_base_i.c \
	base/tsk_base_i.h \
	base/tsk_endian.c \
	base/tsk_error.c \
	base/tsk_error_win32.cpp \
	base/tsk_list.c \
	base/tsk_lock.c \
	base/tsk_parse.c \
	base/tsk_printf.c \
	base/tsk_stack.c \
	base/tsk_unicode.c \
	base/tsk_unicode.h \
	base/tsk_version.c \
	base/XGetopt.c

# Merge the libraries into one
lib_LTLIBRARIES = libtsk.la
libtsk_la_SOURCES =
libtsk_la_LIBADD = \
	auto/libtskauto.la \
	base/libtskbase.la \
	fs/libtskfs.la \
	hashdb/libtskhashdb.la \
	img/libtskimg.la \
	pool/libtskpool.la \
	util/Bitlocker/libtskbitlocker.la \
	util/libtskutil.la \
	vs/libtskvs.la

# current:revision:age
libtsk_la_LDFLAGS = -version-info 21:1:2 $(LIBTSK_LDFLAGS)

EXTRA_DIST = \
	tsk_tools_i.h \
	docs/Doxyfile \
	docs/*.dox \
	docs/*.html \
	tsk.pc.in

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = tsk.pc

# TODO: This can be done more simply from configure.ac
tsk.pc: tsk.pc.in Makefile
	sed -e 's![@]prefix[@]!$(prefix)!g' \
      -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
      -e 's![@]includedir[@]!$(includedir)!g' \
      -e 's![@]libdir[@]!$(libdir)!g' \
      -e 's![@]PACKAGE_NAME[@]!$(PACKAGE_NAME)!g' \
      -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
      -e 's![@]AX_PACKAGE_REQUIRES[@]!$(AX_PACKAGE_REQUIRES)!g' \
      -e 's![@]PACKAGE_LIBS_PRIVATE[@]!$(PACKAGE_LIBS_PRIVATE)!g' \
      -e 's![@]AX_PACKAGE_REQUIRES_PRIVATE[@]!$(AX_PACKAGE_REQUIRES_PRIVATE)!g' \
      $< >$@

CLEANFILES = tsk.pc
