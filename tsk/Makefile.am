# Compile the sub directories
SUBDIRS = img fs hashdb util util/Bitlocker

AM_CPPFLAGS = -I..
AM_CXXFLAGS = -Wall -Wextra

noinst_LTLIBRARIES = \
	auto/libtskauto.la \
	base/libtskbase.la \
	pool/libtskpool.la \
	vs/libtskvs.la

auto_libtskauto_la_AM_CFLAGS = $(AM_CFLAGS) -Wmultichar -Wsign-promo -Wno-overloaded-virtual
auto_libtskauto_la_AM_CXXFLAGS = $(AM_CXXFLAGS) -Wmultichar -Wsign-promo -Wno-overloaded-virtual
auto_libtskauto_la_SOURCES = \
	auto/auto.cpp \
	auto/auto_db.cpp \
	auto/case_db.cpp \
	auto/db_sqlite.cpp \
	auto/guid.cpp \
	auto/guid.h \
	auto/is_image_supported.cpp \
	auto/tsk_auto.h \
	auto/tsk_auto_i.h \
	auto/tsk_case_db.h \
	auto/tsk_case_db.h \
	auto/tsk_db.cpp \
	auto/tsk_db.h \
	auto/tsk_db_sqlite.h \
	auto/tsk_is_image_supported.h

# Compile the bundled sqlite3 if there isn't an existing lib to use
if !HAVE_LIBSQLITE3
auto_libtskauto_la_SOURCES += auto/sqlite3.c auto/sqlite3.h
endif

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

pool_libtskpool_la_AM_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) -I$(srcdir)/.. -Wall
pool_libtskpoo_la_CXXFLAGS = $(AM_CXXFLAGS) -Werror
pool_libtskpool_la_SOURCES = \
	pool/apfs_pool_compat.cpp \
	pool/apfs_pool.cpp \
	pool/img_bfio_handle.c \
	pool/img_bfio_handle.h \
	pool/lvm_pool_compat.cpp \
	pool/lvm_pool.cpp \
	pool/pool_open.cpp \
	pool/pool_read.cpp \
	pool/pool_types.cpp

vs_libtskvs_la_SOURCES = \
	vs/bsd.c \
	vs/dos.c \
	vs/gpt.c \
	vs/mac.c \
	vs/mm_io.c \
	vs/mm_open.c \
	vs/mm_part.c \
	vs/mm_types.c \
	vs/sun.c \
	vs/tsk_vs_i.h

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
