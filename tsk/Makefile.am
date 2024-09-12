# Compile the sub directories
SUBDIRS = img util util/Bitlocker

AM_CPPFLAGS = -I..
AM_CXXFLAGS = -Wall -Wextra

noinst_LTLIBRARIES = \
	auto/libtskauto.la \
	base/libtskbase.la \
	fs/libtskfs.la \
	hashdb/libtskhashdb.la \
	pool/libtskpool.la \
	vs/libtskvs.la

auto_libtskauto_la_CFLAGS = $(AM_CFLAGS) -Wmultichar -Wsign-promo -Wno-overloaded-virtual
auto_libtskauto_la_CXXFLAGS = $(AM_CXXFLAGS) -Wmultichar -Wsign-promo -Wno-overloaded-virtual
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

fs_libtskfs_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
fs_libtskfs_la_SOURCES = \
	fs/apfs_compat.cpp \
	fs/apfs.cpp \
	fs/apfs_fs.cpp \
	fs/apfs_open.cpp \
	fs/dcalc_lib.c \
	fs/dcat_lib.c \
	fs/decmpfs.c \
	fs/dls_lib.c \
	fs/dstat_lib.c \
	fs/encryptionHelper.cpp \
	fs/exfatfs.c \
	fs/exfatfs_dent.c \
	fs/exfatfs_meta.c \
	fs/ext2fs.c \
	fs/ext2fs_dent.c \
	fs/ext2fs_journal.c \
	fs/fatfs.c \
	fs/fatfs_dent.cpp \
	fs/fatfs_meta.c \
	fs/fatfs_utils.c \
	fs/fatxxfs.c \
	fs/fatxxfs_dent.c \
	fs/fatxxfs_meta.c \
	fs/ffind_lib.c \
	fs/ffs.c \
	fs/ffs_dent.c \
	fs/fls_lib.c \
	fs/fs_attr.c \
	fs/fs_attrlist.c \
	fs/fs_block.c \
	fs/fs_dir.c \
	fs/fs_file.c \
	fs/fs_inode.c \
	fs/fs_io.c \
	fs/fs_load.c \
	fs/fs_name.c \
	fs/fs_open.c \
	fs/fs_parse.c \
	fs/fs_types.c \
	fs/hfs.c \
	fs/hfs_dent.c \
	fs/hfs_journal.c \
	fs/hfs_unicompare.c \
	fs/icat_lib.c \
	fs/ifind_lib.c \
	fs/ils_lib.c \
	fs/iso9660.c \
	fs/iso9660_dent.c \
	fs/logical_fs.cpp \
	fs/lzvn.c \
	fs/lzvn.h \
	fs/nofs_misc.c \
	fs/ntfs.c \
	fs/ntfs_dent.cpp \
	fs/rawfs.c \
	fs/swapfs.c \
	fs/tsk_fs_i.h \
	fs/unix_misc.c \
	fs/usnjls_lib.c \
	fs/usn_journal.c \
	fs/walk_cpp.cpp \
	fs/yaffs.cpp

hashdb_libtskhashdb_la_SOURCES = \
	hashdb/binsrch_index.cpp \
	hashdb/encase.c \
	hashdb/hashkeeper.c \
	hashdb/hdb_base.c \
	hashdb/idxonly.c \
	hashdb/md5sum.c \
	hashdb/nsrl.c \
	hashdb/sqlite_hdb.cpp \
	hashdb/tsk_hashdb.c \
	hashdb/tsk_hashdb.h \
	hashdb/tsk_hashdb_i.h \
	hashdb/tsk_hash_info.h

pool_libtskpool_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES) -I$(srcdir)/.. -Wall
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
