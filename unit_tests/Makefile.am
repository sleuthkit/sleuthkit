#
# Unit tests:
# Instead of linking with ../tsk/libtsk.la, we recompile everything from scratch
# and link into a single executable.
# THis makes things easier with codecov.


AM_CPPFLAGS = -I.. -I$(srcdir)/..  $(CATCH2_CPPFLAGS)
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument $(PTHREAD_CFLAGS)
# LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS)
check_PROGRAMS = runner

auto_src = \
	../tsk/auto/auto.cpp \
	../tsk/auto/auto_db.cpp \
	../tsk/auto/db_sqlite.cpp \
	../tsk/auto/case_db.cpp \
	../tsk/auto/guid.cpp \
	../tsk/auto/tsk_db.cpp \
	../tsk/auto/tsk_case_db.h \
	../tsk/auto/tsk_auto.h \
	../tsk/auto/tsk_auto_i.h \
	../tsk/auto/tsk_case_db.h \
	../tsk/auto/tsk_db.h \
	../tsk/auto/tsk_db_sqlite.h \
	../tsk/auto/guid.h \
	../tsk/auto/is_image_supported.cpp \
	../tsk/auto/tsk_is_image_supported.h

# Compile the bundled sqlite3 if there isn't an existing lib to use
if !HAVE_LIBSQLITE3
	auto_src += sqlite3.c sqlite3.h
endif

base_src = \
	../tsk/base/crc.c \
	../tsk/base/crc.h \
	../tsk/base/md5c.c \
	../tsk/base/mymalloc.c \
	../tsk/base/sha1c.c \
	../tsk/base/tsk_base_i.c \
	../tsk/base/tsk_base_i.h \
	../tsk/base/tsk_endian.c \
	../tsk/base/tsk_error.c \
	../tsk/base/tsk_error_win32.cpp \
	../tsk/base/tsk_list.c \
	../tsk/base/tsk_lock.c \
	../tsk/base/tsk_parse.c \
	../tsk/base/tsk_printf.c \
	../tsk/base/tsk_stack.c \
	../tsk/base/tsk_unicode.c \
	../tsk/base/tsk_unicode.h \
	../tsk/base/tsk_version.c \
	../tsk/base/XGetopt.c


fs_src = \
	../tsk/fs/tsk_fs_i.h \
	../tsk/fs/fs_inode.c \
	../tsk/fs/fs_io.c \
	../tsk/fs/fs_block.c \
	../tsk/fs/fs_open.c \
	../tsk/fs/fs_name.c \
	../tsk/fs/fs_dir.c \
	../tsk/fs/fs_types.c \
	../tsk/fs/fs_attr.c \
	../tsk/fs/fs_attrlist.c \
	../tsk/fs/fs_load.c \
	../tsk/fs/fs_parse.c \
	../tsk/fs/fs_file.c \
	../tsk/fs/unix_misc.c \
	../tsk/fs/nofs_misc.c \
	../tsk/fs/ffs.c \
	../tsk/fs/ \
	../tsk/fs/ffs_dent.c \
	../tsk/fs/ext2fs.c \
	../tsk/fs/ext2fs_dent.c \
	../tsk/fs/ext2fs_journal.c \
	../tsk/fs/fatfs.c \
	../tsk/fs/fatfs_meta.c \
	../tsk/fs/fatfs_dent.cpp \
	../tsk/fs/fatxxfs.c \
	../tsk/fs/fatxxfs_meta.c \
	../tsk/fs/fatxxfs_dent.c \
	../tsk/fs/exfatfs.c \
	../tsk/fs/exfatfs_meta.c \
	../tsk/fs/exfatfs_dent.c \
	../tsk/fs/fatfs_utils.c \
	../tsk/fs/ntfs.c \
	../tsk/fs/ntfs_dent.cpp \
	../tsk/fs/swapfs.c \
	../tsk/fs/rawfs.c \
	../tsk/fs/iso9660.c \
	../tsk/fs/iso9660_dent.c \
	../tsk/fs/hfs.c \
	../tsk/fs/hfs_dent.c \
	../tsk/fs/hfs_journal.c \
	../tsk/fs/hfs_unicompare.c \
	../tsk/fs/decmpfs.c \
	../tsk/fs/lzvn.c \
	../tsk/fs/lzvn.h \
	../tsk/fs/dcalc_lib.c \
	../tsk/fs/dcat_lib.c \
	../tsk/fs/dls_lib.c \
	../tsk/fs/dstat_lib.c \
	../tsk/fs/ffind_lib.c \
	../tsk/fs/fls_lib.c \
	../tsk/fs/icat_lib.c \
	../tsk/fs/ifind_lib.c \
	../tsk/fs/ils_lib.c \
	../tsk/fs/usn_journal.c \
	../tsk/fs/usnjls_lib.c \
	../tsk/fs/walk_cpp.cpp \
	../tsk/fs/yaffs.cpp \
	../tsk/fs/logical_fs.cpp \
	../tsk/fs/apfs.cpp \
	../tsk/fs/apfs_compat.cpp \
	../tsk/fs/apfs_fs.cpp \
	../tsk/fs/apfs_open.cpp \
	../tsk/fs/encryptionHelper.cpp

hashdb_src = \
	../tsk/hashdb/encase.c \
	../tsk/hashdb/hashkeeper.c \
	../tsk/hashdb/idxonly.c \
	../tsk/hashdb/md5sum.c \
	../tsk/hashdb/nsrl.c \
	../tsk/hashdb/sqlite_hdb.cpp \
	../tsk/hashdb/binsrch_index.cpp \
	../tsk/hashdb/tsk_hashdb.c \
	../tsk/hashdb/hdb_base.c \
	../tsk/hashdb/tsk_hash_info.h \
	../tsk/hashdb/tsk_hashdb.h \
	../tsk/hashdb/tsk_hashdb_i.h

img_src = \
	../tsk/img/aff.c \
	../tsk/img/aff.h \
	../tsk/img/aff4.c \
	../tsk/img/aff4.h \
	../tsk/img/ewf.cpp \
	../tsk/img/ewf.h \
	../tsk/img/img_io.c \
	../tsk/img/img_open.cpp \
	../tsk/img/img_types.c \
	../tsk/img/img_writer.cpp \
	../tsk/img/img_writer.h \
	../tsk/img/logical_img.c \
	../tsk/img/logical_img.h \
	../tsk/img/mult_files.cpp \
	../tsk/img/raw.c \
	../tsk/img/raw.h \
	../tsk/img/tsk_img_i.h \
	../tsk/img/unsupported_types.c \
	../tsk/img/unsupported_types.h \
	../tsk/img/vhd.c \
	../tsk/img/vhd.h \
	../tsk/img/vmdk.c \
	../tsk/img/vmdk.h

pool_src = \
	../tsk/pool/pool_open.cpp \
	../tsk/pool/pool_read.cpp \
	../tsk/pool/pool_types.cpp \
	../tsk/pool/apfs_pool_compat.cpp \
	../tsk/pool/apfs_pool.cpp \
	../tsk/pool/img_bfio_handle.c \
	../tsk/pool/img_bfio_handle.h \
	../tsk/pool/lvm_pool_compat.cpp \
	../tsk/pool/lvm_pool.cpp


util_src = \
	../tsk/util/crypto.cpp \
	../tsk/util/detect_encryption.c \
	../tsk/util/file_system_utils.c

vs_src = \
	../tsk/vs/mm_open.c \
	../tsk/vs/mm_part.c \
	../tsk/vs/mm_types.c \
	../tsk/vs/mm_io.c \
	../tsk/vs/bsd.c \
	../tsk/vs/dos.c \
	../tsk/vs/gpt.c \
	../tsk/vs/mac.c \
	../tsk/vs/sun.c \
	../tsk/vs/tsk_vs_i.h

runner_SOURCES = runner.cpp mult_files_test.cpp errors_test.cpp  catch.hpp $(auto_src) $(base_src) $(fs_src) $(hashdb_src) $(img_src) \
	$(pool_src) $(util_src) $(vs_src)
