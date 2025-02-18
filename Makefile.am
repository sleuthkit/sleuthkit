ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/tsk $(SQLITE3_CPPFLAGS) $(CRYPTO_CPPFLAGS) $(AFFLIB_CPPFLAGS) $(AFF4_CPPFLAGS) $(EWF_CPPFLAGS) $(QCOW_CPPFLAGS) $(VHDI_CPPFLAGS) $(VMDK_CPPFLAGS) $(VSLVM_CPPFLAGS) $(BFIO_CPPFLAGS) $(ZLIB_CPPFLAGS)
AM_CFLAGS = -Wall -Wextra $(PTHREAD_CFLAGS) $(SQLITE3_CFLAGS) $(CRYPTO_CFLAGS) $(AFFLIB_CFLAGS) $(AFF4_CFLAGS) $(EWF_CFLAGS) $(QCOW_CFLAGS) $(VHDI_CFLAGS) $(VMDK_CFLAGS) $(VSLVM_CFLAGS) $(BFIO_CFLAGS) $(ZLIB_CFLAGS)
AM_CXXFLAGS = -Wall -Wextra -Woverloaded-virtual $(PTHREAD_CXXFLAGS) $(CRYPTO_CXXFLAGS) $(SQLITE3_CXXFLAGS) $(AFFLIB_CXXFLAGS) $(AFF4_CXXFLAGS) $(EWF_CXXFLAGS) $(QCOW_CXXFLAGS) $(VHDI_CXXFLAGS) $(VMDK_CXXFLAGS) $(VSLVM_CXXFLAGS) $(BFIO_CXXFLAGS) $(ZLIB_CXXFLAGS)
AM_LDFLAGS = $(SQLITE3_LDFLAGS) $(AFFLIB_LDFLAGS) $(CRYPTO_LDFLAGS) $(AFF4_LDFLAGS) $(EWF_LDFLAGS) $(QCOW_LDFLAGS) $(VHDI_LDFLAGS) $(VMDK_LDFLAGS) $(VSLVM_LDFLAGS) $(BFIO_LDFLAGS) $(ZLIB_LDFLAGS)

CLEANFILES = *.gcov

# File that we want to include in the dist
EXTRA_DIST = \
	API-CHANGES.txt \
	ChangeLog.txt \
	INSTALL.txt \
	NEWS.txt \
	README_win32.txt \
	README.md \
	bindings/java/README.txt \
	bindings/java/*.xml \
	bindings/java/doxygen/Doxyfile \
	bindings/java/doxygen/*.dox \
	bindings/java/doxygen/*.html \
	bindings/java/nbproject/project.xml \
	bindings/java/src/org/sleuthkit/datamodel/*.java \
	bindings/java/src/org/sleuthkit/datamodel/*.html \
	bindings/java/src/org/sleuthkit/datamodel/*.properties \
	bindings/java/src/org/sleuthkit/datamodel/blackboardutils/*.java \
	bindings/java/src/org/sleuthkit/datamodel/blackboardutils/attributes/*.java \
	bindings/java/src/org/sleuthkit/datamodel/Examples/*.java \
	bindings/java/src/*.html \
	case-uco/java/*.xml \
	case-uco/java/*.md \
	case-uco/java/nbproject/*.xml \
	case-uco/java/nbproject/*.properties \
	case-uco/java/src/org/sleuthkit/caseuco/*.java \
	case-uco/java/test/org/sleuthkit/caseuco/*.java \
	docs/README.txt \
	licenses/README.md \
	licenses/GNUv2-COPYING \
	licenses/GNUv3-COPYING \
	licenses/IBM-LICENSE \
	licenses/Apache-LICENSE-2.0.txt \
	licenses/cpl1.0.txt \
	licenses/bsd.txt \
	licenses/mit.txt \
	m4/*.m4 \
	packages/sleuthkit.spec \
	win32/BUILDING.txt \
	win32/*/*.vcxproj \
	win32/tsk-win.sln \
	win32/NugetPackages.props \
	win32/docs/*

nobase_include_HEADERS = \
	tsk/auto/guid.h \
	tsk/auto/tsk_auto.h \
	tsk/auto/tsk_is_image_supported.h \
	tsk/base/tsk_base.h \
	tsk/base/tsk_os.h \
	tsk/base/tsk_os_cpp.h \
	tsk/fs/apfs_compat.hpp \
	tsk/fs/apfs_fs.h \
	tsk/fs/apfs_fs.hpp \
	tsk/fs/decmpfs.h \
	tsk/fs/encryptionHelper.h \
	tsk/fs/tsk_apfs.h \
	tsk/fs/tsk_apfs.hpp \
	tsk/fs/tsk_btrfs.h \
	tsk/fs/tsk_exfatfs.h \
	tsk/fs/tsk_ext2fs.h \
	tsk/fs/tsk_fatfs.h \
	tsk/fs/tsk_fatxxfs.h \
	tsk/fs/tsk_xfs.h \
	tsk/fs/tsk_ffs.h \
	tsk/fs/tsk_fs.h \
	tsk/fs/tsk_hfs.h \
	tsk/fs/tsk_iso9660.h \
	tsk/fs/tsk_logical_fs.h \
	tsk/fs/tsk_ntfs.h \
	tsk/fs/tsk_yaffs.h \
	tsk/hashdb/tsk_hashdb.h \
	tsk/img/logical_img.h \
	tsk/img/pool.hpp \
	tsk/img/tsk_img.h \
	tsk/libtsk.h \
	tsk/pool/apfs_pool_compat.hpp \
	tsk/pool/lvm_pool_compat.hpp \
	tsk/pool/pool_compat.hpp \
	tsk/pool/tsk_apfs.h \
	tsk/pool/tsk_apfs.hpp \
	tsk/pool/tsk_pool.h \
	tsk/pool/tsk_pool.hpp \
	tsk/tsk_incs.h \
	tsk/util/Bitlocker/BitlockerParser.h \
	tsk/util/Bitlocker/BitlockerUtils.h \
	tsk/vs/tsk_vs.h \
	tsk/util/Bitlocker/DataTypes.h \
	tsk/util/Bitlocker/MetadataEntry.h \
	tsk/util/Bitlocker/MetadataUtils.h \
	tsk/util/Bitlocker/MetadataValueAesCcmEncryptedKey.h \
	tsk/util/Bitlocker/MetadataValue.h \
	tsk/util/Bitlocker/MetadataValueKey.h \
	tsk/util/Bitlocker/MetadataValueOffsetAndSize.h \
	tsk/util/Bitlocker/MetadataValueStretchKey.h \
	tsk/util/Bitlocker/MetadataValueUnicode.h \
	tsk/util/Bitlocker/MetadataValueVolumeMasterKey.h \
	tsk/util/crypto.hpp \
	tsk/util/detect_encryption.h \
	tsk/util/file_system_utils.h \
	tsk/util/lw_shared_ptr.hpp \
	tsk/util/span.hpp \
	tsk/vs/tsk_bsd.h \
	tsk/vs/tsk_dos.h \
	tsk/vs/tsk_gpt.h \
	tsk/vs/tsk_mac.h \
	tsk/vs/tsk_sun.h

nobase_dist_data_DATA = \
	tsk/sorter/default.sort \
	tsk/sorter/freebsd.sort \
	tsk/sorter/images.sort \
	tsk/sorter/linux.sort \
	tsk/sorter/openbsd.sort \
	tsk/sorter/solaris.sort \
	tsk/sorter/windows.sort

#
# Library
#

TSK_LIBS = \
	tsk/libtsk.la \
	$(TSK_LIB_LIBS)

TSK_LIB_LIBS = \
	$(PTHREAD_LIBS) \
	$(SQLITE3_LIBS) \
	$(CRYPTO_LIBS) \
	$(AFFLIB_LIBS) \
	$(AFF4_LIBS) \
	$(EWF_LIBS) \
	$(QCOW_LIBS) \
	$(VHDI_LIBS) \
	$(VMDK_LIBS) \
	$(VSLVM_LIBS) \
	$(BFIO_LIBS) \
	$(ZLIB_LIBS) \
	$(STDCPP_LIBS)

noinst_LTLIBRARIES = \
	tools/libtsktools.la \
	tsk/auto/libtskauto.la \
	tsk/base/libtskbase.la \
	tsk/fs/libtskfs.la \
	tsk/hashdb/libtskhashdb.la \
	tsk/img/libtskimg.la \
	tsk/pool/libtskpool.la \
	tsk/util/libtskutil.la \
	tsk/util/Bitlocker/libtskbitlocker.la \
	tsk/vs/libtskvs.la

tsk_auto_libtskauto_la_CFLAGS = $(AM_CFLAGS) -Wmultichar
tsk_auto_libtskauto_la_CXXFLAGS = $(AM_CXXFLAGS) -Wmultichar -Wsign-promo
tsk_auto_libtskauto_la_SOURCES = \
	tsk/auto/auto.cpp \
	tsk/auto/auto_db.cpp \
	tsk/auto/case_db.cpp \
	tsk/auto/db_sqlite.cpp \
	tsk/auto/guid.cpp \
	tsk/auto/guid.h \
	tsk/auto/is_image_supported.cpp \
	tsk/auto/tsk_auto.h \
	tsk/auto/tsk_auto_i.h \
	tsk/auto/tsk_case_db.h \
	tsk/auto/tsk_case_db.h \
	tsk/auto/tsk_db.cpp \
	tsk/auto/tsk_db.h \
	tsk/auto/tsk_db_sqlite.h \
	tsk/auto/tsk_is_image_supported.h

# Compile the bundled sqlite3 if there isn't an existing lib to use
if !HAVE_LIBSQLITE3
AM_CPPFLAGS += -Ivendors
tsk_auto_libtskauto_la_SOURCES += vendors/sqlite3.c vendors/sqlite3.h
endif

tsk_base_libtskbase_la_SOURCES = \
	tsk/base/crc.c \
	tsk/base/crc.h \
	tsk/base/md5c.c \
	tsk/base/mymalloc.c \
	tsk/base/sha1c.c \
	tsk/base/tsk_base_i.c \
	tsk/base/tsk_base_i.h \
	tsk/base/tsk_endian.c \
	tsk/base/tsk_error.c \
	tsk/base/tsk_error_win32.cpp \
	tsk/base/tsk_list.c \
	tsk/base/tsk_lock.c \
	tsk/base/tsk_parse.c \
	tsk/base/tsk_printf.c \
	tsk/base/tsk_stack.c \
	tsk/base/tsk_unicode.c \
	tsk/base/tsk_unicode.h \
	tsk/base/tsk_version.c \
	tsk/base/XGetopt.c

tsk_fs_libtskfs_la_SOURCES = \
	tsk/fs/apfs_compat.cpp \
	tsk/fs/apfs.cpp \
	tsk/fs/apfs_fs.cpp \
	tsk/fs/apfs_open.cpp \
	tsk/fs/dcalc_lib.cpp \
	tsk/fs/btrfs.cpp \
	tsk/fs/btrfs_csum.cpp \
	tsk/fs/dcat_lib.cpp \
	tsk/fs/decmpfs.cpp \
	tsk/fs/dls_lib.cpp \
	tsk/fs/dstat_lib.cpp \
	tsk/fs/encryptionHelper.cpp \
	tsk/fs/exfatfs.c \
	tsk/fs/exfatfs_dent.cpp \
	tsk/fs/exfatfs_meta.cpp \
	tsk/fs/ext2fs.cpp \
	tsk/fs/ext2fs_dent.cpp \
	tsk/fs/ext2fs_journal.cpp \
	tsk/fs/fatfs.cpp \
	tsk/fs/fatfs_dent.cpp \
	tsk/fs/fatfs_meta.cpp \
	tsk/fs/fatfs_utils.c \
	tsk/fs/fatxxfs.c \
	tsk/fs/fatxxfs_dent.c \
	tsk/fs/fatxxfs_meta.cpp \
	tsk/fs/ffind_lib.c \
	tsk/fs/ffs.cpp \
	tsk/fs/ffs_dent.cpp \
	tsk/fs/fls_lib.cpp \
	tsk/fs/fs_attr.cpp \
	tsk/fs/fs_attrlist.c \
	tsk/fs/fs_block.c \
	tsk/fs/fs_dir.cpp \
	tsk/fs/fs_file.cpp \
	tsk/fs/fs_inode.c \
	tsk/fs/fs_io.c \
	tsk/fs/fs_load.cpp \
	tsk/fs/fs_name.cpp \
	tsk/fs/fs_open.c \
	tsk/fs/fs_parse.c \
	tsk/fs/fs_types.c \
	tsk/fs/hfs.cpp \
	tsk/fs/hfs_dent.cpp \
	tsk/fs/hfs_journal.cpp \
	tsk/fs/hfs_unicompare.cpp \
	tsk/fs/icat_lib.cpp \
	tsk/fs/ifind_lib.cpp \
	tsk/fs/ils_lib.cpp \
	tsk/fs/iso9660.cpp \
	tsk/fs/iso9660_dent.cpp \
	tsk/fs/logical_fs.cpp \
	tsk/fs/lzvn.c \
	tsk/fs/lzvn.h \
	tsk/fs/nofs_misc.cpp \
	tsk/fs/ntfs.cpp \
	tsk/fs/ntfs_dent.cpp \
	tsk/fs/rawfs.c \
	tsk/fs/swapfs.c \
	tsk/fs/tsk_fs_i.h \
	tsk/fs/unix_misc.cpp \
	tsk/fs/usnjls_lib.cpp \
	tsk/fs/usn_journal.cpp \
	tsk/fs/walk_cpp.cpp \
	tsk/fs/yaffs.cpp \
	tsk/fs/xfs.cpp \
	tsk/fs/xfs_dent.cpp

tsk_hashdb_libtskhashdb_la_SOURCES = \
	tsk/hashdb/binsrch_index.cpp \
	tsk/hashdb/encase.cpp \
	tsk/hashdb/hashkeeper.c \
	tsk/hashdb/hdb_base.cpp \
	tsk/hashdb/idxonly.cpp \
	tsk/hashdb/md5sum.cpp \
	tsk/hashdb/nsrl.cpp \
	tsk/hashdb/sqlite_hdb.cpp \
	tsk/hashdb/tsk_hashdb.cpp \
	tsk/hashdb/tsk_hashdb.h \
	tsk/hashdb/tsk_hashdb_i.h \
	tsk/hashdb/tsk_hash_info.h

tsk_img_libtskimg_la_SOURCES = \
	tsk/img/aff4.cpp \
	tsk/img/aff4.h \
	tsk/img/aff.c \
	tsk/img/aff.h \
	tsk/img/ewf.cpp \
	tsk/img/ewf.h \
	tsk/img/img_io.cpp \
	tsk/img/img_open.cpp \
	tsk/img/img_open.h \
	tsk/img/img_types.c \
	tsk/img/img_writer.cpp \
	tsk/img/img_writer.h \
	tsk/img/legacy_cache.cpp \
	tsk/img/legacy_cache.h \
	tsk/img/logical_img.cpp \
	tsk/img/logical_img.h \
	tsk/img/mult_files.cpp \
	tsk/img/mult_files.h \
	tsk/img/qcow.cpp \
	tsk/img/qcow.h \
	tsk/img/raw.cpp \
	tsk/img/raw.h \
	tsk/img/tsk_img_i.h \
	tsk/img/unsupported_types.cpp \
	tsk/img/unsupported_types.h \
	tsk/img/vhd.cpp \
	tsk/img/vhd.h \
	tsk/img/vmdk.cpp \
	tsk/img/vmdk.h

tsk_pool_libtskpool_la_SOURCES = \
	tsk/pool/apfs_pool_compat.cpp \
	tsk/pool/apfs_pool.cpp \
	tsk/pool/img_bfio_handle.cpp \
	tsk/pool/img_bfio_handle.h \
	tsk/pool/lvm_pool_compat.cpp \
	tsk/pool/lvm_pool.cpp \
	tsk/pool/pool_open.cpp \
	tsk/pool/pool_read.cpp \
	tsk/pool/pool_types.cpp

tsk_util_libtskutil_la_SOURCES = \
	tsk/util/crypto.cpp \
	tsk/util/detect_encryption.c \
	tsk/util/file_system_utils.cpp

tsk_util_Bitlocker_libtskbitlocker_la_SOURCES = \
	tsk/util/Bitlocker/BitlockerParser.cpp \
	tsk/util/Bitlocker/BitlockerUtils.cpp \
	tsk/util/Bitlocker/DataTypes.cpp \
	tsk/util/Bitlocker/MetadataEntry.cpp \
	tsk/util/Bitlocker/MetadataUtils.cpp \
	tsk/util/Bitlocker/MetadataValueAesCcmEncryptedKey.cpp \
	tsk/util/Bitlocker/MetadataValueKey.cpp \
	tsk/util/Bitlocker/MetadataValueOffsetAndSize.cpp \
	tsk/util/Bitlocker/MetadataValueStretchKey.cpp \
	tsk/util/Bitlocker/MetadataValueUnicode.cpp \
	tsk/util/Bitlocker/MetadataValueVolumeMasterKey.cpp

tsk_vs_libtskvs_la_SOURCES = \
	tsk/vs/bsd.c \
	tsk/vs/dos.c \
	tsk/vs/gpt.c \
	tsk/vs/mac.c \
	tsk/vs/mm_io.c \
	tsk/vs/mm_open.c \
	tsk/vs/mm_part.c \
	tsk/vs/mm_types.c \
	tsk/vs/sun.c \
	tsk/vs/tsk_vs_i.h

# Merge the libraries into one
lib_LTLIBRARIES = tsk/libtsk.la
tsk_libtsk_la_SOURCES =
tsk_libtsk_la_LIBADD = \
	tsk/auto/libtskauto.la \
	tsk/base/libtskbase.la \
	tsk/fs/libtskfs.la \
	tsk/hashdb/libtskhashdb.la \
	tsk/img/libtskimg.la \
	tsk/pool/libtskpool.la \
	tsk/util/Bitlocker/libtskbitlocker.la \
	tsk/util/libtskutil.la \
	tsk/vs/libtskvs.la \
	$(TSK_LIB_LIBS)

# current:revision:age
tsk_libtsk_la_LDFLAGS = $(AM_LDFLAGS) -version-info 21:1:2 $(LIBTSK_LDFLAGS)

EXTRA_DIST += \
	tsk/tsk_tools_i.h \
	tsk/docs/Doxyfile \
	tsk/docs/*.dox \
	tsk/docs/*.html \
	tsk/tsk.pc.in

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = tsk/tsk.pc

#EXTRA_DIST = .indent.pro

#
# Tools
#

bin_PROGRAMS = \
	tools/autotools/tsk_comparedir \
	tools/autotools/tsk_gettimes \
	tools/autotools/tsk_imageinfo \
	tools/autotools/tsk_loaddb \
	tools/autotools/tsk_recover \
	tools/fiwalk/plugins/jpeg_extract \
	tools/fiwalk/src/fiwalk \
	tools/fstools/blkcalc \
	tools/fstools/blkcat \
	tools/fstools/blkls \
	tools/fstools/blkstat \
	tools/fstools/ffind \
	tools/fstools/fls \
	tools/fstools/fcat \
	tools/fstools/fsstat \
	tools/fstools/icat \
	tools/fstools/ifind \
	tools/fstools/ils \
	tools/fstools/istat \
	tools/fstools/jcat \
	tools/fstools/jls \
	tools/fstools/usnjls \
	tools/hashtools/hfind \
	tools/imgtools/img_cat \
	tools/imgtools/img_stat \
	tools/pooltools/pstat \
	tools/srchtools/srch_strings \
	tools/srchtools/sigfind \
	tools/vstools/mmls \
	tools/vstools/mmstat \
	tools/vstools/mmcat

tools_libtsktools_la_SOURCES = \
	tools/util.cpp \
	tools/util.h

tools_autotools_tsk_comparedir_LDADD = $(TSK_LIBS)
tools_autotools_tsk_comparedir_SOURCES = \
	tools/autotools/tsk_comparedir.cpp \
	tools/autotools/tsk_comparedir.h

tools_autotools_tsk_gettimes_LDADD = $(TSK_LIBS)
tools_autotools_tsk_gettimes_SOURCES = tools/autotools/tsk_gettimes.cpp

tools_autotools_tsk_imageinfo_LDADD = $(TSK_LIBS)
tools_autotools_tsk_imageinfo_SOURCES = tools/autotools/tsk_imageinfo.cpp

tools_autotools_tsk_loaddb_LDADD = $(TSK_LIBS)
tools_autotools_tsk_loaddb_SOURCES = tools/autotools/tsk_loaddb.cpp

tools_autotools_tsk_recover_LDADD = $(TSK_LIBS)
tools_autotools_tsk_recover_SOURCES = tools/autotools/tsk_recover.cpp

tools_fiwalk_plugins_jpeg_extract_SOURCES = tools/fiwalk/plugins/jpeg_extract.cpp

EXTRA_DIST += \
	tools/fiwalk/plugins/docx_extractor.py \
	tools/fiwalk/plugins/docx_grep.py \
	tools/fiwalk/plugins/ficonfig.txt \
	tools/fiwalk/plugins/jpeg_extract.java \
	tools/fiwalk/plugins/Libextract_plugin.java \
	tools/fiwalk/plugins/odf_extractor.py \
	tools/fiwalk/plugins/word_extract.java \
	tools/fiwalk/src/config-simple.txt \
	tools/fiwalk/src/ficonfig.txt \
	tools/fiwalk/src/lua_utf8.c \
	tools/fiwalk/src/README_PLUGINS.txt \
	tools/fiwalk/src/word-count-plugin.sh

tools/fiwalk/plugins/plugins.jar: tools/fiwalk/plugins/jpeg_extract.class tools/fiwalk/plugins/word_extract.class tools/fiwalk/plugins/Libextract_plugin.class
	jar cfv tools/fiwalk/plugins/plugins.jar tools/fiwalk/plugins/jpeg_extract.class tools/fiwalk/plugins/word_extract.class tools/fiwalk/plugins/Libextract_plugin.class

tools/fiwalk/plugins/jpeg_extract.class: tools/fiwalk/plugins/jpeg_extract.java
	javac tools/fiwalk/plugins/jpeg_extract.java

tools/fiwalk/plugins/word_extract.class: tools/fiwalk/plugins/word_extract.java
	javac tools/fiwalk/plugins/word_extract.java

tools/fiwalk/plugins/Libextract_plugin.class: tools/fiwalk/plugins/Libextract_plugin.java
	javac tools/fiwalk/plugins/Libextract_plugin.java

noinst_LTLIBRARIES += tools/fiwalk/src/libfiwalk.la

tools_fiwalk_src_libfiwalk_la_LIBADD = $(TSK_LIBS)
tools_fiwalk_src_libfiwalk_la_SOURCES = \
	tools/fiwalk/src/arff.cpp \
	tools/fiwalk/src/arff.h \
	tools/fiwalk/src/base64.cpp \
	tools/fiwalk/src/base64.h \
	tools/fiwalk/src/content.cpp \
	tools/fiwalk/src/content.h \
	tools/fiwalk/src/dfxml.cpp \
	tools/fiwalk/src/dfxml.h \
	tools/fiwalk/src/fiwalk.cpp \
	tools/fiwalk/src/fiwalk.h \
	tools/fiwalk/src/fiwalk_tsk.cpp \
	tools/fiwalk/src/hash_t.h \
	tools/fiwalk/src/hexbuf.c \
	tools/fiwalk/src/hexbuf.h \
	tools/fiwalk/src/plugin.cpp \
	tools/fiwalk/src/plugin.h \
	tools/fiwalk/src/sha2.c \
	tools/fiwalk/src/sha2.h \
	tools/fiwalk/src/unicode_escape.cpp \
	tools/fiwalk/src/unicode_escape.h \
	tools/fiwalk/src/utils.c \
	tools/fiwalk/src/utils.h

tools_fiwalk_src_fiwalk_LDADD = tools/fiwalk/src/libfiwalk.la $(TSK_LIBS)
tools_fiwalk_src_fiwalk_SOURCES = tools/fiwalk/src/fiwalk_main.cpp

EXTRA_DIST += tools/fstools/fscheck.cpp

tools_fstools_blkcalc_LDADD = $(TSK_LIBS)
tools_fstools_blkcalc_SOURCES = tools/fstools/blkcalc.cpp

tools_fstools_blkcat_LDADD = $(TSK_LIBS)
tools_fstools_blkcat_SOURCES = tools/fstools/blkcat.cpp

tools_fstools_blkls_LDADD = $(TSK_LIBS)
tools_fstools_blkls_SOURCES = tools/fstools/blkls.cpp

tools_fstools_blkstat_LDADD = $(TSK_LIBS)
tools_fstools_blkstat_SOURCES = tools/fstools/blkstat.cpp

tools_fstools_ffind_LDADD = $(TSK_LIBS)
tools_fstools_ffind_SOURCES = tools/fstools/ffind.cpp

tools_fstools_fls_LDADD = $(TSK_LIBS) tools/libtsktools.la
tools_fstools_fls_SOURCES = tools/fstools/fls.cpp

tools_fstools_fcat_LDADD = $(TSK_LIBS)
tools_fstools_fcat_SOURCES = tools/fstools/fcat.cpp

tools_fstools_fsstat_LDADD = $(TSK_LIBS)
tools_fstools_fsstat_SOURCES = tools/fstools/fsstat.cpp

tools_fstools_icat_LDADD = $(TSK_LIBS)
tools_fstools_icat_SOURCES = tools/fstools/icat.cpp

tools_fstools_ifind_LDADD = $(TSK_LIBS)
tools_fstools_ifind_SOURCES = tools/fstools/ifind.cpp

tools_fstools_ils_LDADD = $(TSK_LIBS)
tools_fstools_ils_SOURCES = tools/fstools/ils.cpp

tools_fstools_istat_LDADD = $(TSK_LIBS)
tools_fstools_istat_SOURCES = tools/fstools/istat.cpp

tools_fstools_jcat_LDADD = $(TSK_LIBS)
tools_fstools_jcat_SOURCES = tools/fstools/jcat.cpp

tools_fstools_jls_LDADD = $(TSK_LIBS)
tools_fstools_jls_SOURCES = tools/fstools/jls.cpp

tools_fstools_usnjls_LDADD = $(TSK_LIBS)
tools_fstools_usnjls_SOURCES = tools/fstools/usnjls.cpp

EXTRA_DIST += tools/hashtools/md5.c tools/hashtools/sha1.c

tools_hashtools_hfind_LDADD = $(TSK_LIBS)
tools_hashtools_hfind_SOURCES = tools/hashtools/hfind.cpp

tools_imgtools_img_cat_LDADD = $(TSK_LIBS)
tools_imgtools_img_cat_SOURCES = tools/imgtools/img_cat.cpp

tools_imgtools_img_stat_LDADD = $(TSK_LIBS)
tools_imgtools_img_stat_SOURCES = tools/imgtools/img_stat.cpp

tools_pooltools_pstat_LDADD = $(TSK_LIBS)
tools_pooltools_pstat_SOURCES = tools/pooltools/pstat.cpp

tools_srchtools_srch_strings_SOURCES = tools/srchtools/srch_strings.c

tools_srchtools_sigfind_LDADD = $(TSK_LIBS)
tools_srchtools_sigfind_SOURCES = tools/srchtools/sigfind.cpp

tools_vstools_mmls_LDADD = $(TSK_LIBS) tools/libtsktools.la
tools_vstools_mmls_SOURCES = tools/vstools/mmls.cpp

tools_vstools_mmstat_LDADD = $(TSK_LIBS)
tools_vstools_mmstat_SOURCES = tools/vstools/mmstat.cpp

tools_vstools_mmcat_LDADD = $(TSK_LIBS)
tools_vstools_mmcat_SOURCES = tools/vstools/mmcat.cpp

bin_SCRIPTS = tools/sorter/sorter tools/timeline/mactime

CLEANFILES += $(bin_SCRIPTS)

EXTRA_DIST += \
	tools/sorter/sorter.base \
	tools/sorter/.perltidyrc \
	tools/timeline/mactime.base \
	tools/timeline/.perltidyrc

tools/timeline/mactime: tools/timeline/mactime.base Makefile
	@echo "#!$(PERL) -w" >$@
	@echo "my \$$VER=\"$(VERSION)\";" >>$@
	@cat $(srcdir)/tools/timeline/mactime.base >>$@
	@chmod +x $@

tools/sorter/sorter: tools/sorter/sorter.base Makefile
	@echo "#!$(PERL) -w" >$@
	@echo "my \$$BIN_DIR=\"$(bindir)\";" >>$@
	@echo "my \$$DATA_DIR=\"$(datadir)\";" >>$@
	@echo "my \$$VER=\"$(VERSION)\";" >>$@
	@cat $(srcdir)/tools/sorter/sorter.base >>$@
	@chmod +x $@

#indent:
#	pushd sorter ; perltidy -b sorter.base ; popd
#	pushd timeline ; perltidy -b mactime.base ; popd

EXTRA_DIST += tests/runtests.sh

check_SCRIPTS = \
	test/check_static.sh \
	test/test_libraries.sh \
	test/test_static_tools.sh \
	test/img_dump/img_differ.sh \
	test/img_dump/test_imgs.sh \
	test/img_dump/test_imgs_E01.sh \
	test/legacy/runtests.sh \
	test/tools/tool_differ.sh \
	test/tools/fstools/test_fls.sh \
	test/tools/vstools/test_mmls.sh \
	test/tools/vstools/test_mmls_E01.sh

TESTS =	\
	test/runner \
	test/test_libraries.sh \
	test/fiwalk/fiwalk_test \
	test/img_dump/test_imgs.sh \
	test/legacy/runtests.sh \
	test/tools/fstools/test_fls.sh \
	test/tools/vstools/test_mmls.sh

if HAVE_E01
TESTS += \
	test/img_dump/test_imgs_E01.sh \
	test/tools/vstools/test_mmls_E01.sh
endif

if BUILD_STATIC
TESTS += test/test_static_tools.sh
endif

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER =

if USE_WINE
TESTS_ENVIRONMENT = WINE=wine
endif

LOG_COMPILER = scripts/test_runner.sh

# TODO: nothing runs fs_attrlist_apis, fs_name_apis, fs_thread_test, read_apis
check_PROGRAMS = \
	test/runner \
	test/fiwalk/fiwalk_test \
	test/img_dump/img_dump \
	test/legacy/fs_attrlist_apis \
	test/legacy/fs_fname_apis \
	test/legacy/fs_thread_test \
	test/legacy/read_apis

test_runner_CPPFLAGS = $(AM_CPPFLAGS) -Ivendors $(CATCH2_CPPFLAGS)
test_runner_LDADD = $(TSK_LIBS)
test_runner_SOURCES = \
	test/tsk/base/test_tsk_error.cpp \
	test/tsk/img/test_aff4.cpp \
	test/tsk/img/test_ewf.cpp \
	test/tsk/img/test_img_io.cpp \
	test/tsk/img/test_img_open.cpp \
	test/tsk/img/test_mult_files.cpp \
	test/tsk/img/test_qcow.cpp \
	test/tsk/img/test_raw.cpp \
	test/tsk/img/test_vhd.cpp \
	test/tsk/img/test_vmdk.cpp \
	test/tsk/util/test_crypto.cpp \
	test/tsk/hashdb/test_binsrch_index.cpp \
	test/runner.cpp

EXTRA_test_runner_DEPENDENCIES = test/get_images/test_images.txt

test_fiwalk_fiwalk_test_CPPFLAGS = $(AM_CPPFLAGS) -Ivendors $(CATCH2_CPPFLAGS)
test_fiwalk_fiwalk_test_LDADD = $(TSK_LIBS)
test_fiwalk_fiwalk_test_SOURCES = \
	test/fiwalk/fiwalk_test.cpp \
	$(tools_fiwalk_src_libfiwalk_la_SOURCES)

EXTRA_test_fiwalk_fiwalk_test_DEPENDENCIES = test/get_images/test_images.txt

test/get_images/test_images.txt: test/get_images/test_images.yaml test/get_images/get_test_images.bash test/get_images/get_test_images.py
	test/get_images/get_test_images.bash

CLEANFILES += test/get_images/test_images.txt

test_img_dump_img_dump_LDADD = $(TSK_LIBS)
test_img_dump_img_dump_SOURCES = test/img_dump/img_dump.cpp

test_legacy_fs_fname_apis_LDADD = $(TSK_LIBS)
test_legacy_fs_fname_apis_SOURCES = test/legacy/fs_fname_apis.cpp

test_legacy_fs_attrlist_apis_LDADD = $(TSK_LIBS)
test_legacy_fs_attrlist_apis_SOURCES = test/legacy/fs_attrlist_apis.cpp

test_legacy_fs_thread_test_LDADD = $(TSK_LIBS)
test_legacy_fs_thread_test_SOURCES = \
	test/legacy/fs_thread_test.cpp \
	test/legacy/tsk_thread.cpp \
	test/legacy/tsk_thread.h

test_legacy_read_apis_LDADD = $(TSK_LIBS)
test_legacy_read_apis_SOURCES = test/legacy/read_apis.cpp

#
# Java
#

# Compile java bindings if all of the dependencies exist
if X_JNI

if OFFLINE
ant_args=-Doffline=true
if CUSTOM_DEFAULT_JAR_LOCATION
ant_args+= -Ddefault-jar-location="@DEFAULT_JAR_LOCATION@"
endif
endif

tsk_jar = $(top_builddir)/bindings/java/dist/sleuthkit-$(PACKAGE_VERSION).jar
jardir = $(prefix)/share/java

$(tsk_jar):
	cd bindings/java ; ant dist $(ant_args)

clean-tsk__jar:
	cd bindings/java ; ant clean

CLEANFILES += $(tsk_jar)

jar_DATA = $(tsk_jar) $(tsk_caseuco_jar)

lib_LTLIBRARIES += bindings/java/jni/libtsk_jni.la

bindings_java_jni_libtsk_jni_la_CPPFLAGS = $(AM_CPPFLAGS) $(JNI_CPPFLAGS)
bindings_java_jni_libtsk_jni_la_LIBADD = $(TSK_LIBS)
bindings_java_jni_libtsk_jni_la_SOURCES = \
	bindings/java/jni/auto_db_java.cpp \
	bindings/java/jni/auto_db_java.h \
	bindings/java/jni/dataModel_SleuthkitJNI.cpp \
	bindings/java/jni/dataModel_SleuthkitJNI.h

tsk_caseuco_jar = $(top_builddir)/case-uco/java/dist/sleuthkit-caseuco-$(PACKAGE_VERSION).jar

$(tsk_caseuco_jar):
	cd case-uco/java ; ant $(ant_args)

clean-tsk_caseuco_jar:
	cd case-uco/java ; ant clean

CLEANFILES += $(tsk_caseuco_jar)

clean_java = clean-tsk_jar clean-tsk_caseuco_jar

endif

clean-local: $(clean_java)

.PHONY: clean-tsk_jar clean-tsk_caseuco_jar

#
# Docs
#

api-docs:
	doxygen tsk/docs/Doxyfile
	cd bindings/java/doxygen; doxygen Doxyfile

man-html:
	cd man; build-html

dist_man_MANS = \
	man/blkcalc.1 \
	man/blkcat.1 \
	man/blkls.1 \
	man/blkstat.1 \
	man/fcat.1 \
	man/ffind.1 \
	man/fls.1 \
	man/fsstat.1 \
	man/hfind.1 \
	man/icat.1 \
	man/ifind.1 \
	man/ils.1 \
	man/img_cat.1 \
	man/img_stat.1 \
	man/istat.1 \
	man/jcat.1 \
	man/jls.1 \
	man/mactime.1 \
	man/mmcat.1 \
	man/mmls.1 \
	man/mmstat.1 \
	man/sigfind.1 \
	man/sorter.1 \
	man/tsk_comparedir.1 \
	man/tsk_gettimes.1 \
	man/tsk_loaddb.1 \
	man/tsk_recover.1 \
	man/usnjls.1

noinst_PROGRAMS = \
	samples/callback_cpp_style \
	samples/callback_style \
	samples/posix_cpp_style \
	samples/posix_style

samples_callback_cpp_style_LDADD = $(TSK_LIBS)
samples_callback_cpp_style_SOURCES = samples/callback-cpp-style.cpp

samples_callback_style_LDADD = $(TSK_LIBS)
samples_callback_style_SOURCES = samples/callback-style.cpp

samples_posix_cpp_style_LDADD = $(TSK_LIBS)
samples_posix_cpp_style_SOURCES = samples/posix-cpp-style.cpp

samples_posix_style_LDADD = $(TSK_LIBS)
samples_posix_style_SOURCES = samples/posix-style.cpp

#
# OSSFuzz fuzz targets fuzz targets
#

if HAVE_LIB_FUZZING_ENGINE
noinst_PROGRAMS += \
	fls_apfs_fuzzer \
	fls_ext_fuzzer \
	fls_fat_fuzzer \
	fls_hfs_fuzzer \
	fls_iso9660_fuzzer \
	fls_ntfs_fuzzer \
	fls_btrfs_fuzzer \
	mmls_dos_fuzzer \
	mmls_gpt_fuzzer \
	mmls_mac_fuzzer \
	mmls_sun_fuzzer

fls_apfs_fuzzer_SOURCES = \
	ossfuzz/fls_apfs_fuzzer.cc \
	ossfuzz/mem_img.h

fls_apfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_btrfs_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_btrfs_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_BTRFS_DETECT \
	$(AM_CPPFLAGS)

fls_btrfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_ext_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_ext_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_EXT_DETECT \
	$(AM_CPPFLAGS)

fls_ext_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_fat_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_fat_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_FAT_DETECT \
	$(AM_CPPFLAGS)

fls_fat_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_hfs_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_hfs_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_HFS \
	$(AM_CPPFLAGS)

fls_hfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_iso9660_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_iso9660_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_ISO9660 \
	$(AM_CPPFLAGS)

fls_iso9660_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

fls_ntfs_fuzzer_SOURCES = \
	ossfuzz/fls_fuzzer.cc \
	ossfuzz/mem_img.h

fls_ntfs_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_NTFS \
	$(AM_CPPFLAGS)

fls_ntfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

mmls_dos_fuzzer_SOURCES = \
	ossfuzz/mem_img.h \
	ossfuzz/mmls_fuzzer.cc

mmls_dos_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_DOS \
	$(AM_CPPFLAGS)

mmls_dos_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

mmls_gpt_fuzzer_SOURCES = \
	ossfuzz/mem_img.h \
	ossfuzz/mmls_fuzzer.cc

mmls_gpt_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_GPT \
	$(AM_CPPFLAGS)

mmls_gpt_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

mmls_mac_fuzzer_SOURCES = \
	ossfuzz/mem_img.h \
	ossfuzz/mmls_fuzzer.cc

mmls_mac_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_MAC \
	$(AM_CPPFLAGS)

mmls_mac_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)

mmls_sun_fuzzer_SOURCES = \
	ossfuzz/mem_img.h \
	ossfuzz/mmls_fuzzer.cc

mmls_sun_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_SUN \
	$(AM_CPPFLAGS)

mmls_sun_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	$(TSK_LIBS)
endif # HAVE_LIB_FUZZING_ENGINE
