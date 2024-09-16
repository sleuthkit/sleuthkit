ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = -I$(srcdir)/tsk
AM_CFLAGS += -Wall -Wextra -Wno-unused-parameter
AM_CXXFLAGS += -Wall -Wextra -Wno-unused-parameter -Wno-overloaded-virtual

CLEANFILES =

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

nobase_include_HEADERS = \
	tsk/auto/guid.h \
	tsk/auto/tsk_auto.h \
	tsk/auto/tsk_is_image_supported.h \
	tsk/base/tsk_base.h \
	tsk/base/tsk_os.h \
	tsk/fs/apfs_compat.hpp \
	tsk/fs/apfs_fs.h \
	tsk/fs/apfs_fs.hpp \
	tsk/fs/decmpfs.h \
	tsk/fs/encryptionHelper.h \
	tsk/fs/tsk_apfs.h \
	tsk/fs/tsk_apfs.hpp \
	tsk/fs/tsk_exfatfs.h \
	tsk/fs/tsk_ext2fs.h \
	tsk/fs/tsk_fatfs.h \
	tsk/fs/tsk_fatxxfs.h \
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

TSK_LIB = tsk/libtsk.la

noinst_LTLIBRARIES = \
	tsk/auto/libtskauto.la \
	tsk/base/libtskbase.la \
	tsk/fs/libtskfs.la \
	tsk/hashdb/libtskhashdb.la \
	tsk/img/libtskimg.la \
	tsk/pool/libtskpool.la \
	tsk/util/libtskutil.la \
	tsk/util/Bitlocker/libtskbitlocker.la \
	tsk/vs/libtskvs.la

tsk_auto_libtskauto_la_CFLAGS = $(AM_CFLAGS) -Wmultichar -Wsign-promo
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
tsk_auto_libtskauto_la_SOURCES += tsk/auto/sqlite3.c tsk/auto/sqlite3.h
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

tsk_fs_libtskfs_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
tsk_fs_libtskfs_la_SOURCES = \
	tsk/fs/apfs_compat.cpp \
	tsk/fs/apfs.cpp \
	tsk/fs/apfs_fs.cpp \
	tsk/fs/apfs_open.cpp \
	tsk/fs/dcalc_lib.c \
	tsk/fs/dcat_lib.c \
	tsk/fs/decmpfs.c \
	tsk/fs/dls_lib.c \
	tsk/fs/dstat_lib.c \
	tsk/fs/encryptionHelper.cpp \
	tsk/fs/exfatfs.c \
	tsk/fs/exfatfs_dent.c \
	tsk/fs/exfatfs_meta.c \
	tsk/fs/ext2fs.c \
	tsk/fs/ext2fs_dent.c \
	tsk/fs/ext2fs_journal.c \
	tsk/fs/fatfs.c \
	tsk/fs/fatfs_dent.cpp \
	tsk/fs/fatfs_meta.c \
	tsk/fs/fatfs_utils.c \
	tsk/fs/fatxxfs.c \
	tsk/fs/fatxxfs_dent.c \
	tsk/fs/fatxxfs_meta.c \
	tsk/fs/ffind_lib.c \
	tsk/fs/ffs.c \
	tsk/fs/ffs_dent.c \
	tsk/fs/fls_lib.c \
	tsk/fs/fs_attr.c \
	tsk/fs/fs_attrlist.c \
	tsk/fs/fs_block.c \
	tsk/fs/fs_dir.c \
	tsk/fs/fs_file.c \
	tsk/fs/fs_inode.c \
	tsk/fs/fs_io.c \
	tsk/fs/fs_load.c \
	tsk/fs/fs_name.c \
	tsk/fs/fs_open.c \
	tsk/fs/fs_parse.c \
	tsk/fs/fs_types.c \
	tsk/fs/hfs.c \
	tsk/fs/hfs_dent.c \
	tsk/fs/hfs_journal.c \
	tsk/fs/hfs_unicompare.c \
	tsk/fs/icat_lib.c \
	tsk/fs/ifind_lib.c \
	tsk/fs/ils_lib.c \
	tsk/fs/iso9660.c \
	tsk/fs/iso9660_dent.c \
	tsk/fs/logical_fs.cpp \
	tsk/fs/lzvn.c \
	tsk/fs/lzvn.h \
	tsk/fs/nofs_misc.c \
	tsk/fs/ntfs.c \
	tsk/fs/ntfs_dent.cpp \
	tsk/fs/rawfs.c \
	tsk/fs/swapfs.c \
	tsk/fs/tsk_fs_i.h \
	tsk/fs/unix_misc.c \
	tsk/fs/usnjls_lib.c \
	tsk/fs/usn_journal.c \
	tsk/fs/walk_cpp.cpp \
	tsk/fs/yaffs.cpp

tsk_hashdb_libtskhashdb_la_SOURCES = \
	tsk/hashdb/binsrch_index.cpp \
	tsk/hashdb/encase.c \
	tsk/hashdb/hashkeeper.c \
	tsk/hashdb/hdb_base.c \
	tsk/hashdb/idxonly.c \
	tsk/hashdb/md5sum.c \
	tsk/hashdb/nsrl.c \
	tsk/hashdb/sqlite_hdb.cpp \
	tsk/hashdb/tsk_hashdb.c \
	tsk/hashdb/tsk_hashdb.h \
	tsk/hashdb/tsk_hashdb_i.h \
	tsk/hashdb/tsk_hash_info.h

tsk_img_libtskimg_la_SOURCES = \
	tsk/img/aff4.c \
	tsk/img/aff4.h \
	tsk/img/aff.c \
	tsk/img/aff.h \
	tsk/img/ewf.cpp \
	tsk/img/ewf.h \
	tsk/img/img_io.c \
	tsk/img/img_open.cpp \
	tsk/img/img_types.c \
	tsk/img/img_writer.cpp \
	tsk/img/img_writer.h \
	tsk/img/logical_img.c \
	tsk/img/logical_img.h \
	tsk/img/mult_files.cpp \
	tsk/img/mult_files.h \
	tsk/img/qcow.c \
	tsk/img/qcow.h \
	tsk/img/raw.c \
	tsk/img/raw.h \
	tsk/img/tsk_img_i.h \
	tsk/img/unsupported_types.c \
	tsk/img/unsupported_types.h \
	tsk/img/vhd.c \
	tsk/img/vhd.h \
	tsk/img/vmdk.c \
	tsk/img/vmdk.h

tsk_pool_libtskpool_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
tsk_pool_libtskpool_la_CXXFLAGS = $(AM_CXXFLAGS) -Werror
tsk_pool_libtskpool_la_SOURCES = \
	tsk/pool/apfs_pool_compat.cpp \
	tsk/pool/apfs_pool.cpp \
	tsk/pool/img_bfio_handle.c \
	tsk/pool/img_bfio_handle.h \
	tsk/pool/lvm_pool_compat.cpp \
	tsk/pool/lvm_pool.cpp \
	tsk/pool/pool_open.cpp \
	tsk/pool/pool_read.cpp \
	tsk/pool/pool_types.cpp

tsk_util_libtskutil_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
tsk_util_libtskutil_la_CXXFLAGS = $(AM_CXXFLAGS) -Werror
tsk_util_libtskutil_la_SOURCES = \
	tsk/util/crypto.cpp \
	tsk/util/detect_encryption.c \
	tsk/util/file_system_utils.c

tsk_util_Bitlocker_libtskbitlocker_la_CPPFLAGS = $(AM_CPPFLAGS) $(OPENSSL_INCLUDES)
tsk_util_Bitlocker_libtskbitlocker_la_CXXFLAGS = $(AM_CXXFLAGS) -Werror
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
	tsk/vs/libtskvs.la

# current:revision:age
tsk_libtsk_la_LDFLAGS = -version-info 21:1:2 $(LIBTSK_LDFLAGS)

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

tools_autotools_tsk_comparedir_LDADD = $(TSK_LIB)
tools_autotools_tsk_comparedir_SOURCES = \
	tools/autotools/tsk_comparedir.cpp \
	tools/autotools/tsk_comparedir.h

tools_autotools_tsk_gettimes_LDADD = $(TSK_LIB)
tools_autotools_tsk_gettimes_SOURCES = tools/autotools/tsk_gettimes.cpp

tools_autotools_tsk_imageinfo_LDADD = $(TSK_LIB)
tools_autotools_tsk_imageinfo_SOURCES = tools/autotools/tsk_imageinfo.cpp

tools_autotools_tsk_loaddb_LDADD = $(TSK_LIB)
tools_autotools_tsk_loaddb_SOURCES = tools/autotools/tsk_loaddb.cpp

tools_autotools_tsk_recover_LDADD = $(TSK_LIB)
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

tools_fiwalk_src_libfiwalk_la_LIBADD = $(TSK_LIB)
tools_fiwalk_src_libfiwalk_la_SOURCES = \
	tools/fiwalk/src/arff.cpp \
	tools/fiwalk/src/arff.h \
	tools/fiwalk/src/base64.cpp \
	tools/fiwalk/src/base64.h \
	tools/fiwalk/src/content.cpp \
	tools/fiwalk/src/content.h \
	tools/fiwalk/src/dfxml.cpp \
	tools/fiwalk/src/dfxml.h \
	tools/fiwalk/src/fiwalk.cpp  \
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

tools_fiwalk_src_fiwalk_LDADD = tools/fiwalk/src/libfiwalk.la
tools_fiwalk_src_fiwalk_SOURCES = tools/fiwalk/src/fiwalk_main.cpp

EXTRA_DIST += tools/fstools/fscheck.cpp

tools_fstools_blkcalc_LDADD = $(TSK_LIB)
tools_fstools_blkcalc_SOURCES = tools/fstools/blkcalc.cpp

tools_fstools_blkcat_LDADD = $(TSK_LIB)
tools_fstools_blkcat_SOURCES = tools/fstools/blkcat.cpp

tools_fstools_blkls_LDADD = $(TSK_LIB)
tools_fstools_blkls_SOURCES = tools/fstools/blkls.cpp

tools_fstools_blkstat_LDADD = $(TSK_LIB)
tools_fstools_blkstat_SOURCES = tools/fstools/blkstat.cpp

tools_fstools_ffind_LDADD = $(TSK_LIB)
tools_fstools_ffind_SOURCES = tools/fstools/ffind.cpp

tools_fstools_fls_LDADD = $(TSK_LIB)
tools_fstools_fls_SOURCES = tools/fstools/fls.cpp

tools_fstools_fcat_LDADD = $(TSK_LIB)
tools_fstools_fcat_SOURCES = tools/fstools/fcat.cpp

tools_fstools_fsstat_LDADD = $(TSK_LIB)
tools_fstools_fsstat_SOURCES = tools/fstools/fsstat.cpp

tools_fstools_icat_LDADD = $(TSK_LIB)
tools_fstools_icat_SOURCES = tools/fstools/icat.cpp

tools_fstools_ifind_LDADD = $(TSK_LIB)
tools_fstools_ifind_SOURCES = tools/fstools/ifind.cpp

tools_fstools_ils_LDADD = $(TSK_LIB)
tools_fstools_ils_SOURCES = tools/fstools/ils.cpp

tools_fstools_istat_LDADD = $(TSK_LIB)
tools_fstools_istat_SOURCES = tools/fstools/istat.cpp

tools_fstools_jcat_LDADD = $(TSK_LIB)
tools_fstools_jcat_SOURCES = tools/fstools/jcat.cpp

tools_fstools_jls_LDADD = $(TSK_LIB)
tools_fstools_jls_SOURCES = tools/fstools/jls.cpp

tools_fstools_usnjls_LDADD = $(TSK_LIB)
tools_fstools_usnjls_SOURCES = tools/fstools/usnjls.cpp

EXTRA_DIST += tools/hashtools/md5.c tools/hashtools/sha1.c

tools_hashtools_hfind_LDADD = $(TSK_LIB)
tools_hashtools_hfind_SOURCES = tools/hashtools/hfind.cpp

tools_imgtools_img_cat_LDADD = $(TSK_LIB)
tools_imgtools_img_cat_SOURCES = tools/imgtools/img_cat.cpp

tools_imgtools_img_stat_LDADD = $(TSK_LIB)
tools_imgtools_img_stat_SOURCES = tools/imgtools/img_stat.cpp

tools_pooltools_pstat_LDADD = $(TSK_LIB)
tools_pooltools_pstat_SOURCES = tools/pooltools/pstat.cpp

tools_srchtools_srch_strings_SOURCES = tools/srchtools/srch_strings.c

tools_srchtools_sigfind_LDADD = $(TSK_LIB)
tools_srchtools_sigfind_SOURCES = tools/srchtools/sigfind.cpp

tools_vstools_mmls_LDADD = $(TSK_LIB)
tools_vstools_mmls_SOURCES = tools/vstools/mmls.cpp

tools_vstools_mmstat_LDADD = $(TSK_LIB)
tools_vstools_mmstat_SOURCES = tools/vstools/mmstat.cpp

tools_vstools_mmcat_LDADD = $(TSK_LIB)
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
	tests/runtests.sh \
	tests/test_imgs.sh \
	tests/test_libraries.sh

TESTS = $(check_SCRIPTS)

TEST_EXTENSIONS = .sh
SH_LOG_COMPILER =

# TODO: nothing runs these (except for img_dump)!
check_PROGRAMS = \
	tests/fs_attrlist_apis \
	tests/fs_fname_apis \
	tests/fs_thread_test \
	tests/img_dump \
	tests/read_apis

tests_fs_fname_apis_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
tests_fs_fname_apis_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
tests_fs_fname_apis_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
tests_fs_fname_apis_LDADD = $(TSK_LIB)
tests_fs_fname_apis_SOURCES = tests/fs_fname_apis.cpp

tests_fs_attrlist_apis_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
tests_fs_attrlist_apis_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
tests_fs_attrlist_apis_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
tests_fs_attrlist_apis_LDADD = $(TSK_LIB)
tests_fs_attrlist_apis_SOURCES = tests/fs_attrlist_apis.cpp

tests_fs_thread_test_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
tests_fs_thread_test_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
tests_fs_thread_test_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
tests_fs_thread_test_LDADD = $(TSK_LIB)
tests_fs_thread_test_SOURCES = \
	tests/fs_thread_test.cpp \
	tests/tsk_thread.cpp \
	tests/tsk_thread.h

tests_img_dump_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
tests_img_dump_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
tests_img_dump_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
tests_img_dump_LDADD = $(TSK_LIB)
tests_img_dump_SOURCES = tests/img_dump.cpp

tests_read_apis_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
tests_read_apis_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
tests_read_apis_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
tests_read_apis_LDADD = $(TSK_LIB)
tests_read_apis_SOURCES = tests/read_apis.cpp

# Unit tests:
# Instead of linking with ../tsk/libtsk.la, we recompile everything from scratch
# and link into a single executable.
# THis makes things easier with codecov.

check_PROGRAMS += unit_tests/runner

# TODO: enable running unit_tests as part of 'make check'
#TESTS += unit_tests/runner

unit_tests_runner_CPPFLAGS = $(AM_CPPFLAGS) $(CATCH2_CPPFLAGS)
unit_tests_runner_CFLAGS = $(AM_CFLAGS) $(PTHREAD_CFLAGS)
unit_tests_runner_CXXFLAGS = $(AM_CXXFLAGS) $(PTHREAD_CFLAGS)
unit_tests_runner_LDFLAGS = $(AM_LDFLAGS) $(PTHREAD_LIBS)
unit_tests_runner_SOURCES = \
	unit_tests/catch.hpp \
	unit_tests/errors_test.cpp \
	unit_tests/fiwalk_test.cpp \
	unit_tests/mult_files_test.cpp \
	unit_tests/runner.cpp \
	$(tsk_auto_libtskauto_la_SOURCES) \
	$(tsk_base_libtskbase_la_SOURCES) \
	$(tsk_fs_libtskfs_la_SOURCES) \
	$(tsk_hashdb_libtskhashdb_la_SOURCES) \
	$(tsk_img_libtskimg_la_SOURCES) \
	$(tsk_pool_libtskpool_la_SOURCES) \
	$(tsk_util_libtskutil_la_SOURCES) \
	$(tsk_vs_libtskvs_la_SOURCES) \
	$(tools_fiwalk_src_libfiwalk_la_SOURCES)

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
bindings_java_jni_libtsk_jni_la_LIBADD = $(TSK_LIB)
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

noinst_PROGRAMS = \
	samples/callback_cpp_style \
	samples/callback_style \
	samples/posix_cpp_style \
	samples/posix_style

samples_callback_cpp_style_LDADD = $(TSK_LIB)
samples_callback_cpp_style_SOURCES = samples/callback-cpp-style.cpp

samples_callback_style_LDADD = $(TSK_LIB)
samples_callback_style_SOURCES = samples/callback-style.cpp

samples_posix_cpp_style_LDADD = $(TSK_LIB)
samples_posix_cpp_style_SOURCES = samples/posix-cpp-style.cpp

samples_posix_style_LDADD = $(TSK_LIB)
samples_posix_style_SOURCES = samples/posix-style.cpp
