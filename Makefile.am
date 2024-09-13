AM_CPPFLAGS = -I. -I$(srcdir)
AM_CFLAGS += -Wall -Wno-unused-command-line-argument
AM_CXXFLAGS += -Wall -Wno-overloaded-virtual -Wno-unused-command-line-argument

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

ACLOCAL_AMFLAGS = -I m4

# Compile java bindings if all of the dependencies existed
if X_JNI
  JAVA_BINDINGS=bindings/java
  JAVA_CASEUCO=case-uco/java
else
  JAVA_BINDINGS=
  JAVA_CASEUCO=
endif

SUBDIRS = tsk tools tests unit_tests $(JAVA_BINDINGS) $(JAVA_CASEUCO)

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

TSK_LIB = tsk/libtsk.la

#EXTRA_DIST = .indent.pro

noinst_PROGRAMS = \
	samples/callback_cpp_style \
	samples/callback_style \
	samples/posix_cpp_style \
	samples/posix_style

samples_callback_cpp_style_SOURCES = samples/callback-cpp-style.cpp
samples_callback_style_SOURCES = samples/callback-style.cpp
samples_posix_style_SOURCES = samples/posix-style.cpp
samples_posix_cpp_style_SOURCES = samples/posix-cpp-style.cpp

bin_PROGRAMS = \
	tools/autotools/tsk_comparedir \
	tools/autotools/tsk_gettimes \
	tools/autotools/tsk_imageinfo \
	tools/autotools/tsk_loaddb \
	tools/autotools/tsk_recover \
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
tools_autotools_tsk_comparedir_SOURCES = tools/autotools/tsk_comparedir.cpp tools/autotools/tsk_comparedir.h

tools_autotools_tsk_gettimes_LDADD = $(TSK_LIB)
tools_autotools_tsk_gettimes_SOURCES = tools/autotools/tsk_gettimes.cpp

tools_autotools_tsk_imageinfo_LDADD = $(TSK_LIB)
tools_autotools_tsk_imageinfo_SOURCES = tools/autotools/tsk_imageinfo.cpp

tools_autotools_tsk_loaddb_LDADD = $(TSK_LIB)
tools_autotools_tsk_loaddb_SOURCES = tools/autotools/tsk_loaddb.cpp

tools_autotools_tsk_recover_LDADD = $(TSK_LIB)
tools_autotools_tsk_recover_SOURCES = tools/autotools/tsk_recover.cpp

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

tools_srchtools_srch_strings_SOURCES = srch_strings.c

tools_srchtools_sigfind_LDADD = $(TSK_LIB)
tools_srchtools_sigfind_SOURCES = sigfind.cpp

tools_vstools_mmls_LDADD = $(TSK_LIB)
tools_vstools_mmls_SOURCES = tools/vstools/mmls.cpp

tools_vstools_mmstat_LDADD = $(TSK_LIB)
tools_vstools_mmstat_SOURCES = tools/vstools/mmstat.cpp

tools_vstools_mmcat_LDADD =  $(TSK_LIB)
tools_vstools_mmcat_SOURCES = tools/vstools/mmcat.cpp

api-docs:
	doxygen tsk/docs/Doxyfile
	cd bindings/java/doxygen; doxygen Doxyfile

man-html:
	cd man; build-html
