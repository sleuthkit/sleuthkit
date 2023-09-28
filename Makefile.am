# File that we want to include in the dist
EXTRA_DIST = README_win32.txt README.md INSTALL.txt ChangeLog.txt NEWS.txt API-CHANGES.txt \
    licenses/README.md licenses/GNUv2-COPYING licenses/GNUv3-COPYING licenses/IBM-LICENSE \
    licenses/Apache-LICENSE-2.0.txt licenses/cpl1.0.txt licenses/bsd.txt licenses/mit.txt \
    m4/*.m4 \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/*/*.vcxproj \
    win32/tsk-win.sln \
    win32/NugetPackages.props \
    win32/docs/* \
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
    case-uco/java/test/org/sleuthkit/caseuco/*.java

ACLOCAL_AMFLAGS = -I m4

# directories to compile
if CPPUNIT
  UNIT_TESTS=unit_tests
endif

# Compile java bindings if all of the dependencies existed
if X_JNI
  JAVA_BINDINGS=bindings/java
  JAVA_CASEUCO=case-uco/java
else   
  JAVA_BINDINGS=
  JAVA_CASEUCO=
endif

SUBDIRS = tsk tools tests ossfuzz samples man $(UNIT_TESTS) $(JAVA_BINDINGS) $(JAVA_CASEUCO)

nobase_include_HEADERS = tsk/libtsk.h tsk/tsk_incs.h \
    tsk/base/tsk_base.h tsk/base/tsk_os.h \
    tsk/img/tsk_img.h tsk/vs/tsk_vs.h tsk/img/pool.hpp tsk/img/logical_img.h \
    tsk/vs/tsk_bsd.h tsk/vs/tsk_dos.h tsk/vs/tsk_gpt.h \
    tsk/vs/tsk_mac.h tsk/vs/tsk_sun.h \
    tsk/fs/tsk_fs.h tsk/fs/tsk_ffs.h tsk/fs/tsk_ext2fs.h tsk/fs/tsk_fatfs.h \
    tsk/fs/tsk_ntfs.h tsk/fs/tsk_iso9660.h tsk/fs/tsk_hfs.h tsk/fs/tsk_yaffs.h tsk/fs/tsk_logical_fs.h \
    tsk/fs/tsk_apfs.h tsk/fs/tsk_apfs.hpp tsk/fs/apfs_fs.h tsk/fs/apfs_fs.hpp tsk/fs/apfs_compat.hpp \
    tsk/fs/decmpfs.h tsk/fs/tsk_exfatfs.h tsk/fs/tsk_fatxxfs.h \
    tsk/hashdb/tsk_hashdb.h tsk/auto/tsk_auto.h \
    tsk/auto/tsk_is_image_supported.h tsk/auto/guid.h \
    tsk/pool/tsk_pool.h tsk/pool/tsk_pool.hpp tsk/pool/tsk_apfs.h tsk/pool/tsk_apfs.hpp \
	tsk/pool/pool_compat.hpp tsk/pool/apfs_pool_compat.hpp \
    tsk/pool/lvm_pool_compat.hpp \
    tsk/util/crypto.hpp tsk/util/lw_shared_ptr.hpp tsk/util/span.hpp \
    tsk/util/detect_encryption.h tsk/util/file_system_utils.h

nobase_dist_data_DATA = tsk/sorter/default.sort tsk/sorter/freebsd.sort \
    tsk/sorter/images.sort tsk/sorter/linux.sort tsk/sorter/openbsd.sort \
    tsk/sorter/solaris.sort tsk/sorter/windows.sort 

api-docs:
	doxygen tsk/docs/Doxyfile
	cd bindings/java/doxygen; doxygen Doxyfile

man-html:
	cd man;build-html
