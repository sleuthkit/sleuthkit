# Files that we want to include in the dist
EXTRA_DIST = README_win32.txt README.txt INSTALL.txt ChangeLog.txt NEWS.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/blkcalc/blkcalc.vcproj win32/blkcat/blkcat.vcproj \
    win32/blkls/blkls.vcproj win32/blkstat/blkstat.vcproj \
    win32/ffind/ffind.vcproj win32/fls/fls.vcproj \
    win32/fsstat/fsstat.vcproj win32/hfind/hfind.vcproj \
    win32/icat/icat.vcproj win32/ifind/ifind.vcproj \
    win32/ils/ils.vcproj win32/img_cat/img_cat.vcproj \
    win32/img_stat/img_stat.vcproj \
    win32/istat/istat.vcproj win32/jcat/jcat.vcproj \
    win32/jls/jls.vcproj win32/mmls/mmls.vcproj \
    win32/mmstat/mmstat.vcproj win32/mmcat/mmcat.vcproj \
    win32/tsk_recover/tsk_recover.vcproj win32/tsk_loaddb/tsk_loaddb.vcproj \
    win32/tsk_comparedir/tsk_compare.vcproj \
    win32/tsk_gettimes/tsk_gettimes.vcproj \
    win32/tsk-win.sln \
    win32/libauxtools/libauxtools.vcproj \
    win32/libfstools/libfstools.vcproj \
    win32/libhashdbtools/libhashdbtools.vcproj \
    win32/libimgtools/libimgtools.vcproj \
    win32/libmmtools/libmmtools.vcproj  \
    win32/libautotools/libautotools.vcproj  \
    win32/posix-sample/posix-sample.vcproj \
    win32/callback-sample/callback-sample.vcproj \
    bindings/java/README.txt \
    bindings/java/build.xml \
    bindings/java/jni/dataModel_SleuthkitJNI.cpp \
    bindings/java/jni/dataModel_SleuthkitJNI.h \
    bindings/java/jni/tskAutoDbJNI.h \
    bindings/java/src/org/sleuthkit/datamodel/Content.java \
    bindings/java/src/org/sleuthkit/datamodel/Directory.java \
    bindings/java/src/org/sleuthkit/datamodel/File.java \
    bindings/java/src/org/sleuthkit/datamodel/FileSystem.java \
    bindings/java/src/org/sleuthkit/datamodel/FsContent.java \
    bindings/java/src/org/sleuthkit/datamodel/Image.java \
    bindings/java/src/org/sleuthkit/datamodel/Sleuthkit.java \
    bindings/java/src/org/sleuthkit/datamodel/SleuthkitJNI.java \
    bindings/java/src/org/sleuthkit/datamodel/TskData.java \
    bindings/java/src/org/sleuthkit/datamodel/TskException.java \
    bindings/java/src/org/sleuthkit/datamodel/Volume.java \
    bindings/java/src/org/sleuthkit/datamodel/VolumeSystem.java 

CLEANFILES = tsk3/tsk_incs.h

# directories to compile
if CPPUNIT
  UNIT_TESTS=unit_tests
endif
if X_JNI
  JNI=bindings/java/jni
endif
SUBDIRS = tsk3 tools tests samples man $(UNIT_TESTS) $(JNI)

nobase_include_HEADERS = tsk3/libtsk.h tsk3/tsk_incs.h \
    tsk3/base/tsk_base.h tsk3/base/tsk_os.h \
    tsk3/img/tsk_img.h tsk3/vs/tsk_vs.h \
    tsk3/vs/tsk_bsd.h tsk3/vs/tsk_dos.h tsk3/vs/tsk_gpt.h \
    tsk3/vs/tsk_mac.h tsk3/vs/tsk_sun.h \
    tsk3/fs/tsk_fs.h tsk3/fs/tsk_ffs.h tsk3/fs/tsk_ext2fs.h tsk3/fs/tsk_fatfs.h \
    tsk3/fs/tsk_ntfs.h tsk3/fs/tsk_iso9660.h tsk3/fs/tsk_hfs.h \
    tsk3/hashdb/tsk_hashdb.h tsk3/auto/tsk_auto.h

nobase_dist_data_DATA = tsk3/sorter/default.sort tsk3/sorter/freebsd.sort \
    tsk3/sorter/images.sort tsk3/sorter/linux.sort tsk3/sorter/openbsd.sort \
    tsk3/sorter/solaris.sort tsk3/sorter/windows.sort 

api-docs:
	doxygen tsk3/docs/Doxyfile

man-html:
	cd man;build-html
