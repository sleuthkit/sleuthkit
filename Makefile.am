# File that we want to include in the dist
EXTRA_DIST = README_win32.txt README.txt INSTALL.txt ChangeLog.txt NEWS.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    m4/*.m4 \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/NOTES.txt \
    win32/*/*.vcproj \
    win32/tsk-win.sln \
    win32/docs/* \
    bindings/java/README.txt \
    bindings/java/*.xml \
    bindings/java/doxygen/* \
    bindings/java/nbproject/project.xml \
    bindings/java/src/org/sleuthkit/datamodel/*.java \
    bindings/java/src/org/sleuthkit/datamodel/*.html \
    bindings/java/src/*.html \
    bindings/java/test \
    bindings/java/teststandards \
    framework/*.txt \
    framework/*.h \
    framework/Extraction/*.cpp \
    framework/Extraction/*.h \
    framework/File/*.cpp \
    framework/File/*.h \
    framework/Pipeline/*.cpp \
    framework/Pipeline/*.h \
    framework/SampleConfig/*.xml \
    framework/Services/*.cpp \
    framework/Services/*.h \
    framework/TskModules/* \
    framework/Utilities/*.cpp \
    framework/Utilities/*.h \
    framework/docs/* \
    framework/man/* \
    framework/tsk_analyzeimg/*.cpp \
    framework/tsk_validatepipeline/*.cpp \
    framework/win32/*/*.vcproj \
    framework/win32/*/*.sln \
    framework/win32/Makefile

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
	doxygen framework/docs/Doxyfile
	doxygen bindings/java/doxygen/Doxyfile

framework-docs:

man-html:
	cd man;build-html
