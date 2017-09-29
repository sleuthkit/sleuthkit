# File that we want to include in the dist
EXTRA_DIST = README_win32.txt README.md INSTALL.txt ChangeLog.txt NEWS.txt API-CHANGES.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    m4/*.m4 \
    docs/README.txt \
    packages/sleuthkit.spec \
    win32/BUILDING.txt \
    win32/NOTES.txt \
    win32/*/*.vcxproj \
    win32/tsk-win.sln \
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
    bindings/java/src/org/sleuthkit/datamodel/Examples/*.java \
    bindings/java/src/*.html \
    framework/*.txt \
    framework/Makefile.am \
    framework/bootstrap \
    framework/config/* \
    framework/config.h.in \
    framework/configure.ac \
    framework/m4/* \
    framework/tsk/framework/*.h \
    framework/tsk/framework/Makefile.am \
    framework/tsk/framework/extraction/Makefile.am \
    framework/tsk/framework/extraction/*.cpp \
    framework/tsk/framework/extraction/*.h \
    framework/tsk/framework/file/Makefile.am \
    framework/tsk/framework/file/*.cpp \
    framework/tsk/framework/file/*.h \
    framework/tsk/framework/pipeline/Makefile.am \
    framework/tsk/framework/pipeline/*.cpp \
    framework/tsk/framework/pipeline/*.h \
    framework/tsk/framework/services/Makefile.am \
    framework/tsk/framework/services/*.cpp \
    framework/tsk/framework/services/*.h \
    framework/tsk/framework/utilities/Makefile.am \
    framework/tsk/framework/utilities/*.cpp \
    framework/tsk/framework/utilities/*.h \
    framework/modules/* \
    framework/SampleConfig/*.xml \
    framework/docs/* \
    framework/man/* \
    framework/tools/tsk_analyzeimg/Makefile.am \
    framework/tools/tsk_analyzeimg/*.cpp \
    framework/tools/tsk_validatepipeline/Makefile.am \
    framework/tools/tsk_validatepipeline/*.cpp \
    framework/tools/Makefile.am \
    framework/msvcpp/*/*.vcxproj \
    framework/msvcpp/*/*.sln \
    framework/msvcpp/Makefile

ACLOCAL_AMFLAGS = -I m4

# directories to compile
if CPPUNIT
  UNIT_TESTS=unit_tests
endif

# Compile java bindings if all of the dependencies existed
if X_JNI
  JAVA_BINDINGS=bindings/java
else   
  JAVA_BINDINGS=
endif

SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JAVA_BINDINGS) 

nobase_include_HEADERS = tsk/libtsk.h tsk/tsk_incs.h \
    tsk/base/tsk_base.h tsk/base/tsk_os.h \
    tsk/img/tsk_img.h tsk/vs/tsk_vs.h \
    tsk/vs/tsk_bsd.h tsk/vs/tsk_dos.h tsk/vs/tsk_gpt.h \
    tsk/vs/tsk_mac.h tsk/vs/tsk_sun.h \
    tsk/fs/tsk_fs.h tsk/fs/tsk_ffs.h tsk/fs/tsk_ext2fs.h tsk/fs/tsk_fatfs.h \
    tsk/fs/tsk_ntfs.h tsk/fs/tsk_iso9660.h tsk/fs/tsk_hfs.h tsk/fs/tsk_yaffs.h \
    tsk/fs/tsk_exfatfs.h tsk/fs/tsk_fatxxfs.h \
    tsk/hashdb/tsk_hashdb.h tsk/auto/tsk_auto.h \
    tsk/auto/tsk_is_image_supported.h

nobase_dist_data_DATA = tsk/sorter/default.sort tsk/sorter/freebsd.sort \
    tsk/sorter/images.sort tsk/sorter/linux.sort tsk/sorter/openbsd.sort \
    tsk/sorter/solaris.sort tsk/sorter/windows.sort 

api-docs:
	doxygen tsk/docs/Doxyfile
# doxygen framework/docs/Doxyfile
	cd bindings/java/doxygen; doxygen Doxyfile

man-html:
	cd man;build-html
