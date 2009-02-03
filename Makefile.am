# Files that we want to include in the dist
EXTRA_DIST = README_win32.txt README.txt INSTALL.txt CHANGES.txt \
    licenses/GNU-COPYING licenses/IBM-LICENSE licenses/cpl1.0.txt \
    docs/library-api.txt \
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
    win32/tsk-win.sln \
    win32/libauxtools/libauxtools.vcproj \
    win32/libfstools/libfstools.vcproj \
    win32/libhashdbtools/libhashdbtools.vcproj \
    win32/libimgtools/libimgtools.vcproj \
    win32/libmmtools/libmmtools.vcproj  \
    win32/posix-sample/posix-sample.vcproj \
    win32/callback-sample/callback-sample.vcproj


# directories to compile
SUBDIRS = tsk3 tools tests samples docs man

nobase_include_HEADERS = tsk3/libtsk.h tsk3/tsk_incs.h \
    tsk3/base/tsk_base.h tsk3/base/tsk_os.h \
    tsk3/img/tsk_img.h tsk3/vs/tsk_vs.h \
    tsk3/vs/tsk_bsd.h tsk3/vs/tsk_dos.h tsk3/vs/tsk_gpt.h \
    tsk3/vs/tsk_mac.h tsk3/vs/tsk_sun.h \
    tsk3/fs/tsk_fs.h tsk3/fs/tsk_ffs.h tsk3/fs/tsk_ext2fs.h tsk3/fs/tsk_fatfs.h \
    tsk3/fs/tsk_ntfs.h tsk3/fs/tsk_iso9660.h tsk3/fs/tsk_hfs.h \
    tsk3/hashdb/tsk_hashdb.h

nobase_dist_data_DATA = tsk3/sorter/default.sort tsk3/sorter/freebsd.sort \
    tsk3/sorter/images.sort tsk3/sorter/linux.sort tsk3/sorter/openbsd.sort \
    tsk3/sorter/solaris.sort tsk3/sorter/windows.sort 

api-docs:
	doxygen tsk3/docs/Doxyfile

man-html:
	cd man;build-html
