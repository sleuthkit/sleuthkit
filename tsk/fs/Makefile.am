AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskfs.la
# Note that the .h files are in the top-level Makefile
libtskfs_la_SOURCES  = tsk_fs_i.h fs_inode.c fs_io.c fs_block.c fs_open.c \
    fs_name.c fs_dir.c fs_types.c fs_attr.c fs_attrlist.c fs_load.c \
    fs_parse.c fs_file.c \
    unix_misc.c nofs_misc.c \
    ffs.c ffs_dent.c ext2fs.c ext2fs_dent.c ext2fs_journal.c \
    fatfs.c fatfs_meta.c fatfs_dent.cpp \
    fatxxfs.c fatxxfs_meta.c fatxxfs_dent.c \
    exfatfs.c exfatfs_meta.c exfatfs_dent.c \
    fatfs_utils.c \
    ntfs.c ntfs_dent.cpp swapfs.c rawfs.c \
    iso9660.c iso9660_dent.c \
    hfs.c hfs_dent.c hfs_journal.c hfs_unicompare.c lzvn.c lzvn.h \
    dcalc_lib.c dcat_lib.c dls_lib.c dstat_lib.c ffind_lib.c \
    fls_lib.c icat_lib.c ifind_lib.c ils_lib.c usn_journal.c usnjls_lib.c \
    walk_cpp.cpp yaffs.cpp

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
