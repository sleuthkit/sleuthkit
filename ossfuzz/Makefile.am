if HAVE_LIB_FUZZING_ENGINE
AM_CPPFLAGS = \
	-I.. \
	-I$(srcdir)/..

bin_PROGRAMS = \
	fls_apfs_fuzzer \
	fls_ext_fuzzer \
	fls_fat_fuzzer \
	fls_hfs_fuzzer \
	fls_iso9660_fuzzer \
	fls_ntfs_fuzzer \
	mmls_dos_fuzzer \
	mmls_gpt_fuzzer \
	mmls_mac_fuzzer \
	mmls_sun_fuzzer

fls_apfs_fuzzer_SOURCES = \
	fls_apfs_fuzzer.cc \
	mem_img.h

fls_apfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

fls_ext_fuzzer_SOURCES = \
	fls_fuzzer.cc \
	mem_img.h

fls_ext_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_EXT_DETECT \
	$(AM_CPPFLAGS)

fls_ext_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

fls_fat_fuzzer_SOURCES = \
	fls_fuzzer.cc \
	mem_img.h

fls_fat_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_FAT_DETECT \
	$(AM_CPPFLAGS)

fls_fat_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

fls_hfs_fuzzer_SOURCES = \
	fls_fuzzer.cc \
	mem_img.h

fls_hfs_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_HFS \
	$(AM_CPPFLAGS)

fls_hfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

fls_iso9660_fuzzer_SOURCES = \
	fls_fuzzer.cc \
	mem_img.h

fls_iso9660_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_ISO9660 \
	$(AM_CPPFLAGS)

fls_iso9660_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

fls_ntfs_fuzzer_SOURCES = \
	fls_fuzzer.cc \
	mem_img.h

fls_ntfs_fuzzer_CPPFLAGS = \
	-DFSTYPE=TSK_FS_TYPE_NTFS \
	$(AM_CPPFLAGS)

fls_ntfs_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

mmls_dos_fuzzer_SOURCES = \
	mem_img.h \
	mmls_fuzzer.cc

mmls_dos_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_DOS \
	$(AM_CPPFLAGS)

mmls_dos_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

mmls_gpt_fuzzer_SOURCES = \
	mem_img.h \
	mmls_fuzzer.cc

mmls_gpt_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_GPT \
	$(AM_CPPFLAGS)

mmls_gpt_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

mmls_mac_fuzzer_SOURCES = \
	mem_img.h \
	mmls_fuzzer.cc

mmls_mac_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_MAC \
	$(AM_CPPFLAGS)

mmls_mac_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la

mmls_sun_fuzzer_SOURCES = \
	mem_img.h \
	mmls_fuzzer.cc

mmls_sun_fuzzer_CPPFLAGS = \
	-DVSTYPE=TSK_VS_TYPE_SUN \
	$(AM_CPPFLAGS)

mmls_sun_fuzzer_LDADD = \
	@LIB_FUZZING_ENGINE@ \
	../tsk/libtsk.la
endif

MAINTAINERCLEANFILES = \
	Makefile.in

distclean: clean
	/bin/rm -f Makefile
