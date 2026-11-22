AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
EXTRA_DIST = .indent.pro ftl100_LICENSE.txt

noinst_LTLIBRARIES = libtskimg.la
libtskimg_la_SOURCES = img_open.cpp img_types.c ftl100.cpp ftl100.h ftl100_reader.h raw.c raw.h logical_img.c logical_img.h \
    aff.c aff.h ewf.cpp ewf.h tsk_img_i.h img_io.c mult_files.c \
    vhd.c vhd.h vmdk.c vmdk.h img_writer.cpp img_writer.h unsupported_types.c unsupported_types.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
