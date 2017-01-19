AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall
EXTRA_DIST = .indent.pro 

noinst_LTLIBRARIES = libtskimg.la
libtskimg_la_SOURCES = img_open.c img_types.c raw.c raw.h \
    aff.c aff.h ewf.c ewf.h tsk_img_i.h img_io.c mult_files.c \
    vhd.c vhd.h vmdk.c vmdk.h img_writer.cpp img_writer.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
