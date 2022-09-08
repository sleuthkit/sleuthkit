AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
EXTRA_DIST = .indent.pro 

noinst_LTLIBRARIES = libtskimg.la

libtskimg_la_SOURCES = \
	aff.c \
	aff.h \
	ewf.cpp \
	ewf.h \
	img_io.c \
	img_open.cpp \
	img_types.c \
	img_writer.cpp \
	img_writer.h \
	logical_img.c \
	logical_img.h \
	mult_files.c \
	raw.c \
  raw.h \
	tsk_img_i.h \
	unsupported_types.c \
	unsupported_types.h \
	vhd.c \
	vhd.h \
	vmdk.c \
	vmdk.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
