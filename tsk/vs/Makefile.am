AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskvs.la
# Note that the .h files are in the top-level Makefile
libtskvs_la_SOURCES = mm_open.c mm_part.c mm_types.c mm_io.c \
    bsd.c dos.c gpt.c mac.c sun.c tsk_vs_i.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
