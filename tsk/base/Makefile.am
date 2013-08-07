AM_CPPFLAGS = -I../.. -Wall 

noinst_LTLIBRARIES = libtskbase.la
libtskbase_la_SOURCES = md5c.c mymalloc.c sha1c.c \
    crc.c crc.h \
    tsk_endian.c tsk_error.c tsk_list.c tsk_parse.c tsk_printf.c \
    tsk_unicode.c tsk_version.c tsk_stack.c XGetopt.c tsk_base_i.h \
    tsk_lock.c tsk_error_win32.cpp 

EXTRA_DIST = .indent.pro

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
