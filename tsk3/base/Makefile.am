AM_CFLAGS = -I../.. -Wall 

noinst_LTLIBRARIES = libtskbase.la
libtskbase_la_SOURCES = md5c.c mymalloc.c sha1c.c \
    tsk_endian.c tsk_error.c tsk_list.c tsk_parse.c tsk_printf.c \
    tsk_unicode.c tsk_version.c tsk_stack.c XGetopt.c tsk_base_i.h

EXTRA_DIST = .indent.pro

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
