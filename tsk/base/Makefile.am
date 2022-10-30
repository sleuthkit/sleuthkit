AM_CPPFLAGS = -I../..

noinst_LTLIBRARIES = libtskbase.la
libtskbase_la_SOURCES = \
	crc.c \
	crc.h \
	md5c.c \
	mymalloc.c \
	sha1c.c \
	tsk_base_i.c \
	tsk_base_i.h \
	tsk_endian.c \
	tsk_error.c \
	tsk_error_win32.cpp \
	tsk_list.c \
	tsk_lock.c \
	tsk_parse.c \
	tsk_printf.c \
	tsk_stack.c \
	tsk_unicode.c \
	tsk_unicode.h \
	tsk_version.c \
	XGetopt.c

EXTRA_DIST = .indent.pro

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
