bin_PROGRAMS = srch_strings sigfind
EXTRA_DIST = .indent.pro
AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall

srch_strings_SOURCES = srch_strings.c

sigfind_SOURCES = sigfind.cpp 
sigfind_LDADD = ../../tsk3/libtsk3.la
sigfind_LDFLAGS = -static

indent:
	indent *.c *.cpp

clean-local:
	-rm -f *.c~ *.cpp~
