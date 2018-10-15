bin_PROGRAMS = srch_strings sigfind
EXTRA_DIST = .indent.pro
AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
AM_CXXFLAGS += -Wno-unused-command-line-argument
AM_CFLAGS += -Wno-unused-command-line-argument

srch_strings_SOURCES = srch_strings.c

sigfind_SOURCES = sigfind.cpp 
sigfind_LDADD = ../../tsk/libtsk.la
sigfind_LDFLAGS = -static

indent:
	indent *.c *.cpp

clean-local:
	-rm -f *.c~ *.cpp~
