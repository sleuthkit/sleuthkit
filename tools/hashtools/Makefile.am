AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la
EXTRA_DIST = .indent.pro md5.c sha1.c

bin_PROGRAMS = hfind

hfind_SOURCES = hfind.cpp

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~
