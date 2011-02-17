AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
LDADD = ../../tsk3/libtsk3.la
LDFLAGS += -static
EXTRA_DIST = .indent.pro md5.c sha1.c

bin_PROGRAMS = hfind

hfind_SOURCES = hfind.cpp

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~
