AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall
LDADD = ../../tsk/libtsk.la
EXTRA_DIST = .indent.pro

bin_PROGRAMS = pstat
pstat_SOURCES = pstat.cpp

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
