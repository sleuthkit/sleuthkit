AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la
EXTRA_DIST = .indent.pro

bin_PROGRAMS = mmls mmstat mmcat
mmls_SOURCES = mmls.cpp
mmstat_SOURCES = mmstat.cpp
mmcat_SOURCES = mmcat.cpp

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
