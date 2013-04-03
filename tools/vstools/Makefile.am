AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
LDADD = ../../tsk/libtsk.la
LDFLAGS += -static
EXTRA_DIST = .indent.pro

bin_PROGRAMS = mmls mmstat mmcat
mmls_SOURCES = mmls.cpp
mmstat_SOURCES = mmstat.cpp
mmcat_SOURCES = mmcat.cpp

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
