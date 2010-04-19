AM_CPPFLAGS = -I../.. -Wall
LDADD = ../../tsk3/libtsk3.la
LDFLAGS += -static
EXTRA_DIST = .indent.pro

bin_PROGRAMS = tsk_recover tsk_loaddb
tsk_recover_SOURCES = tsk_recover.cpp 
tsk_loaddb_SOURCES = tsk_loaddb.cpp 

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
