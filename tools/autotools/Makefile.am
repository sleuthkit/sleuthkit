AM_CPPFLAGS = -I../.. -Wall
LDADD = ../../tsk3/libtsk3.la
LDFLAGS += -static
EXTRA_DIST = .indent.pro

bin_PROGRAMS = tsk_recover tsk_loaddb tsk_comparedir
tsk_recover_SOURCES = tsk_recover.cpp tsk_recover.h
tsk_loaddb_SOURCES = tsk_loaddb.cpp 
tsk_comparedir_SOURCES = tsk_comparedir.cpp tsk_comparedir.h

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
