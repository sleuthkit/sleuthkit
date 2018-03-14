AM_CPPFLAGS = -I.. -I$(srcdir)/.. -Wall $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS)
EXTRA_DIST = .indent.pro runtests.sh

check_SCRIPTS = runtests.sh

TESTS = runtests.sh

check_PROGRAMS = read_apis fs_fname_apis fs_attrlist_apis fs_thread_test

read_apis_SOURCES = read_apis.cpp
fs_fname_apis_SOURCES = fs_fname_apis.cpp
fs_attrlist_apis_SOURCES = fs_attrlist_apis.cpp
fs_thread_test_SOURCES = fs_thread_test.cpp tsk_thread.cpp tsk_thread.h

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~ 
	rm -f base.log thread-*.log

