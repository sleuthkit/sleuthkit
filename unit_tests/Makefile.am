AM_CPPFLAGS = -I.. -I$(srcdir)/..  -I/System/Volumes/Data/opt/homebrew/Cellar/cppunit/1.15.1/include/
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS) -lcppunit


SUBDIRS = base img
check_PROGRAMS = runner

runner_SOURCES = runner.cpp base/errors_test.cpp
