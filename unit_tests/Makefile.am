AM_CPPFLAGS = -I.. -I$(srcdir)/..
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS) -lcppunit


SUBDIRS = base
check_PROGRAMS = runner

runner_SOURCES = runner.cpp base/errors_test.cpp
