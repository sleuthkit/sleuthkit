AM_CPPFLAGS = -I.. -I$(srcdir)/..  $(CATCH2_CPPFLAGS)
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS) -L/opt/homebrew/Cellar/cppunit/1.15.1/lib -lcppunit


SUBDIRS = base img
check_PROGRAMS = runner

runner_SOURCES = runner.cpp base/errors_test.cpp
