AM_CPPFLAGS = -I../..
AM_CXXFLAGS += -Wno-unused-command-line-argument $(CPPUNIT_CFLAGS)
LDADD = ../../tsk/libtsk.la $(CPPUNIT_LIBS)
LDFLAGS = -static 

check_PROGRAMS = test_base

test_base_SOURCES = ../runner.cpp errors_test.cpp errors_test.h

TESTS = $(check_PROGRAMS)

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
