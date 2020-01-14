AM_CPPFLAGS = -I../..
AM_CXXFLAGS += $(CPPUNIT_CFLAGS) -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la $(CPPUNIT_LIBS)
LDFLAGS = -static 

TESTS = test_base

check_PROGRAMS = test_base

test_base_SOURCES= ../runner.cpp errors_test.cpp errors_test.h

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
