AM_CPPFLAGS = -I../..

test_base_CPPFLAGS = $(AM_CPPFLAGS) $(CATCH2_CPPFLAGS)
test_base_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)
test_base_LDADD = ../../tsk/libtsk.la $(CATCH2_LIBS)
test_base_SOURCES = errors_test.cpp

check_PROGRAMS = test_base

TESTS = $(check_PROGRAMS)

MAINTAINERCLEANFILES = Makefile.in

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
