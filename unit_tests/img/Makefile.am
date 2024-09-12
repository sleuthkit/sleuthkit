AM_CPPFLAGS = -I../..

test_img_CPPFLAGS = $(AM_CPPFLAGS) $(CATCH2_CPPFLAGS)
test_img_CFLAGS = $(AM_CFLAGS) $(CATCH2_CFLAGS)
test_img_LDADD = ../../tsk/libtsk.la $(CATCH2_LIBS)
test_img_SOURCES = mult_files_test.cpp ../../tsk/img/mult_files.cpp

check_PROGRAMS = test_img

TESTS = $(check_PROGRAMS)

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
