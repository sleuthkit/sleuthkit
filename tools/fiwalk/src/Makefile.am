bin_PROGRAMS = fiwalk test_arff 

AM_CFLAGS = -Wall
AM_CPPFLAGS = -I../../.. -Wall
LDADD = ../../../tsk3/libtsk3.la

TESTS = test_arff test_fiwalk.sh

EXTRA_DIST = ficonfig.txt test_fiwalk.sh

fiwalk_SOURCES = fiwalk.cpp  fiwalk_tsk.cpp fiwalk.h \
	content.cpp content.h \
	arff.cpp arff.h \
	plugin.cpp plugin.h \
	myglob.cpp myglob.h\
	utils.c utils.h \
	xml.cpp xml.h \
	hash_t.h \
	unicode_escape.cpp unicode_escape.h \
	outfile.h base64.h base64.cpp

test_arff_SOURCES = arff.cpp arff.h test_arff.cpp

