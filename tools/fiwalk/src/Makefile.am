bin_PROGRAMS = fiwalk 

AM_CFLAGS = -Wall
AM_CPPFLAGS = -I../../.. -Wall
LDADD = ../../../tsk/libtsk.la

EXTRA_DIST = README_PLUGINS.txt ficonfig.txt \
    config-simple.txt word-count-plugin.sh \
    lua_utf8.c

fiwalk_SOURCES = fiwalk.cpp  fiwalk_tsk.cpp fiwalk.h \
	content.cpp content.h \
	arff.cpp arff.h \
	plugin.cpp plugin.h \
	utils.c utils.h \
	dfxml.cpp dfxml.h \
	hash_t.h hexbuf.c hexbuf.h \
	unicode_escape.cpp unicode_escape.h \
	base64.h base64.cpp \
	sha2.h sha2.c 


