bin_PROGRAMS = fiwalk
AM_CPPFLAGS = -I../../..
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../../tsk/libtsk.la

EXTRA_DIST = README_PLUGINS.txt ficonfig.txt \
    config-simple.txt word-count-plugin.sh \
    lua_utf8.c

fiwalk_SOURCES = \
	arff.cpp \
	arff.h \
	base64.cpp \
	base64.h \
	content.cpp \
	content.h \
	dfxml.cpp \
	dfxml.h \
	fiwalk.cpp  \
	fiwalk_main.cpp  \
	fiwalk.h \
	fiwalk_tsk.cpp \
	hash_t.h \
	hexbuf.c \
	hexbuf.h \
	plugin.cpp \
	plugin.h \
	sha2.c \
	sha2.h \
	unicode_escape.cpp \
	unicode_escape.h \
	utils.c \
	utils.h
