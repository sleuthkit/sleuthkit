AM_CPPFLAGS = -I../..
AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall -Wno-unused-command-line-argument

ACLOCAL_AMFLAGS = -I m4

bin_PROGRAMS = plugins/jpeg_extract src/fiwalk

plugins_jpeg_extract_SOURCES = plugins/jpeg_extract.cpp

EXTRA_DIST = \
	plugins/docx_extractor.py \
	plugins/docx_grep.py \
	plugins/ficonfig.txt \
	plugins/jpeg_extract.java \
	plugins/Libextract_plugin.java \
	plugins/odf_extractor.py \
	plugins/word_extract.java \
	src/config-simple.txt \
	src/ficonfig.txt \
	src/lua_utf8.c \
	src/README_PLUGINS.txt \
	src/word-count-plugin.sh

plugins/plugins.jar: plugins/jpeg_extract.class plugins/word_extract.class plugins/Libextract_plugin.class
	jar cfv plugins/plugins.jar plugins/jpeg_extract.class plugins/word_extract.class plugins/Libextract_plugin.class

plugins/jpeg_extract.class: plugins/jpeg_extract.java
	javac plugins/jpeg_extract.java

plugins/word_extract.class: plugins/word_extract.java
	javac plugins/word_extract.java

plugins/Libextract_plugin.class: plugins/Libextract_plugin.java
	javac plugins/Libextract_plugin.java

src_fiwalk_LDADD =  ../../tsk/libtsk.la
src_fiwalk_SOURCES = \
	src/arff.cpp \
	src/arff.h \
	src/base64.cpp \
	src/base64.h \
	src/content.cpp \
	src/content.h \
	src/dfxml.cpp \
	src/dfxml.h \
	src/fiwalk.cpp  \
	src/fiwalk.h \
	src/fiwalk_main.cpp  \
	src/fiwalk_tsk.cpp \
	src/hash_t.h \
	src/hexbuf.c \
	src/hexbuf.h \
	src/plugin.cpp \
	src/plugin.h \
	src/sha2.c \
	src/sha2.h \
	src/unicode_escape.cpp \
	src/unicode_escape.h \
	src/utils.c \
	src/utils.h
