SUBDIRS = src

AM_CFLAGS = -Wall
AM_CXXFLAGS = -Wall

ACLOCAL_AMFLAGS = -I m4

AM_CXXFLAGS += -Wno-unused-command-line-argument

bin_PROGRAMS = plugins/jpeg_extract

plugins_jpeg_extract_SOURCES = plugins/jpeg_extract.cpp

EXTRA_DIST = \
	plugins/docx_extractor.py \
	plugins/docx_grep.py \
	plugins/ficonfig.txt \
	plugins/jpeg_extract.java \
	plugins/Libextract_plugin.java \
	plugins/odf_extractor.py \
	plugins/word_extract.java

plugins/plugins.jar: plugins/jpeg_extract.class plugins/word_extract.class plugins/Libextract_plugin.class
	jar cfv plugins/plugins.jar plugins/jpeg_extract.class plugins/word_extract.class plugins/Libextract_plugin.class

plugins/jpeg_extract.class: plugins/jpeg_extract.java
	javac plugins/jpeg_extract.java

plugins/word_extract.class: plugins/word_extract.java
	javac plugins/word_extract.java

plugins/Libextract_plugin.class: plugins/Libextract_plugin.java
	javac plugins/Libextract_plugin.java
