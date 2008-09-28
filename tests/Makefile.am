AM_CPPFLAGS = -I.. -Wall 
LDADD = ../tsk3/libtsk3.la
LDFLAGS = -static
EXTRA_DIST = .indent.pro 

noinst_PROGRAMS = read_apis fs_fname_apis fs_attrlist_apis
read_apis_SOURCES = read_apis.cpp
fs_fname_apis_SOURCES = fs_fname_apis.cpp
fs_attrlist_apis_SOURCES = fs_attrlist_apis.cpp

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~ 
