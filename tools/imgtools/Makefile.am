AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
AM_CXXFLAGS += -Wno-unused-command-line-argument
LDADD = ../../tsk/libtsk.la
EXTRA_DIST = .indent.pro

bin_PROGRAMS = img_cat img_stat
img_cat_SOURCES = img_cat.cpp
img_stat_SOURCES = img_stat.cpp

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
