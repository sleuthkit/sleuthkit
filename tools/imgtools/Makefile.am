AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall
LDADD = ../../tsk/libtsk.la
LDFLAGS += -static
EXTRA_DIST = .indent.pro

bin_PROGRAMS = img_cat img_stat
img_cat_SOURCES = img_cat.cpp
img_stat_SOURCES = img_stat.cpp

indent:
	indent *.cpp

clean-local:
	-rm -f *.cpp~
