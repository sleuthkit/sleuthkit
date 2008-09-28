AM_CPPFLAGS = -I../.. -Wall
LDADD = ../../tsk3/libtsk3.la
LDFLAGS = -static
EXTRA_DIST = .indent.pro

bin_PROGRAMS = disk_stat disk_sreset

disk_stat_SOURCES = disk_stat.cpp ide.c disk_ide.h
disk_sreset_SOURCES = disk_sreset.cpp ide.c disk_ide.h

indent:
	indent *.c *.cpp

clean-local:
	-rm -f *.c~ *.cpp~
