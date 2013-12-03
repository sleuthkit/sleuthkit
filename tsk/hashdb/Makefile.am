AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskhashdb.la
libtskhashdb_la_SOURCES = binsrch_index.c sqlite_index.cpp \
    tm_lookup.cpp md5sum.c nsrl.c \
    hdb_open.cpp hdb_index.cpp \
    hashkeeper.c idxonly.c encase.c tsk_hashdb_i.h

indent:
	indent *.cpp *.c *.h

clean-local:
	-rm -f *.c~ *.h~
