AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskhashdb.la
libtskhashdb_la_SOURCES = tm_lookup.c md5sum_index.c nsrl_index.c \
    hk_index.c idxonly_index.c encase_index.c tsk_hashdb_i.h

indent:
	indent *.c *.h

clean-local:
	-rm -f *.c~ *.h~
