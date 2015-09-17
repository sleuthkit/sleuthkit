AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskhashdb.la
libtskhashdb_la_SOURCES =  \
    encase.c hashkeeper.c idxonly.c md5sum.c nsrl.c \
    sqlite_hdb.cpp binsrch_index.cpp tsk_hashdb.c hdb_base.c \
    tsk_hash_info.h tsk_hashdb.h tsk_hashdb_i.h

indent:
	indent *.cpp *.c *.h

clean-local:
	-rm -f *.c~ *.h~
