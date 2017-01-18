AM_CPPFLAGS = -I../.. -I$(srcdir)/../.. -Wall  -Wmultichar -Wstrict-null-sentinel -Woverloaded-virtual -Wsign-promo
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskauto.la
# Note that the .h files are in the top-level Makefile
libtskauto_la_SOURCES = auto.cpp auto_db.cpp sqlite3.c sqlite3.h db_sqlite.cpp db_postgresql.cpp case_db.cpp guid.cpp tsk_db.cpp tsk_case_db.h tsk_auto.h tsk_auto_i.h tsk_case_db.h tsk_db.h tsk_db_sqlite.h tsk_db_postgresql.h db_connection_info.h guid.h 

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
