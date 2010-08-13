AM_CPPFLAGS = -I../.. -Wall 
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskauto.la
# Note that the .h files are in the top-level Makefile
libtskauto_la_SOURCES = auto.cpp tsk_auto.h tsk_auto_i.h auto_db.cpp sqlite3.c sqlite3.h

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
