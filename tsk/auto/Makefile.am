AM_CPPFLAGS = -I../.. -I$(srcdir)/../..
AM_CFLAGS += -Wmultichar -Wsign-promo -Wno-overloaded-virtual
AM_CXXFLAGS += -Wmultichar -Wsign-promo -Wno-overloaded-virtual
EXTRA_DIST = .indent.pro

noinst_LTLIBRARIES = libtskauto.la
# Note that the .h files are in the top-level Makefile
libtskauto_la_SOURCES = auto.cpp auto_db.cpp db_sqlite.cpp \
	case_db.cpp guid.cpp tsk_db.cpp tsk_case_db.h \
	tsk_auto.h tsk_auto_i.h tsk_case_db.h tsk_db.h tsk_db_sqlite.h \
	guid.h is_image_supported.cpp \
    tsk_is_image_supported.h

# Compile the bundled sqlite3 if there isn't an existing lib to use.
# sqlite3.c is a third-party file we do not maintain; suppress all compiler
# warnings for it so our -Wall/-Wextra build flags do not produce noise we
# cannot fix.  The target-specific AM_CFLAGS override is a GNU make feature
# that applies only to this one translation unit.
if !HAVE_LIBSQLITE3
libtskauto_la_SOURCES += sqlite3.c sqlite3.h
sqlite3.lo: AM_CFLAGS = -w
endif

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.cpp~ *.h~
