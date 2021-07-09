AM_CPPFLAGS = $(OPENSSL_INCLUDES) -I../.. -I$(srcdir)/../.. -Wall
AM_CXXFLAGS = -Wall -Wextra -Werror
EXTRA_DIST = .indent.pro 

noinst_LTLIBRARIES = libtskpool.la
libtskpool_la_SOURCES = pool_open.cpp pool_read.cpp pool_types.cpp \
	apfs_pool_compat.cpp apfs_pool.cpp

indent:
	indent *.c *.cpp *.h *.hpp

clean-local:
	-rm -f *.c~ *.cpp~ *.h~ *.hpp~
