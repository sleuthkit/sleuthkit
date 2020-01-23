# Compile the sub directories
SUBDIRS = base img vs fs hashdb auto pool util

# Merge the libraries into one
lib_LTLIBRARIES = libtsk.la
libtsk_la_SOURCES =
libtsk_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la \
    auto/libtskauto.la pool/libtskpool.la util/libtskutil.la
# current:revision:age
libtsk_la_LDFLAGS = -version-info 20:0:1 $(LIBTSK_LDFLAGS)

EXTRA_DIST = tsk_tools_i.h docs/Doxyfile docs/*.dox docs/*.html
