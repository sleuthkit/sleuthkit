# Compile the sub directories
SUBDIRS = base img vs fs hashdb auto

# Merge the libraries into one
lib_LTLIBRARIES = libtsk.la
libtsk_la_SOURCES =
libtsk_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la \
    auto/libtskauto.la
# current:revision:age
libtsk_la_LDFLAGS = -version-info 17:7:4 $(LIBTSK_LDFLAGS)

EXTRA_DIST = tsk_tools_i.h docs/Doxyfile docs/*.dox docs/*.html
