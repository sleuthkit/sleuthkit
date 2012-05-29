# Compile the sub directories
SUBDIRS = base img vs fs hashdb auto

# Merge the libraries into one
lib_LTLIBRARIES = libtsk3.la
libtsk3_la_SOURCES =
libtsk3_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la \
    auto/libtskauto.la
# current:revision:age
libtsk3_la_LDFLAGS = -version-info 8:0:5

EXTRA_DIST = tsk_tools_i.h docs/Doxyfile docs/*.dox docs/*.html
