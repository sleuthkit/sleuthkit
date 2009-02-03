# Compile the sub directories
SUBDIRS = base img vs fs hashdb

# Merge the libraries into one
lib_LTLIBRARIES = libtsk3.la
libtsk3_la_SOURCES =
libtsk3_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la
# current:revision:age
libtsk3_la_LDFLAGS = -version-info 4:3:1

EXTRA_DIST = tsk_tools_i.h docs/Doxyfile docs/main.dox \
    docs/basics.dox docs/img.dox docs/vs.dox docs/fs.dox \
    docs/base.dox docs/hashdb.dox docs/footer.html
