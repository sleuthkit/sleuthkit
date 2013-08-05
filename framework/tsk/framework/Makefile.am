SUBDIRS = extraction file pipeline services utilities

# Merge the libraries into one
lib_LTLIBRARIES = libtskframework.la
libtskframework_la_SOURCES =
libtskframework_la_LIBADD = extraction/libfwextract.la \
                            file/libfwfile.la \
                            pipeline/libfwpipe.la \
                            services/libfwserv.la \
                            utilities/libfwutil.la

# current:revision:age
libtskframework_la_LDFLAGS = -version-info 0:0:0
