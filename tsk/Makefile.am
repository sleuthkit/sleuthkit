# Compile the sub directories
SUBDIRS = base img vs fs hashdb auto pool util

# Merge the libraries into one
lib_LTLIBRARIES = libtsk.la
libtsk_la_SOURCES =
libtsk_la_LIBADD = base/libtskbase.la img/libtskimg.la \
    vs/libtskvs.la fs/libtskfs.la hashdb/libtskhashdb.la \
    auto/libtskauto.la pool/libtskpool.la util/libtskutil.la
# current:revision:age
libtsk_la_LDFLAGS = -version-info 21:1:2 $(LIBTSK_LDFLAGS)

EXTRA_DIST = tsk_tools_i.h docs/Doxyfile docs/*.dox docs/*.html \
   tsk.pc.in

pkgconfigdir = $(libdir)/pkgconfig
nodist_pkgconfig_DATA = tsk.pc

tsk.pc: tsk.pc.in Makefile
	sed -e 's![@]prefix[@]!$(prefix)!g' \
      -e 's![@]exec_prefix[@]!$(exec_prefix)!g' \
      -e 's![@]includedir[@]!$(includedir)!g' \
      -e 's![@]libdir[@]!$(libdir)!g' \
      -e 's![@]PACKAGE_NAME[@]!$(PACKAGE_NAME)!g' \
      -e 's![@]PACKAGE_VERSION[@]!$(PACKAGE_VERSION)!g' \
      -e 's![@]AX_PACKAGE_REQUIRES[@]!$(AX_PACKAGE_REQUIRES)!g' \
      -e 's![@]PACKAGE_LIBS_PRIVATE[@]!$(PACKAGE_LIBS_PRIVATE)!g' \
      -e 's![@]AX_PACKAGE_REQUIRES_PRIVATE[@]!$(AX_PACKAGE_REQUIRES_PRIVATE)!g' \
      $< >$@

CLEANFILES = tsk.pc
