ACLOCAL_AMFLAGS = -I m4
AM_CXXFLAGS = $(FW_INCLUDE) $(TSK_INCLUDE) -Wall
LDFLAGS="-lexif"

# this will be true if libexif was found by configure. 
# We don't have configure fail at runtime because then no modules
# can be compiled. 
if HAS_LIBEXIF

lib_LTLIBRARIES = libtskLibExifModule.la
libtskLibExifModule_la_SOURCES = LibExifModule.cpp
libtskLibExifModule_la_LIBADD = $(FW_LIBS)

else

bin_PROGRAMS = no_libmagic

.PHONY: no_libmagic
no_libmagic_SOURCES = 
no_libmagic:
	@echo "Nothing to do for ExifModule, libexif not found."

endif
