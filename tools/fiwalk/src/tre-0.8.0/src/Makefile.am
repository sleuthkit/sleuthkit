## Process this file with automake to produce Makefile.in

localedir = $(datadir)/locale
INCLUDES = -I$(top_srcdir)/lib

if TRE_AGREP
bin_PROGRAMS = agrep

agrep_SOURCES = agrep.c
agrep_LDADD = ../lib/libtre.la $(LTLIBINTL)
agrep_CFLAGS = -DLOCALEDIR=\"$(localedir)\"
if TRE_PROFILE
agrep_LDFLAGS = -static
endif
endif
