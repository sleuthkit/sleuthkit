## Process this file with automake to produce Makefile.in

SUBDIRS = agrep

check_PROGRAMS = retest randtest test-str-source
EXTRA_PROGRAMS = bench
LDADD = $(LTLIBINTL)

retest_SOURCES = retest.c
if TRE_MULTIBYTE
check_PROGRAMS += wretest
wretest_SOURCES = retest.c
wretest_CPPFLAGS = -DWRETEST $(AM_CPPFLAGS)
endif TRE_MULTIBYTE

randtest_SOURCES = randtest.c

bench_SOURCES = bench.c
bench_LDADD = ../lib/libtre.la $(LDADD) -lm

test_str_source_SOURCES = test-str-source.c
test_str_source_LDADD = ../lib/libtre.la $(LDADD) -lm

if TRE_DEBUG
  retest_LDADD = ../lib/libtre.la $(LDADD)
if TRE_MULTIBYTE
  wretest_LDADD = ../lib/libtre.la $(LDADD)
endif TRE_MULTIBYTE
  randtest_LDADD = ../lib/libtre.la $(LDADD)
else !TRE_DEBUG
  ## Debugging is not turned on.  Make a malloc-debugging version of the
  ## library and use it with `retest' and `randtest'.  Malloc-debugging is
  ## not used for the debugging version since it would just get in the way.
  check_LTLIBRARIES = libxtre.la
  libxtre_la_SOURCES =			\
	../lib/tre-mem.c		\
	../lib/tre-stack.c		\
	../lib/tre-ast.c		\
	../lib/tre-parse.c		\
	../lib/tre-compile.c		\
	../lib/tre-match-parallel.c	\
	../lib/tre-match-backtrack.c	\
	../lib/regcomp.c		\
	../lib/regexec.c		\
	../lib/regerror.c		\
	../lib/xmalloc.c
if TRE_APPROX
  libxtre_la_SOURCES += ../lib/tre-match-approx.c
endif TRE_APPROX
  libxtre_la_CFLAGS = -DMALLOC_DEBUGGING

  retest_CFLAGS = -DMALLOC_DEBUGGING
  retest_LDADD = libxtre.la $(LDADD)
if TRE_MULTIBYTE
  wretest_CFLAGS = -DMALLOC_DEBUGGING
  wretest_LDADD = libxtre.la $(LDADD)
endif TRE_MULTIBYTE
  randtest_CFLAGS = -DMALLOC_DEBUGGING
  randtest_LDADD = libxtre.la $(LDADD)
endif !TRE_DEBUG

INCLUDES = -I$(top_srcdir)/lib

EXTRA_DIST = build-tests.sh

TESTS = test-str-source retest
if TRE_MULTIBYTE
TESTS += wretest
endif TRE_MULTIBYTE
