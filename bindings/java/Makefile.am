# Compile the sub directories
SUBDIRS = jni

tsk_jar = $(top_builddir)/bindings/java/dist/sleuthkit-$(PACKAGE_VERSION).jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_jar)

if OFFLINE
 ant_args=-Doffline=true
else

endif


$(tsk_jar):

all-local:
	ant -f $(srcdir)/build.xml \
	    -Djni.build.dir=$(abs_builddir)/jni \
	    -Dbuild=$(abs_builddir)/build \
	    -Ddist=$(abs_builddir)/dist \
	    -Dlib=$(abs_builddir)/lib \
	    -Dtest-runtime=$(abs_builddir)/test-runtime \
	    dist $(ant_args)

CLEANFILES = $(tsk_jar)

clean-local:
	ant -f $(srcdir)/build.xml \
	    -Djni.build.dir=$(abs_builddir)/jni \
	    -Dbuild=$(abs_builddir)/build \
	    -Ddist=$(abs_builddir)/dist \
	    -Dlib=$(abs_builddir)/lib \
	    -Dtest-runtime=$(abs_builddir)/test-runtime \
	    clean || echo ant not installed
