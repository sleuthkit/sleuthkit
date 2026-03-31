tsk_caseuco_jar = $(top_builddir)/case-uco/java/dist/sleuthkit-caseuco-$(PACKAGE_VERSION).jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_caseuco_jar)

if OFFLINE
 ant_args=-Doffline=true
else

endif


$(tsk_caseuco_jar):

all-local:
	ant -f $(srcdir)/build.xml \
	    -Dbuild.dir=$(abs_builddir)/build \
	    -Ddist.dir=$(abs_builddir)/dist \
	    -Dlib=$(abs_builddir)/lib \
	    -Dbindings.dist=$(abs_top_builddir)/bindings/java/dist \
	    $(ant_args)

CLEANFILES = $(tsk_caseuco_jar)

clean-local:
	ant -f $(srcdir)/build.xml \
	    -Dbuild.dir=$(abs_builddir)/build \
	    -Ddist.dir=$(abs_builddir)/dist \
	    -Dlib=$(abs_builddir)/lib \
	    -Dbindings.dist=$(abs_top_builddir)/bindings/java/dist \
	    clean || echo ant not installed
