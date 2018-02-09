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
	ant dist $(ant_args)

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
