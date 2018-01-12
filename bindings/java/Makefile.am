# Compile the sub directories
SUBDIRS = jni

tsk_jar = $(top_builddir)/bindings/java/dist/libtsk-${PACKAGE_VERSION}.jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_jar)

$(tsk_jar):

all-local:
	ant dist

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
