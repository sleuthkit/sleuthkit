# Compile the sub directories
SUBDIRS = jni

tsk_jar = $(top_builddir)/bindings/java/dist/sleuthkit-$(PACKAGE_VERSION).jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_jar)

if OFFLINE
 ant_args=-Doffline=true
if CUSTOM_DEFAULT_JAR_LOCATION
  ant_args+= -Ddefault-jar-location="@DEFAULT_JAR_LOCATION@"
else
endif
else

endif


$(tsk_jar):

all-local:
	ant dist $(ant_args)

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
