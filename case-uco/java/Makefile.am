tsk_caseuco_jar = $(top_builddir)/case-uco/java/dist/sleuthkit-caseuco-$(PACKAGE_VERSION).jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_caseuco_jar)

if OFFLINE
 ant_args=-Doffline=true
else

endif


$(tsk_caseuco_jar):

all-local:
	ant $(ant_args)

CLEANFILES = $(tsk_caseuco_jar)

clean-local:
	ant clean
