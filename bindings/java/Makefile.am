SUBDIRS = jni

tsk_jar = $(top_builddir)/bindings/java/dist/Tsk_DataModel.jar
jardir = $(datadir)/java
jar_DATA = $(tsk_jar)

$(tsk_jar): 
	ant dist	

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
