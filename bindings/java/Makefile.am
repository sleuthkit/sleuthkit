SUBDIRS = jni

Z_PATH=@Z_PATH@
EWF_PATH=@EWF_PATH@
ANT_PROPS=

if X_ZLIB
  ANT_PROPS+=-Dlib.z.path=$(Z_PATH)
endif

if X_LIBEWF
  ANT_PROPS+=-Dlib.ewf.path=$(EWF_PATH)
endif

tsk_jar = $(top_builddir)/bindings/java/dist/Tsk_DataModel.jar
jardir = /usr/share/java
jar_DATA = $(tsk_jar)


$(tsk_jar): 
	ant dist $(ANT_PROPS) 

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
