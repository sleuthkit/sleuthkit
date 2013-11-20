Z_PATH=@Z_PATH@
EWF_PATH=@EWF_PATH@
ANT_PROPS=

# Compile the sub directories
SUBDIRS = jni

if X_ZLIB
  ANT_PROPS+=-Dlib.z.path=$(Z_PATH)
endif

if X_LIBEWF
  ANT_PROPS+=-Dlib.ewf.path=$(EWF_PATH)
endif

tsk_jar = $(top_builddir)/bindings/java/dist/Tsk_DataModel.jar
jardir = $(prefix)/share/java
jar_DATA = $(tsk_jar)

$(tsk_jar):

all-local:
	ant dist $(ANT_PROPS) -Dcalled.from=all-local

CLEANFILES = $(tsk_jar)

clean-local:
	ant clean
