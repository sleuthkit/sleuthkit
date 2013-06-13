AM_CPPFLAGS = -I../../.. -I$(srcdir)/../../.. -Wall $(JNI_CPPFLAGS)
EXTRA_DIST = .indent.pro 

lib_LTLIBRARIES = libtsk_jni.la
libtsk_jni_la_SOURCES = dataModel_SleuthkitJNI.cpp dataModel_SleuthkitJNI.h 
libtsk_jni_la_LIBADD = ../../../tsk/libtsk.la

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.c~ *.h~
