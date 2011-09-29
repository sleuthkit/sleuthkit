AM_CPPFLAGS = -I../../.. -I$(srcdir)/../../.. -Wall $(JNI_CPPFLAGS)
EXTRA_DIST = .indent.pro 

lib_LTLIBRARIES = libtsk3jni.la
libtsk3jni_la_SOURCES = dataModel_SleuthkitJNI.cpp dataModel_SleuthkitJNI.h 

indent:
	indent *.cpp *.h

clean-local:
	-rm -f *.c~ *.h~
