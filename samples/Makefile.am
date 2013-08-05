AM_CPPFLAGS = -I.. -I$(srcdir)/.. -Wall 
LDADD = ../tsk/libtsk.la
AM_LDFLAGS = -static
EXTRA_DIST = .indent.pro 

noinst_PROGRAMS = posix_style callback_style posix_cpp_style callback_cpp_style
posix_style_SOURCES = posix-style.cpp
callback_style_SOURCES = callback-style.cpp
posix_cpp_style_SOURCES = posix-cpp-style.cpp
callback_cpp_style_SOURCES = callback-cpp-style.cpp

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~ 
