AM_CPPFLAGS = -I.. -Wall 
LDADD = ../tsk3/libtsk3.la
LDFLAGS = -static
EXTRA_DIST = .indent.pro 

noinst_PROGRAMS = posix_style callback_style
posix_style_SOURCES = posix-style.cpp
callback_style_SOURCES = callback-style.cpp

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~ 
