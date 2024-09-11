AM_CPPFLAGS = -I.. -I$(srcdir)/..  $(CATCH2_CPPFLAGS)
AM_CFLAGS += $(PTHREAD_CFLAGS)
AM_CXXFLAGS += -Wno-unused-command-line-argument $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS)
runner_SOURCES = runner.cpp mult_files_test.cpp errors_test.cpp  catch.hpp
check_PROGRAMS = runner
