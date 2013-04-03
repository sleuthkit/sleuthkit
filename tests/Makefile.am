AM_CPPFLAGS = -I.. -I$(srcdir)/.. -Wall $(PTHREAD_CFLAGS)
LDADD = ../tsk/libtsk.la
LDFLAGS += -static $(PTHREAD_LIBS)
EXTRA_DIST = .indent.pro 

noinst_PROGRAMS = read_apis fs_fname_apis fs_attrlist_apis fs_thread_test
read_apis_SOURCES = read_apis.cpp
fs_fname_apis_SOURCES = fs_fname_apis.cpp
fs_attrlist_apis_SOURCES = fs_attrlist_apis.cpp
fs_thread_test_SOURCES = fs_thread_test.cpp tsk_thread.cpp tsk_thread.h

indent:
	indent *.cpp 

clean-local:
	-rm -f *.cpp~ 
	rm -f base.log thread-*.log

IMAGE_DIR=$(HOME)/from_brian
NTHREADS=1
NITERS=1

# The 'check' target can be run by the normal build process, but we
# don't (yet) check in a set of standard test images.  So, our target
# must be run manually for now.  For example, to run all fs images
# through 10 threads with 2 iterations per thread:
#
#  make check-manual NTHREADS=10 NITERS=2 IMAGE_DIR=/path/to/test/images/
#
check-manual:
	$(MAKE) check_ext2fs check_diffs
	$(MAKE) check_ffs check_diffs
	$(MAKE) check_hfs check_diffs
	$(MAKE) check_ntfs check_diffs
	$(MAKE) check_fatfs check_diffs

check_ext2fs: fs_thread_test
	rm -f base.log thread-*.log
	./fs_thread_test -f ext2 $(IMAGE_DIR)/ext2fs.dd 1 1
	mv thread-0.log base.log
	./fs_thread_test -f ext2 $(IMAGE_DIR)/ext2fs.dd $(NTHREADS) $(NITERS)

check_ffs: fs_thread_test
	rm -f base.log thread-*.log
	./fs_thread_test -f ufs $(IMAGE_DIR)/misc-ufs1.dd 1 1
	mv thread-0.log base.log
	./fs_thread_test -f ufs $(IMAGE_DIR)/misc-ufs1.dd $(NTHREADS) $(NITERS)

check_hfs: fs_thread_test
	rm -f base.log thread-*.log
	./fs_thread_test -f hfs -o 64 $(IMAGE_DIR)/test_hfs.dmg 1 1
	mv thread-0.log base.log
	./fs_thread_test -f hfs -o 64 $(IMAGE_DIR)/test_hfs.dmg $(NTHREADS) $(NITERS)

check_ntfs: fs_thread_test
	rm -f base.log thread-*.log
	./fs_thread_test -f ntfs $(IMAGE_DIR)/ntfs-img-kw-1.dd 1 1
	mv thread-0.log base.log
	./fs_thread_test -f ntfs $(IMAGE_DIR)/ntfs-img-kw-1.dd $(NTHREADS) $(NITERS)

check_fatfs: fs_thread_test
	rm -f base.log thread-*.log
	./fs_thread_test -f fat $(IMAGE_DIR)/fat32.dd 1 1
	mv thread-0.log base.log
	./fs_thread_test -f fat $(IMAGE_DIR)/fat32.dd $(NTHREADS) $(NITERS)

check_diffs:
	@for i in thread-*.log; do \
	  echo diff base.log $$i; \
	  diff base.log $$i || exit 1; \
	done;
