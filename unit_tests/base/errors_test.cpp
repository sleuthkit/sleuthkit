/*
 * errors_test.cpp
 *
 *  Created on: Oct 22, 2010
 *      Author: benson
 */

#include <libtsk.h>
#include <tsk_config.h>
#include <cstring>

#ifdef HAVE_PTHREAD
#ifdef __APPLE__
#include <mach/semaphore.h>
#include <mach/task.h>
extern "C" mach_port_t mach_task_self(void);
#define SEM_TYPE semaphore_t
#else
#include <errno.h>
#include <semaphore.h>
#define SEM_TYPE sem_t
#endif
#endif

#include "errors_test.h"

// Registers the fixture into the 'registry'
CPPUNIT_TEST_SUITE_REGISTRATION( ErrorsTest );

void ErrorsTest::setUp() {}
void ErrorsTest::tearDown() {}

void ErrorsTest::testInitialState() {
	TSK_ERROR_INFO *ei;

	ei = tsk_error_get_info();
	CPPUNIT_ASSERT(0 == ei->t_errno);
	CPPUNIT_ASSERT(0 == ei->errstr[0]);
	CPPUNIT_ASSERT(0 == ei->errstr2[0]);
}

void ErrorsTest::testLengthChecks() {
	TSK_ERROR_INFO *ei;

	ei = tsk_error_get_info();
	std::string s;
	for (unsigned x = 0; x < 4096; x ++) {
		s = s + std::string("x");
	}
	tsk_error_set_errstr("%s", s.c_str());
	std::string es(tsk_error_get_errstr());
	CPPUNIT_ASSERT(es.size() < 1025);
}

#ifdef HAVE_PTHREAD

struct xErrorsTestShared {
	SEM_TYPE sync_barrier;
	bool errno_check_failed;
	bool errstr_check_failed;
	bool errstr2_check_failed;
	bool failure;

	xErrorsTestShared() {
		failure = false;
		errno_check_failed = false;
		errstr_check_failed = false;
		errstr2_check_failed = false;
	}
};

/*
 * This thread sets error variables, updates the semaphore,
 * waits on the semaphore, and reads them back.
 */
void * thread_1(void *arg) {
	xErrorsTestShared * shared = (xErrorsTestShared*) arg;
	// wait to be told to start.
#ifdef __APPLE__
	kern_return_t se = semaphore_wait(shared->sync_barrier);
	if (se != 0) {
		fprintf(stderr, "sem_wait failed: %d\n", se);
		shared->failure = true;
	}
#else
	if (sem_wait(&shared->sync_barrier) != 0) {
		fprintf(stderr, "sem_wait failed: %s\n", strerror(errno));
		shared->failure = true;
	}
#endif
	tsk_error_set_errno(42);
	tsk_error_set_errstr("I just set errno to %d.", 42);
	tsk_error_set_errstr2("Indeed, I just set errno to %d.", 42);
#ifdef __APPLE__
	se = semaphore_signal(shared->sync_barrier);
	if (se != 0) {
		fprintf(stderr, "sem_signal failed: %d\n", se);
		shared->failure = true;
	}
	se = semaphore_wait(shared->sync_barrier);
	if (se != 0) {
		fprintf(stderr, "sem_wait failed: %d\n", se);
		shared->failure = true;
	}
#else
	sem_post(&shared->sync_barrier);
	sem_wait(&shared->sync_barrier);
#endif
	shared->errno_check_failed = 42 != tsk_error_get_errno();
	char const * s = tsk_error_get_errstr();
	shared->errstr_check_failed = 0 != strcmp("I just set errno to 42.", s);
	s = tsk_error_get_errstr2();
	shared->errstr2_check_failed = 0 != strcmp("Indeed, I just set errno to 42.", s);
	return 0;
}

void ErrorsTest::testMultithreaded()
{
	xErrorsTestShared shared;
	tsk_error_reset();
	// start semaphore unlocked. Thread will lock.
#ifdef __APPLE__
	kern_return_t se;
	se = semaphore_create(mach_task_self(), &shared.sync_barrier, SYNC_POLICY_FIFO, 0);
	if (se != 0) {
		fprintf(stderr, "sem_init failed: %d\n", se);
				CPPUNIT_FAIL("Could not initialize semaphore");
	}
#else
	if (sem_init(&shared.sync_barrier, 0, 0)) {
		fprintf(stderr, "sem_init failed: %s\n", strerror(errno));
		CPPUNIT_FAIL("Could not initialize semaphore");
	}
#endif

	pthread_t thread1;

	int pte = pthread_create(&thread1, 0, thread_1, &shared);
	if (pte != 0) {
		fprintf(stderr, "pthread_create failed: %d\n", pte);
		CPPUNIT_FAIL("pthread_create failed.");
	}

#ifdef __APPLE__
	se = semaphore_signal(shared.sync_barrier);
	if (se != 0) {
		fprintf(stderr, "semaphore_signal failed: %d\n", se);
			CPPUNIT_FAIL("Could not post to semaphore");

	}
	se = semaphore_wait(shared.sync_barrier);
	if (se != 0) {
		fprintf(stderr, "semaphore_wait failed: %d\n", se);
			CPPUNIT_FAIL("Could not post to semaphore");

	}
#else
	// give thread permission to proceed
	if (sem_post(&shared.sync_barrier) != 0) {
		fprintf(stderr, "sem_post failed: %s\n", strerror(errno));
		CPPUNIT_FAIL("Could not post to semaphore");
	}
	// wait for thread to set some things.
	if (sem_wait(&shared.sync_barrier) != 0) {
		fprintf(stderr, "sem_wait failed: %s\n", strerror(errno));
		CPPUNIT_FAIL("Could not wait on semaphore");
	}
#endif
	CPPUNIT_ASSERT(0 == tsk_error_get_errno());
	CPPUNIT_ASSERT(0 == tsk_error_get_errstr()[0]);
	CPPUNIT_ASSERT(0 == tsk_error_get_errstr2()[0]);
	// give thread permission to proceed
#ifdef __APPLE__
	se = semaphore_signal(shared.sync_barrier);
	if (se != 0) {
		fprintf(stderr, "semaphore_signal failed: %d\n", se);
		CPPUNIT_FAIL("Could not post to semaphore");
	}
#else
	if (sem_post(&shared.sync_barrier) != 0) {
		fprintf(stderr, "sem_post failed: %s\n", strerror(errno));
		CPPUNIT_FAIL("Could not post to semaphore");
	}
#endif

	void *exitval = 0;
	pte = pthread_join(thread1, &exitval);
	if (pte != 0) {
		fprintf(stderr, "pthread_join failed: %d\n", pte);
	    CPPUNIT_FAIL("pthread_join failed.");
	}
	CPPUNIT_ASSERT(!shared.errno_check_failed);
	CPPUNIT_ASSERT(!shared.errstr_check_failed);
	CPPUNIT_ASSERT(!shared.errstr2_check_failed);
}
#endif


