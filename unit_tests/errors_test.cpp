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

#include "catch.hpp"

TEST_CASE("void ErrorsTest::testInitialState()","[errors]") {
	TSK_ERROR_INFO *ei;

	ei = tsk_error_get_info();
	REQUIRE(0 == ei->t_errno);
	REQUIRE(0 == ei->errstr[0]);
	REQUIRE(0 == ei->errstr2[0]);
}

TEST_CASE("void ErrorsTest::testLengthChecks()","[errors]") {
	TSK_ERROR_INFO *ei;

	ei = tsk_error_get_info();
	std::string s;
	for (unsigned x = 0; x < 4096; x ++) {
		s = s + std::string("x");
	}
	tsk_error_set_errstr("%s", s.c_str());
	std::string es(tsk_error_get_errstr());
	REQUIRE(es.size() < 1025);
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

TEST_CASE("void ErrorsTest::testMultithreaded()","[errors]"){
	xErrorsTestShared shared;
	tsk_error_reset();
	// start semaphore unlocked. Thread will lock.
#ifdef __APPLE__
	kern_return_t se;
	se = semaphore_create(mach_task_self(), &shared.sync_barrier, SYNC_POLICY_FIFO, 0);
        REQUIRE(se==0);
#else
	REQUIRE(sem_init(&shared.sync_barrier, 0, 0)==0);
#endif

	pthread_t thread1;

	int pte = pthread_create(&thread1, 0, thread_1, &shared);
        REQUIRE(pte==0);

#ifdef __APPLE__
	se = semaphore_signal(shared.sync_barrier);
        REQUIRE(se==0);
	se = semaphore_wait(shared.sync_barrier);
	REQUIRE(se==0);
#else
	// give thread permission to proceed
	REQUIRE (sem_post(&shared.sync_barrier) == 0);
	// wait for thread to set some things.
	REQUIRE (sem_wait(&shared.sync_barrier) == 0);
#endif
	REQUIRE(0 == tsk_error_get_errno());
	REQUIRE(0 == tsk_error_get_errstr()[0]);
	REQUIRE(0 == tsk_error_get_errstr2()[0]);
	// give thread permission to proceed
#ifdef __APPLE__
	se = semaphore_signal(shared.sync_barrier);
        REQUIRE(se==0);
#else
	REQUIRE (sem_post(&shared.sync_barrier) == 0);{
#endif

	void *exitval = 0;
	pte = pthread_join(thread1, &exitval);
        REQUIRE(pte == 0);
	REQUIRE(!shared.errno_check_failed);
	REQUIRE(!shared.errstr_check_failed);
	REQUIRE(!shared.errstr2_check_failed);
        }
 }
#endif
