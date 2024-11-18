/*
 * errors_test.cpp
 *
 *  Created on: Oct 22, 2010
 *      Author: benson
 */

#include "tsk/tsk_config.h"
#include "tsk/libtsk.h"

#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>

#include "catch.hpp"

TEST_CASE("void ErrorsTest::testInitialState()","[errors]") {
  tsk_error_reset();
  TSK_ERROR_INFO *ei = tsk_error_get_info();
  REQUIRE(0 == ei->t_errno);
  REQUIRE(0 == ei->errstr[0]);
  REQUIRE(0 == ei->errstr2[0]);
}

TEST_CASE("void ErrorsTest::testLengthChecks()","[errors]") {
  tsk_error_reset();
  tsk_error_get_info();
  const std::string s(4096, 'x');
  tsk_error_set_errstr("%s", s.c_str());
  std::string es(tsk_error_get_errstr());
  REQUIRE(es.size() < 1025);
}

struct xErrorsTestShared {
  bool errno_check_failed = false;
  bool errstr_check_failed = false;
  bool errstr2_check_failed = false;
};

/*
 * This thread sets error variables, updates the semaphore,
 * waits on the semaphore, and reads them back.
 */
void thread_1(xErrorsTestShared& shared, std::mutex& m, std::condition_variable& cv, int& state) {
  {
    // wait to be told to start
    std::unique_lock<std::mutex> l(m);
    cv.wait(l, [&]{ return state == 1; });

    tsk_error_set_errno(42);
    tsk_error_set_errstr("I just set errno to %d.", 42);
    tsk_error_set_errstr2("Indeed, I just set errno to %d.", 42);

    state = 2;
  }
  cv.notify_one();

  {
    // wait to be told to start
    std::unique_lock<std::mutex> l(m);
    cv.wait(l, [&]{ return state == 3; });

    shared.errno_check_failed = 42 != tsk_error_get_errno();
    char const* s = tsk_error_get_errstr();
    shared.errstr_check_failed = 0 != strcmp("I just set errno to 42.", s);
    s = tsk_error_get_errstr2();
    shared.errstr2_check_failed = 0 != strcmp("Indeed, I just set errno to 42.", s);
  }
  cv.notify_one();
}

#ifdef TSK_MULTITHREAD_LIB

TEST_CASE("void ErrorsTest::testMultithreaded()","[errors]") {
  xErrorsTestShared shared;
  tsk_error_reset();

  std::condition_variable cv;
  std::mutex m;

  int state = 0;

  // start the child
  std::thread child(thread_1, std::ref(shared), std::ref(m), std::ref(cv), std::ref(state));

  // give child permission to proceed
  {
    std::lock_guard<std::mutex> l(m);
    state = 1;
  }
  cv.notify_one();

  // wait for child to set some things.
  {
    std::unique_lock<std::mutex> l(m);
    cv.wait(l, [&]{ return state == 2; });
  }

  REQUIRE(tsk_error_get_errno() == 0);
  REQUIRE(std::strlen(tsk_error_get_errstr()) == 0);
  REQUIRE(std::strlen(tsk_error_get_errstr2()) == 0);

  // give child permission to proceed
  {
    std::lock_guard<std::mutex> l(m);
    state = 3;
  }
  cv.notify_one();

  child.join();

  REQUIRE(!shared.errno_check_failed);
  REQUIRE(!shared.errstr_check_failed);
  REQUIRE(!shared.errstr2_check_failed);
}

#endif
