/*
 * errors_test.h
 *
 *  Created on: Oct 22, 2010
 *      Author: benson
 */

#ifndef ERRORS_TEST_H_
#define ERRORS_TEST_H_

#include <cppunit/extensions/HelperMacros.h>

class ErrorsTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE( ErrorsTest );
  CPPUNIT_TEST(testInitialState);
  CPPUNIT_TEST(testLengthChecks);
#ifdef HAVE_PTHREAD
  CPPUNIT_TEST(testMultithreaded);
#endif
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp();
  void tearDown();

  void testConstructor();
  void testInitialState();
  void testLengthChecks();
#ifdef HAVE_PTHREAD
  void testMultithreaded();
#endif
};


#endif /* ERRORS_TEST_H_ */
