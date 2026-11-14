/*
 * bitlocker_test.h
 *
 * Tests for the BitLocker password encoding: BitLocker hashes a password as UTF-16LE, and that
 * must not depend on the size of wchar_t (2 bytes on Windows, 4 on Linux and macOS).
 */

#ifndef BITLOCKER_TEST_H_
#define BITLOCKER_TEST_H_

#include <cppunit/extensions/HelperMacros.h>

class BitlockerTest : public CppUnit::TestFixture
{
  CPPUNIT_TEST_SUITE( BitlockerTest );
  CPPUNIT_TEST(testAscii);
  CPPUNIT_TEST(testBmp);
  CPPUNIT_TEST(testSupplementary);
  CPPUNIT_TEST(testEmpty);
  CPPUNIT_TEST(testInvalidUtf8);
  CPPUNIT_TEST_SUITE_END();

public:
  void setUp();
  void tearDown();

  void testAscii();
  void testBmp();
  void testSupplementary();
  void testEmpty();
  void testInvalidUtf8();
};

#endif /* BITLOCKER_TEST_H_ */
