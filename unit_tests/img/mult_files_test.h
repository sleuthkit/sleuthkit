#ifndef MULT_FILES_TEST_H
#define MULT_FILES_TEST_H

#include <cppunit/extensions/HelperMacros.h>

class MultFilesTest : public CppUnit::TestFixture {
  CPPUNIT_TEST_SUITE(MultFilesTest);
  CPPUNIT_TEST(testSegmentsAlphabetic);
  CPPUNIT_TEST(testSegmentsBin);
  CPPUNIT_TEST(testSegmentsDmg);
  CPPUNIT_TEST(testSegmentsNone);
  CPPUNIT_TEST(testSegmentsNumericOneBased);
  CPPUNIT_TEST(testSegmentsNumericZeroBased);
  CPPUNIT_TEST_SUITE_END();

public:
  void testSegmentsAlphabetic();
  void testSegmentsBin();
  void testSegmentsDmg();
  void testSegmentsNone();
  void testSegmentsNumericOneBased();
  void testSegmentsNumericZeroBased();
};

#endif
