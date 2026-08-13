/*
 * The Sleuth Kit
 *
 * Unit tests for the XPRESS (MS-XCA) decoders in tsk/fs/xpress.c.
 *
 * The vectors were produced by an independent pure-Python encoder and
 * include the worked example from MS-XCA section 3.1 (a8 dc 00 00 ff 26 01,
 * which decodes to 100 repetitions of "abc").
 */
#ifndef XPRESS_TEST_H
#define XPRESS_TEST_H

#include <cppunit/extensions/HelperMacros.h>

class XpressTest : public CPPUNIT_NS::TestFixture {
    CPPUNIT_TEST_SUITE(XpressTest);
    CPPUNIT_TEST(testPlainLz77);
    CPPUNIT_TEST(testHuffman);
    CPPUNIT_TEST(testCorruptInput);
    CPPUNIT_TEST_SUITE_END();

public:
    void testPlainLz77();
    void testHuffman();
    void testCorruptInput();
};

#endif /* XPRESS_TEST_H */