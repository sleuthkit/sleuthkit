/*
 * The Sleuth Kit
 *
 * Unit tests for the XPRESS (MS-XCA) decoders in tsk/fs/xpress.c.
 */
#include <string.h>
#include <vector>

#include <libtsk.h>
#include "tsk/fs/xpress.h"

#include "xpress_test.h"
#include "xpress_test_data.h"

// Registers the fixture into the 'registry'
CPPUNIT_TEST_SUITE_REGISTRATION(XpressTest);

static int decodeVector(const XpressTestVector &v, std::vector<unsigned char> &out) {
    out.resize(v.plain);
    if (v.huff) {
        return xpress_huffman_decode(out.data(), out.size(), v.data, v.coded);
    }
    return xpress_plain_lz77_decode(out.data(), out.size(), v.data, v.coded);
}

void XpressTest::testPlainLz77() {
    for (size_t i = 0; i < sizeof(kXpressVectors) / sizeof(kXpressVectors[0]); i++) {
        const XpressTestVector &v = kXpressVectors[i];
        if (v.huff) {
            continue;
        }
        std::vector<unsigned char> out;
        int got = decodeVector(v, out);
        CPPUNIT_ASSERT_EQUAL((int)v.plain, got);
        CPPUNIT_ASSERT(out.size() == v.plain);
        // Round-trips decode to the same content the Python encoder started
        // from; the first byte is a stable fingerprint per case.
        if (i == 0) {
            CPPUNIT_ASSERT(memcmp(out.data(), "GHOST//RECOVER", 14) == 0);
        }
        if (i == 1) {
            CPPUNIT_ASSERT(memcmp(out.data(), "abcabcabc", 9) == 0);
        }
    }
}

void XpressTest::testHuffman() {
    for (size_t i = 0; i < sizeof(kXpressVectors) / sizeof(kXpressVectors[0]); i++) {
        const XpressTestVector &v = kXpressVectors[i];
        if (!v.huff) {
            continue;
        }
        std::vector<unsigned char> out;
        int got = decodeVector(v, out);
        CPPUNIT_ASSERT_EQUAL((int)v.plain, got);
        CPPUNIT_ASSERT(out.size() == v.plain);
        // The last vector is the MS-XCA 3.1 worked example.
        if (i == sizeof(kXpressVectors) / sizeof(kXpressVectors[0]) - 1) {
            CPPUNIT_ASSERT(memcmp(out.data(), "abcabcabc", 9) == 0);
        }
    }
}

void XpressTest::testCorruptInput() {
    std::vector<unsigned char> out(256);
    const unsigned char bogus[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    // Truncated flag group.
    CPPUNIT_ASSERT_EQUAL(-1,
        xpress_plain_lz77_decode(out.data(), out.size(), bogus, 3));
    // Huffman stream too short for its 256-byte code table.
    CPPUNIT_ASSERT_EQUAL(-1,
        xpress_huffman_decode(out.data(), out.size(), bogus, 16));
}