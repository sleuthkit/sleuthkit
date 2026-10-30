/*
 * bitlocker_test.cpp
 *
 * Tests for convertUtf8ToUtf16Le(), which turns a BitLocker password into the UTF-16LE bytes
 * that are hashed. It used to go through std::wstring, so on Linux and macOS, where wchar_t is
 * 4 bytes, every password hashed to the wrong value.
 */

#include <libtsk.h>
#include <tsk_config.h>

#include <string>
#include <vector>

#include "bitlocker_test.h"

#ifdef HAVE_LIBMBEDTLS

#include "tsk/util/Bitlocker/BitlockerUtils.h"

// Registers the fixture into the 'registry'
CPPUNIT_TEST_SUITE_REGISTRATION( BitlockerTest );

static std::vector<uint8_t> toUtf16Le(const std::string& utf8) {
	std::vector<uint8_t> bytes;
	CPPUNIT_ASSERT(convertUtf8ToUtf16Le(utf8, bytes));
	return bytes;
}

void BitlockerTest::setUp() {}
void BitlockerTest::tearDown() {}

void BitlockerTest::testAscii() {
	const uint8_t expected[] = { 'a', 0, 'b', 0, '1', 0 };
	CPPUNIT_ASSERT(toUtf16Le("ab1") == std::vector<uint8_t>(expected, expected + sizeof(expected)));
}

void BitlockerTest::testBmp() {
	// U+00DC (Latin-1), U+03A9 (Greek), U+20AC (euro sign)
	const uint8_t expected[] = { 0xDC, 0x00, 0xA9, 0x03, 0xAC, 0x20 };
	CPPUNIT_ASSERT(toUtf16Le("\xC3\x9C\xCE\xA9\xE2\x82\xAC") == std::vector<uint8_t>(expected, expected + sizeof(expected)));
}

void BitlockerTest::testSupplementary() {
	// U+1F600 is the surrogate pair D83D DE00
	const uint8_t expected[] = { 0x3D, 0xD8, 0x00, 0xDE };
	CPPUNIT_ASSERT(toUtf16Le("\xF0\x9F\x98\x80") == std::vector<uint8_t>(expected, expected + sizeof(expected)));
}

void BitlockerTest::testEmpty() {
	CPPUNIT_ASSERT(toUtf16Le("").empty());
}

void BitlockerTest::testInvalidUtf8() {
	std::vector<uint8_t> bytes;
	CPPUNIT_ASSERT(!convertUtf8ToUtf16Le("\xC3", bytes));          // truncated sequence
	CPPUNIT_ASSERT(!convertUtf8ToUtf16Le("ab\xFF", bytes));        // byte that never starts a sequence
}

#endif
