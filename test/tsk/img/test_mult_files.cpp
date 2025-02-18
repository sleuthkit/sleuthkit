#include "tsk/img/mult_files.h"

#include "catch.hpp"

TEST_CASE("testSegmentsAlphabetic", "[mult_files]") {
  TSK_TOSTRINGSTREAM os;
  TSK_TSTRING base = _TSK_T("x");

  for (TSK_TSTRING sep: {_TSK_T("."), _TSK_T("_"), _TSK_T("")}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("aaa")).c_str());

    CHECK(pfunc(1, os) == name + _TSK_T("aab"));
    os.str(_TSK_T(""));
    CHECK(pfunc(25, os) == name + _TSK_T("aaz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(26, os) == name + _TSK_T("aba"));
    os.str(_TSK_T(""));
    CHECK(pfunc(51, os) == name + _TSK_T("abz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(52, os) == name + _TSK_T("aca"));
    os.str(_TSK_T(""));
    CHECK(pfunc(675, os) == name + _TSK_T("azz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(676, os) == name + _TSK_T("baa"));
    os.str(_TSK_T(""));
    CHECK(pfunc(17575, os) == name + _TSK_T("zzz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(17576, os) == _TSK_T(""));
    os.str(_TSK_T(""));
  }

  for (TSK_TSTRING sep: {_TSK_T("."), _TSK_T("_"), _TSK_T("")}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("aaaa")).c_str());

    CHECK(pfunc(1, os) == name + _TSK_T("aaab"));
    os.str(_TSK_T(""));
    CHECK(pfunc(25, os) == name + _TSK_T("aaaz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(26, os) == name + _TSK_T("aaba"));
    os.str(_TSK_T(""));
    CHECK(pfunc(51, os) == name + _TSK_T("aabz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(52, os) == name + _TSK_T("aaca"));
    os.str(_TSK_T(""));
    CHECK(pfunc(675, os) == name + _TSK_T("aazz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(676, os) == name + _TSK_T("abaa"));
    os.str(_TSK_T(""));
    CHECK(pfunc(17575, os) == name + _TSK_T("azzz"));
    os.str(_TSK_T(""));
    CHECK(pfunc(17576, os) == name + _TSK_T("baaa"));
    os.str(_TSK_T(""));
  }
}

TEST_CASE("testSegmentsBin", "[mult_files]") {
  TSK_TOSTRINGSTREAM os;
  const auto pfunc = getSegmentPattern(_TSK_T("file.bin"));

  CHECK(pfunc(1, os) == _TSK_T("file(2).bin"));
  os.str(_TSK_T(""));
  CHECK(pfunc(9, os) == _TSK_T("file(10).bin"));
  os.str(_TSK_T(""));
  CHECK(pfunc(99, os) == _TSK_T("file(100).bin"));
  os.str(_TSK_T(""));
  CHECK(pfunc(999, os) == _TSK_T("file(1000).bin"));
}

TEST_CASE("testSegmentsDmg", "[mult_files]") {
  TSK_TOSTRINGSTREAM os;
  const auto pfunc = getSegmentPattern(_TSK_T("file.dmg"));

  CHECK(pfunc(1, os) == _TSK_T("file.002.dmgpart"));
  os.str(_TSK_T(""));
  CHECK(pfunc(9, os) == _TSK_T("file.010.dmgpart"));
  os.str(_TSK_T(""));
  CHECK(pfunc(99, os) == _TSK_T("file.100.dmgpart"));
  os.str(_TSK_T(""));
  CHECK(pfunc(999, os) == _TSK_T("file.1000.dmgpart"));
}

TEST_CASE("testSegmentsNone", "[mult_files]") {
  const auto pfunc = getSegmentPattern(_TSK_T("some.img"));
  CHECK(!pfunc);
}

TEST_CASE("testSegmentsNumericOneBased") {
  TSK_TOSTRINGSTREAM os;
  TSK_TSTRING base = _TSK_T("file");

  for (TSK_TCHAR sep: {'.', '_'}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("001")).c_str());
    os.str(_TSK_T(""));
    CHECK(pfunc(1, os) == name + _TSK_T("002"));
    os.str(_TSK_T(""));
    CHECK(pfunc(9, os) == name + _TSK_T("010"));
    os.str(_TSK_T(""));
    CHECK(pfunc(99, os) == name + _TSK_T("100"));
    os.str(_TSK_T(""));
    CHECK(pfunc(999, os) == name + _TSK_T("1000"));
  }

  for (TSK_TCHAR sep: {_TSK_T('.'), _TSK_T('_')}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("00001")).c_str());
    os.str(_TSK_T(""));
    CHECK(pfunc(1, os) == name + _TSK_T("00002"));
    os.str(_TSK_T(""));
    CHECK(pfunc(9, os) == name + _TSK_T("00010"));
    os.str(_TSK_T(""));
    CHECK(pfunc(99, os) == name + _TSK_T("00100"));
    os.str(_TSK_T(""));
    CHECK(pfunc(999, os) == name + _TSK_T("01000"));
  }
}

TEST_CASE("testSegmentsNumericZeroBased", "[mult_files]") {
  TSK_TOSTRINGSTREAM os;
  TSK_TSTRING base = _TSK_T("file");

  for (TSK_TCHAR sep: {_TSK_T('.'), _TSK_T('_')}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("000")).c_str());
    os.str(_TSK_T(""));
    CHECK(pfunc(1, os) == name + _TSK_T("001"));
    os.str(_TSK_T(""));
    CHECK(pfunc(10, os) == name + _TSK_T("010"));
    os.str(_TSK_T(""));
    CHECK(pfunc(100, os) == name + _TSK_T("100"));
    os.str(_TSK_T(""));
    CHECK(pfunc(1000, os) == name + _TSK_T("1000"));
  }

  for (TSK_TCHAR sep: {_TSK_T('.'), _TSK_T('_')}) {
    const TSK_TSTRING name = base + sep;
    const auto pfunc = getSegmentPattern((name + _TSK_T("00000")).c_str());
    os.str(_TSK_T(""));
    CHECK(pfunc(1, os) == name + _TSK_T("00001"));
    os.str(_TSK_T(""));
    CHECK(pfunc(10, os) == name + _TSK_T("00010"));
    os.str(_TSK_T(""));
    CHECK(pfunc(100, os) == name + _TSK_T("00100"));
    os.str(_TSK_T(""));
    CHECK(pfunc(1000, os) == name + _TSK_T("01000"));
  }
}
