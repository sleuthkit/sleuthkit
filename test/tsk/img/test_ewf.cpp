/*
 * test_ewf.cpp:
 *
 * test framework for catch_runner.cpp.
 *
 * Uses disk images stored at $srcdir/test/data/
 */

#include "tsk/img/tsk_img_i.h"
#include "tsk/img/ewf.h"

#if HAVE_LIBEWF

#include <string>
#include <cstdlib>  // getenv or _wgetenv
#include <stdexcept>
#include <algorithm>
#include <memory>

#include "test/tsk/img/test_img.h"
#include "catch.hpp"

TEST_CASE("ewf_open not a file") {
    std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("not_a_file"));
    const TSK_TCHAR* images[] = { path.c_str() };
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("ewf_open not an E01") {
    std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
    const TSK_TCHAR* images[] = { path.c_str() };
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("ewf_open ok") {
    std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.E01"));
    const TSK_TCHAR* images[] = { path.c_str() };
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("ewf_open backslash path separator ok") {
    std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("test\\data\\image\\image.E01"));
    const TSK_TCHAR* images[] = { path.c_str() };
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif

void check_glob_E01( const TSK_TCHAR* path, bool ok, const std::vector<TSK_TSTRING>& exp)
{
  const auto glob = glob_E01(path);
  CHECK(bool(glob) == ok);
  if (ok && glob) {
    CHECK(glob.value() == exp);
  }
}

TEST_CASE("glob_E01") {
  const std::tuple<const TSK_TCHAR*, bool, std::vector<const TSK_TCHAR*>> tcase[] = {
    { _TSK_T("image/image.E01"), true, { _TSK_T("image/image.E01") } },
    { _TSK_T("image/not_a_file.E01"), true, {} },
    { _TSK_T("image/not_a_file"), false, {} },
    { _TSK_T("bogus.E01"), true, { _TSK_T("bogus.E01"), _TSK_T("bogus.E02") } }
  };

  for (const auto& [rel_path, ok, rel_exp_vec] : tcase) {
    std::basic_string<TSK_TCHAR> abs_path = prepend_test_data_dir(rel_path);

    std::vector<TSK_TSTRING> abs_exp;
    for (const auto& rel : rel_exp_vec) {
      abs_exp.push_back(prepend_test_data_dir(rel));
    }

#ifdef TSK_WIN32
    // Convert slashes to backslashes
    fix_slashes_for_windows(abs_path);
    for (auto& e : abs_exp) {
        fix_slashes_for_windows(e);
    }

    const TSK_TCHAR* path_bs = abs_path.c_str();
    CAPTURE(path_bs);
    check_glob_E01(path_bs, ok, abs_exp);
#else
    CAPTURE(abs_path);
    check_glob_E01(abs_path.c_str(), ok, abs_exp);
#endif
  }
}
#endif
