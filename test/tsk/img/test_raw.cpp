#include "tsk/img/tsk_img_i.h"
#include "tsk/img/raw.h"

#include "catch.hpp"
#include "test/tsk/img/test_img.h"  // includes prepend_test_data_dir and fix_slashes_for_windows

#include <memory>
#include <string>

TEST_CASE("raw_open not a file") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("not_a_file"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("raw_open segment not a file") {
  // test/data/a_file.1 is a directory
  // it's there to make sure that the auto-expander doesn't include directories.
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("a_file.0"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("raw_open ok") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 0),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("raw_open backslash path separator ok") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
  fix_slashes_for_windows(path);
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif
