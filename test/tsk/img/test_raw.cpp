#include "tsk/img/tsk_img_i.h"
#include "tsk/img/raw.h"

#include "catch.hpp"

#include <memory>

TEST_CASE("raw_open not a file") {
  const TSK_TCHAR* const images[] = { _TSK_T("not_a_file") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("raw_open segment not a file") {
  // test/tsk/img/a_file.1 is a directory
  const TSK_TCHAR* const images[] = { _TSK_T("test/tsk/img/a_file.0") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("raw_open ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 0),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("raw_open backslash path separator ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    raw_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif
