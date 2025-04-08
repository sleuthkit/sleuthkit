#include "tsk/img/tsk_img_i.h"
#include "tsk/img/qcow.h"

#if HAVE_LIBQCOW

#include <memory>

#include "catch.hpp"

TEST_CASE("qcow_open not a file") {
  const TSK_TCHAR* const images[] = { _TSK_T("not_a_file") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    qcow_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("qcow_open 2 images") {
  const TSK_TCHAR* const images[] = { _TSK_T("a"), _TSK_T("b") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    qcow_open(2, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("qcow_open not a QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    qcow_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("qcow_open ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.qcow") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    qcow_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("qcow_open backslash path separator ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.qcow") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    qcow_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif

#endif
