#include "tsk/img/tsk_img_i.h"
#include "tsk/img/vmdk.h"

#if HAVE_LIBVMDK

#include <memory>

#include "catch.hpp"

TEST_CASE("vmdk_open not a file") {
  const TSK_TCHAR* const images[] = { _TSK_T("not_a_file") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vmdk_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vmdk_open 2 images") {
  const TSK_TCHAR* const images[] = { _TSK_T("a"), _TSK_T("b") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vmdk_open(2, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vmdk_open not a VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vmdk_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vmdk_open ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vmdk") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vmdk_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("vmdk_open backslash path separator ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.vmdk") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vmdk_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif

#endif
