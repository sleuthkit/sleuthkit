#include "tsk/img/tsk_img_i.h"

#include <memory>

#include "catch.hpp"

TEST_CASE("tsk_img_open 0 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(0, images, TSK_IMG_TYPE_DETECT, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open -1 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(-1, images, TSK_IMG_TYPE_DETECT, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}
