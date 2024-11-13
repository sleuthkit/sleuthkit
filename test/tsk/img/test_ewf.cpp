#include "tsk/img/tsk_img_i.h"
#include "tsk/img/ewf.h"

#if HAVE_LIBEWF

#include <memory>

#include "catch.hpp"

TEST_CASE("ewf_open not a file") {
  const TSK_TCHAR* const images[] = { _TSK_T("not_a_file") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("ewf_open not an E01") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("ewf_open ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.E01") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}

#endif
