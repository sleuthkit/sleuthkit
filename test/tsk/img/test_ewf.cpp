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

#ifdef TSK_WIN32
TEST_CASE("ewf_open backslash path separator ok") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.E01") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    ewf_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif

TEST_CASE("glob_E01") {
  const std::tuple<const TSK_TCHAR*, bool, std::vector<TSK_TSTRING>> tcase[] = {
    { _TSK_T("test/data/image.E01"), true, { _TSK_T("test/data/image.E01") } },
    { _TSK_T("test/data/not_a_file.E01"), true, {} },
    { _TSK_T("test/data/not_a_file"), false, {} },
    { _TSK_T("test/data/bogus.E01"), true, { _TSK_T("test/data/bogus.E01"), _TSK_T("test/data/bogus.E02") } }
  };

  for (const auto& [path, ok, exp]: tcase) {
    CAPTURE(path);
    const auto glob = glob_E01(path);
    CHECK(bool(glob) == ok);
    if (ok && glob) {
      CHECK(glob.value() == exp);
    }
  }
}

#endif
