#include "tsk/img/tsk_img_i.h"
#include "tsk/img/vhd.h"

#if HAVE_LIBVHDI

#include <memory>
#include <string>

#include "catch.hpp"
#include "test/tsk/img/test_img.h"  // for prepend_test_data_dir and fix_slashes_for_windows

TEST_CASE("vhdi_open not a file") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("not_a_file"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vhdi_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vhdi_open 2 images") {
  std::basic_string<TSK_TCHAR> path1 = prepend_test_data_dir(_TSK_T("a"));
  std::basic_string<TSK_TCHAR> path2 = prepend_test_data_dir(_TSK_T("b"));
  const TSK_TCHAR* const images[] = { path1.c_str(), path2.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vhdi_open(2, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vhdi_open not a VHD") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vhdi_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("vhdi_open ok") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.vhd"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vhdi_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}

#ifdef TSK_WIN32
TEST_CASE("vhdi_open backslash path separator ok") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.vhd"));
  fix_slashes_for_windows(path);
  const TSK_TCHAR* const images[] = { path.c_str() };

  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    vhdi_open(1, images, 1234),
    tsk_img_close
  };
  REQUIRE(img);
}
#endif

#endif // HAVE_LIBVHDI
