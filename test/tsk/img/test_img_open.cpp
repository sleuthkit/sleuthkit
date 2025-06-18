#include "tsk/img/tsk_img_i.h"
#include "tsk/img/img_open.h"
#include "test/tsk/img/test_img.h"
#include "catch.hpp"


#include <algorithm>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

TEST_CASE("tsk_img_open 0 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(0, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_NOFILE);
}

TEST_CASE("tsk_img_open -1 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(-1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_open null images") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, nullptr, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_NOFILE);
}

TEST_CASE("tsk_img_open_utf8 0 images") {
  const char* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(0, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_NOFILE);
}

TEST_CASE("tsk_img_open_utf8 -1 images") {
  const char* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(-1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_open_utf8 null images") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(1, nullptr, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_NOFILE);
}

TEST_CASE("tsk_img_open sector size") {
  std::basic_string<TSK_TCHAR> path = prepend_test_data_dir(_TSK_T("image/image.dd"));
  const TSK_TCHAR* const images[] = { path.c_str() };

  const std::pair<unsigned int, bool> tcase[] = {
    { 0, true },
    { 1, false },
    { 512, true },
    { 513, false },
    { 1024, true }
  };

  for (const auto& [ss, exp] : tcase) {
    DYNAMIC_SECTION("sector size " << ss) {
      std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
        tsk_img_open(1, images, TSK_IMG_TYPE_RAW, ss),
        tsk_img_close
      };
      CHECK(bool(img) == exp);
    }
  }
}

TEST_CASE("sector_size_ok") {
  const std::pair<unsigned int, bool> tcase[] = {
    { 0, true },
    { 1, false },
    { 512, true },
    { 513, false },
    { 1024, true }
  };

  for (const auto& [ss, exp]: tcase) {
//    DYNAMIC_SECTION("sector size " << ss);
    CHECK(sector_size_ok(ss) == exp);
  }
}

TEST_CASE("images_ok") {
  const char* const one[] = { "one" };
  const char* const two[] = { "one", "two" };

  const std::tuple<int, const char* const*, bool> tcase[] = {
    { -1, nullptr, false },
    {  0, nullptr, false },
    {  1, nullptr, false },
    {  2, nullptr, false },
    { -1, one,     false },
    {  0, one,     false },
    {  1, one,     true },
    {  2, one,     true }, // bad, but no way to check this
    { -1, two,     false },
    {  0, two,     false },
    {  1, two,     true },
    {  2, two,     true }
  };

  for (const auto& [num_img, images, exp]: tcase) {
    CHECK(images_ok(num_img, images) == exp);
  }
}

TEST_CASE("type_name") {
  const std::pair<TSK_IMG_TYPE_ENUM, std::string> tcase[] = {
    { TSK_IMG_TYPE_AFF_AFF, "AFF" },
    { TSK_IMG_TYPE_AFF_AFD, "AFF" },
    { TSK_IMG_TYPE_AFF_AFM, "AFF" },
    { TSK_IMG_TYPE_AFF_ANY, "AFF" },
    { TSK_IMG_TYPE_EWF_EWF, "EWF" },
    { TSK_IMG_TYPE_VMDK_VMDK, "VMDK" },
    { TSK_IMG_TYPE_VHD_VHD, "VHD" },
    { TSK_IMG_TYPE_AFF4_AFF4, "AFF4" },
    { TSK_IMG_TYPE_QCOW_QCOW, "QCOW" }
  };

  for (const auto& [t, exp]: tcase) {
//    DYNAMIC_SECTION("type " << t << ");
    CHECK(type_name(t) == exp);
  }
}

void check_image_open(
  const TSK_TCHAR* const* images,
  TSK_IMG_TYPE_ENUM type,
  bool ok,
  uint32_t exp_type_or_err
)
{
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, type, 0),
    tsk_img_close
  };

  CHECK(bool(img) == ok);
  if (ok) {
    if (img) {
      CHECK(img->itype == exp_type_or_err);
    }
  }
  else {
    CHECK(tsk_error_get_errno() == exp_type_or_err);
  }
}

TEST_CASE("tsk_img_open") {
  using Case = std::tuple<
    const TSK_TCHAR*,
    TSK_IMG_TYPE_ENUM,
    bool,
    uint32_t
  >;

  const Case raw_cases[] = {
#ifdef HAVE_LIBEWF
    { _TSK_T("image/image.E01"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_EWF_EWF },
    { _TSK_T("image/image.E01"), TSK_IMG_TYPE_EWF_EWF, true, TSK_IMG_TYPE_EWF_EWF },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_EWF_EWF, false, TSK_ERR_IMG_MAGIC },
#else
    { _TSK_T("image/image.E01"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.E01"), TSK_IMG_TYPE_EWF_EWF, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBQCOW
    { _TSK_T("image/image.qcow"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_QCOW_QCOW },
    { _TSK_T("image/image.qcow"), TSK_IMG_TYPE_QCOW_QCOW, true, TSK_IMG_TYPE_QCOW_QCOW },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_QCOW_QCOW, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("image/image.qcow"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.qcow"), TSK_IMG_TYPE_QCOW_QCOW, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBVHDI
    { _TSK_T("image/image.vhd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_VHD_VHD },
    { _TSK_T("image/image.vhd"), TSK_IMG_TYPE_VHD_VHD, true, TSK_IMG_TYPE_VHD_VHD },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_VHD_VHD, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("image/image.vhd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.vhd"), TSK_IMG_TYPE_VHD_VHD, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBVMDK
    { _TSK_T("image/image.vmdk"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_VMDK_VMDK },
    { _TSK_T("image/image.vmdk"), TSK_IMG_TYPE_VMDK_VMDK, true, TSK_IMG_TYPE_VMDK_VMDK },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_VMDK_VMDK, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("image/image.vmdk"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.vmdk"), TSK_IMG_TYPE_VMDK_VMDK, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_RAW, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("image/image.dd"), TSK_IMG_TYPE_UNSUPP, false, TSK_ERR_IMG_UNSUPTYPE }
  };

  for (const auto& [rel_path, type, ok, exp_type_or_err] : raw_cases) {
    // Construct full path and preserve its lifetime in this scope
    std::basic_string<TSK_TCHAR> abs_path = prepend_test_data_dir(rel_path);
    const TSK_TCHAR* image_path = abs_path.c_str();

    CAPTURE(image_path);
    CAPTURE(type);
    check_image_open(&image_path, type, ok, exp_type_or_err);

#ifdef TSK_WIN32
    // Backslash variant
    std::basic_string<TSK_TCHAR> path_bs = abs_path;
    std::replace(path_bs.begin(), path_bs.end(), _TSK_T('/'), _TSK_T('\\'));
    const TSK_TCHAR* image_bs = path_bs.c_str();

    CAPTURE(image_bs);
    check_image_open(&image_bs, type, ok, exp_type_or_err);
#endif
  }
}
