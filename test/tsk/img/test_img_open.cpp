#include "tsk/img/tsk_img_i.h"
#include "tsk/img/img_open.h"

#include <algorithm>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "catch.hpp"

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
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };

  const std::pair<unsigned int, bool> tcase[] = {
    { 0, true },
    { 1, false },
    { 512, true },
    { 513, false },
    { 1024, true }
  };

  for (const auto& [ss, exp]: tcase) {
//    DYNAMIC_SECTION("sector size " << ss);
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
      tsk_img_open(1, images, TSK_IMG_TYPE_RAW, ss),
      tsk_img_close
    };
    CHECK(bool(img) == exp);
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
  // image path : type arg : ok? : expected type : expected errno
  const std::tuple<
    const TSK_TCHAR*,
    TSK_IMG_TYPE_ENUM,
    bool,
    uint32_t
  > tcase[] = {
#ifdef HAVE_LIBEWF
    { _TSK_T("test/data/image.E01"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_EWF_EWF },
    { _TSK_T("test/data/image.E01"), TSK_IMG_TYPE_EWF_EWF, true, TSK_IMG_TYPE_EWF_EWF },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_EWF_EWF, false, TSK_ERR_IMG_MAGIC },
#else
    { _TSK_T("test/data/image.E01"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.E01"), TSK_IMG_TYPE_EWF_EWF, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBQCOW
    { _TSK_T("test/data/image.qcow"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_QCOW_QCOW },
    { _TSK_T("test/data/image.qcow"), TSK_IMG_TYPE_QCOW_QCOW, true, TSK_IMG_TYPE_QCOW_QCOW },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_QCOW_QCOW, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("test/data/image.qcow"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.qcow"), TSK_IMG_TYPE_QCOW_QCOW, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBVHDI
    { _TSK_T("test/data/image.vhd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_VHD_VHD },
    { _TSK_T("test/data/image.vhd"), TSK_IMG_TYPE_VHD_VHD, true, TSK_IMG_TYPE_VHD_VHD },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_VHD_VHD, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("test/data/image.vhd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.vhd"), TSK_IMG_TYPE_VHD_VHD, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
#ifdef HAVE_LIBVMDK
    { _TSK_T("test/data/image.vmdk"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_VMDK_VMDK },
    { _TSK_T("test/data/image.vmdk"), TSK_IMG_TYPE_VMDK_VMDK, true, TSK_IMG_TYPE_VMDK_VMDK },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_VMDK_VMDK, false, TSK_ERR_IMG_OPEN },
#else
    { _TSK_T("test/data/image.vmdk"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.vmdk"), TSK_IMG_TYPE_VMDK_VMDK, false, TSK_ERR_IMG_UNSUPTYPE },
#endif
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_DETECT, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_RAW, true, TSK_IMG_TYPE_RAW },
    { _TSK_T("test/data/image.dd"), TSK_IMG_TYPE_UNSUPP, false, TSK_ERR_IMG_UNSUPTYPE }
  };

  for (const auto& [image, type, ok, exp_type_or_err]: tcase) {
    CAPTURE(image);
    CAPTURE(type);
//    DYNAMIC_SECTION(image << ' ' << type);
    check_image_open(&image, type, ok, exp_type_or_err);
#ifdef TSK_WIN32
    // check same path, with backslashes
    std::wstring img(image);
    std::replace(img.begin(), img.end(), '/', '\\');
    const auto* image_bs = img.c_str();
    CAPTURE(image_bs);
//    DYNAMIC_SECTION(image_bs << ' ' << type);
    check_image_open(&image_bs, type, ok, exp_type_or_err);
#endif
  }
}
