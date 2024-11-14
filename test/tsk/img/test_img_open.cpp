#include "tsk/img/tsk_img_i.h"
#include "tsk/img/img_open.h"

#include <memory>
#include <utility>

#include "catch.hpp"

TEST_CASE("tsk_img_open 0 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(0, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open -1 images") {
  const TSK_TCHAR* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(-1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open null images") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, nullptr, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open_utf8 0 images") {
  const char* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(0, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open_utf8 -1 images") {
  const char* const images[] = {};
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(-1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
}

TEST_CASE("tsk_img_open_utf8 null images") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open_utf8(1, nullptr, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(!img);
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

TEST_CASE("tsk_img_open detect E01") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.E01") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
#ifdef HAVE_LIBEWF
  REQUIRE(img->itype == TSK_IMG_TYPE_EWF_EWF);
#else
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
#endif
}

TEST_CASE("tsk_img_open detect QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.qcow") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
#ifdef HAVE_LIBQCOW
  REQUIRE(img->itype == TSK_IMG_TYPE_QCOW_QCOW);
#else
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
#endif
}

TEST_CASE("tsk_img_open detect VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
#ifdef HAVE_LIBVHDI
  REQUIRE(img->itype == TSK_IMG_TYPE_VHD_VHD);
#else
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
#endif
}

TEST_CASE("tsk_img_open detect VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vmdk") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
#ifdef HAVE_LIBVMDK
  REQUIRE(img->itype == TSK_IMG_TYPE_VMDK_VMDK);
#else
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
#endif
}

TEST_CASE("tsk_img_open detect raw") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
}

TEST_CASE("tsk_img_open E01") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.E01") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_EWF_EWF, 0),
    tsk_img_close
  };
#ifdef HAVE_LIBEWF
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_EWF_EWF);
#else
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
#endif
}

TEST_CASE("tsk_img_open QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.qcow") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_QCOW_QCOW, 0),
    tsk_img_close
  };
#ifdef HAVE_LIBQCOW
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_QCOW_QCOW);
#else
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
#endif
}

TEST_CASE("tsk_img_open VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VHD_VHD, 0),
    tsk_img_close
  };
#ifdef HAVE_LIBVHDI
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_VHD_VHD);
#else
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
#endif
}

TEST_CASE("tsk_img_open VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vmdk") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VMDK_VMDK, 0),
    tsk_img_close
  };
#ifdef HAVE_LIBVMDK
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_VMDK_VMDK);
#else
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
#endif
}

TEST_CASE("tsk_img_open raw") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_RAW, 0),
    tsk_img_close
  };
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
}

TEST_CASE("tsk_img_open unsupported") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_UNSUPP, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
}

#ifdef HAVE_LIBEWF
TEST_CASE("tsk_img_open not EWF") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_EWF_EWF, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_MAGIC);
}
#endif

#ifdef HAVE_LIBQCOW
TEST_CASE("tsk_img_open not QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_QCOW_QCOW, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}
#endif

#ifdef HAVE_LIBVHDI
TEST_CASE("tsk_img_open not VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VHD_VHD, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}
#endif

#ifdef HAVE_LIBVHDI
TEST_CASE("tsk_img_open not VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VMDK_VMDK, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}
#endif
