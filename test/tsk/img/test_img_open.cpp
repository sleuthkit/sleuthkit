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

void detect_E01(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open detect E01") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.E01") };
  detect_E01(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open detect E01 bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.E01") };
  detect_E01(images);
}
#endif

void detect_QCOW(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open detect QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.qcow") };
  detect_QCOW(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open detect QCOW bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.qcow") };
  detect_QCOW(images);
}
#endif

void detect_VHD(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open detect VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  detect_VHD(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open detect VHD bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  detect_VHD(images);
}
#endif

void detect_VMDK(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open detect VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vmdk") };
  detect_VMDK(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open detect VMDK bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.vmdk") };
  detect_VMDK(images);
}
#endif

void detect_raw(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
}

TEST_CASE("tsk_img_open detect raw") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  detect_raw(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open detect raw bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  detect_raw(images);
}
#endif

void open_E01(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open E01") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.E01") };
  open_E01(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open E01 bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.E01") };
  open_E01(images);
}
#endif

void open_QCOW(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.qcow") };
  open_QCOW(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open QCOW bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.qcow") };
  open_QCOW(images);
}
#endif

void open_VHD(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  open_VHD(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open VHD bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vhd") };
  open_VHD(images);
}
#endif

void open_VMDK(const TSK_TCHAR* const* images) {
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

TEST_CASE("tsk_img_open VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.vmdk") };
  open_VMDK(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open VMDK bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.vmdk") };
  open_VMDK(images);
}
#endif

void open_raw(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_RAW, 0),
    tsk_img_close
  };
  REQUIRE(img);
  REQUIRE(img->itype == TSK_IMG_TYPE_RAW);
}

TEST_CASE("tsk_img_open raw") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_raw(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open raw bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  open_raw(images);
}
#endif

void open_unsupported(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_UNSUPP, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_UNSUPTYPE);
}

TEST_CASE("tsk_img_open unsupported") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_unsupported(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open unsupported bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  open_unsupported(images);
}
#endif

#ifdef HAVE_LIBEWF
void open_not_E01(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_EWF_EWF, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_MAGIC);
}

TEST_CASE("tsk_img_open not EWF") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_not_E01(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open not EWF bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  open_not_E01(images);
}
#endif
#endif

#ifdef HAVE_LIBQCOW
void open_not_QCOW(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_QCOW_QCOW, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}

TEST_CASE("tsk_img_open not QCOW") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_not_QCOW(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open not QCOW bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_not_QCOW(images);
}
#endif
#endif

#ifdef HAVE_LIBVHDI
void open_not_VHD(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VHD_VHD, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}

TEST_CASE("tsk_img_open not VHD") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_not_VHD(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open not VHD bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  open_not_VHD(images);
}
#endif
#endif

#ifdef HAVE_LIBVMDK
void open_not_VMDK(const TSK_TCHAR* const* images) {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(1, images, TSK_IMG_TYPE_VMDK_VMDK, 0),
    tsk_img_close
  };
  REQUIRE(!img);
  REQUIRE(tsk_error_get_errno() == TSK_ERR_IMG_OPEN);
}

TEST_CASE("tsk_img_open not VMDK") {
  const TSK_TCHAR* const images[] = { _TSK_T("test/data/image.dd") };
  open_not_VMDK(images);
}

#ifdef TSK_WIN32
TEST_CASE("tsk_img_open not VMDK bs") {
  const TSK_TCHAR* const images[] = { _TSK_T("test\\data\\image.dd") };
  open_not_VMDK(images);
}
#endif
#endif
