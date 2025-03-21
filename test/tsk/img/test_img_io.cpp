#include "tsk/img/tsk_img_i.h"
#include "tsk/img/img_open.h"
#include "tsk/img/legacy_cache.h"

#include <limits>
#include <memory>

#include "catch.hpp"

TEST_CASE("tsk_img_read null img") {
  char buf[1];
  CHECK(tsk_img_read(nullptr, 0, buf, 1) == -1);
  CHECK(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_read null buffer") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_free)> img{
    (TSK_IMG_INFO*) tsk_img_malloc(sizeof(IMG_INFO)),
    tsk_img_free
  };
  REQUIRE(img);

  CHECK(tsk_img_read(img.get(), 0, nullptr, 1) == -1);
  CHECK(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_read negative offset") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_free)> img{
    (TSK_IMG_INFO*) tsk_img_malloc(sizeof(IMG_INFO)),
    tsk_img_free
  };
  REQUIRE(img);

  char buf[1];
  CHECK(tsk_img_read(img.get(), -1, buf, 1) == -1);
  CHECK(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_read offset past end") {
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_free)> img{
    (TSK_IMG_INFO*) tsk_img_malloc(sizeof(IMG_INFO)),
    tsk_img_free
  };
  REQUIRE(img);

  img->size = 1;
  char buf[1];
  CHECK(tsk_img_read(img.get(), 2, buf, 1) == -1);
  CHECK(tsk_error_get_errno() == TSK_ERR_IMG_READ_OFF);
}

TEST_CASE("tsk_img_read length overflow") {
  // Overflow isn't possible when size_t is smaller than TSK_OFF_T
  if (std::numeric_limits<size_t>::max() > std::numeric_limits<TSK_OFF_T>::max()) {
    std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_free)> img{
      (TSK_IMG_INFO*) tsk_img_malloc(sizeof(IMG_INFO)),
      tsk_img_free
    };
    REQUIRE(img);

    img->size = 1;
    char buf[1];
    CHECK(tsk_img_read(img.get(), 0, buf, std::numeric_limits<size_t>::max()) == -1);
    CHECK(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
  }
}

TEST_CASE("tsk_img_read inner function failed") {

  const auto closer = [](TSK_IMG_INFO* img) {
    auto cache = static_cast<LegacyCache*>(reinterpret_cast<IMG_INFO*>(img)->cache);
    delete cache;
    tsk_img_free(img);
  };

  std::unique_ptr<TSK_IMG_INFO, decltype(closer)> img{
    (TSK_IMG_INFO*) tsk_img_malloc(sizeof(IMG_INFO)),
    closer
  };

  REQUIRE(img);

  reinterpret_cast<IMG_INFO*>(img.get())->cache = new LegacyCache();

  reinterpret_cast<IMG_INFO*>(img.get())->cache_read = tsk_img_read_legacy;

  reinterpret_cast<IMG_INFO*>(img.get())->read = [](TSK_IMG_INFO*, TSK_OFF_T, char*, size_t) {
    return (ssize_t) -1;
  };

  img->size = 1 << 20;
  img->sector_size = 512;

  char buf[1];

  CHECK(tsk_img_read(img.get(), 0, buf, 1) == -1);
  // don't check errno, nothing here will have set it
}
