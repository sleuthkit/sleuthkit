#include "tsk/img/tsk_img_i.h"
#include "tsk/img/img_open.h"

#include <memory>

#include "catch.hpp"

TEST_CASE("tsk_img_read null img") {
  char buf[1];
  CHECK(tsk_img_read(nullptr, 0, buf, 1) == -1);
  CHECK(tsk_error_get_errno() == TSK_ERR_IMG_ARG);
}

TEST_CASE("tsk_img_read inner function failed") {
  const auto closer = [](TSK_IMG_INFO* img) {
    tsk_deinit_lock(&(img->cache_lock));
    tsk_img_free(img);
  };

  std::unique_ptr<TSK_IMG_INFO, decltype(closer)> img{
    (TSK_IMG_INFO*) tsk_img_malloc(sizeof(TSK_IMG_INFO)),
    closer
  };

  REQUIRE(img);
  tsk_init_lock(&(img->cache_lock));

  img->read = [](TSK_IMG_INFO*, TSK_OFF_T, char*, size_t) {
    return (ssize_t) -1;
  };

  img->size = 1 << 20;
  img->sector_size = 512;

  char buf[1];

  CHECK(tsk_img_read(img.get(), 0, buf, 1) == -1);
  // don't check errno, nothing here will have set it
}
