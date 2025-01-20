/*
 * The Sleuth Kit
 *
 *
 * Copyright (c) 2010, 2025 Basis Technology Corp.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

#define CATCH_CONFIG_MAIN
#define CATCH_CONFIG_CONSOLE_WIDTH 80
#define CATCH_CONFIG_ENABLE_BENCHMARKING

#include "catch.hpp"

#include "tsk/libtsk.h"

#include "tsk/img/img_cache.h"
#include "tsk/img/legacy_cache.h"
//#include "tsk/img/lru_cache.h"
#include "tsk/img/no_cache.h"
#include "tsk/img/tsk_img_i.h"

#include <future>
#include <iostream>
#include <memory>
#include <vector>

class Walker: public TskAuto {
public:
  virtual ~Walker() {}

  virtual TSK_FILTER_ENUM filterPool(const TSK_POOL_INFO*) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterPoolVol(const TSK_POOL_VOLUME_INFO*) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVs(const TSK_VS_INFO*) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO*) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO*) override {
    return TSK_FILTER_CONT;
  }

  virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE*, const char*) override {
    return TSK_OK;
  }
};

/*
TEST_CASE("bench") {
  const TSK_TCHAR* const images[] = { _TSK_T("../fsrip/testdata/img/TinyOSX.E01") };

  BENCHMARK("legacy bench") {
    std::shared_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
      tsk_img_open(1, images, TSK_IMG_TYPE_EWF_EWF, 0),
      tsk_img_close
    };
    REQUIRE(img);

    const auto img_ptr = img.get();

    std::vector<std::future<uint8_t>> results;

    for (size_t i = 0; i < 10; ++i) {
      std::future<uint8_t> f = std::async(
        std::launch::async,
        [img_ptr]() {
          Walker w;
          w.openImageHandle(img_ptr);
          return w.findFilesInImg();
        }
      );

      results.push_back(std::move(f));
    }

    uint8_t x = 0;
    for (auto& f: results) {
      f.wait();
      x |= f.get();
    }
    return x;
  };
}
*/

std::ostream& operator<<(std::ostream& o, const Stats& s) {
  return o << s.hits << ' '
           << s.misses << ' '
           << s.hit_bytes << ' '
           << s.miss_bytes << ' '
           << s.hit_ns << ' '
           << s.miss_ns;
}

std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> open_img(
  const std::vector<const TSK_TCHAR*>& images
)
{
  std::unique_ptr<TSK_IMG_INFO, decltype(&tsk_img_close)> img{
    tsk_img_open(images.size(), images.data(), TSK_IMG_TYPE_DETECT, 0),
    tsk_img_close
  };
  REQUIRE(img);
  return img;
}

void do_walk(TSK_IMG_INFO* img) {
  Walker w;
  w.openImageHandle(img);
  if (w.findFilesInImg() != 0) {
    for (const auto& e: w.getErrorList()) {
      std::cerr << w.errorRecordToString(e) << std::endl;
    }
  }
}

void do_walks(TSK_IMG_INFO* img, size_t n) {
  std::vector<std::thread> threads;
  std::vector<std::future<void>> results;

  for (size_t i = 0; i < n; ++i) {
/*
    std::future<void> f = std::async(
      std::launch::async,
      [img]() { do_walk(img); }
    );
*/
    std::packaged_task<void(TSK_IMG_INFO*)> task(do_walk);
    std::future<void> f = task.get_future();
    threads.emplace_back(std::move(task), img);
    results.push_back(std::move(f));
  }

  for (auto& t: threads) {
    t.join();
  }

  for (auto& f: results) {
    f.wait();
  }
}

void test_caching(
  const char* fname,
  void (*fsetup)(TSK_IMG_INFO*),
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  std::cout << fname << ' ' << threads << ' ';
  auto img = open_img(images);
  img->cache_free(img.get());
  fsetup(img.get());
  img->cache_holder = img->cache_create(img.get());
  do_walks(img.get(), threads);
  std::cout << img->stats << '\n';
}

TEST_CASE("stats") {
  const std::tuple<const char*, void (*)(TSK_IMG_INFO*)> caches[] = {
    {
      "tsk_img_read_no_cache",
      [](TSK_IMG_INFO* img) {
        img->cache_read = tsk_img_read_no_cache;
        img->cache_create = no_cache_create;
        img->cache_clone = no_cache_clone;
        img->cache_clear = no_cache_clear;
        img->cache_free = no_cache_free;
      }
    },
    {
      "tsk_img_read_legacy",
      [](TSK_IMG_INFO* img) {
        img->cache_read = tsk_img_read_legacy;
        img->cache_create = legacy_cache_create;
        img->cache_clone = legacy_cache_clone;
        img->cache_clear = legacy_cache_clear;
        img->cache_free = legacy_cache_free;
      }
    },
/*
    {
      "tsk_img_read_lru",
      [](TSK_IMG_INFO* img) {
        img->cache_read = tsk_img_read_lru;
        img->cache_create = lru_cache_create;
        img->cache_clone = lru_cache_clone;
        img->cache_clear = lru_cache_clear;
        img->cache_free = lru_cache_free;
        img->cache_holder = img->cache_create(img);
      }
    },
*/
/*
    {
      "tsk_img_read_lru_tsk_lock",
      [](TSK_IMG_INFO* img) {
        img->cache_read = tsk_img_read_lru_own_lock;
        img->cache_create = lru_cache_create;
        img->cache_clone = lru_cache_clone;
        img->cache_clear = lru_cache_clear;
        img->cache_free = [](TSK_IMG_INFO*) {};
//        img->cache_free = lru_cache_free;

        std::shared_ptr<Cache> cache{new LRUImgCacheLockingTsk(1024)};
        img->cache_holder = cache.get();
        return std::static_pointer_cast<void>(cache);
      }
    }
*/
  };

  std::vector<std::vector<const TSK_TCHAR*>> images{
//     { _TSK_T("../fsrip/testdata/img/TinyOSX.E01") },
     { _TSK_T("/home/juckelman/Downloads/win7-64-nfury-c-drive.E01") }
  };

  std::cout << "name threads h m \"h bytes\" \"m bytes\" \"h ns\" \"m ns\"\n";

  for (const auto& imgs: images) {
    for (const auto threads: { 1, 10 }) {
      for (const auto& [fname, fsetup]: caches) {
        test_caching(fname, fsetup, imgs, threads);
      }
    }
  }
}
