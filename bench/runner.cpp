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
#include "tsk/img/lru_cache.h"
#include "tsk/img/no_cache.h"
#include "tsk/img/tsk_img_i.h"

#include <cstring>
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

Stats do_walk(TSK_IMG_INFO* img) {
  Walker w;
  w.openImageHandle(img);
  if (w.findFilesInImg() != 0) {
    for (const auto& e: w.getErrorList()) {
      std::cerr << w.errorRecordToString(e) << std::endl;
    }
  }
  return reinterpret_cast<IMG_INFO*>(img)->stats;
}

template <class Func, class... Types>
std::vector<std::future<typename std::invoke_result<Func, Types...>::type>>
run_tasks(size_t n, Func func, Types... args)
{
  std::vector<std::thread> threads;
  std::vector<std::future<typename std::invoke_result<Func, Types...>::type>> futures;

  for (size_t i = 0; i < n; ++i) {
    std::packaged_task task(func);
    futures.push_back(task.get_future());
    threads.emplace_back(std::move(task), args...);
  }

  for (auto& t: threads) {
    t.join();
  }

  return futures;
}

struct CacheFuncs {
  ssize_t (*read)(TSK_IMG_INFO* img, TSK_OFF_T off, char *buf, size_t len);
  void* (*create)(TSK_IMG_INFO* img);
  void* (*clone)(const TSK_IMG_INFO* img);
  void (*free)(TSK_IMG_INFO* img);
  void (*clear)(TSK_IMG_INFO* img);
};

void set_cache_funcs(TSK_IMG_INFO* img, const CacheFuncs& cfuncs) {
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img);
  iif->cache_read = cfuncs.read;
  iif->cache_create = cfuncs.create;
  iif->cache_clone = cfuncs.clone;
  iif->cache_free = cfuncs.free;
  iif->cache_clear = cfuncs.clear;
}

void test_caching_shared_img(
  const char* fname,
  const CacheFuncs& cfuncs,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  std::cout << fname << " sisc " << threads << ' ';

  auto img = open_img(images);

  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());

  iif->cache_free(img.get());
  set_cache_funcs(img.get(), cfuncs);
  iif->cache = iif->cache_create(img.get());

  const auto getimg = [&img]() { return img.get(); };

  const auto futures = run_tasks(
    threads,
    [getimg](){ do_walk(getimg()); }
  );

  for (auto& f: futures) {
    f.wait();
  }

  std::cout << iif->stats << '\n';
}

void test_caching_own_img(
  const char* fname,
  const CacheFuncs& cfuncs,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  std::cout << fname << " oioc " << threads << ' ';

  const auto getimg = [&]() {
    auto img = open_img(images);

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());
    iif->cache_free(img.get());
    set_cache_funcs(img.get(), cfuncs);
    iif->cache = iif->cache_create(img.get());

    return img;
  };

  auto futures = run_tasks(
    threads,
    [getimg](){
      auto img = getimg();
      return do_walk(img.get());
    }
  );

  // collect the per-thread stats
  Stats stats{};
  for (auto& f: futures) {
    const auto s = f.get();

    stats.hits += s.hits;
    stats.hit_ns += s.hit_ns;
    stats.hit_bytes += s.hit_bytes;
    stats.misses += s.misses;
    stats.miss_ns += s.miss_ns;
    stats.miss_bytes += s.miss_bytes;
  }

  std::cout << stats << '\n';
}

void test_caching_own_img_shared_cache(
  const char* fname,
  const CacheFuncs& cfuncs,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  if (!std::strstr(fname, "finer_lock")) {
    return;
  }

  std::cout << fname << " oisc " << threads << ' ';

  auto cache = cfuncs.create(nullptr);

  const auto getimg = [&]() {
    auto img = open_img(images);

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());
    iif->cache_free(img.get());
    set_cache_funcs(img.get(), cfuncs);
    iif->cache = cache;

    return img;
  };

  auto futures = run_tasks(
    threads,
    [getimg](){
      auto img = getimg();
      return do_walk(img.get());
    }
  );

  // collect the per-thread stats
  Stats stats{};
  for (auto& f: futures) {
    const auto s = f.get();

    stats.hits += s.hits;
    stats.hit_ns += s.hit_ns;
    stats.hit_bytes += s.hit_bytes;
    stats.misses += s.misses;
    stats.miss_ns += s.miss_ns;
    stats.miss_bytes += s.miss_bytes;
  }

  std::cout << stats << '\n';
}

TEST_CASE("stats") {
  const std::tuple<
    const char*,
    CacheFuncs
  > caches[] = {
    {
      "tsk_img_read_no_cache",
      CacheFuncs{
        tsk_img_read_no_cache,
        no_cache_create,
        no_cache_clone,
        no_cache_free,
        no_cache_clear
      }
    },
    {
      "tsk_img_read_legacy",
      CacheFuncs{
        tsk_img_read_legacy,
        legacy_cache_create,
        legacy_cache_clone,
        legacy_cache_clear,
        legacy_cache_free
      }
    },
    {
      "tsk_img_read_lru",
      CacheFuncs{
        tsk_img_read_lru,
        lru_cache_create,
        lru_cache_clone,
        lru_cache_clear,
        lru_cache_free
      }
    },
    {
      "tsk_img_read_lru_finer_lock",
      CacheFuncs{
        tsk_img_read_lru_finer_lock,
        lru_cache_create,
        lru_cache_clone,
        lru_cache_clear,
        lru_cache_free
      }
    },
    {
      "tsk_img_read_lru_tsk_lock",
      CacheFuncs{
        tsk_img_read_lru,
        [](TSK_IMG_INFO*) { return static_cast<void*>(new LRUImgCacheLockingTsk(1024)); },
        lru_cache_clone,
        lru_cache_clear,
        lru_cache_free
      }
    },
    {
      "tsk_img_read_lru_tsk_finer_lock",
      CacheFuncs{
        tsk_img_read_lru_finer_lock,
        [](TSK_IMG_INFO*) { return static_cast<void*>(new LRUImgCacheLockingTsk(1024)); },
        lru_cache_clone,
        lru_cache_clear,
        lru_cache_free
      }
    }
  };

  std::vector<std::vector<const TSK_TCHAR*>> images{
//     { _TSK_T("../fsrip/testdata/img/TinyOSX.E01") },
     { _TSK_T("/home/juckelman/Downloads/win7-64-nfury-c-drive.E01") }
  };

  std::cout << "name sharing threads h m \"h bytes\" \"m bytes\" \"h ns\" \"m ns\"\n";

  for (const auto& imgs: images) {
    for (const auto threads: { 1, 10 }) {
      for (const auto& [fname, cfuncs]: caches) {
        test_caching_shared_img(fname, cfuncs, imgs, threads);
        test_caching_own_img(fname, cfuncs, imgs, threads);
        test_caching_own_img_shared_cache(fname, cfuncs, imgs, threads);
      }
    }
  }
}
