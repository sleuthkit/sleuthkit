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

#include "tsk/img/lru_cache.h"
#include "tsk/img/tsk_img_i.h"

#include <cstring>
#include <future>
#include <iostream>
#include <memory>
#include <vector>

#ifdef READ_STATS

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

struct CacheSetup {
  size_t cache_size;
  ssize_t (*read)(TSK_IMG_INFO* img, TSK_OFF_T off, char *buf, size_t len);
  void* (*create)(int cache_size);
  void* (*clone)(const void* data);
  void (*free)(void* data);
  void (*clear)(void* data);
};

void set_cache_funcs(TSK_IMG_INFO* img, const CacheSetup& csetup) {
  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img);
  iif->cache_read = csetup.read;
  iif->cache_clone = csetup.clone;
  iif->cache_free = csetup.free;
  iif->cache_clear = csetup.clear;
}

void test_caching_shared_img(
  const char* fname,
  const CacheSetup& csetup,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  std::cout << fname << " sisc " << threads << ' ';

  auto img = open_img(images);

  IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());

  iif->cache_free(iif->cache);
  set_cache_funcs(img.get(), csetup);
  iif->cache = csetup.create(-1);

  const auto getimg = [&img]() { return img.get(); };

  const auto futures = run_tasks(
    threads,
    [getimg](){ do_walk(getimg()); }
  );

  for (auto& f: futures) {
    f.wait();
  }

  std::cout << iif->stats << std::endl;
}

void test_caching_own_img(
  const char* fname,
  const CacheSetup& csetup,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  std::cout << fname << " oioc " << threads << ' ';

  const auto getimg = [&]() {
    auto img = open_img(images);

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());
    iif->cache_free(iif->cache);
    set_cache_funcs(img.get(), csetup);
    iif->cache = csetup.create(-1);

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

  std::cout << stats << std::endl;
}

void test_caching_own_img_shared_cache(
  const char* fname,
  const CacheSetup& csetup,
  const std::vector<const TSK_TCHAR*>& images,
  size_t threads
)
{
  if (!std::strstr(fname, "lru")) {
    return;
  }

  std::cout << fname << " oisc " << threads << ' ';

  auto cache = csetup.create(-1);

  const auto getimg = [&]() {
    auto img = open_img(images);

    IMG_INFO* iif = reinterpret_cast<IMG_INFO*>(img.get());
    iif->cache_free(iif->cache);
    set_cache_funcs(img.get(), csetup);
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

  std::cout << stats << std::endl;
}

TEST_CASE("stats") {
  const std::tuple<
    const char*,
    CacheSetup
  > caches[] = {
/*
    {
      "tsk_img_read_no_cache",
      CacheSetup{
        0,
        tsk_img_read_no_cache,
        no_cache_create,
        no_cache_clone,
        no_cache_free,
        no_cache_clear
      }
    },
*/
    {
      "tsk_img_read_cache",
      CacheSetup{
        1024,
        tsk_img_read_cache,
        lru_cache_create,
        lru_cache_clone,
        lru_cache_free,
        lru_cache_clear,
      }
    },
    {
      "tsk_img_read_cache_tsk",
      CacheSetup{
        1024,
        tsk_img_read_cache,
        [](int) { return static_cast<void*>(new LRUBlockCacheLockingTsk(1024)); },
        lru_cache_clone,
        [](void* data) { delete static_cast<LRUBlockCacheLockingTsk*>(data); },
        lru_cache_clear
      }
    }
  };

  std::vector<std::vector<const TSK_TCHAR*>> images{
//     { _TSK_T("../fsrip/testdata/img/TinyOSX.E01") },
     { _TSK_T("/home/juckelman/Downloads/win7-64-nfury-c-drive.E01") }
  };

  std::cout << "name sharing threads h m \"h bytes\" \"m bytes\" \"h ns\" \"m ns\"" << std::endl;

  for (const auto& imgs: images) {
    for (const auto threads: { 1, 10 }) {
      for (const auto& [fname, csetup]: caches) {
        test_caching_shared_img(fname, csetup, imgs, threads);
        test_caching_own_img(fname, csetup, imgs, threads);
//        test_caching_own_img_shared_cache(fname, csetup, imgs, threads);
      }
    }
  }
}

#endif
