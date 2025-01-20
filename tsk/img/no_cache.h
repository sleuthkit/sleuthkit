#ifndef _NO_CACHE_H
#define _NO_CACHE_H

#include "../base/tsk_base_i.h"

#include <mutex>

struct NoCache {
  NoCache();

  void lock();

  void unlock();

  std::mutex m;
  std::unique_lock<std::mutex> l;
};

struct TSK_IMG_INFO;

void* no_cache_create(TSK_IMG_INFO* img_info);

void* no_cache_clone(const TSK_IMG_INFO* img_info);

void no_cache_clear(TSK_IMG_INFO* img_info);

void no_cache_free(TSK_IMG_INFO* img_info);

#endif
