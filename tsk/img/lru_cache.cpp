#include "lru_cache.h"

void* lru_cache_create(TSK_IMG_INFO*) {
  return new LRUImgCacheLocking(1024);
}

void* lru_cache_clone(const TSK_IMG_INFO*) {
  return new LRUImgCacheLocking(1024);
}

void lru_cache_clear(TSK_IMG_INFO* img_info) {
  auto cache = static_cast<Cache*>(img_info->cache_holder);
  cache->clear();
}

void lru_cache_free(TSK_IMG_INFO* img_info) {
  delete static_cast<Cache*>(img_info->cache_holder);
}
