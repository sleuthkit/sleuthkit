#include "legacy_cache.h"
#include "tsk_img.h"

#include <cstring>

LegacyCache::LegacyCache():
  cache{},
  cache_off{},
  cache_age{},
  cache_len{}
{
  tsk_init_lock(&cache_lock);
}

LegacyCache::~LegacyCache() {
  tsk_deinit_lock(&cache_lock);
}

void LegacyCache::lock() {
  tsk_take_lock(&cache_lock);
}

void LegacyCache::unlock() {
  tsk_release_lock(&cache_lock);
}

void LegacyCache::clear() {
  // Setting the lengths to zero should invalidate the cache.
  std::memset(cache_len, 0, sizeof(cache_len));
}

void* legacy_cache_create(TSK_IMG_INFO*) {
    return new LegacyCache();
}

void* legacy_cache_clone(const TSK_IMG_INFO*) {
    return new LegacyCache();
}

void legacy_cache_clear(TSK_IMG_INFO* img_info) {
    auto cache = static_cast<LegacyCache*>(img_info->cache_holder);
    cache->lock();
    cache->clear();
    cache->unlock();
}

void legacy_cache_free(TSK_IMG_INFO* img_info) {
    delete static_cast<LegacyCache*>(img_info->cache_holder);
}
