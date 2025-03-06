#include "legacy_cache.h"

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
