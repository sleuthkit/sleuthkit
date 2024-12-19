#include "legacy_cache.h"

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
