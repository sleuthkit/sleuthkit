#include "lru_cache.h"
#include "tsk_img_i.h"

LRUBlockCache::LRUBlockCache(size_t cache_size): cache(cache_size) {}

const char* LRUBlockCache::get(uint64_t key) {
  return cache.get(key)->data();
}

void LRUBlockCache::put(uint64_t key, const char* val) {
  std::array<char, CHUNK_SIZE> v;
  std::copy(val, val + CHUNK_SIZE, std::begin(v));
  cache.put(key, v);
}

size_t LRUBlockCache::cache_size() const {
  return cache.size();
}

size_t LRUBlockCache::chunk_size() const {
  return CHUNK_SIZE;
}

void LRUBlockCache::clear() {
  cache.clear();
}

LRUBlockCacheLocking::LRUBlockCacheLocking(size_t cache_size):
  LRUBlockCache(cache_size)
{}

void LRUBlockCacheLocking::lock() {
  mutex.lock();
}

void LRUBlockCacheLocking::unlock() {
  mutex.unlock();
}

LRUBlockCacheLockingTsk::LRUBlockCacheLockingTsk(size_t cache_size):
  LRUBlockCache(cache_size)
{
  tsk_init_lock(&l);
}

LRUBlockCacheLockingTsk::~LRUBlockCacheLockingTsk() {
  tsk_deinit_lock(&l);
}

void LRUBlockCacheLockingTsk::lock() {
  tsk_take_lock(&l);
}

void LRUBlockCacheLockingTsk::unlock() {
  tsk_release_lock(&l);
}

using Cache = LRUBlockCacheLocking;

void* lru_cache_create(int cache_size) {
  return new Cache(cache_size == -1 ? 1024 : cache_size);
}

void* lru_cache_clone(const void* data) {
  return new Cache(reinterpret_cast<const Cache*>(data)->cache_size());
}

void lru_cache_clear(void* data) {
  auto cache = static_cast<Cache*>(data);
  std::scoped_lock lock{*cache};
  cache->clear();
}

void lru_cache_free(void* data) {
  delete static_cast<Cache*>(data);
}

const char* lru_cache_get(void* data, TSK_OFF_T off) {
  auto cache = static_cast<Cache*>(data);
  std::scoped_lock lock{*cache};
  return cache->get(off);
}

void lru_cache_put(void* data, TSK_OFF_T off, const char* buf) {
  auto cache = static_cast<Cache*>(data);
  std::scoped_lock lock{*cache};
  cache->put(off, buf);
}

size_t lru_cache_chunk_size(const void* data) {
  return static_cast<const Cache*>(data)->chunk_size();
}
