#include "lru_cache.h"
#include "tsk_img_i.h"

LRUBlockCache::LRUBlockCache(size_t cache_size, size_t chunk_size):
  cache(cache_size),
  ch_size(chunk_size)
{}

const char* LRUBlockCache::get(uint64_t key) {
  const auto v = cache.get(key);
  return v ? v->data() : nullptr;
}

void LRUBlockCache::put(uint64_t key, const char* val) {
  cache.put(key, std::vector<char>(val, val + ch_size));
}

size_t LRUBlockCache::cache_size() const {
  return cache.size();
}

size_t LRUBlockCache::chunk_size() const {
  return ch_size;
}

void LRUBlockCache::clear() {
  cache.clear();
}

LRUBlockCacheLocking::LRUBlockCacheLocking(
  size_t cache_size,
  size_t chunk_size):
  LRUBlockCache(cache_size, chunk_size)
{}

void LRUBlockCacheLocking::lock() {
  mutex.lock();
}

void LRUBlockCacheLocking::unlock() {
  mutex.unlock();
}

const char* LRUBlockCacheLocking::get(uint64_t key) {
  std::scoped_lock lock{*this};
  return LRUBlockCache::get(key);
}

void LRUBlockCacheLocking::put(uint64_t key, const char* val) {
  std::scoped_lock lock{*this};
  LRUBlockCache::put(key, val);
}

void LRUBlockCacheLocking::clear() {
  std::scoped_lock lock{*this};
  LRUBlockCache::clear();
}
