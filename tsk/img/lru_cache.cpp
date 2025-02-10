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
