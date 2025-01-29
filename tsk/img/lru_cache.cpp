#include "lru_cache.h"
#include "tsk_img_i.h"

LRUImgCache::LRUImgCache(size_t cache_size): LRUCache(cache_size) {}

const char* LRUImgCache::get(uint64_t key) {
  return LRUCache::get(key)->data();
}

void LRUImgCache::put(uint64_t key, const char* val) {
  std::array<char, CHUNK_SIZE> v;
  std::copy(val, val + CHUNK_SIZE, std::begin(v));
  LRUCache::put(key, v);
}

size_t LRUImgCache::cache_size() const {
  return size();
}

size_t LRUImgCache::chunk_size() const {
  return CHUNK_SIZE;
}

void LRUImgCache::clear() {
  LRUCache::clear();
}

LRUImgCacheLocking::LRUImgCacheLocking(size_t cache_size):
  LRUImgCache(cache_size)
{}

void LRUImgCacheLocking::lock() {
  mutex.lock();
}

void LRUImgCacheLocking::unlock() {
  mutex.unlock();
}

LRUImgCacheLockingTsk::LRUImgCacheLockingTsk(size_t cache_size):
  LRUImgCache(cache_size)
{
  tsk_init_lock(&l);
}

LRUImgCacheLockingTsk::~LRUImgCacheLockingTsk() {
  tsk_deinit_lock(&l);
}

void LRUImgCacheLockingTsk::lock() {
  tsk_take_lock(&l);
}

void LRUImgCacheLockingTsk::unlock() {
  tsk_release_lock(&l);
}

void* lru_cache_create(TSK_IMG_INFO* img) {
  return new LRUImgCacheLocking(reinterpret_cast<IMG_INFO*>(img)->cache_size);
}

void* lru_cache_clone(const TSK_IMG_INFO* img) {
  return new LRUImgCacheLocking(reinterpret_cast<const IMG_INFO*>(img)->cache_size);
}

void lru_cache_clear(TSK_IMG_INFO* img_info) {
  auto cache = static_cast<Cache*>(reinterpret_cast<IMG_INFO*>(img_info)->cache);
  std::scoped_lock lock{*cache};
  cache->clear();
}

void lru_cache_free(TSK_IMG_INFO* img_info) {
  delete static_cast<Cache*>(reinterpret_cast<IMG_INFO*>(img_info)->cache);
}

const char* lru_cache_get(TSK_IMG_INFO* img_info, TSK_OFF_T off) {
  auto cache = static_cast<Cache*>(reinterpret_cast<IMG_INFO*>(img_info)->cache);
//  std::scoped_lock lock{*cache};
  return cache->get(off);
}

void lru_cache_put(TSK_IMG_INFO* img_info, TSK_OFF_T off, const char* buf) {
  auto cache = static_cast<Cache*>(reinterpret_cast<IMG_INFO*>(img_info)->cache);
//  std::scoped_lock lock{*cache};
  cache->put(off, buf);
}
