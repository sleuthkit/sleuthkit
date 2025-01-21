#ifndef _TSK_IMG_LRU_CACHE_H
#define _TSK_IMG_LRU_CACHE_H

#include "img_cache.h"
#include "tsk_img_i.h"

#include <array>
#include <cstring>
#include <list>
#include <mutex>
#include <unordered_map>
#include <utility>

template <class K,
          class V,
          class L = std::list<std::pair<K, V>>,
          class H = std::unordered_map<K, typename L::iterator>>
class LRUCache {
public:
  typedef K key_type;
  typedef V value_type;
  typedef H hash_type;
  typedef L list_type;

  LRUCache(size_t max):
    N(max)
  {}

  const value_type* get(const key_type& key) {
    auto i = hash.find(key);
    if (i != hash.end()) {
      // found existing key, make its item MRU
      items.splice(items.begin(), items, i->second);
      return &(i->second->second);
    }
    else {
      return nullptr;
    }
  }

  void put(const key_type& key, const value_type& val) {
    // try adding new key to hash
    auto r = hash.emplace(key, items.end());
    if (r.second) {
      // new key inserted
      if (items.size() < N) {
        // allocate a new item
        items.emplace_front(key, V());
      }
      else {
        // reuse LRU item
        items.splice(items.begin(), items, std::prev(items.end()));
        if (items.front().first != key) {
          // remove the key from the reused LRU item
          hash.erase(items.front().first);
        }
      }
      (r.first->second = items.begin())->first = key;
    }
    else {
      // found existing key, reset the value and put the item to the front
      items.splice(items.begin(), items, r.first->second);
    }

    items.front().second = val;
  }

  size_t size() const {
    return N;
  }

  void clear() {
    hash.clear();
  }

  typename std::list<std::pair<key_type, value_type>>::const_iterator begin() const {
    return items.cbegin();
  }

  typename std::list<std::pair<key_type, value_type>>::const_iterator end() const {
    return items.cend();
  }

private:
  const size_t N;

  list_type items;
  hash_type hash;
};

const size_t CHUNK_SIZE = 65536;

class LRUImgCache: public Cache, LRUCache<uint64_t, std::array<char, CHUNK_SIZE>> {
public:
  LRUImgCache(size_t cache_size): LRUCache(cache_size) {}

  virtual const char* get(uint64_t key) {
    return LRUCache::get(key)->data();
  }

  virtual void put(uint64_t key, const char* val) {
    std::array<char, CHUNK_SIZE> v;
    std::copy(val, val + CHUNK_SIZE, std::begin(v));
    LRUCache::put(key, v);
  }

  virtual size_t cache_size() const {
    return size();
  }

  virtual size_t chunk_size() const {
    return CHUNK_SIZE;
  }

/*
  virtual const Stats& stats() const {
    return the_stats;
  }

  virtual Stats& stats() {
    return the_stats;
  }
*/

  virtual void lock() {}

  virtual void unlock() {}

  virtual void clear() {
    LRUCache::clear();
  }
};

class LRUImgCacheLocking: public LRUImgCache {
public:
  LRUImgCacheLocking(size_t cache_size): 
    LRUImgCache(cache_size),
    l{m, std::defer_lock}
  {}

  virtual void lock() override {
    l.lock(); 
  }

  virtual void unlock() override {
    l.unlock();
  }

  virtual void clear() override {
    l.lock();
    LRUImgCache::clear();
    l.unlock(); 
  }

private:
  std::mutex m;
  std::unique_lock<std::mutex> l;
};

class LRUImgCacheLockingTsk: public LRUImgCache {
public:
  LRUImgCacheLockingTsk(size_t cache_size): 
    LRUImgCache(cache_size)
  {
    tsk_init_lock(&l);
  }

  ~LRUImgCacheLockingTsk() {
    tsk_deinit_lock(&l);
  }

  virtual void lock() override {
    tsk_take_lock(&l);
  }

  virtual void unlock() override {
    tsk_release_lock(&l);
  }

private:
  tsk_lock_t l;
};

struct TSK_IMG_INFO;

void* lru_cache_create(TSK_IMG_INFO* img_info);

void* lru_cache_clone(const TSK_IMG_INFO* img_info);

void lru_cache_clear(TSK_IMG_INFO* img_info);

void lru_cache_free(TSK_IMG_INFO* img_info);

#endif
