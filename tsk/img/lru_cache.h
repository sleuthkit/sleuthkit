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
  LRUImgCache(size_t cache_size);

  virtual ~LRUImgCache() = default;

  virtual const char* get(uint64_t key) override;

  virtual void put(uint64_t key, const char* val) override;

  virtual size_t cache_size() const override;

  virtual size_t chunk_size() const override;

/*
  virtual const Stats& stats() const {
    return the_stats;
  }

  virtual Stats& stats() {
    return the_stats;
  }
*/

  virtual void clear() override;
};

class LRUImgCacheLocking: public LRUImgCache {
public:
  LRUImgCacheLocking(size_t cache_size);

  virtual ~LRUImgCacheLocking() = default;

  virtual void lock() override;

  virtual void unlock() override;

private:
  std::mutex mutex;
};

class LRUImgCacheLockingTsk: public LRUImgCache {
public:
  LRUImgCacheLockingTsk(size_t cache_size);

  virtual ~LRUImgCacheLockingTsk();

  virtual void lock() override;

  virtual void unlock() override;

private:
  tsk_lock_t l;
};

struct TSK_IMG_INFO;

void* lru_cache_create(TSK_IMG_INFO* img_info);

void* lru_cache_clone(const TSK_IMG_INFO* img_info);

void lru_cache_clear(TSK_IMG_INFO* img_info);

void lru_cache_free(TSK_IMG_INFO* img_info);

#endif
