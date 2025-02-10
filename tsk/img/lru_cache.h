#ifndef _TSK_IMG_LRU_CACHE_H
#define _TSK_IMG_LRU_CACHE_H

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
      // found existing key, reset the value and move the item to the front
      items.splice(items.begin(), items, r.first->second);
    }

    items.front().second = val;
  }

  size_t size() const {
    return N;
  }

  void clear() {
    hash.clear();
    items.clear();
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

class LRUBlockCache {
public:
  LRUBlockCache(size_t cache_size);

  const char* get(uint64_t key);

  void put(uint64_t key, const char* val);

  size_t cache_size() const;

  size_t chunk_size() const;

  void clear();

private:
  LRUCache<uint64_t, std::array<char, CHUNK_SIZE>> cache;
};

class LRUBlockCacheLocking: public LRUBlockCache {
public:
  LRUBlockCacheLocking(size_t cache_size);

  void lock();

  void unlock();

  const char* get(uint64_t key);

  void put(uint64_t key, const char* val);

  void clear();

private:
  std::mutex mutex;
};

#endif
