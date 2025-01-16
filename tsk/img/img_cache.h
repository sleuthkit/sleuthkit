#ifndef _TSK_IMG_IMG_CACHE_H
#define _TSK_IMG_IMG_CACHE_H

#include <cstddef>
#include <cstdint>

class Cache {
public:
  virtual ~Cache() = default;

  virtual const char* get(uint64_t key) = 0;

  virtual void put(uint64_t key, const char* val) = 0;

  virtual size_t chunk_size() const = 0;

  virtual size_t cache_size() const = 0;

  virtual void lock() = 0;

  virtual void unlock() = 0;
};

#endif
