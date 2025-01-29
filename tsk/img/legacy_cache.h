#ifndef _LEGACY_CACHE_H
#define _LEGACY_CACHE_H

#include "../base/tsk_base_i.h"

#define TSK_IMG_INFO_CACHE_NUM  32
#define TSK_IMG_INFO_CACHE_LEN  65536

struct LegacyCache {
  tsk_lock_t cache_lock;  ///< Lock for cache and associated values
  char cache[TSK_IMG_INFO_CACHE_NUM][TSK_IMG_INFO_CACHE_LEN];     ///< read cache (r/w shared - lock)
  TSK_OFF_T cache_off[TSK_IMG_INFO_CACHE_NUM];    ///< starting byte offset of corresponding cache entry (r/w shared - lock)
  int cache_age[TSK_IMG_INFO_CACHE_NUM];  ///< "Age" of corresponding cache entry, higher means more recently used (r/w shared - lock)
  size_t cache_len[TSK_IMG_INFO_CACHE_NUM];       ///< Length of cache entry used (0 if never used) (r/w shared - lock)

  LegacyCache();

  ~LegacyCache();

  void lock();

  void unlock();

  void clear();
};

#endif
