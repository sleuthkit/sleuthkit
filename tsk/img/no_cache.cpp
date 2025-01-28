#include "no_cache.h"
#include "tsk_img_i.h"

void* no_cache_create(TSK_IMG_INFO*) {
  return new NoCache();
}

void* no_cache_clone(const TSK_IMG_INFO*) {
  return new NoCache();
}

void no_cache_clear(TSK_IMG_INFO*) {}

void no_cache_free(TSK_IMG_INFO* img_info) {
  delete static_cast<NoCache*>(reinterpret_cast<IMG_INFO*>(img_info)->cache);
}
