#include "no_cache.h"
#include "tsk_img_i.h"

void* no_cache_create(TSK_IMG_INFO*) {
  return nullptr;
}

void* no_cache_clone(const void*) {
  return nullptr;
}

void no_cache_clear(void*) {}

void no_cache_free(void*) {}
