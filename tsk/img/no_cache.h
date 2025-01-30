#ifndef _NO_CACHE_H
#define _NO_CACHE_H

struct TSK_IMG_INFO;

void* no_cache_create(TSK_IMG_INFO* img_info);

void* no_cache_clone(const void* data);

void no_cache_clear(void* data);

void no_cache_free(void* data);

#endif
