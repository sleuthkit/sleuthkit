#include "tsk_img_i.h"

void tsk_init_cache_lock(TSK_IMG_INFO* img_info) {
  tsk_init_lock(&(img_info->cache_lock));
}

void tsk_deinit_cache_lock(TSK_IMG_INFO* img_info) {
  tsk_deinit_lock(&(img_info->cache_lock));
}

void tsk_take_cache_lock(TSK_IMG_INFO* img_info) {
  tsk_take_lock(&(img_info->cache_lock));
}

void tsk_release_cache_lock(TSK_IMG_INFO* img_info) {
  tsk_release_lock(&(img_info->cache_lock));
}
