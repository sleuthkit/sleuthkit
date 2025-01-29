/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#ifndef _TSK_IMG_I_H
#define _TSK_IMG_I_H

/*
 * Contains the internal library definitions for the disk image functions.  This should
 * be included by the code in the img library.
 */

// include the base internal header file
#include "tsk/base/tsk_base_i.h"

// include the external disk image header file
#include "tsk_img.h"

// other standard includes
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cygwin needs this, but not everyone defines it
#ifndef O_BINARY
#define O_BINARY 0
#endif

struct IMG_INFO {
  TSK_IMG_INFO img_info;

  size_t cache_size;
  size_t cache_chunk_size;
  void* cache;
  Stats stats;

  ssize_t (*cache_read)(TSK_IMG_INFO* img, TSK_OFF_T off, char *buf, size_t len);

  const char* (*cache_get)(void* data, TSK_OFF_T off);
  void (*cache_put)(void* data, TSK_OFF_T off, const char* buf);

  void* (*cache_create)(TSK_IMG_INFO* img);
  void* (*cache_clone)(const TSK_IMG_INFO* img);
  void (*cache_free)(void* data);
  void (*cache_clear)(void* data);

  ssize_t (*read)(TSK_IMG_INFO* img, TSK_OFF_T off, char *buf, size_t len);
  void (*close)(TSK_IMG_INFO*);
  void (*imgstat)(TSK_IMG_INFO*, FILE*);
};

extern void *tsk_img_malloc(size_t);
extern void tsk_img_free(void *);

extern int tsk_img_copy_image_names(TSK_IMG_INFO* img_info, const TSK_TCHAR* const images[], int num);
extern void tsk_img_free_image_names(TSK_IMG_INFO* img_info);
extern TSK_TCHAR **tsk_img_findFiles(const TSK_TCHAR * a_startingName,
    int *a_numFound);

ssize_t tsk_img_read_no_cache(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len
);

ssize_t tsk_img_read_lru(
  TSK_IMG_INFO* a_img_info,
  TSK_OFF_T a_off,
  char* a_buf,
  size_t a_len
);

#ifdef __cplusplus
}
#endif

#endif
