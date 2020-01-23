/** \@file Public C API */

#pragma once

#include <stdint.h>
#include "../base/tsk_base.h"
#include "../img/tsk_img.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct TSK_FS_ATTR_RUN TSK_FS_ATTR_RUN;

typedef enum {
  TSK_POOL_TYPE_DETECT = 0x0000,  ///< Use autodetection methods
  TSK_POOL_TYPE_APFS = 0x0001,    ///< APFS Pooled Volumes
  TSK_POOL_TYPE_UNSUPP = 0xffff,  ///< Unsupported pool container type
} TSK_POOL_TYPE_ENUM;

#define TSK_POOL_INFO_TAG 0x504F4C4C

typedef enum {
  TSK_POOL_VOLUME_FLAG_ENCRYPTED = 0x0001,
  TSK_POOL_VOLUME_FLAG_CASE_SENSITIVE = 0x0002,
} TSK_POOL_VOLUME_FLAGS;

#define TSK_POOL_VOL_INFO_TAG 0x50564F4C

typedef struct TSK_VS_PART_INFO TSK_VS_PART_INFO;
typedef struct TSK_IMG_INFO TSK_IMG_INFO;

typedef struct _TSK_POOL_VOLUME_INFO {
  uint32_t tag;  ///< Set to TSK_POOL_VOLUME_INFO_TAG when struct is alloc
  int index;     ///< Index of Volume
  char *desc;    ///< Description
  char *password_hint;                 ///< Password hint for encrypted volumes
  uint64_t block;                      ///< Starting Block number
  uint64_t num_blocks;                 ///< Number of blocks in the volume
  struct _TSK_POOL_VOLUME_INFO *next;  ///< Next Volume
  struct _TSK_POOL_VOLUME_INFO *prev;  ///< Previous Volume
  TSK_POOL_VOLUME_FLAGS flags;
} TSK_POOL_VOLUME_INFO;

typedef struct _TSK_POOL_INFO {
  uint32_t tag;              ///< Set to TSK_POOL_INFO_TAG when struct is alloc
  TSK_POOL_TYPE_ENUM ctype;  ///< Type of pool container
  uint32_t block_size;       ///< Block size
  uint64_t num_blocks;       ///< Number of blocks
  int num_vols;              ///< Number of volumes
  uint64_t img_offset;       ///< The image offset of the pool
  TSK_POOL_VOLUME_INFO *vol_list;  ///< Linked list of volume info structs

  // Callbacks
  void (*close)(const struct _TSK_POOL_INFO *);  ///< \internal
  uint8_t (*poolstat)(const struct _TSK_POOL_INFO *pool,
                      FILE *hFile);  ///< \internal
  TSK_IMG_INFO* (*get_img_info)(const struct _TSK_POOL_INFO *pool,
      TSK_DADDR_T pvol_block);  ///< \internal

  void *impl;  ///< \internal Implementation specific pointer

} TSK_POOL_INFO;

extern const TSK_POOL_INFO *tsk_pool_open_sing(const TSK_VS_PART_INFO *part,
                                               TSK_POOL_TYPE_ENUM type);

extern const TSK_POOL_INFO *tsk_pool_open(int num_vols,
                                          const TSK_VS_PART_INFO *const parts[],
                                          TSK_POOL_TYPE_ENUM type);

extern const TSK_POOL_INFO *tsk_pool_open_img_sing(TSK_IMG_INFO *img,
                                                   TSK_OFF_T offset,
                                                   TSK_POOL_TYPE_ENUM type);

extern const TSK_POOL_INFO *tsk_pool_open_img(int num_imgs,
                                              TSK_IMG_INFO *const imgs[],
                                              const TSK_OFF_T offsets[],
                                              TSK_POOL_TYPE_ENUM type);

extern void tsk_pool_close(const TSK_POOL_INFO *);

extern ssize_t tsk_pool_read(TSK_POOL_INFO *a_fs, TSK_OFF_T a_off, char *a_buf,
                             size_t a_len);

extern TSK_FS_ATTR_RUN *tsk_pool_unallocated_runs(const TSK_POOL_INFO *);

// Type functions
extern TSK_POOL_TYPE_ENUM tsk_pool_type_toid(const TSK_TCHAR *str);
extern TSK_POOL_TYPE_ENUM tsk_pool_type_toid_utf8(const char *str);
extern void tsk_pool_type_print(FILE *hFile);
extern const char *tsk_pool_type_toname(TSK_POOL_TYPE_ENUM ptype);

#ifdef __cplusplus
}  // extern "C"
#endif
