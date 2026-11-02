#ifndef _TSK_TFFS_NOR_H
#define _TSK_TFFS_NOR_H

#include "tsk_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TFFS_NOR_ENTRY_HEADER_SIZE 4
#define TFFS_NOR_ENTRY_ALIGNMENT 4
#define TFFS_NOR_DELETED_ID 0
#define TFFS_NOR_ERASED_VALUE 0xffff
#define TFFS_NOR_NAME_TABLE_ID 511

TSK_FS_INFO *tffs_nor_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset,
    TSK_FS_TYPE_ENUM a_ftype, const char *a_pass, uint8_t a_test);

/* NOR entry fields are stored as two big-endian 16-bit values: ID, then size. */
typedef struct {
    uint16_t file_id;
    uint16_t data_size;
} TFFS_NOR_ENTRY_HEADER;

#ifdef __cplusplus
}
#endif

#endif 