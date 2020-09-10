#pragma once

#include <stdint.h>

#include "tsk_fs.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * If a file is compressed, then it will have an extended attribute
 * with name com.apple.decmpfs.  The value of that attribute is a data
 * structure, arranged as shown in the following struct, possibly followed
 * by some actual compressed data.
 *
 * If compression_type = 3, then data follows this compression header, in-line.
 * If the first byte of that data is 0xF, then the data is not really compressed, so
 * the following bytes are the data.  Otherwise, the data following the compression
 * header is zlib-compressed.
 *
 * If the compression_type = 4, then compressed data is stored in the file's resource
 * fork, in a resource of type CMPF.  There will be a single resource in the fork, and
 * it will have this type.  The beginning of the resource is a table of offsets for
 * successive compression units within the resource.
 */

typedef struct {
    /* this structure represents the xattr on disk; the fields below are little-endian */
    uint8_t compression_magic[4];
    uint8_t compression_type[4];
    uint8_t uncompressed_size[8];
    unsigned char attr_bytes[0];        /* the bytes of the attribute after the header, if any. */
} DECMPFS_DISK_HEADER;

typedef enum {
  DECMPFS_TYPE_ZLIB_ATTR = 3,
  DECMPFS_TYPE_ZLIB_RSRC = 4,
  DECMPFS_TYPE_DATALESS = 5,
  DECMPFS_TYPE_LZVN_ATTR = 7,
  DECMPFS_TYPE_LZVN_RSRC = 8,
  DECMPFS_TYPE_RAW_ATTR = 9,
  DECMPFS_TYPE_RAW_RSRC = 10
} DECMPFS_TYPE_ENUM;

#define COMPRESSION_UNIT_SIZE 65536U

extern int zlib_inflate(char* source,
                        uint64_t sourceLen,
                        char* dest,
                        uint64_t destLen,
                        uint64_t* uncompressedLength,
                        unsigned long* bytesConsumed);

extern int decmpfs_file_read_zlib_attr(TSK_FS_FILE* fs_file,
                            char* buffer,
                            TSK_OFF_T attributeLength,
                            uint64_t uncSize);

extern int decmpfs_file_read_lzvn_attr(TSK_FS_FILE* fs_file,
                            char* buffer,
                            TSK_OFF_T attributeLength,
                            uint64_t uncSize);

extern uint8_t decmpfs_attr_walk_zlib_rsrc(const TSK_FS_ATTR * fs_attr,
                            int flags,
                            TSK_FS_FILE_WALK_CB a_action,
                            void *ptr);

extern uint8_t decmpfs_attr_walk_lzvn_rsrc(const TSK_FS_ATTR * fs_attr,
                            int flags,
                            TSK_FS_FILE_WALK_CB a_action,
                            void *ptr);

extern ssize_t decmpfs_file_read_zlib_rsrc(const TSK_FS_ATTR * a_fs_attr,
                            TSK_OFF_T a_offset,
                            char *a_buf,
                            size_t a_len);

extern ssize_t decmpfs_file_read_lzvn_rsrc(const TSK_FS_ATTR * a_fs_attr,
                            TSK_OFF_T a_offset,
                            char *a_buf,
                            size_t a_len);

#ifdef __cplusplus
}
#endif
