/*
 * Copyright (c) 2017 Communication Security Establishment.  All rights reserved
 *
 * qcow2
 *
 * This software is distributed under the Common Public License 1.0
 */

/*
 * Header for QCOW2 data structures and functions.
 */

#ifndef _TSK_IMG_QCOW2_H
#define _TSK_IMG_QCOW2_H

#include "img_writer.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef TSK_WIN32
    typedef HANDLE  QCOW_FILE_T;
#else
    typedef int     QCOW_FILE_T;
#endif

    extern TSK_IMG_INFO *qcow2_open(int a_num_img,
        const TSK_TCHAR * const a_images[], unsigned int a_ssize);
    
    typedef struct {
        union {
            struct {
                uint64_t l2_offset : 56;
                uint64_t reserved : 7;              /* Set to zero */
                uint64_t in_use : 1;                /* Refcount is 1 */
            };
            uint64_t entry;
        };
    } QCOW_2_L1_entry;

    typedef struct {
        union {
            struct {
                uint64_t offset : 56;               /* Has special meaning if compressed */
                uint64_t reserved : 6;              /* Set to zero */
                uint64_t compressed : 1;            /* L2 entry is compressed */
                uint64_t in_use : 1;                /* Refcount is 1 */
            };
            uint64_t entry;
            struct {
                uint64_t compressed_entry : 62;     /* Need a macro to use this */
                uint64_t pad : 2;
            };
        };
    } QCOW_2_L2_entry;

    typedef struct _IMG_QCOW2_INFO {
        TSK_IMG_INFO img_info;

        struct {
            uint32_t magic;                         /* Must be "QFI\xfb" */
            uint32_t version;                       /* Must be 1 or 2 */

            uint64_t backing_file_offset;           /* Absolute offset */
            uint32_t backing_file_size;             /* In bytes, not including NULL byte */
                                                    /* Backing file seems to be UTF8, relative path */

            uint32_t cluster_bits;                  /* Power of two */
            uint64_t size;                          /* In bytes */
            uint32_t crypt_method;

            uint32_t l1_size;                       /* Entry cardinality */
            uint64_t l1_table_offset;               /* Absolute offset */

            uint64_t refcount_table_offset;
            uint32_t refcount_table_clusters;

            uint32_t nb_snapshots;
            uint64_t snapshots_offset;
        } header;

        struct {
            UTF8 * image_path;                      /* Allocated */
            UTF8 * image_name;                      /* Ptr to name part of file */
            UTF8 * backing_path;                    /* Allocated */
            UTF8 * backing_name;                    /* Ptr to name part of file */
            QCOW_2_L1_entry * l1_cache;
            struct _IMG_QCOW2_INFO *backing_meta;
            QCOW_FILE_T handle;
            uint64_t cluster_bytes;
            void * comp_buffer;                     /* Allocated IFF there's a compressed cluster */
            void * ucmp_buffer;                     /* Allocated IFF there's a compressed cluster */
        } meta;

    } IMG_QCOW2_INFO;

#ifdef __cplusplus
}
#endif
#endif

