/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
** 
** This software is distributed under the Common Public License 1.0 
*/

/*
 * Contains the structures and function APIs for YAFFSFS file system support.
 */

#ifndef _TSK_YAFFSFS_H
#define _TSK_YAFFSFS_H

#include <map>
#include <utility>

#ifdef __cplusplus
extern "C" {
#endif

/*
** Constants
*/
#define YAFFSFS_MAXNAMLEN	255

#define YAFFS_DEFAULT_PAGE_SIZE     2048
#define YAFFS_DEFAULT_SPARE_SIZE    64

/* Don't scan more than YAFFS_MAX_SCAN_SIZE data when trying to detect a yaffs2 filesystem */
#define YAFFS_MAX_SCAN_SIZE (64 * 1024 * 1024 * 1024)

/*
** Yaffs Object Flags
*/
    typedef enum {
        NONE,
        YAFFS_HEADER,
        YAFFS_CHUNK,
        YAFFS_PAGES,
        YAFFS_SPARES,
        YAFFS_PAGES_AND_SPARES,
        UNKNOWN
    } YAFFS_OBJECT_FLAGS;

/*
** Yaffs2 Header Object
*/

#define YAFFS_HEADER_NAME_LENGTH   256
#define YAFFS_HEADER_ALIAS_LENGTH  160
    typedef struct yaffsObj_header {
        uint32_t obj_type;
        uint32_t parent_id;
        char name[YAFFS_HEADER_NAME_LENGTH];
        uint32_t file_mode;
        uint32_t user_id;
        uint32_t group_id;
        uint32_t atime;
        uint32_t mtime;
        uint32_t ctime;
        uint32_t file_size;
        uint32_t equivalent_id;
        char alias[YAFFS_HEADER_ALIAS_LENGTH];
        uint32_t rdev_mode;
        uint32_t win_ctime[2];
        uint32_t win_atime[2];
        uint32_t win_mtime[2];
        uint32_t inband_obj_id;
        uint32_t inband_is_shrink;
        uint32_t file_size_high;
        uint32_t reserved[1];
        int shadows_obj;
        uint32_t is_shrink;
    } YaffsHeader;

/*
** Spare object - this is subject to change...
*/

#define YAFFS_OBJECT_SPACE              0x40000
#define YAFFS_MAX_OBJECT_ID             (YAFFS_OBJECT_SPACE - 1)
#define YAFFS_LOWEST_SEQUENCE_NUMBER    0x00001000
#define YAFFS_HIGHEST_SEQUENCE_NUMBER   0xefffff00
#define YAFFS_SPARE_FLAGS_IS_HEADER     0x80000000
#define YAFFS_SPARE_PARENT_ID_MASK      0x0fffffff
#define YAFFS_SPARE_OBJECT_TYPE_SHIFT   28
#define YAFFS_SPARE_OBJECT_TYPE_MASK    0xf0000000


    typedef struct yaffsObj_spare {
        uint32_t seq_number;
        uint32_t object_id;
        uint32_t chunk_id;

        uint32_t has_extra_fields;
        uint32_t extra_object_type;
        uint32_t extra_parent_id;
    } YaffsSpare;

/*
** Holds the metadata for a single YAFFS2 chunk.
*/
    typedef enum {
        YAFFS_CHUNK_DEAD,       /* Either bad or unallocated */
        YAFFS_CHUNK_META,       /* Contains a header */
        YAFFS_CHUNK_DATA        /* Contains file data */
    } YaffsChunkType;

    typedef struct _YaffsChunk {
        YaffsChunkType type;
        YaffsSpare *spare;
        YaffsHeader *header;
    } YaffsChunk;

/* File system State Values */
#define YAFFSFS_STATE_VALID	0x0001  /* unmounted correctly */
#define YAFFSFS_STATE_ERROR	0x0002  /* errors detected */

/*
 * Special File Objects for the YAFFS2 File system
 */
#define YAFFS_OBJECT_ROOT 1
#define YAFFS_OBJECT_FIRST 1
#define YAFFS_OBJECT_LOSTNFOUND 2
#define YAFFS_OBJECT_UNLINKED 3
#define YAFFS_OBJECT_DELETED 4

#define YAFFS_OBJECT_ROOT_NAME           ""
#define YAFFS_OBJECT_LOSTNFOUND_NAME     "lost+found"
#define YAFFS_OBJECT_UNLINKED_NAME       "<unlinked>"
#define YAFFS_OBJECT_DELETED_NAME        "<deleted>"

/*
 * Yaffs File Types...
 */
#define YAFFS_TYPE_UNKNOWN 0
#define YAFFS_TYPE_FILE    1
#define YAFFS_TYPE_SOFTLINK 2
#define YAFFS_TYPE_DIRECTORY 3
#define YAFFS_TYPE_HARDLINK 4
#define YAFFS_TYPE_SPECIAL 5



    struct _YaffsCacheVersion;
    struct _YaffsCacheChunk;

    typedef struct _YaffsCacheObject {
        struct _YaffsCacheObject *yco_next;

        uint32_t yco_obj_id;

        struct _YaffsCacheVersion *yco_latest;
    } YaffsCacheObject;

#define YAFFS_OBJECT_ID_MASK         0x0003ffff
#define YAFFS_VERSION_NUM_SHIFT      18
#define YAFFS_VERSION_NUM_MASK       0x00003fff

    typedef struct _YaffsCacheVersion {
        struct _YaffsCacheVersion *ycv_prior;

        uint32_t ycv_version;
        uint32_t ycv_seq_number;

        struct _YaffsCacheChunk *ycv_header_chunk;
        struct _YaffsCacheChunk *ycv_first_chunk;
        struct _YaffsCacheChunk *ycv_last_chunk;
    } YaffsCacheVersion;

    typedef struct _YaffsCacheChunk {
        struct _YaffsCacheChunk *ycc_next;
        struct _YaffsCacheChunk *ycc_prev;

        TSK_OFF_T ycc_offset;
        uint32_t ycc_seq_number;
        uint32_t ycc_obj_id;
        uint32_t ycc_chunk_id;
        uint32_t ycc_parent_id;
        uint32_t ycc_n_bytes;
    } YaffsCacheChunk;

    typedef struct _YaffsCacheChunkGroup {
        YaffsCacheChunk *cache_chunks_head;
        YaffsCacheChunk *cache_chunks_tail;
    } YaffsCacheChunkGroup;

    /*
     * Structure of an yaffsfs file system handle.
     */
    typedef struct {
        TSK_FS_INFO fs_info;    /* super class */

        unsigned int page_size;
        unsigned int spare_size;
        unsigned int chunks_per_block;

        uint32_t max_obj_id;
        uint32_t max_version;

        // Offsets into the spare area
        unsigned int spare_seq_offset;
        unsigned int spare_obj_id_offset;
        unsigned int spare_chunk_id_offset;
        unsigned int spare_nbytes_offset;

        tsk_lock_t cache_lock;
        YaffsCacheObject *cache_objects;
         std::map < uint32_t, YaffsCacheChunkGroup > *chunkMap;

        // If the user specified that the image is YAFFS2, print out additional verbose error messages
        int autoDetect;
    } YAFFSFS_INFO;

#define YAFFS_FILE_CONTENT_LEN 0

#ifdef __cplusplus
}
#endif
#endif
