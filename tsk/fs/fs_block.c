/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2008-2011 Brian Carrier, Basis Technology.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file fs_block.c
 * Contains functions to allocate, free, and read data into a TSK_FS_BLOCK structure. 
 */

#include <errno.h>
#include "tsk_fs_i.h"

/**
 * \internal
 * Allocate a TSK_FS_BLOCK structure.  
 * @param a_fs File system to create block for
 * @returns NULL on error
 */
TSK_FS_BLOCK *
tsk_fs_block_alloc(TSK_FS_INFO * a_fs)
{
    TSK_FS_BLOCK *fs_block;

    fs_block = (TSK_FS_BLOCK *) tsk_malloc(sizeof(TSK_FS_BLOCK));
    if (fs_block == NULL)
        return NULL;

    fs_block->buf = (char *) tsk_malloc(a_fs->block_size);
    if (fs_block->buf == NULL) {
        free(fs_block);
        return NULL;
    }
    fs_block->tag = TSK_FS_BLOCK_TAG;
    fs_block->addr = 0;
    fs_block->flags = 0;
    fs_block->fs_info = a_fs;

    return fs_block;
}

/**
 * \ingroup fslib
 * Free the memory associated with the TSK_FS_BLOCK structure. 
 * @param a_fs_block Block to free
 */
void
tsk_fs_block_free(TSK_FS_BLOCK * a_fs_block)
{
    if (a_fs_block->buf)
        free(a_fs_block->buf);
    a_fs_block->tag = 0;
    free(a_fs_block);
}



TSK_FS_BLOCK *
tsk_fs_block_get(TSK_FS_INFO * a_fs, TSK_FS_BLOCK * a_fs_block,
    TSK_DADDR_T a_addr)
{
    return tsk_fs_block_get_flag(a_fs, a_fs_block, a_addr,
        a_fs->block_getflags(a_fs, a_addr));
}

/**
 * \ingroup fslib
 * Get the contents and flags of a specific file system block. Note that if the block contains
 * compressed data, then this function will return the compressed data with the RAW flag set. 
 * The uncompressed data can be obtained only from the file-level functions.
 *
 * @param a_fs The file system to read the block from.
 * @param a_fs_block The structure to write the block data into or NULL to have one created.
 * @param a_addr The file system address to read.
 * @param a_flags Flag to assign to the returned TSK_FS_BLOCK (use if you already have it as part of a block_walk-type scenario)
 * @return The TSK_FS_BLOCK with the data or NULL on error.  (If a_fs_block was not NULL, this will
 * be the same structure). 
 */
TSK_FS_BLOCK *
tsk_fs_block_get_flag(TSK_FS_INFO * a_fs, TSK_FS_BLOCK * a_fs_block,
    TSK_DADDR_T a_addr, TSK_FS_BLOCK_FLAG_ENUM a_flags)
{
    TSK_OFF_T offs;
    ssize_t cnt;
    size_t len;

    if (a_fs == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tsk_fs_block_get: fs unallocated");
        return NULL;
    }
    if (a_fs_block == NULL) {
        a_fs_block = tsk_fs_block_alloc(a_fs);
    }
    else if ((a_fs_block->tag != TSK_FS_BLOCK_TAG)
        || (a_fs_block->buf == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tsk_fs_block_get: fs_block unallocated");
        return NULL;
    }

    len = a_fs->block_size;

    if (a_addr > a_fs->last_block_act) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        if (a_addr <= a_fs->last_block)
            tsk_error_set_errstr
                ("tsk_fs_block_get: Address missing in partial image: %"
                PRIuDADDR ")", a_addr);
        else
            tsk_error_set_errstr
                ("tsk_fs_block_get: Address is too large for image: %"
                PRIuDADDR ")", a_addr);
        return NULL;
    }

    a_fs_block->fs_info = a_fs;
    a_fs_block->addr = a_addr;
    a_fs_block->flags = a_flags;
    a_fs_block->flags |= TSK_FS_BLOCK_FLAG_RAW;
    offs = (TSK_OFF_T) a_addr *a_fs->block_size;

    if ((a_fs_block->flags & TSK_FS_BLOCK_FLAG_AONLY) == 0) {
        cnt =
            tsk_img_read(a_fs->img_info, a_fs->offset + offs,
            a_fs_block->buf, len);
        if (cnt != len) {
            return NULL;
        }
    }
    return a_fs_block;
}



/**
 * \internal
 * Set the fields of a FS_BLOCk structure.  This is internally used to set the data from a 
 * larger buffer so that larger disk reads can occur. 
 *
 * @param a_fs File system
 * @param a_fs_block Block to load data into
 * @param a_addr Address where data is from
 * @param a_flags Flags for data
 * @param a_buf Buffer to copy data from  and into a_fs_block (block_size will be copied)
 * @returns 1 on error, 0 on success
 */
int
tsk_fs_block_set(TSK_FS_INFO * a_fs, TSK_FS_BLOCK * a_fs_block,
    TSK_DADDR_T a_addr, TSK_FS_BLOCK_FLAG_ENUM a_flags, char *a_buf)
{
    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tsk_fs_block_set: fs_info unallocated");
        return 1;
    }
    if ((a_fs_block->tag != TSK_FS_BLOCK_TAG) || (a_fs_block->buf == NULL)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tsk_fs_block_set: fs_block unallocated");
        return 1;
    }
    a_fs_block->fs_info = a_fs;
    if ((a_flags & TSK_FS_BLOCK_FLAG_AONLY) == 0)
        memcpy(a_fs_block->buf, a_buf, a_fs->block_size);
    a_fs_block->addr = a_addr;
    a_fs_block->flags = a_flags;
    return 0;
}


/** 
 * \ingroup fslib
 *
 * Cycle through a range of file system blocks and call the callback function
 * with the contents and allocation status of each. 
 *
 * @param a_fs File system to analyze
 * @param a_start_blk Block address to start walking from
 * @param a_end_blk Block address to walk to
 * @param a_flags Flags used during walk to determine which blocks to call callback with
 * @param a_action Callback function
 * @param a_ptr Pointer that will be passed to callback
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_block_walk(TSK_FS_INFO * a_fs,
    TSK_DADDR_T a_start_blk, TSK_DADDR_T a_end_blk,
    TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags, TSK_FS_BLOCK_WALK_CB a_action,
    void *a_ptr)
{
    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("tsk_fs_block_walk: FS_INFO structure is not allocated");
        return 1;
    }
    return a_fs->block_walk(a_fs, a_start_blk, a_end_blk, a_flags,
        a_action, a_ptr);
}
