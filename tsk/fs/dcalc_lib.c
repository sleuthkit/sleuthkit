/*
** blkcalc
** The Sleuth Kit 
**
** Calculates the corresponding block number between 'blkls' and 'dd' images
** when given an 'blkls' block number, it determines the block number it
** had in a 'dd' image.  When given a 'dd' image, it determines the
** value it would have in a 'blkls' image (if the block is unallocated)
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier. All Rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc. All Rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file dcalc_lib.c
 * Contains the library API functions used by the TSK blkcalc command
 * line tool.
 */

#include "tsk_fs_i.h"


/** \internal 
 * Structure to store data for callbacks.
*/
typedef struct {
    TSK_DADDR_T count;
    TSK_DADDR_T uncnt;
    uint8_t found;
    TSK_OFF_T flen;
} BLKCALC_DATA;



/* function used when -d is given
**
** keeps a count of unallocated blocks seen thus far
**
** If the specified block is allocated, an error is given, else the
** count of unalloc blocks is given 
**
** This is called for all blocks (alloc and unalloc)
*/
static TSK_WALK_RET_ENUM
count_dd_act(const TSK_FS_BLOCK * fs_block, void *ptr)
{
    BLKCALC_DATA *data = (BLKCALC_DATA *) ptr;

    if (fs_block->flags & TSK_FS_BLOCK_FLAG_UNALLOC)
        data->uncnt++;

    if (data->count-- == 0) {
        if (fs_block->flags & TSK_FS_BLOCK_FLAG_UNALLOC)
            tsk_printf("%" PRIuDADDR "\n", data->uncnt);
        else
            printf
                ("ERROR: unit is allocated, it will not be in an blkls image\n");

        data->found = 1;
        return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}

/*
** count how many unalloc blocks there are.
**
** This is called for unalloc blocks only
*/
static TSK_WALK_RET_ENUM
count_blkls_act(const TSK_FS_BLOCK * fs_block, void *ptr)
{
    BLKCALC_DATA *data = (BLKCALC_DATA *) ptr;

    if (data->count-- == 0) {
        tsk_printf("%" PRIuDADDR "\n", fs_block->addr);
        data->found = 1;
        return TSK_WALK_STOP;
    }
    return TSK_WALK_CONT;
}


/* SLACK SPACE  call backs */
static TSK_WALK_RET_ENUM
count_slack_file_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off,
    TSK_DADDR_T addr, char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags,
    void *ptr)
{
    BLKCALC_DATA *data = (BLKCALC_DATA *) ptr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "count_slack_file_act: Remaining File:  %" PRIuOFF
            "  Buffer: %" PRIuSIZE "\n", data->flen, size);

    /* This is not the last data unit */
    if (data->flen >= size) {
        data->flen -= size;
    }
    /* We have passed the end of the allocated space */
    else if (data->flen == 0) {
        if (data->count-- == 0) {
            tsk_printf("%" PRIuDADDR "\n", addr);
            data->found = 1;
            return TSK_WALK_STOP;

        }
    }
    /* This is the last data unit and there is unused space */
    else if (data->flen < size) {
        if (data->count-- == 0) {
            tsk_printf("%" PRIuDADDR "\n", addr);
            data->found = 1;
            return TSK_WALK_STOP;

        }
        data->flen = 0;
    }

    return TSK_WALK_CONT;
}

static TSK_WALK_RET_ENUM
count_slack_inode_act(TSK_FS_FILE * fs_file, void *ptr)
{
    BLKCALC_DATA *data = (BLKCALC_DATA *) ptr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "count_slack_inode_act: Processing meta data: %" PRIuINUM
            "\n", fs_file->meta->addr);

    /* We will now do a file walk on the content */
    if (TSK_FS_TYPE_ISNTFS(fs_file->fs_info->ftype) == 0) {
        data->flen = fs_file->meta->size;
        if (tsk_fs_file_walk(fs_file,
                TSK_FS_FILE_WALK_FLAG_SLACK, count_slack_file_act, ptr)) {

            /* ignore any errors */
            if (tsk_verbose)
                tsk_fprintf(stderr, "Error walking file %" PRIuINUM,
                    fs_file->meta->addr);
            tsk_error_reset();
        }
    }

    /* For NTFS we go through each non-resident attribute */
    else {
        int i, cnt;

        cnt = tsk_fs_file_attr_getsize(fs_file);
        for (i = 0; i < cnt; i++) {
            const TSK_FS_ATTR *fs_attr =
                tsk_fs_file_attr_get_idx(fs_file, i);
            if (!fs_attr)
                continue;

            if (fs_attr->flags & TSK_FS_ATTR_NONRES) {
                data->flen = fs_attr->size;
                if (tsk_fs_file_walk_type(fs_file, fs_attr->type,
                        fs_attr->id, TSK_FS_FILE_WALK_FLAG_SLACK,
                        count_slack_file_act, ptr)) {
                    /* ignore any errors */
                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "Error walking file %" PRIuINUM,
                            fs_file->meta->addr);
                    tsk_error_reset();
                }
            }
        }
    }
    return TSK_WALK_CONT;
}




/* Return 1 if block is not found, 0 if it was found, and -1 on error */
int8_t
tsk_fs_blkcalc(TSK_FS_INFO * fs, TSK_FS_BLKCALC_FLAG_ENUM a_lclflags,
    TSK_DADDR_T a_cnt)
{
    BLKCALC_DATA data;

    data.count = a_cnt;
    data.found = 0;

    if (a_lclflags == TSK_FS_BLKCALC_BLKLS) {
        if (tsk_fs_block_walk(fs, fs->first_block, fs->last_block,
                (TSK_FS_BLOCK_WALK_FLAG_UNALLOC |
                    TSK_FS_BLOCK_WALK_FLAG_META |
                    TSK_FS_BLOCK_WALK_FLAG_CONT |
                    TSK_FS_BLOCK_WALK_FLAG_AONLY), count_blkls_act, &data))
            return -1;
    }
    else if (a_lclflags == TSK_FS_BLKCALC_DD) {
        if (tsk_fs_block_walk(fs, fs->first_block, fs->last_block,
                (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
                    TSK_FS_BLOCK_WALK_FLAG_UNALLOC |
                    TSK_FS_BLOCK_WALK_FLAG_META |
                    TSK_FS_BLOCK_WALK_FLAG_CONT |
                    TSK_FS_BLOCK_WALK_FLAG_AONLY), count_dd_act, &data))
            return -1;
    }
    else if (a_lclflags == TSK_FS_BLKCALC_SLACK) {
        if (fs->inode_walk(fs, fs->first_inum, fs->last_inum,
                TSK_FS_META_FLAG_ALLOC, count_slack_inode_act, &data))
            return -1;
    }

    if (data.found == 0) {
        tsk_printf("Block too large\n");
        return 1;
    }
    else {
        return 0;
    }
}
