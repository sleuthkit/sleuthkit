/*
** blkstat
** The Sleuth Kit 
**
** Get the details about a data unit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file dstat_lib.c
 * Contains the library API functions used by the TSK blkstat command
 * line tool.
 */

#include "tsk_fs_i.h"

#include "tsk_ffs.h"
#include "tsk_ext2fs.h"
#include "tsk_fatfs.h"


static TSK_WALK_RET_ENUM
blkstat_act(const TSK_FS_BLOCK * fs_block, void *ptr)
{
    tsk_printf("%s: %" PRIuDADDR "\n", fs_block->fs_info->duname,
        fs_block->addr);
    tsk_printf("%sAllocated%s\n",
        (fs_block->flags & TSK_FS_BLOCK_FLAG_ALLOC) ? "" : "Not ",
        (fs_block->flags & TSK_FS_BLOCK_FLAG_META) ? " (Meta)" : "");

    if (TSK_FS_TYPE_ISFFS(fs_block->fs_info->ftype)) {
        FFS_INFO *ffs = (FFS_INFO *) fs_block->fs_info;
        tsk_printf("Group: %" PRI_FFSGRP "\n", ffs->grp_num);
    }
    else if (TSK_FS_TYPE_ISEXT(fs_block->fs_info->ftype)) {
        EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) fs_block->fs_info;
        if (fs_block->addr >= ext2fs->first_data_block)
            tsk_printf("Group: %" PRI_EXT2GRP "\n", ext2fs->grp_num);
    }
    else if (TSK_FS_TYPE_ISFAT(fs_block->fs_info->ftype)) {
        FATFS_INFO *fatfs = (FATFS_INFO *) fs_block->fs_info;
        /* Does this have a cluster address? */
        if (fs_block->addr >= fatfs->firstclustsect) {
            tsk_printf("Cluster: %" PRIuDADDR "\n",
                (2 + (fs_block->addr -
                        fatfs->firstclustsect) / fatfs->csize));
        }
    }

    return TSK_WALK_STOP;
}


uint8_t
tsk_fs_blkstat(TSK_FS_INFO * fs, TSK_DADDR_T addr)
{
    int flags =
        (TSK_FS_BLOCK_WALK_FLAG_UNALLOC | TSK_FS_BLOCK_WALK_FLAG_ALLOC |
        TSK_FS_BLOCK_WALK_FLAG_META | TSK_FS_BLOCK_WALK_FLAG_CONT |
        TSK_FS_BLOCK_WALK_FLAG_AONLY);
    return tsk_fs_block_walk(fs, addr, addr, flags, blkstat_act, NULL);
}
