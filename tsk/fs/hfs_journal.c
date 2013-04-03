/*
 * The Sleuth Kit
 * 
 *  This software is distributed under the Common Public License 1.0
 */

/**
 * \file hfs_journal.c
 * Contains the internal TSK HFS+ journal code -- not included in code by default.
 */
#include "tsk_fs_i.h"
#include "tsk_hfs.h"

uint8_t
hfs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_fprintf(stderr, "jopen not implemented for HFS yet");

    return 0;
}

uint8_t
hfs_jentry_walk(TSK_FS_INFO * fs, int flags, TSK_FS_JENTRY_WALK_CB action,
    void *ptr)
{
    tsk_fprintf(stderr, "jentry_walk not implemented for HFS yet");

    return 0;
}

uint8_t
hfs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int flags, TSK_FS_JBLK_WALK_CB action, void *ptr)
{

    tsk_fprintf(stderr, "jblk_walk not implemented for HFS yet");

    return 0;
}
