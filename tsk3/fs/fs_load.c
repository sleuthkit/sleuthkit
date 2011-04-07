/* 
 * The Sleuth Kit
 * 
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

/** \file fs_load.c
 * Contains a general file walk callback that can be
 * used to load file content into a buffer.
 */
#include "tsk_fs_i.h"


/* File Walk Action to load the journal 
 * TSK_FS_LOAD_FILE is defined in fs_tools.h
*/

TSK_WALK_RET_ENUM
tsk_fs_load_file_action(TSK_FS_FILE * fs_file, TSK_OFF_T a_off,
    TSK_DADDR_T addr, char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags,
    void *ptr)
{
    TSK_FS_LOAD_FILE *buf1 = (TSK_FS_LOAD_FILE *) ptr;
    size_t cp_size;

    if (size > buf1->left)
        cp_size = buf1->left;
    else
        cp_size = size;

    memcpy(buf1->cur, buf, cp_size);
    buf1->left -= cp_size;
    buf1->cur = (char *) ((uintptr_t) buf1->cur + cp_size);

    if (buf1->left > 0)
        return TSK_WALK_CONT;
    else
        return TSK_WALK_STOP;
}
