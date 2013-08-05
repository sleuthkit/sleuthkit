/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "tsk_fs_i.h"

/**
 *\file swapfs.c
 * Contains the internal "swapfs" specific functions. The "swap" file system is used to process 
 * an arbitrary chunk of data as 4096-byte pages that have no other structure.
 * This means that you can use the data-level tools, but that is it.  This is similar to
 * the rawfs code, but a different block size. This is primarily intended for Unix systems
 * that have a swap space partition.  Much of the code for swap and rawfs are similar and therefore
 * share tsk_fs_nofs_XXXX functions, such as tsk_fs_nofs_close()
 */


/** \internal
 * Open part of a disk image as "swap" space.  This assumes no structure exists. 
 * Data are organized into 4096-byte pages.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where swap space starts.
 * @returns NULL on error 
 */
TSK_FS_INFO *
swapfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset)
{
    TSK_OFF_T len;
    TSK_FS_INFO *fs;

    // clean up any error messages that are lying around
    tsk_error_reset();

    fs = (TSK_FS_INFO *) tsk_fs_malloc(sizeof(*fs));
    if (fs == NULL)
        return NULL;


    /* All we need to set are the block sizes and max bloc size etc. */
    fs->img_info = img_info;
    fs->offset = offset;
    fs->ftype = TSK_FS_TYPE_SWAP;
    fs->duname = "Page";
    fs->flags = 0;
    fs->tag = TSK_FS_INFO_TAG;

    fs->inum_count = 0;
    fs->root_inum = 0;
    fs->first_inum = 0;
    fs->last_inum = 0;

    len = img_info->size;
    fs->block_count = len / 4096;
    if (len % 4096)
        fs->block_count++;

    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->block_size = 4096;
    fs->dev_bsize = img_info->sector_size;

    /* Pointers to functions */
    fs->close = tsk_fs_nofs_close;
    fs->fsstat = tsk_fs_nofs_fsstat;

    fs->block_walk = tsk_fs_nofs_block_walk;
    fs->block_getflags = tsk_fs_nofs_block_getflags;

    fs->inode_walk = tsk_fs_nofs_inode_walk;
    fs->istat = tsk_fs_nofs_istat;
    fs->file_add_meta = tsk_fs_nofs_file_add_meta;

    fs->get_default_attr_type = tsk_fs_nofs_get_default_attr_type;
    fs->load_attrs = tsk_fs_nofs_make_data_run;

    fs->dir_open_meta = tsk_fs_nofs_dir_open_meta;
    fs->name_cmp = tsk_fs_nofs_name_cmp;

    fs->jblk_walk = tsk_fs_nofs_jblk_walk;
    fs->jentry_walk = tsk_fs_nofs_jentry_walk;
    fs->jopen = tsk_fs_nofs_jopen;
    fs->journ_inum = 0;

    return (fs);
}
