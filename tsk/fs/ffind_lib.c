/*
** ffind  (file find)
** The Sleuth Kit 
**
** Find the file that uses the specified inode (including deleted files)
** 
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved 
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ffind_lib.c
 * Contains the library API functions used by the TSK ffind command
 * line tool.
 */
#include "tsk_fs_i.h"
#include "tsk_ntfs.h"           // NTFS has an optimized version of this function



/** \internal 
* Structure to store data for callbacks.
*/
typedef struct {
    TSK_INUM_T inode;
    uint8_t flags;
    uint8_t found;
} FFIND_DATA;


static TSK_WALK_RET_ENUM
find_file_act(TSK_FS_FILE * fs_file, const char *a_path, void *ptr)
{
    FFIND_DATA *data = (FFIND_DATA *) ptr;

    /* We found it! */
    if (fs_file->name->meta_addr == data->inode) {
        data->found = 1;
        if (fs_file->name->flags & TSK_FS_NAME_FLAG_UNALLOC)
            tsk_printf("* ");

        tsk_printf("/%s%s\n", a_path, fs_file->name->name);

        if (!(data->flags & TSK_FS_FFIND_ALL)) {
            return TSK_WALK_STOP;
        }
    }
    return TSK_WALK_CONT;
}


/* Return 0 on success and 1 on error */
uint8_t
tsk_fs_ffind(TSK_FS_INFO * fs, TSK_FS_FFIND_FLAG_ENUM lclflags,
    TSK_INUM_T a_inode,
    TSK_FS_ATTR_TYPE_ENUM type, uint8_t type_used,
    uint16_t id, uint8_t id_used, TSK_FS_DIR_WALK_FLAG_ENUM flags)
{
    FFIND_DATA data;

    data.found = 0;
    data.flags = lclflags;
    data.inode = a_inode;

    /* Since we start the walk on the root inode, then this will not show
     ** up in the above functions, so do it now
     */
    if (data.inode == fs->root_inum) {
        if (flags & TSK_FS_DIR_WALK_FLAG_ALLOC) {
            tsk_printf("/\n");
            data.found = 1;

            if (!(lclflags & TSK_FS_FFIND_ALL))
                return 0;
        }
    }

    if (TSK_FS_TYPE_ISNTFS(fs->ftype)) {
        if (ntfs_find_file(fs, data.inode, type, type_used, id, id_used,
                flags, find_file_act, &data))
            return 1;
    }
    else {
        if (tsk_fs_dir_walk(fs, fs->root_inum, flags, find_file_act,
                &data))
            return 1;
    }

    if (data.found == 0) {

        /* With FAT, we can at least give the name of the file and call
         * it orphan 
         */
        if (TSK_FS_TYPE_ISFAT(fs->ftype)) {
            TSK_FS_FILE *fs_file =
                tsk_fs_file_open_meta(fs, NULL, data.inode);
            if ((fs_file != NULL) && (fs_file->meta != NULL)
                && (fs_file->meta->name2 != NULL)) {
                if (fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC)
                    tsk_printf("* ");
                tsk_printf("%s/%s\n", TSK_FS_ORPHAN_STR,
                    fs_file->meta->name2->name);
            }
            if (fs_file)
                tsk_fs_file_close(fs_file);
        }
        else {
            tsk_printf("File name not found for inode\n");
        }
    }
    return 0;
}
