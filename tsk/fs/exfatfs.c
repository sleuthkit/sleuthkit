/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file exfatfs.c
 * Contains the internal TSK exFAT file system code to handle basic file system
 * processing for opening file system, processing sectors, and directory entries. 
 */

#include "tsk_fs_i.h"
#include "tsk_exfatfs.h"

int
exfatfs_open(FATFS_INFO *fatfs, int using_backup_boot_sector)
{
    const char *func_name = "exfatfs_open";

    // RJCTODO

	return 0;
}
