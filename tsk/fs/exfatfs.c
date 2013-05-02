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

static int 
exfatfs_get_block_sizes(FATFS_INFO *fatfs, TSK_FS_INFO *fs, exfatfs_sb *fatsb)
{
    const char *func_name = "exfatfs_get_block_sizes";

    // Bytes per sector must be a base 2 logarithm, defining a range of sizes
    // with a min of 512 bytes and a max of 4096 bytes. 
    fatfs->ssize_sh = (uint16_t)fatsb->bytes_per_sector;
    if (fatfs->ssize_sh < 9 || fatfs->ssize_sh > 12)
    {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("sector size (%d) is not a multiple of device size (%d), do you have a disk image instead of a partition image?", fatfs->ssize, fs->dev_bsize);
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid sector size (%d)\n", func_name, fatfs->ssize);
        }
        return 0;
    }
    fatfs->ssize = (1 << fatfs->ssize_sh);

    // Sectors per cluster must be a base 2 logarithm. The max cluster size is 
    // 32 MiB, so the sum of the bytes per sector and sectors per cluster logs 
    // cannot exceed 25.
    if (fatfs->ssize_sh + fatsb->sectors_per_cluster > 25) {
        return 0;
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid cluster size (%d)\n", func_name, fatfs->csize);
        }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a FATFS file system (cluster size)");
    }
    fatfs->csize = (1 << fatsb->sectors_per_cluster);

    return 1;
}

static int 
exfatfs_get_num_fats(FATFS_INFO *fatfs, TSK_FS_INFO *fs, exfatfs_sb *fatsb)
{
    const char *func_name = "exfatfs_get_num_fats";

    // There will be one FAT for exFAT and two FATs for TexFAT.
    fatfs->numfat = fatsb->num_fats;
    if ((fatfs->numfat != 1) && (fatfs->numfat != 2)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: Invalid number of FATS (%d)\n", func_name, fatfs->numfat);
        }
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a FATFS file system (number of FATs)");
        return 0;
        }

    return 1;
}

int
exfatfs_open(FATFS_INFO *fatfs)
{
    const char *func_name = "exfatfs_open";
	TSK_FS_INFO *fs = &(fatfs->fs_info);
	exfatfs_sb *fatsb = (exfatfs_sb*)(&fatfs->boot_sector_buffer);

    tsk_error_reset();

    if (!exfatfs_get_block_sizes(fatfs, fs, fatsb)) {
        return 0;
    }

    if (!exfatfs_get_num_fats(fatfs, fs, fatsb)) {
        return 0;
    }

	return 1;
}
