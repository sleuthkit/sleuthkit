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
 * \file fatfs.c
 * Contains the internal TSK FAT file system code to handle basic file system 
 * processing for opening file system, processing sectors, and directory entries. 
 */

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include "tsk_fatxxfs.h"
#include "tsk_exfatfs.h"

typedef struct
{
    uint8_t data[FAT_BOOT_SECTOR_SIZE - 2];
    uint8_t magic[2];
} FAT_BOOT_SECTOR_RECORD;
// RJCTODO: Add packed directive

TSK_FS_INFO *
fatfs_open(TSK_IMG_INFO *a_img_info, TSK_OFF_T a_offset, TSK_FS_TYPE_ENUM a_ftype, uint8_t a_test)
{
    const char *func_name = "fatfs_open";
    FATFS_INFO *fatfs = NULL;
    TSK_FS_INFO *fs = NULL;
    TSK_OFF_T boot_sector_offset = 0;
	int find_boot_sector_attempt = 0;
    ssize_t bytes_read = 0;
    FAT_BOOT_SECTOR_RECORD *bootSector;
    int using_backup_boot_sector = 0;

    tsk_error_reset();

    if (TSK_FS_TYPE_ISFAT(a_ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Invalid FS Type", func_name);
        return NULL;
    }

	// RJCTODO: Add validation of other parameters?

	// Allocate an FATFS_INFO and initialize its generic TSK_FS_INFO members. 
    if ((fatfs = (FATFS_INFO*)tsk_fs_malloc(sizeof(FATFS_INFO))) == NULL) {
        return NULL;
	}
    fs = &(fatfs->fs_info);
    fs->ftype = a_ftype;
    fs->img_info = a_img_info;
    fs->offset = a_offset;
    fs->dev_bsize = a_img_info->sector_size;
    fs->tag = TSK_FS_INFO_TAG;

	// Look for a FAT boot sector. Try up to three times because FAT32 and exFAT file systems have backup boot sectors.
    for (find_boot_sector_attempt = 0; find_boot_sector_attempt < 3; ++find_boot_sector_attempt) {
        if (find_boot_sector_attempt == 1) {
			// The FATXX backup boot sector is located in sector 6, look there.
            boot_sector_offset = 6 * fs->img_info->sector_size; 
		}
        else if (find_boot_sector_attempt == 2) {
			// The exFAT backup boot sector is located in sector 12, look there.
            boot_sector_offset = 12 * fs->img_info->sector_size;
		}

        // Read in the prospective boot sector. 
        bytes_read = tsk_fs_read(fs, boot_sector_offset, fatfs->boot_sector_buffer, FAT_BOOT_SECTOR_SIZE);
        if (bytes_read != FAT_BOOT_SECTOR_SIZE) {
            if (bytes_read >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: boot sector", func_name); // RJCTODO: Is this a helpful error message?
			free(fatfs);
			return NULL;
        }

        // Check it out...
        bootSector = (FAT_BOOT_SECTOR_RECORD*)fatfs->boot_sector_buffer;
        if (tsk_fs_guessu16(fs, bootSector->magic, FATFS_FS_MAGIC) != 0) {
            // No magic, look for a backup boot sector. 
            if ((tsk_getu16(TSK_LIT_ENDIAN, bootSector->magic) == 0) && (find_boot_sector_attempt < 3)) {
                continue;
            }
            else {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_MAGIC);
                tsk_error_set_errstr("Not a FATFS file system (magic)");
                if (tsk_verbose) {
                    fprintf(stderr, "%s: Incorrect FATFS magic\n", func_name);
				}
				free(fatfs);
				return NULL;
            }
        }
        else {
            // Found the magic.
            using_backup_boot_sector = boot_sector_offset > 0;
            if (using_backup_boot_sector && tsk_verbose) {
				fprintf(stderr, "%s: Using backup boot sector\n", func_name);
            }
            break;
        }
    }

	// Attempt to open the file system as one of the FAT types.
	// RJCTODO: Should this return an error if not detecting and a specific type of FAT fs is specified?
	if ((a_ftype == TSK_FS_TYPE_FAT_DETECT && !fatxxfs_open(fatfs, using_backup_boot_sector) && !exfatfs_open(fatfs, using_backup_boot_sector)) ||
		(a_ftype == TSK_FS_TYPE_EXFAT && !exfatfs_open(fatfs, using_backup_boot_sector)) ||
		(!fatxxfs_open(fatfs, using_backup_boot_sector)))
	{
		free(fatfs);
		return NULL;
	}

	return (TSK_FS_INFO*)fatfs;
}