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
 * \file tsk_exfatfs.h
 * Contains the structures and function APIs for TSK exFATXX file system
 * support.
 */

#ifndef _TSK_EXFATFS_H
#define _TSK_EXFATFS_H

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Boot sector structure for exFAT file systems (TSK_FS_INFO_TYPE_EX_FAT).
     */
    typedef struct { //RJCTODO: Add doxygen comments to each member, make names better
        uint8_t jump_to_boot_code[3];
        uint8_t fs_name[8];
        uint8_t must_be_zeros[53];
		uint8_t partition_offset[8];
		uint8_t vol_len_in_sectors[8];            
		uint8_t fat_offset[4];          
		uint8_t fat_len[4];               
		uint8_t cluster_heap_offset[4];
		uint8_t cluster_cnt[4];
		uint8_t root_dir_cluster[4];
		uint8_t vol_serial_no[4];
		uint8_t fs_rev[2];
		uint8_t vol_flags[2];
		uint8_t bytes_per_sector;
		uint8_t sectors_per_cluster;
		uint8_t num_fats; /* 2 if TexFAT in use, otherwise 1 */
		uint8_t drive_select; /* Used by INT 13 */
		uint8_t percent_in_use;
		uint8_t reserved[7];
		uint8_t boot_code[390];
		uint8_t signature[2];
	} exfatfs_sb;

    /**
     * Allocation bitmap directory entry structure for exFAT file systems (TSK_FS_INFO_TYPE_EX_FAT).
     */
    typedef struct {
        uint8_t entry_type; /**< Directory entry type. */ 
        uint8_t flags; /**< Bit zero is 0 for the first bitmap, 1 for the second bitmap (if TexFAT). */
        uint8_t reserved[18]; /**< Reserved. */
        uint8_t first_cluster_addr[4]; /**< Cluster address of the allocation bitmap. */
        uint8_t length_in_buytes[8]; /**< Size of the allocation bitmap. */
    } ALLOC_BITMAP_DIR_ENTRY;

	/**
	 * \internal
	 * Open part of a disk image as an exFAT file system. 
	 *
	 * @param fatfs Generic FAT file system info with boot sector buffer
	 * @returns 1 on sucess, 0 otherwise
	 */
	extern int exfatfs_open(FATFS_INFO *fatfs);

    // RJCTODO: Add comment
    extern int8_t exfatfs_is_clust_alloc(FATFS_INFO * fatfs, TSK_DADDR_T clust);

#ifdef __cplusplus
}
#endif

#endif
