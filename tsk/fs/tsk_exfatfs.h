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
        char fs_name[8];
        uint8_t must_be_zeros[53];
		uint8_t partition_offset[8];
		uint8_t vol_len_in_sectors[8];            
		uint8_t fat_offset[4];          
		uint8_t fat_len[4];               
		uint8_t cluster_heap_offset[4];
		uint8_t cluster_cnt[4];
		uint8_t root_dir_cluster[4];
		char vol_serial_no[4];
		char fs_rev[2];
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
	 * \internal
	 * Open part of a disk image as an exFAT file system. 
	 *
	 * @param fatfs Generic FAT file system info with boot sector buffer
	 * @returns 1 on sucess, 0 otherwise
	 */
	extern int exfatfs_open(FATFS_INFO *fatfs);

#ifdef __cplusplus
}
#endif

#endif
