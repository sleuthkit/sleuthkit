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

/**
 * exFAT uses 32 byte directory entries.
 */
#define EXFAT_DIR_ENTRY_SIZE_IN_BYTES 32 

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * Boot sector structure for exFAT file systems (TSK_FS_INFO_TYPE_EX_FAT).
     * The boot sector will be at least 512 bytes in length. There will be one
     * FAT for exFAT and two FATs for TexFAT (transactional FAT).
     */
    typedef struct { 
        uint8_t jump_to_boot_code[3];
        uint8_t fs_name[8];
        uint8_t must_be_zeros[53];
		uint8_t partition_offset[8];
		uint8_t vol_len_in_sectors[8];            
		uint8_t fat_offset[4];          
		uint8_t fat_len_in_sectors[4];               
		uint8_t cluster_heap_offset[4];
		uint8_t cluster_cnt[4];
		uint8_t root_dir_cluster[4];
		uint8_t vol_serial_no[4];
		uint8_t fs_revision[2];
		uint8_t vol_flags[2];
		uint8_t bytes_per_sector;
		uint8_t sectors_per_cluster;
		uint8_t num_fats; 
		uint8_t drive_select;
		uint8_t percent_of_cluster_heap_in_use;
		uint8_t reserved[7];
		uint8_t boot_code[390];
		uint8_t signature[2];
	} EXFATFS_BOOT_SECTOR;

    /**
     * exFAT directory entry types, the first byte of a directory entry.
     */
    enum TSK_FS_EXFAT_DIR_ENTRY_TYPE_ENUM {
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_VOLUME_LABEL = 0x83,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_VOLUME_GUID = 0xA0,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_ALLOC_BITMAP = 0x81,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_UPCASE_TABLE = 0x82,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_TEX_FAT = 0xA1,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_ACL = 0xE2,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_FILE = 0x85,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_FILE_STREAM_EXT = 0xC0,     
        TSK_FS_EXFAT_DIR_ENTRY_TYPE_FILE_NAME_EXT = 0xC1,     
    };

    /**
     * Allocation bitmap directory entry structure for exFAT file systems
     * (TSK_FS_INFO_TYPE_EX_FAT). There will be one allocation bitmap for 
     * exFAT and two for TexFAT (transactional FAT). Bit zero of the flags
     * byte is 0 in the directory entry for the first bitmap, 1 for in the 
     * directory entry for the second bitmap.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t flags;
        uint8_t reserved[18];
        uint8_t first_cluster_addr[4];
        uint8_t length_in_bytes[8];
    } EXFATFS_ALLOC_BITMAP_DIR_ENTRY;

	/**
	 * \internal
	 * Open part of a disk image as an exFAT file system. 
	 *
	 * @param a_fatfs Generic FAT file system info with boot sector buffer
	 * @returns 1 on sucess, 0 otherwise
	 */
	extern int exfatfs_open(FATFS_INFO *a_fatfs);

	/**
	 * \internal
	 * Determine whether a specified cluster is allocated. 
	 *
	 * @param a_fatfs Generic FAT file system info with boot sector buffer
     * @param cluster_addr address of the cluster to check 
	 * @returns 1 if the cluster is allocated, 0 otherwise
	 */
    extern int exfatfs_is_clust_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T cluster_addr);

#ifdef __cplusplus
}
#endif

#endif
