/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/*
 * This code makes use of research presented in the following paper:
 * "Reverse Engineering the exFAT File System" by Robert Shullich
 * Retrieved May 2013 from: 
 * http://www.sans.org/reading_room/whitepapers/forensics/reverse-engineering-microsoft-exfat-file-system_33274
 *
 * Some additional details concerning TexFAT were obtained in May 2013
 * from:
 * http://msdn.microsoft.com/en-us/library/ee490643(v=winembedded.60).aspx
*/

/**
 * \file tsk_exfatfs.h
 * Contains the structures and functions for TSK exFATXX file system support.
 */

#ifndef _TSK_EXFATFS_H
#define _TSK_EXFATFS_H

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

/**
 * exFAT uses up to 15 UTF-16 characters for volume labels.
 */
#define EXFATFS_MAX_VOLUME_LABEL_LEN 15

/**
 * Up to 15 UTF-16 characters of a file name may be contained in an exFAT
 * file name directory entry. The total number of characters in the
 * file name is found in the file stream directory entry for a file.
 */
#define EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH 15

/**
 * The first cluster of the exFAT cluster heap (data area) is cluster #2.
 */
#define EXFATFS_FIRST_CLUSTER 2

/**
 * RJCTODO: comment or remove 
 */
#define EXFATFS_INODE_BUFFER_SIZE (2 * (FATFS_DENTRY_SIZE))

/**
 * File names for exFAT "virtual files" corresponding to non-file 
 * directory entries.
 */
#define EXFATFS_NO_VOLUME_LABEL_VIRT_FILENAME "$VOLUME_LABEL_NONE"   
#define EXFATFS_VOLUME_GUID_VIRT_FILENAME "$VOLUME_GUID"   
#define EXFATFS_ALLOC_BITMAP_VIRT_FILENAME "$ALLOC_BITMAP"   
#define EXFATFS_UPCASE_TABLE_VIRT_FILENAME "$UPCASE_TABLE"   
#define EXFATFS_TEX_FAT_VIRT_FILENAME "$TEX_FAT"   
#define EXFATFS_ACT_VIRT_FILENAME "$ACT"   

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
	} EXFATFS_VOL_BOOT_REC;

    /**
     * exFAT directory entry types, the first byte of a directory entry.
     */
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM {
        EXFATFS_DIR_ENTRY_TYPE_NONE = 0x00,
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL = 0x83,     
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY = 0x03,     
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID = 0xA0,     
        EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP = 0x81,     
        EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE = 0x82,     
        EXFATFS_DIR_ENTRY_TYPE_TEX_FAT = 0xA1,     
        EXFATFS_DIR_ENTRY_TYPE_ACT = 0xE2,     
        EXFATFS_DIR_ENTRY_TYPE_FILE = 0x85,     
        EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED = 0x05,     
        EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM = 0xC0,     
        EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED = 0x40,  
        EXFATFS_DIR_ENTRY_TYPE_FILE_NAME = 0xC1,     
        EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED = 0x41     
    };

    /**
     * Volume label directory entry structure for exFAT file systems.
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t utf16_char_count;
        uint8_t volume_label[30];
    } EXFATFS_VOL_LABEL_DIR_ENTRY;

    /**
     * Volume GUID directory entry structure for exFAT file systems.
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t secondary_entries_count;
        uint8_t check_sum[2];
        uint8_t flags[2];
        uint8_t volume_guid[16];
        uint8_t reserved[10];
    } EXFATFS_VOL_GUID_DIR_ENTRY;

    /**
     * Allocation bitmap directory entry structure for exFAT file systems.
     * There will be one allocation bitmap for exFAT and two for TexFAT 
     * (transactional exFAT). Bit zero of the flags byte is 0 in the directory
     * entry for the first bitmap, 1 for in the directory entry for the second 
     * bitmap.
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t flags;
        uint8_t reserved[18];
        uint8_t first_cluster_of_bitmap[4];
        uint8_t length_of_alloc_bitmap_in_bytes[8];
    } EXFATFS_ALLOC_BITMAP_DIR_ENTRY;

    /**
     * UP-Case table directory entry structure for exFAT file systems.
     * The UP-Case table is used to convert file names to upper case when
     * required.
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t reserved1[3];
        uint8_t table_check_sum[4];
        uint8_t reserved2[12];
        uint8_t first_cluster_of_table[4];
        uint8_t table_length_in_bytes[8];
    } EXFATFS_UPCASE_TABLE_DIR_ENTRY;

    /**
     * TexFAT (transactional exFAT) directory entry structure for exFAT file 
     * systems. 
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t reserved[31];
    } EXFATFS_TEXFAT_DIR_ENTRY;

    /**
     * Windows CE access control table directory entry structure for exFAT 
     * file systems.
     *
     * Found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t reserved[31];
    } EXFATFS_ACCESS_CTRL_TABLE_DIR_ENTRY;

    /**
     * File directory entry structure for exFAT file systems.
     * It will be followed by a stream directory entry and 1-17 file name
     * entries. The stream and file name entries are secondary entries.
     *
     * A file entry and its stream and file name entries constitute 
     * a file entry set.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t secondary_entries_count;
        uint8_t check_sum[2];
        uint8_t attrs[2];
        uint8_t reserved1[2];
        uint8_t ctime[4];
        uint8_t mtime[4];
        uint8_t atime[4];
        uint8_t ctime_10_ms_increments;
        uint8_t ltime_10_ms_increments;
        uint8_t ctime_time_zone_offset;
        uint8_t mtime_time_zone_offset;
        uint8_t atime_time_zone_offset;
        uint8_t reserved2[7];
    } EXFATFS_FILE_DIR_ENTRY;

    /**
     * Stream extension directory entry structure for exFAT file systems.
     * It will be preceded by a file directory entry and followed by 1-17
     * file name directory entries. The stream and file name entries are 
     * secondary entries.
     *
     * A file entry and its stream and file name entries constitute 
     * a file entry set.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t flags;
        uint8_t reserved1;
        uint8_t file_name_length;
        uint8_t file_name_hash[2];
        uint8_t reserved2[2];
        uint8_t valid_data_length[8];
        uint8_t reserved3[4];
        uint8_t first_cluster_addr[4];
        uint8_t data_length[8];
    } EXFATFS_FILE_STREAM_DIR_ENTRY;

    /**
     * File name extension directory entry structure for exFAT file systems.
     * It will be preceded by 0-16 file name entries, a stream entry, and
     * a file entry.
     *
     * A file entry and its stream and file name entries constitute 
     * a file entry set.
     *
     * Note that file names are not null-terminated.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t flags;
        uint8_t utf16_name_chars[30];
    } EXFATFS_FILE_NAME_DIR_ENTRY;

    //RJCTODO: Comments
    typedef struct {
        FATFS_DENTRY primary_dentry;
        FATFS_DENTRY secondary_dentry;
    } EXFATFS_INODE;

    // RJCTODO: Consider marking header as internal, splitting up, etc.

	extern int 
    exfatfs_open(FATFS_INFO *a_fatfs);

    extern int8_t 
    exfatfs_is_clust_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr);

    extern enum EXFATFS_DIR_ENTRY_TYPE_ENUM 
    exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic);

    extern enum EXFATFS_DIR_ENTRY_TYPE_ENUM 
    exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
        uint8_t a_basic);

    extern TSK_RETVAL_ENUM
    exfatfs_inode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
        EXFATFS_INODE *a_inode, TSK_DADDR_T a_sect, TSK_INUM_T a_inum);

    extern uint8_t
    exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
        TSK_INUM_T a_inum, TSK_DADDR_T a_sect, uint8_t a_do_basic_test);

    extern void
    exfatfs_istat_attrs(TSK_FS_INFO *a_fs, TSK_INUM_T a_inum, FILE *a_hFile);

#ifdef __cplusplus
}
#endif

#endif
