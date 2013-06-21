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
 * Contains declarations of structures and functions specific to TSK exFAT 
 * file system support.
 */

#ifndef _TSK_EXFATFS_H
#define _TSK_EXFATFS_H

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"

/**
 * \internal
 *
 * Per TSK convention, exFAT file system functions return integer 0 on success
 * and integer 1 on failure. 
 */
#define EXFATFS_OK 0

/**
 * \internal
 *
 * Per TSK convention, exFAT file system functions return integer 0 on success
 * and integer 1 on failure. 
 */
#define EXFATFS_FAIL 1

/**
 * \internal
 * The first cluster of an exFAT cluster heap (data area) is cluster #2.
 */
#define EXFATFS_FIRST_CLUSTER 2

/**
 * \internal
 * An exFAT volume name directory entry includes from 0 to 15 UTF-16 
 * characters.
 */
#define EXFATFS_MAX_VOLUME_LABEL_LEN 15

/**
 * \internal
 * AnS exFAT file entry set consists of a file directory entry followed by a
 * file stream directory entry and at least one file name directory entry.
 * The file stream and file name entries are the secondary entries.
 */
#define EXFATFS_MIN_FILE_SECONDARY_DENTRIES_COUNT 2 

/**
 * \internal
 * An exFAT file entry set consists of a file directory entry followed by a
 * file stream directory entry and up to seventeen file name directory entries.
 * The file stream and file name entries are the secondary entries.
 */
#define EXFATFS_MAX_FILE_SECONDARY_DENTRIES_COUNT 18

/**
 * \internal
 * An exFAT file name directory entry includes from 1 to 15 UTF-16 characters.
 */
#define EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH 15

/**
 * \internal
 * In an exFAT file stream directory entry, the second bit of the general 
 * secondary flags byte is set if there is no FAT chain for a file, i.e., the
 * file is not fragmented.
 */
#define EXFATFS_INVALID_FAT_CHAIN_MASK 0x02

/**
 * \internal
 * Buffer size for conversion of exFAT UTF-16 strings to UTF-8 strings.
 */
#define EXFATFS_MAX_NAME_LEN_UTF8 1024

/**
 * Name for an exFAT volume label directory entry that has an empty label, with 
 * the "$" prefix that is used to indicate "special file" directory entries and
 * non-file directory entries.
 */
#define EXFATFS_EMPTY_VOLUME_LABEL_DENTRY_NAME "$EMPTY_VOLUME_LABEL"   

/**
 * Name for an exFAT volume GUID directory entry, with the "$" prefix that is
 * used to indicate "special file" directory entries and non-file directory 
 * entries.
 */
#define EXFATFS_VOLUME_GUID_DENTRY_NAME "$VOLUME_GUID"   

/**
 * Name for an exFAT allocation bitmap directory entry, with the "$" prefix 
 * that is used to indicate "special file" directory entries and non-file 
 * directory entries.
 */
#define EXFATFS_ALLOC_BITMAP_DENTRY_NAME "$ALLOC_BITMAP"   

/**
 * Name for an exFAT upcase table directory entry, with the "$" prefix that is 
 * used to indicate "special file" directory entries and non-file directory 
 * entries.
 */
#define EXFATFS_UPCASE_TABLE_DENTRY_NAME "$UPCASE_TABLE"   

/**
 * Name for an exFAT TexFAT directory entry, with the "$" prefix that is used 
 * to indicate "special file" directory entries and non-file directory entries.
 */
#define EXFATFS_TEX_FAT_DENTRY_NAME "$TEX_FAT"   

/**
 * Name for an exFAT access control table directory entry, with the "$" prefix
 * that is used to indicate "special file" directory entries and non-file 
 * directory entries.
 */
#define EXFATFS_ACT_DENTRY_NAME "$ACCESS_CONTROL_TABLE"   

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \internal
     * Master boot record (MBR) structure for exFAT file systems. The MBR will
     * be at least 512 bytes in length, but may be padded for larger sector 
     * sizes. It is part of a larger structure called the volume boot record 
     * (VBR) that includes OEM parameters, reserved space, and a hash value. 
     * There  should be both a primary and a backup VBR, so there is a primary 
     * MBR and a backup MBR.
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
	} EXFATFS_MASTER_BOOT_REC;

    /**
     * exFAT directory entry types, the first byte of a directory entry.
     */
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM {
        EXFATFS_DIR_ENTRY_TYPE_NONE = 0xFF,
        EXFATFS_DIR_ENTRY_TYPE_UNUSED = 0x00,
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL = 0x83,     
        EXFATFS_DIR_ENTRY_TYPE_EMPTY_VOLUME_LABEL = 0x03,     
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID = 0xA0,     
        EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP = 0x81,     
        EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE = 0x82,     
        EXFATFS_DIR_ENTRY_TYPE_TEX_FAT = 0xA1,     
        EXFATFS_DIR_ENTRY_TYPE_ACT = 0xE2,     
        EXFATFS_DIR_ENTRY_TYPE_FILE = 0x85,     
        EXFATFS_DIR_ENTRY_TYPE_UNALLOC_FILE = 0x05,     
        EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM = 0xC0,     
        EXFATFS_DIR_ENTRY_TYPE_UNALLOC_FILE_STREAM = 0x40,  
        EXFATFS_DIR_ENTRY_TYPE_FILE_NAME = 0xC1,     
        EXFATFS_DIR_ENTRY_TYPE_UNALLOC_FILE_NAME = 0x41     
    };
    typedef enum EXFATFS_DIR_ENTRY_TYPE_ENUM EXFATFS_DIR_ENTRY_TYPE_ENUM;

    /**
     * Volume label directory entry structure for exFAT file systems. This 
     * type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t utf16_char_count;
        uint8_t volume_label[30];
    } EXFATFS_VOL_LABEL_DIR_ENTRY;

    /**
     * Volume GUID directory entry structure for exFAT file systems. This type
     * of entry should be found only in the root directory.
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
     * bitmap. This type of entry should be found only in the root directory.
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
     * required. This type of entry should be found only in the root directory.
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
     * systems. This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t reserved[31];
    } EXFATFS_TEXFAT_DIR_ENTRY;

    /**
     * Access control table directory entry structure for exFAT file systems.
     * This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t reserved[31];
    } EXFATFS_ACCESS_CTRL_TABLE_DIR_ENTRY;

    /**
     * \internal
     * It will be followed by a stream directory entry and 1-17 file name
     * entries. The stream and file name entries are secondary entries. A file
     * entry and its stream and file name entries constitute a file directory
     * entry set.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t secondary_entries_count;
        uint8_t check_sum[2];
        uint8_t attrs[2];
        uint8_t reserved1[2];
        uint8_t created_time[2];
        uint8_t created_date[2];
        uint8_t modified_time[2];
        uint8_t modified_date[2];
        uint8_t accessed_time[2];
        uint8_t accessed_date[2];
        uint8_t created_time_tenths_of_sec;
        uint8_t modified_time_tenths_of_sec;
        uint8_t created_time_time_zone_offset;
        uint8_t modified_time_time_zone_offset;
        uint8_t accessed_time_time_zone_offset;
        uint8_t reserved2[7];
    } EXFATFS_FILE_DIR_ENTRY;

    /**
     * Stream extension directory entry structure for exFAT file systems.
     * It will be preceded by a file directory entry and followed by 1-17
     * file name directory entries. The stream and file name entries are 
     * secondary entries. A file entry and its stream and file name entries 
     * constitute a file directory entry set.
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
     * a file entry. A file entry and its stream and file name entries 
     * constitute a file directory entry set. Note that file names are not 
     * null-terminated. The length of a file name is stored in the file stream
     * entry of the file direcotry entry set.
     */
    typedef struct {
        uint8_t entry_type;
        uint8_t flags;
        uint8_t utf16_name_chars[30];
    } EXFATFS_FILE_NAME_DIR_ENTRY;

	extern uint8_t 
    exfatfs_open(FATFS_INFO *a_fatfs);

    extern int8_t 
    exfatfs_is_clust_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr);

    extern uint8_t
    exfatfs_fsstat(TSK_FS_INFO *a_fs, FILE *a_hFile);

    extern enum EXFATFS_DIR_ENTRY_TYPE_ENUM 
    exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_sector_is_alloc, 
        uint8_t a_do_basic_test_only); // RJCTODO: Last param is awkward

    extern enum EXFATFS_DIR_ENTRY_TYPE_ENUM 
    exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_basic);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, 
        FATFS_DENTRY *a_dentry,  uint8_t a_sector_is_alloc, 
        uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
         uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern uint8_t
    exfatfs_find_file_stream_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_file_entry_inum, 
        TSK_DADDR_T a_sector, uint8_t a_sector_is_alloc,  
        EXFATFS_DIR_ENTRY_TYPE_ENUM a_file_dentry_type,
        FATFS_DENTRY *a_stream_dentry);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM
    exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
        uint8_t a_sector_is_alloc, uint8_t a_do_basic_test_only);

    extern TSK_RETVAL_ENUM
    exfatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FATFS_DENTRY *a_dentry, FATFS_DENTRY *a_secondary_dentry, 
        uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file);

    extern uint8_t
    exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
        TSK_INUM_T a_inum);

    extern uint8_t
    exfatfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FILE *a_hFile);

    extern uint8_t
    exfatfs_should_skip_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FATFS_DENTRY *a_dentry, unsigned int a_selection_flags, 
        int a_cluster_is_alloc);

    extern TSK_RETVAL_ENUM
    exfatfs_dent_parse_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
        TSK_OFF_T a_buf_len, TSK_DADDR_T *a_sector_addrs);

#ifdef __cplusplus
}
#endif

#endif
