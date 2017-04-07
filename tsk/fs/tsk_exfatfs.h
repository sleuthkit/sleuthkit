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
 * The first cluster of an exFAT cluster heap (data area) is cluster #2.
 */
#define EXFATFS_FIRST_CLUSTER 2

/**
 * \internal
 * An exFAT volume label should have 11 UTF-16 characters, but in practice
 * the name can extend into the reserved bytes and have a length up to 15
 * characters. 
 */
#define EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR 15
#define EXFATFS_MAX_VOLUME_LABEL_LEN_BYTE 30

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
 * Each character is stored in UTF-16, so the buffer is actually 30-bytes.
 */
#define EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_CHARS 15
#define EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_BYTES 30

/**
 * \internal
 * An exFAT file name can be a maximum of 255 UTF-16 characters.
 */
#define EXFATFS_MAX_FILE_NAME_LENGTH_UTF16_CHARS 255

/**
 * \internal
 * In an exFAT file stream directory entry, the second bit of the general 
 * secondary flags byte is set if there is no FAT chain for a file, i.e., the
 * file is not fragmented.
 */
#define EXFATFS_INVALID_FAT_CHAIN_MASK 0x02

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
        uint8_t jump_to_boot_code[3]; ///< 0xEB7690
        uint8_t fs_name[8];           ///< "EXFAT "
        uint8_t must_be_zeros[53];    ///< @brief Must be 0x00
        uint8_t partition_offset[8];  ///< @brief Sector address
        uint8_t vol_len_in_sectors[8];  ///< @brief Size of total volume in sectors
        uint8_t fat_offset[4];          ///< Sector address of first FAT
        uint8_t fat_len_in_sectors[4];  ///< Size of FAT in sectors
        uint8_t cluster_heap_offset[4]; ///< Sector address of the data region
        uint8_t cluster_cnt[4];         ///< Number of clusters in the cluster heap
        uint8_t root_dir_cluster[4];    ///< Cluster address of the root directory
        uint8_t vol_serial_no[4];     ///< Volume serial number
        uint8_t fs_revision[2];       ///< VV.MM
        uint8_t vol_flags[2];         ///< Flags: ActiveFAT, Volume Dirty, Media Failure, Clear to Zero, and Reserved
        uint8_t bytes_per_sector;     ///< Power of 2. Minimum 2^9 = 512 bytes, maximum 2^12 = 4096 bytes
        uint8_t sectors_per_cluster;  ///< Power of 2. Minimum 2^1 = 2. Maximum is dependant on the fact that the max cluster size is 32 MiB
        uint8_t num_fats;             ///< 1 or 2 (only 2 if TexFAT is in use)
        uint8_t drive_select;         ///< Used by INT 13
        uint8_t percent_of_cluster_heap_in_use;  ///< Percentage of the heap in use
        uint8_t reserved[7];      ///< Reserved
        uint8_t boot_code[390];   ///< Boot program
        uint8_t signature[2];     ///< 0xAA55
    } EXFATFS_MASTER_BOOT_REC;

     /**
     * exFAT directory entry type byte, containing both the type and
     * the allocation status
     */
    typedef uint8_t EXFATFS_DIR_ENTRY_TYPE;

    /**
     * exFAT directory entry types, the first byte of a directory entry minus the
     * high order bit (which gives allocation status)
     */
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM {
        EXFATFS_DIR_ENTRY_TYPE_NONE = 0x00,         ///< 0x00
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL = 0x03, ///< 0x03
        EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID = 0x20,  ///< 0x20
        EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP = 0x01, ///< 0x01
        EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE = 0x02, ///< 0x02
        EXFATFS_DIR_ENTRY_TYPE_TEXFAT = 0x21,       ///< 0x21
        EXFATFS_DIR_ENTRY_TYPE_ACT = 0x62,          ///< 0x62
        EXFATFS_DIR_ENTRY_TYPE_FILE = 0x05,         ///< 0x05
        EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM = 0x40,  ///< 0x40
        EXFATFS_DIR_ENTRY_TYPE_FILE_NAME = 0x41     ///< 0x41
    };
    typedef enum EXFATFS_DIR_ENTRY_TYPE_ENUM EXFATFS_DIR_ENTRY_TYPE_ENUM;

    /**
     * Volume label directory entry structure for exFAT file systems. This 
     * type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;        ///< 0x83 normally, 0x03 if the media was formatted without a volume label
        uint8_t volume_label_length_chars;  ///< Number of characters in the volume label
        uint8_t volume_label[EXFATFS_MAX_VOLUME_LABEL_LEN_BYTE];  ///< Volume label in UTF16
    } EXFATFS_VOL_LABEL_DIR_ENTRY;

    /**
     * Volume GUID directory entry structure for exFAT file systems. This type
     * of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;    ///< 0xA0
        uint8_t secondary_entries_count;  ///< Always zero
        uint8_t check_sum[2];     ///< Set checksum
        uint8_t flags[2];         ///< Flags: Allocation possible, no FAT chain, custom
        uint8_t volume_guid[16];  ///< Volume GUID
        uint8_t reserved[10];     ///< Reserved
    } EXFATFS_VOL_GUID_DIR_ENTRY;

    /**
     * Allocation bitmap directory entry structure for exFAT file systems.
     * There will be one allocation bitmap for exFAT and two for TexFAT 
     * (transactional exFAT). Bit zero of the flags byte is 0 in the directory
     * entry for the first bitmap and 1 in the directory entry for the second 
     * bitmap. This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;   ///< 0x81
        uint8_t flags;        ///< 0x00 for first bitmap, 0x01 for the second
        uint8_t reserved[18]; ///< Reserved
        uint8_t first_cluster_of_bitmap[4];  ///< Cluster address of first data block
        uint8_t length_of_alloc_bitmap_in_bytes[8];  ///< Length of the data
    } EXFATFS_ALLOC_BITMAP_DIR_ENTRY;

    /**
     * UP-Case table directory entry structure for exFAT file systems.
     * The UP-Case table is used to convert file names to upper case when
     * required. This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;   ///< 0x82
        uint8_t reserved1[3]; ///< Reserved
        uint8_t table_check_sum[4];  ///< UP-Case table checksum
        uint8_t reserved2[12];       ///< Reserved
        uint8_t first_cluster_of_table[4]; ///< Cluster address of first data block
        uint8_t table_length_in_bytes[8];  ///< Length of the data
    } EXFATFS_UPCASE_TABLE_DIR_ENTRY;

    /**
     * TexFAT (transactional exFAT) directory entry structure for exFAT file 
     * systems. This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;    ///< 0xA1
        uint8_t reserved[31];  ///< Reserved
    } EXFATFS_TEXFAT_DIR_ENTRY;

    /**
     * Access control table directory entry structure for exFAT file systems.
     * This type of entry should be found only in the root directory.
     */
    typedef struct {
        uint8_t entry_type;   ///< 0xE2
        uint8_t reserved[31]; ///< Reserved
    } EXFATFS_ACCESS_CTRL_TABLE_DIR_ENTRY;

    /**
     * \internal
     * It will be followed by a stream directory entry and 1-17 file name
     * entries. The stream and file name entries are secondary entries. A file
     * entry and its stream and file name entries constitute a file directory
     * entry set.
     */
    typedef struct {
        uint8_t entry_type;   ///< 0x85 if allocated, 0x05 if deleted
        uint8_t secondary_entries_count; ///< Number of entries following the primary directory entry (Range: 2 to 18)
        uint8_t check_sum[2];     ///< Set checksum
        uint8_t attrs[2];         ///< File attributes
        uint8_t reserved1[2];     ///< Reserved
        uint8_t created_time[2];  ///< Time part of DOS time stamp
        uint8_t created_date[2];  ///< Date part of DOS time stamp
        uint8_t modified_time[2]; ///< Time part of DOS time stamp
        uint8_t modified_date[2]; ///< Date part of DOS time stamp
        uint8_t accessed_time[2]; ///< Time part of DOS time stamp
        uint8_t accessed_date[2]; ///< Date part of DOS time stamp
        uint8_t created_time_tenths_of_sec;   ///< Tenths of seconds part of a DOS time stamp, range is 0-199
        uint8_t modified_time_tenths_of_sec;  ///< Tenths of seconds part of a DOS time stamp, range is 0-199
        uint8_t created_time_time_zone_offset;  ///< Time zone difference to UTC in 15 minute increments
        uint8_t modified_time_time_zone_offset; ///< Time zone difference to UTC in 15 minute increments
        uint8_t accessed_time_time_zone_offset; ///< Time zone difference to UTC in 15 minute increments
        uint8_t reserved2[7];  ///< Reserved
    } EXFATFS_FILE_DIR_ENTRY;

    /**
     * Stream extension directory entry structure for exFAT file systems.
     * It will be preceded by a file directory entry and followed by 1-17
     * file name directory entries. The stream and file name entries are 
     * secondary entries. A file entry and its stream and file name entries 
     * constitute a file directory entry set.
     */
    typedef struct {
        uint8_t entry_type; ///< 0xC0 if allocated, 0x40 if deleted
        uint8_t flags;      ///< Flags: Allocation possible, no FAT chain, custom
        uint8_t reserved1;  ///< Reserved
        uint8_t file_name_length_UTF16_chars;   ///< Number of characters in UTF16 name contained in following file name directory entries
        uint8_t file_name_hash[2];  ///< Hash of up-cased file name
        uint8_t reserved2[2];       ///< Reserved
        uint8_t valid_data_length[8];  ///< How much actual data has been written to the file. Must be less than data_length
        uint8_t reserved3[4];          ///< Reserved
        uint8_t first_cluster_addr[4]; ///< Cluster address of first data block
        uint8_t data_length[8];        ///< Length of the data. Max 256M for directories
    } EXFATFS_FILE_STREAM_DIR_ENTRY;

    /**
     * File name directory entry structure for exFAT file systems.
     * It will be preceded by 0-16 file name entries, a stream entry, and
     * a file entry. A file entry and its stream and file name entries 
     * constitute a file directory entry set. Note that file names are not 
     * null-terminated. The length of a file name is stored in the file stream
     * entry of the file directory entry set.
     */
    typedef struct {
        uint8_t entry_type;  ///< 0xC1 if allocated, 0x41 if deleted
        uint8_t flags;       ///< Flags: Allocation possible, no FAT chain, custom
        uint8_t utf16_name_chars[30];  ///< UTF16 part of file name, max 15 characters
    } EXFATFS_FILE_NAME_DIR_ENTRY;

    extern uint8_t 
    exfatfs_open(FATFS_INFO *a_fatfs);

    extern int8_t 
    exfatfs_is_cluster_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr);

    extern uint8_t
    exfatfs_fsstat(TSK_FS_INFO *a_fs, FILE *a_hFile);

    extern uint8_t 
    exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc, 
        uint8_t a_do_basic_tests_only);

    extern uint8_t
    exfatfs_is_vol_label_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc);

    extern uint8_t
    exfatfs_is_vol_guid_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status);

    extern uint8_t
    exfatfs_is_alloc_bitmap_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status, FATFS_INFO *a_fatfs);

    extern uint8_t
    exfatfs_is_upcase_table_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status, FATFS_INFO *a_fatfs);

    extern uint8_t
    exfatfs_is_texfat_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status);

    extern uint8_t
    exfatfs_is_access_ctrl_table_dentry(FATFS_DENTRY *a_dentry, 
        FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status);

    extern uint8_t
    exfatfs_is_file_dentry(FATFS_DENTRY *a_dentry, FATFS_INFO *a_fatfs);

    extern uint8_t
    exfatfs_is_file_dentry_standalone(FATFS_DENTRY *a_dentry, TSK_ENDIAN_ENUM a_endian);

    extern uint8_t
    exfatfs_is_file_stream_dentry(FATFS_DENTRY *a_dentry, FATFS_INFO *a_fatfs);

    extern uint8_t
    exfatfs_is_file_stream_dentry_standalone(FATFS_DENTRY *a_dentry, TSK_ENDIAN_ENUM a_endian,
        uint64_t a_cluster_heap_size, TSK_DADDR_T a_last_cluster);

    extern uint8_t
    exfatfs_find_file_stream_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_file_entry_inum, 
        TSK_DADDR_T a_sector, uint8_t a_sector_is_alloc,  
        EXFATFS_DIR_ENTRY_TYPE a_file_dentry_type,
        FATFS_DENTRY *a_stream_dentry);

    extern uint8_t
    exfatfs_is_file_name_dentry(FATFS_DENTRY *a_dentry);

    extern TSK_RETVAL_ENUM
    exfatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FATFS_DENTRY *a_dentry, uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file);

    extern uint8_t
    exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file,
        TSK_INUM_T a_inum);

    extern uint8_t
    exfatfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FILE *a_hFile);

    extern uint8_t
    exfatfs_inode_walk_should_skip_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
        FATFS_DENTRY *a_dentry, unsigned int a_selection_flags, 
        int a_cluster_is_alloc);

    extern uint8_t 
    exfatfs_get_alloc_status_from_type(EXFATFS_DIR_ENTRY_TYPE a_dir_entry_type);

    extern EXFATFS_DIR_ENTRY_TYPE_ENUM 
    exfatfs_get_enum_from_type(EXFATFS_DIR_ENTRY_TYPE a_dir_entry_type);

    extern TSK_RETVAL_ENUM
    exfatfs_dent_parse_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
        TSK_OFF_T a_buf_len, TSK_DADDR_T *a_sector_addrs);

#ifdef __cplusplus
}
#endif

#endif
