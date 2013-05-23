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
 * \file exfatfs_meta.c
 * Contains the internal TSK exFAT file system code to access the data in the 
 * metadata data category as defined in the book "File System Forensic 
 * Analysis" by Brian Carrier (pp. 174-175). 
 */

#include "tsk_exfatfs.h" /* Included first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

/**
 * \internal
 * Determine whether a specified cluster is allocated. 
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_cluster_addr Address of the cluster to check. 
 * @return 1 if the cluster is allocated, 0 otherwise.
 */
int8_t 
exfatfs_is_clust_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr)
{
    const char *func_name = "exfatfs_is_clust_alloc";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSK_DADDR_T bitmap_byte_offset = 0;
    uint8_t bitmap_byte[1];
    ssize_t bytes_read = 0;
    TSK_DADDR_T cluster_addr = 0;

    // RJCTODO: Add cluster address validation.
    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) {
        return -1;
    }

     /* Subtract 2 from the cluster address since cluster #2 is 
      * the first cluster. */
    cluster_addr = a_cluster_addr - 2;

    /* Determine the offset of the byte in the allocation bitmap that
     * contains the bit for the specified cluster. */
    bitmap_byte_offset = (a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap * a_fatfs->ssize) + (cluster_addr / 8);

    /* Read the byte. */
    bytes_read = tsk_fs_read(fs, bitmap_byte_offset, (char*)(&bitmap_byte[0]), 1);
    if (bytes_read != 1) {
        if (bytes_read >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: failed to read bitmap byte", func_name);
        return -1;
    }

    /* Check the bit that corresponds to the specified cluster. */
    return (isset(&bitmap_byte[0], cluster_addr) ? 1 : 0);
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT volume label directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_vol_label_dentry";
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    uint8_t i = 0;
    
    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in a volume label directory entry for an 
     * in-depth test. */
    if (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL) {
        if (dentry->utf16_char_count > EXFATFS_MAX_VOLUME_LABEL_LEN) {
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }
    else {
        if (dentry->utf16_char_count != 0x00) {
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }

        for(i = 0; i < EXFATFS_MAX_VOLUME_LABEL_LEN * 2; ++i) {
            /* Every byte of the UTF-16 volume label string should be 0. */
            if (dentry->volume_label[i] != 0x00) {
                return EXFATFS_DIR_ENTRY_TYPE_NONE;
            }
        }
    }

    return EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT volume GUID directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_vol_guid_dentry";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in a volume GUID directory entry for an
     * in-depth test. */
    return EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT allocation bitmap directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_alloc_bitmap_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_bitmap = 0;
    uint64_t length_of_alloc_bitmap_in_bytes = 0;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in an allocation bitmap directory entry for 
     * an in-depth test. */

    /* The length of the allocation bitmap should be consistent with the 
     * number of clusters in the data area as specified in the volume boot
     * record. */
    length_of_alloc_bitmap_in_bytes = tsk_getu64(fs->endian, dentry->length_of_alloc_bitmap_in_bytes);
    if (length_of_alloc_bitmap_in_bytes != (a_fatfs->clustcnt + 7) / 8) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: bitmap length incorrect\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* The first cluster of the bit map should be within the data area.
     * It is usually in the first cluster. */
    first_cluster_of_bitmap = tsk_getu32(fs->endian, dentry->first_cluster_of_bitmap);
    if ((first_cluster_of_bitmap < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_bitmap > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    return EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT UP-Case table directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_table = 0;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in an UP-Case table directory entry
     * for an in-depth test. */

    /* The first cluster of the Up-Case table should be within the 
     * data area. */
    first_cluster_of_table = tsk_getu32(fs->endian, dentry->first_cluster_of_table);
    if ((first_cluster_of_table < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_table > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    return EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT UP-Case table directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_TEX_FAT or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_tex_fat_dentry";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in a UP-TexFAT directory entry
     * for an in-depth test. */
    return EXFATFS_DIR_ENTRY_TYPE_TEX_FAT;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT access control table directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_ACT or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_access_ctrl_table_dentry";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* There is not enough data in an access control table directory entry
     * for an in-depth test. */
    return EXFATFS_DIR_ENTRY_TYPE_ACT;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *file_dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    if (!a_do_basic_test_only == 0)
    {
        // RJCTODO: Check MAC times
    }

    // RJCTODO: Consider using additional tests similar to bulk extractor tests, e.g., sanity check attributes

    /* The MAC times should not be all zero. */ 
    //RJCTODO: Is this legitimate? 
    //if ((tsk_getu16(fs->endian, file_dentry->modifiedtime) == 0) &&
    //    (tsk_getu16(fs->endian, file_dentry->atime) == 0) &&
    //    (tsk_getu16(fs->endian, file_dentry->ctime) == 0))
    //{
    //    if (tsk_verbose) {
    //        fprintf(stderr, "%s: MAC times all zero\n", func_name);
    //    }
    //    return EXFATFS_DIR_ENTRY_TYPE_NONE;
    //}

    return EXFATFS_DIR_ENTRY_TYPE_FILE;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file stream directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    if (!a_do_basic_test_only) {
        // RJCTODO: Validate this entry
    }

    // RJCTODO: Validate this entry

    return EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM;
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file name directory entry.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_dentry A 32 byte buffer. 
 * @param a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE_NAME or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_dentry";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    // RJCTODO: Make sure allocation possible bit is not set. Invalid FAT chain bit should be set.
    // Can this be used for other entries?

    /* There is not enough data in a file name directory entry
     * for an in-depth test. */
    return EXFATFS_DIR_ENTRY_TYPE_FILE_NAME;
}

/**
 * \internal
 * Determines whether a buffer likely contains a directory entry.
 * For the most reliable results, request the in-depth test.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_buf Buffer that may contain a directory entry.
 * @param a_do_basic_test_only 1 if only basic tests should be performed. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_NONE or a member of 
 * EXFATFS_DIR_ENTRY_TYPE_ENUM or indicating a directory entry type.
 */
enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    switch (a_dentry->data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_is_vol_label_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        return exfatfs_is_vol_guid_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_is_alloc_bitmap_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_is_upcase_table_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        return exfatfs_is_tex_fat_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        return exfatfs_is_access_ctrl_table_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
        return exfatfs_is_file_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
        return exfatfs_is_file_stream_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
        return exfatfs_is_file_name_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    default:
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }
}

/**
 * \internal
 * Copy the contents of a volume label entry into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @param a_inum Address of the inode.
 * @return TSK_RETVAL_ENUM.  Errors should only occur for
 * Unicode conversion problems and when this occurs the name will be
 * NULL terminated (but with unknown contents).
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_vol_label_dinode";
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)&a_inode->dentries[0];

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return TSK_ERR;
    }

    if (dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY) {
        if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dentry->volume_label, dentry->utf16_char_count + 1, a_inum, "volume label") == TSKconversionOK) {
            return TSK_OK;
        }
        else {
            return TSK_COR;
        }
    }
    else {
        strcpy(a_fs_meta->name2->name, EXFATFS_NO_VOLUME_LABEL_VIRT_FILENAME);
        return TSK_OK;
    }
}

/**
 * \internal
 * Copy the contents of an allocation bitmap directory entry into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_alloc_bitmap_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode)
{
    const char *func_name = "exfatfs_copy_alloc_bitmap_dinode";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name)) {
        return TSK_ERR;
    }

    strcpy(a_fs_meta->name2->name, EXFATFS_ALLOC_BITMAP_VIRT_FILENAME);
    a_fs_meta->type = TSK_FS_META_TYPE_VIRT; // RJCTODO: Is this correct?

    // RJCTODO:

    return TSK_OK;
}

/**
 * \internal
 * Copy the contents of an UP-Case table directory entry into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_upcase_table_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode)
{
    const char *func_name = "exfatfs_copy_upcase_table_dinode";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name)) {
        return TSK_ERR;
    }

    strcpy(a_fs_meta->name2->name, EXFATFS_UPCASE_TABLE_VIRT_FILENAME);
    a_fs_meta->type = TSK_FS_META_TYPE_VIRT; // RJCTODO: Is this correct?

    // RJCTODO:

    return TSK_OK;
}

/**
 * \internal
 * Copy the contents of a file and a file stream directory entry into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode)
{
    const char *func_name = "exfatfs_copy_file_dinode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *dentry = NULL;
    EXFATFS_FILE_STREAM_DIR_ENTRY *stream_dentry = NULL;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name)) {
        return TSK_ERR;
    }

    /* Treating a file entry and a stream entry as a single inode. */
    dentry = (EXFATFS_FILE_DIR_ENTRY*)(&a_inode->dentries[0]);
    stream_dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)(&a_inode->dentries[1]);

    if (dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_FILE &&
        dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) {
            // RJCTODO: At least assert
            return TSK_ERR;
    }

    if (stream_dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM &&
        stream_dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM) {
            // RJCTODO: At least assert
            return TSK_ERR;
    }

    /* Regular file or directory? */
    if (dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        a_fs_meta->type = TSK_FS_META_TYPE_DIR;
    }
    else {
        a_fs_meta->type = TSK_FS_META_TYPE_REG;
    }

    // RJCTODO: Need to set mode

    /* There is no notion of links in exFAT, just deleted or not deleted. 
     * If the file is not deleted, treat this as having one link. */
    a_fs_meta->nlink = (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) ? 0 : 1;

    a_fs_meta->size = tsk_getu64(fs->endian, stream_dentry->valid_data_length);

    // RJCTODO: Could cut down on code duplication here...
    /* Copy the last modified time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->modified_date))) {
        a_fs_meta->mtime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->modified_time),
            tsk_getu16(fs->endian, dentry->modified_date), 
            dentry->modified_time_10_ms_increments);
    }
    else {
        a_fs_meta->mtime = 0;
        a_fs_meta->mtime_nano = 0;
    }

    /* Copy the last accessed time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->accessed_date))) {
        a_fs_meta->atime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->accessed_time), 
            tsk_getu16(fs->endian, dentry->accessed_date), 0);
    }
    else {
        a_fs_meta->atime = 0;
    }
    a_fs_meta->atime_nano = 0;

    /* exFAT does not have a last changed time. */
    a_fs_meta->ctime = 0;
    a_fs_meta->ctime_nano = 0;

    /* Copy the created time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->created_date))) {
        a_fs_meta->crtime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->created_time),
            tsk_getu16(fs->endian, dentry->created_date), 
            dentry->created_time_10_ms_increments); // RJCTODO: Is this correct? The comments on the conversion routine may be incorrect...
        a_fs_meta->crtime_nano = dos2nanosec(dentry->created_time_10_ms_increments);
    }
    else {
        a_fs_meta->crtime = 0;
        a_fs_meta->crtime_nano = 0;
    }

    // RJCTODO: "File walk with me"

    return TSK_OK;
}

/**
 * \internal
 * Copy the contents of a file name directory entry into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @return TSK_RETVAL_ENUM.  Errors should only occur for
 * Unicode conversion problems and when this occurs the name will be
 * NULL terminated (but with unknown contents).
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_file_name_dinode";
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = NULL;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return TSK_ERR;
    }

    dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)(&a_inode->dentries[0]);

    a_fs_meta->type = TSK_FS_META_TYPE_REG;

    if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dentry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH, a_inum, "file name segment") == TSKconversionOK) {
        return TSK_OK;
    }
    else {
        return TSK_COR;
    }
}

// RJCTODO: Consider using this for FATXX as well.
/**
 * \internal
 * Initialize the members of a TSK_FS_META for copying the contents of an
 * an inode consisiting of or more raw directry entries into it. 
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inum Address of the inode.
 * @param a_is_alloc Allocation status of the inode.
 * @return 1 on success, 0 otherwise.
 */
static uint8_t
exfatfs_inode_copy_init(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, TSK_INUM_T a_inum, uint8_t a_is_alloc)
{
    const char *func_name = "exfatfs_inode_copy_init";
    int8_t ret_val = 0;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return TSK_ERR;
    }

    a_fs_meta->flags = a_is_alloc ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC;
    a_fs_meta->addr = a_inum;
    a_fs_meta->type = TSK_FS_META_TYPE_UNDEF;
    a_fs_meta->mode = TSK_FS_META_MODE_UNSPECIFIED; // RJCTODO: Is this correct? Is it correct for non-file entries?

    /* Default values for metadata that only exists in file inodes. */
    a_fs_meta->nlink = 0;
    a_fs_meta->size = 0;
    a_fs_meta->mtime = 0;
    a_fs_meta->mtime_nano = 0;
    a_fs_meta->atime = 0;
    a_fs_meta->atime_nano = 0;
    a_fs_meta->ctime = 0;
    a_fs_meta->ctime_nano = 0;
    a_fs_meta->crtime = 0;
    a_fs_meta->crtime_nano = 0;

    /* Metadata that does not exist in exFAT. */
    a_fs_meta->uid = 0;
    a_fs_meta->gid = 0;
    a_fs_meta->seq = 0;

    // RJCTODO: What's this all about? For the sectors list? Do we always need it?
    if (a_fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((a_fs_meta =
                tsk_fs_meta_realloc(a_fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 0;
        }
    }

    // RJCTODO: What's this all about?
    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }

    /* Allocate space for a name. */ // RJCTODO: Do we always want to do this? 
    if (a_fs_meta->name2 == NULL) {
        if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST*)tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 0;
        }
        a_fs_meta->name2->next = NULL;
    }

    return 1;
}

/**
 * \internal
 * Copy the contents of one or more raw directory entries into a 
 * TSK_FS_META structure.
 *
 * @param a_fatfs File system that directory entry is from.
 * @param a_fs_meta Generic inode structure to copy data into.
 * @param a_inode Raw inode structure to copy data from.
 * @param a_inum Address of the inode.
 * @param a_is_alloc Allocation status of the inode.
 * @return TSK_RETVAL_ENUM.  Errors should only occur for
 * Unicode conversion problems and when this occurs the name will be
 * NULL terminated (but with unknown contents).
 */
static TSK_RETVAL_ENUM
exfatfs_copy_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, 
    EXFATFS_INODE *a_inode, TSK_INUM_T a_inum, uint8_t a_is_alloc)
{
    const char *func_name = "exfatfs_copy_dinode";

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return TSK_ERR;
    }

    if (!exfatfs_inode_copy_init(a_fatfs, a_fs_meta, a_inum, a_is_alloc)) {
        return TSK_ERR;
    }

    switch (a_inode->dentries[0].data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_copy_vol_label_dinode(a_fatfs, a_fs_meta, a_inode, a_inum);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        strcpy(a_fs_meta->name2->name, EXFATFS_VOLUME_GUID_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_copy_alloc_bitmap_dinode(a_fatfs, a_fs_meta, a_inode);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_copy_upcase_table_dinode(a_fatfs, a_fs_meta, a_inode);
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        strcpy(a_fs_meta->name2->name, EXFATFS_TEX_FAT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        strcpy(a_fs_meta->name2->name, EXFATFS_ACT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
        return exfatfs_copy_file_dinode(a_fatfs, a_fs_meta, a_inode);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
        return exfatfs_copy_file_name_dinode(a_fatfs, a_fs_meta, a_inode, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
    default:
        /* Stream entries are copied in tandem with the corresponding file entry. */
        return TSK_ERR;
    }

    return TSK_OK;
}

uint8_t
exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file, 
    TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_inode_lookup";
    TSK_DADDR_T sector = 0;
    int8_t sect_is_alloc = 0;
    EXFATFS_INODE inode;
    uint64_t inode_offset = 0;
    TSK_DADDR_T cluster_base_sector = 0;
    TSK_INUM_T next_inum = 0;
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
    TSK_RETVAL_ENUM copy_result = TSK_OK;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_file, "a_fs_file", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        return 1;
    }

    /* Map the inode address to a sector. */ 
    sector = FATFS_INODE_2_SECT(a_fatfs, a_inum);
    if (sector > a_fatfs->fs_info.last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " in sector too big for image: %" PRIuDADDR, func_name, a_inum, sector);
        return 1;
    }

    sect_is_alloc = fatfs_is_sectalloc(a_fatfs, sector);
    if (sect_is_alloc == -1) {
        // RJCTODO: Report error?
        return 1;
    }

    if (fatfs_dentry_load(a_fatfs, &inode.dentries[0], a_inum) != 0) {
        // RJCTODO: Report error
        return 1;
    }

    /* Note that only the sector allocation status is used to choose
     * between the basic or in-depth version of the inode validity 
     * test. In other places in the code information about whether or not 
     * the sector that contains the inode is part of a folder is used to 
     * make this decision. Here, that information is not available. Thus, 
     * the test here is less reliable and may result in some false 
     * positives. */
    dentry_type = exfatfs_is_dentry(a_fatfs, &inode.dentries[0], sect_is_alloc);
    if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_NONE ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM) {
            /* Note that stream entries are handled with file entries 
             * below. */
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
            tsk_error_set_errstr("%s: %" PRIuINUM " is not an inode", 
                func_name, a_inum);
            return 1;
    }
    else {
        if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE ||
             dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) {
            
            /* Look for the stream entry in the next entry if: 
             *    a) The file entry is allocated and not at a cluster 
             *       boundary of a fragmented directory.
             *    b) The file entry is unallocated, so there is no
             *       place else to look. */
            next_inum = a_inum + 1;

            if (sect_is_alloc) {
                /* Test for a file entry at a cluster boundary. First, get
                /* the offset of the file entry. */ 
                uint64_t inode_offset = FATFS_INODE_2_OFF(a_fatfs, a_inum);            
                
                /* Then get the base sector of the cluster. */ // RJCTODO: Fix this
                cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, 
                    (FATFS_SECT_2_CLUST(a_fatfs, sector))) + a_fatfs->csize;

                if (inode_offset == 
                    ((cluster_base_sector * a_fatfs->ssize) - sizeof(FATFS_DENTRY))) {
                    // RJCTODO: Figure out where the stream dentry is
                }
                else {
                    next_inum = a_inum + 1; // RJCTODO: Get another var
                }
            }

            if (fatfs_dentry_load(a_fatfs, &inode.dentries[1], next_inum) != 0) {
                // RJCTODO: Report error
                return 1;
            }
        }

        copy_result = exfatfs_copy_dinode(a_fatfs, a_fs_file->meta, 
            &inode, a_inum, sect_is_alloc); 
    }

    if (copy_result == TSK_OK) {
        return 0;
    }
    else if (copy_result == TSK_COR) {
        /* If there was a Unicode conversion error,
         * then still return the inode. */
        if (tsk_verbose) {
            tsk_error_print(stderr);
        }
        tsk_error_reset();
        return 0;
    }
    else {
        return 1;
    }
}

// RJCTODO: Add function header comment
void
exfatfs_istat_attrs(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum,  FILE *a_hFile)
{
    const char *func_name = "exfatfs_istat_attrs";
    FATFS_DENTRY dentry;
    EXFATFS_FILE_DIR_ENTRY *file_dentry = NULL;

    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_is_inum_in_range(a_fatfs, a_inum, func_name)) {
        // RJCTODO: Report error, diff function return type?
        return; 
    }

    if (fatfs_dentry_load(a_fatfs, (FATFS_DENTRY*)(&dentry), a_inum) != 0) {
        // RJCTODO: Report error, diff function return type?
        return; 
    }

    switch (dentry.data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
        file_dentry = (EXFATFS_FILE_DIR_ENTRY*)(&dentry);

        if (file_dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
            tsk_fprintf(a_hFile, "Directory");
        }
        else {
            tsk_fprintf(a_hFile, "File");
        }

        if (file_dentry->attrs[0] & FATFS_ATTR_READONLY) {
            tsk_fprintf(a_hFile, ", Read Only");
        }

        if (file_dentry->attrs[0] & FATFS_ATTR_HIDDEN) {
            tsk_fprintf(a_hFile, ", Hidden");
        }

        if (file_dentry->attrs[0] & FATFS_ATTR_SYSTEM) {
            tsk_fprintf(a_hFile, ", System");
        }

        if (file_dentry->attrs[0] & FATFS_ATTR_ARCHIVE) {
            tsk_fprintf(a_hFile, ", Archive");
        }

        tsk_fprintf(a_hFile, "\n");

        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
        tsk_fprintf(a_hFile, "File Stream\n"); 
        // RJCTODO: Want to print secondary flags? I think so...
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
        tsk_fprintf(a_hFile, "File Name\n");
    default:
        // RJCTODO: Do an error here?
        break;
    }
}

// RJCTODO: Remove when inode_walk is ready
TSK_RETVAL_ENUM
exfatfs_dinode_copy_stub(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
    FATFS_DENTRY *a_dentry, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_dinode_copy_stub";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    int8_t sect_is_alloc = 0;

    if ((fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name)) ||
        (fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name))) {
        return TSK_ERR;
    }

    return TSK_OK;
}
