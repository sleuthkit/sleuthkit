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
 * @param [in] a_fatfs Generic FAT file system info structure.
 * @param [in] a_cluster_addr Address of the cluster to check. 
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

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) {
        return -1;
    }

     /* Subtract 2 from the cluster address since cluster #2 is 
      * the first cluster. */
    cluster_addr = a_cluster_addr - 2;
    if ((cluster_addr < EXFATFS_FIRST_CLUSTER) ||
        (cluster_addr > a_fatfs->lastclust)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: Cluster address out of range", func_name);
    }

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
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_vol_label_dentry";
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    uint8_t i = 0;
    
    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    if (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL) {
        if (dentry->utf16_char_count > EXFATFS_MAX_VOLUME_LABEL_LEN) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: volume label length too long\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }
    else {
        if (dentry->utf16_char_count != 0x00) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: volume label length non-zero for no label entry\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }

        for(i = 0; i < EXFATFS_MAX_VOLUME_LABEL_LEN * 2; ++i) {
            /* Every byte of the UTF-16 volume label string should be 0. */
            if (dentry->volume_label[i] != 0x00) {
                return EXFATFS_DIR_ENTRY_TYPE_NONE;
                fprintf(stderr, 
                    "%s: non-zero byte in label for no label entry\n", func_name);
            }
        }
    }

    if (!a_do_basic_test_only) {
        /* There is not enough data in a volume label entry for an 
         * in-depth test. */
    }

    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT volume GUID directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* There is not enough data in a volume GUID directory entry
     * to test anything but the entry type byte. */
    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT allocation bitmap directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
EXFATFS_DIR_ENTRY_TYPE_ENUM
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

    if (!a_do_basic_test_only) {
        /* The first cluster of the allocation bitmap should be allocated. */
        if (fatfs_is_clustalloc(a_fatfs, (TSK_DADDR_T)first_cluster_of_bitmap) != 1) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster of allocation bitmap not allocated\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }

    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT UP-Case table directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    uint64_t table_size = 0;
    uint32_t first_cluster_of_table = 0;

    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* Check the size and the first cluster address. */
    table_size = tsk_getu64(fs->endian, dentry->table_length_in_bytes);
    first_cluster_of_table = tsk_getu32(fs->endian, dentry->first_cluster_of_table);

    if (table_size == 0) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: table size is zero\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* Is the table size less than the size of the cluster heap 
     * (data area)? The cluster heap size is computed by multiplying the
     * cluster size by the number of sectors in a cluster and then 
     * multiplying by the number of bytes in a sector (the last operation 
     * is optimized as a left shift by the base 2 log of sector size). */
    if (table_size > (a_fatfs->clustcnt * a_fatfs->csize) << a_fatfs->ssize_sh) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: table size too big\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* Is the address of the first cluster in range? */
    if ((first_cluster_of_table < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_table > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, 
                "%s: first cluster not in cluster heap\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    if (!a_do_basic_test_only) {
        /* The first cluster of the table should be allocated. */
        if (fatfs_is_clustalloc(a_fatfs, (TSK_DADDR_T)first_cluster_of_table) != 1) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster of table not allocated\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }

    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT UP-Case table directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_TEX_FAT or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* There is not enough data in a texFAT directory entry
     * to test anything but the entry type byte. */
    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT access control table directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_ACT or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* There is not enough data in an access control table directory entry
     * to test anything but the entry type byte. */
    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    if (dentry->secondary_entries_count < EXFATFS_MIN_FILE_SECONDARY_DENTRIES_COUNT ||
        dentry->secondary_entries_count > EXFATFS_MAX_FILE_SECONDARY_DENTRIES_COUNT) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: secondary entries count out of range\n", 
                func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    /* Make sure the time stamps aren't all zeros. */
    // RJCTODO: Is this a valid test for exFAT?
    if ((tsk_getu16(fs->endian, dentry->modified_date) == 0) &&
        (tsk_getu16(fs->endian, dentry->modified_time) == 0) &&
        (dentry->modified_time_10_ms_increments == 0) && 
        (tsk_getu16(fs->endian, dentry->created_date) == 0) &&
        (tsk_getu16(fs->endian, dentry->created_time) == 0) &&
        (dentry->created_time_10_ms_increments == 0) && 
        (tsk_getu16(fs->endian, dentry->accessed_date) == 0) &&
        (tsk_getu16(fs->endian, dentry->accessed_time) == 0)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: time stamps all zero\n", 
                func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    if (!a_do_basic_test_only) {
        /* There is not enough data in a file directory entry for an 
         * in-depth test. */
        // RJCTODO: Consider using additional tests similar to bulk extractor tests.
    }

    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file stream directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry;
    uint64_t file_size = 0;
    uint32_t first_cluster = 0;

    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* Check the size and the first cluster address. */
    file_size = tsk_getu64(fs->endian, dentry->data_length); // RJCTODO: How does this relate to valid data length?
    first_cluster = tsk_getu32(fs->endian, dentry->first_cluster_addr);
    if (file_size > 0) {
        /* Is the file size less than the size of the cluster heap 
         * (data area)? The cluster heap size is computed by multiplying the
         * cluster size by the number of sectors in a cluster and then 
         * multiplying by the number of bytes in a sector (the last operation 
         * is optimized as a left shift by the base 2 log of sector size). */
        if (file_size > (a_fatfs->clustcnt * a_fatfs->csize) << a_fatfs->ssize_sh) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: file size too big\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }

        /* Is the address of the first cluster in range? */
        if ((first_cluster < EXFATFS_FIRST_CLUSTER) ||
            (first_cluster > a_fatfs->lastclust)) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster not in cluster heap\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }

    if ((!a_do_basic_test_only) && (file_size > 0)) {
        /* If the file is not marked as deleted and has non-zero size, is its
         * first cluster allocated? */
        if ((dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) && 
            (fatfs_is_clustalloc(a_fatfs, (TSK_DADDR_T)first_cluster) != 1)) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: file not deleted, first cluster not allocated\n", func_name);
            }
            return EXFATFS_DIR_ENTRY_TYPE_NONE;
        }
    }

    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether the contents of a 32 byte buffer are likely to be an
 * exFAT file name directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_FILE_NAME or EXFATFS_DIR_ENTRY_TYPE_NONE
 */
static EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);

    /* There is not enough data in a file name directory entry
     * to test anything but the entry type byte. */
    return (EXFATFS_DIR_ENTRY_TYPE_ENUM)a_dentry->data[0];
}

/**
 * \internal
 * Determine whether a buffer likely contains a directory entry.
 * For the most reliable results, request the in-depth test.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_do_basic_test_only Whether to do a basic or in-depth test. 
 * @returns EXFATFS_DIR_ENTRY_TYPE_NONE or another member of 
 * EXFATFS_DIR_ENTRY_TYPE_ENUM indicating a directory entry type.
 */
EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_dentry";
    TSK_FS_INFO *fs = NULL;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_dentry, "a_dentry", func_name)) {
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    fs = &(a_fatfs->fs_info);

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
 * Construct a single, non-resident data run for the TSK_FS_META object of a 
 * TSK_FS_FILE object.  
 *
 * @param [in, out] a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_make_contiguous_data_run(TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_make_contiguous_data_run";
    TSK_FS_META *fs_meta = NULL;
    TSK_FS_INFO *fs = NULL;
    FATFS_INFO *fatfs = NULL;
    TSK_DADDR_T first_cluster = 0;
    TSK_FS_ATTR_RUN *data_run;
    TSK_FS_ATTR *fs_attr = NULL;
    TSK_OFF_T alloc_size = 0;

    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);
    assert(a_fs_file->fs_info != NULL);

    fs_meta = a_fs_file->meta;
    fs = (TSK_FS_INFO*)a_fs_file->fs_info;
    fatfs = (FATFS_INFO*)fs;

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "%s: Loading attrs for inode: %" PRIuINUM
            "\n", func_name, a_fs_file->meta->addr);
    }

    /* Get the stashed first cluster address of the file. If the address does
     * not make sense, set the attribute state to TSK_FS_META_ATTR_ERROR so
     * that there is no subsequent attempt to load a data run for this 
     * file object. */
    first_cluster = ((TSK_DADDR_T*)fs_meta->content_ptr)[0];
    if ((first_cluster > (fatfs->lastclust)) &&
        (FATFS_ISEOF(first_cluster, fatfs->mask) == 0)) {
        fs_meta->attr_state = TSK_FS_META_ATTR_ERROR;
        tsk_error_reset();
        if (fs_meta->flags & TSK_FS_META_FLAG_UNALLOC) {
            tsk_error_set_errno(TSK_ERR_FS_RECOVER);
        }
        else {
            tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        }
        tsk_error_set_errstr
            ("%s: Starting cluster address too large: %"
            PRIuDADDR, func_name, first_cluster);
        return 1;
    }

    /* Figure out the allocated size of the file. The minimum allocation unit
     * for exFAT is a cluster, so the the roundup() function is used to round 
     * up the file size in bytes to a multiple of cluser size in bytes. */
    alloc_size = roundup(fs_meta->size, (fatfs->csize * fs->block_size));

    /* Allocate an attribute list for the file. */
    fs_meta->attr = tsk_fs_attrlist_alloc();

    /* Allocate a non-resident attribute for the file and add it to the
     * attribute list. */
    if ((fs_attr = tsk_fs_attrlist_getnew(fs_meta->attr, 
        TSK_FS_ATTR_NONRES)) == NULL) {
        return 1;
    }

    /* Allocate a single data run for the attribute. For exFAT, a data run is 
     * a contiguous run of sectors. */
    data_run = tsk_fs_attr_run_alloc();
    if (data_run == NULL) {
        return 1;
    }

    /* Set the starting sector address of the run and the length of the run 
     * in sectors. */
    data_run->addr = FATFS_CLUST_2_SECT(fatfs, first_cluster);
    data_run->len = roundup(fs_meta->size, 
        (fatfs->csize * fs->block_size)) / fs->block_size;  

    /* Add the data run to the attribute and add the attribute to the 
     * attribute list. Note that the initial size and the allocation
     * size are the same for exFAT. */
    if (tsk_fs_attr_set_run(a_fs_file, fs_attr, data_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            fs_meta->size,
            data_run->len * fs->block_size,
            data_run->len * fs->block_size, 
            TSK_FS_ATTR_FLAG_NONE, 0)) {
        return 1;
    }

    /* Mark the attribute list as loaded. */
    fs_meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return 0;
}

/**
 * \internal
 * Use a volume label directory entry corresponding to the exFAT 
 * equivalent of an inode to populate the TSK_FS_META object of a 
 * TSK_FS_FILE object.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_inum Address of the inode.
 * @param [in] a_dentries One or more directory entries.
 * @param a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_inode(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, EXFATFS_DENTRY_SET *a_dentries, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_vol_label_inode";
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentries != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)&a_dentries->dentries[0];
    assert(dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL ||
           dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY);

    /* If there is a volume label, copy it to the name field of the 
     * TSK_FS_META structure. */
    if (dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY) {
        if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_file->meta, 
            (UTF16*)dentry->volume_label, dentry->utf16_char_count + 1, 
            a_inum, "volume label") != TSKconversionOK) {
            return TSK_COR;
        }
    }

    return TSK_OK;
}

/**
 * \internal
 * Use an allocation bitmap directory entry corresponding to the exFAT 
 * equivalent of an inode to populate the TSK_FS_META object of a 
 * TSK_FS_FILE object.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param a_dentries [in] One or more directory entries.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_alloc_bitmap_inode(FATFS_INFO *a_fatfs, EXFATFS_DENTRY_SET *a_dentries, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_alloc_bitmap_inode";
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(a_dentries != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)&a_dentries->dentries[0];
    assert(dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP);

    /* Set the file name to a descriptive pseudo file name. */
    strcpy(a_fs_file->meta->name2->name, EXFATFS_ALLOC_BITMAP_VIRT_FILENAME);

    /* Set the size of the allocation bitmap and the address of its 
     * first cluster. */
    ((TSK_DADDR_T*)a_fs_file->meta->content_ptr)[0] = FATFS_SECT_2_CLUST(a_fatfs, a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap);
    a_fs_file->meta->size = a_fatfs->EXFATFS_INFO.length_of_alloc_bitmap_in_bytes;
    
    /* There is no FAT chain walk for the allocation bitmap. Do an eager
     * load instead of a lazy load of its data run. */
    if (exfatfs_make_contiguous_data_run(a_fs_file)) {
        return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * \internal
 * Use an UP-Case table directory entry corresponding to the exFAT equivalent
 * of an inode to populate the TSK_FS_META object of a TSK_FS_FILE object.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param a_dentries [in] One or more directory entries.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_upcase_table_inode(FATFS_INFO *a_fatfs, EXFATFS_DENTRY_SET *a_dentries, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_upcase_table_inode";
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(a_dentries != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)(&a_dentries[0]);
    assert(dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE);

    strcpy(a_fs_file->meta->name2->name, EXFATFS_UPCASE_TABLE_VIRT_FILENAME);

    /* Set the size of the Up-Case table and the address of its 
     * first cluster. */
    ((TSK_DADDR_T*)a_fs_file->meta->content_ptr)[0] = tsk_getu32(a_fatfs->fs_info.endian, dentry->first_cluster_of_table);
    a_fs_file->meta->size = tsk_getu64(a_fatfs->fs_info.endian, dentry->table_length_in_bytes);

    /* There is no FAT chain walk for the upcase table. Do an eager
     * load instead of a lazy load of its data run. */
    if (exfatfs_make_contiguous_data_run(a_fs_file)) {
        return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * \internal
 * Use a a file and a file stream directory entry corresponding to the exFAT 
 * equivalent of an inode to populate the TSK_FS_META object of a TSK_FS_FILE 
 * object.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param a_dentries [in] One or more directory entries.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_inode(FATFS_INFO *a_fatfs, EXFATFS_DENTRY_SET *a_dentries, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_file_inode";
    TSK_FS_INFO *fs = NULL;
    TSK_FS_META *fs_meta =  NULL;
    EXFATFS_FILE_DIR_ENTRY *dentry = NULL;
    EXFATFS_FILE_STREAM_DIR_ENTRY *stream_dentry = NULL;
    uint32_t mode = 0;

    assert(a_fatfs != NULL);
    assert(a_dentries != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    fs = &(a_fatfs->fs_info);
    fs_meta = a_fs_file->meta;

    dentry = (EXFATFS_FILE_DIR_ENTRY*)(&a_dentries->dentries[0]);
    assert(dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE ||
           dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE);

    /* Regular file or directory? */
    if (dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        fs_meta->type = TSK_FS_META_TYPE_DIR;
    }
    else {
        fs_meta->type = TSK_FS_META_TYPE_REG;
    }

    /* Mode? */
    mode = fs_meta->mode; 
    if ((dentry->attrs[0] & FATFS_ATTR_READONLY) == 0) {
        mode |=
            (TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IRGRP |
            TSK_FS_META_MODE_IROTH);
    }
    if ((dentry->attrs[0] & FATFS_ATTR_HIDDEN) == 0) {
        mode |=
            (TSK_FS_META_MODE_IWUSR | TSK_FS_META_MODE_IWGRP |
            TSK_FS_META_MODE_IWOTH);
    }
    fs_meta->mode = (TSK_FS_META_MODE_ENUM)mode;

    /* There is no notion of links in exFAT, just deleted or not deleted. 
     * If the file is not deleted, treat this as having one link. */
    fs_meta->nlink = (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) ? 0 : 1;

    /* Copy the last modified time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->modified_date))) {
        fs_meta->mtime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->modified_time),
            tsk_getu16(fs->endian, dentry->modified_date), 
            dentry->modified_time_10_ms_increments);
    }
    else {
        fs_meta->mtime = 0;
        fs_meta->mtime_nano = 0;
    }

    /* Copy the last accessed time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->accessed_date))) {
        fs_meta->atime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->accessed_time), 
            tsk_getu16(fs->endian, dentry->accessed_date), 0);
    }
    else {
        fs_meta->atime = 0;
    }
    fs_meta->atime_nano = 0;

    /* exFAT does not have a last changed time. */
    fs_meta->ctime = 0;
    fs_meta->ctime_nano = 0;

    /* Copy the created time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, dentry->created_date))) {
        fs_meta->crtime =
            dos2unixtime(tsk_getu16(fs->endian, dentry->created_time),
            tsk_getu16(fs->endian, dentry->created_date), 
            dentry->created_time_10_ms_increments); // RJCTODO: Is this correct? The comments on the conversion routine may be incorrect...
        fs_meta->crtime_nano = dos2nanosec(dentry->created_time_10_ms_increments);
    }
    else {
        fs_meta->crtime = 0;
        fs_meta->crtime_nano = 0;
    }

    stream_dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)(&a_dentries->dentries[1]);
    if (stream_dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM ||
        stream_dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM) {

        assert((dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE && 
                stream_dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) ||
               (dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE &&
                stream_dentry->entry_type == 
                EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM));

        /* Set the size of the file and the address of its first cluster. */
        ((TSK_DADDR_T*)a_fs_file->meta->content_ptr)[0] = 
            tsk_getu32(a_fatfs->fs_info.endian, stream_dentry->first_cluster_addr);
        fs_meta->size = tsk_getu64(fs->endian, stream_dentry->data_length); //RJCTODO: How does this relate to valid data length?

        /* If the FAT chain bit of the secondary flags of the stream entry is set,
         * the file is not fragmented and there is no FAT chain to walk. Do an 
         * eager load instead of a lazy load of its data run. */
        if ((stream_dentry->flags & EXFATFS_INVALID_FAT_CHAIN_MASK) &&
            (exfatfs_make_contiguous_data_run(a_fs_file))) {
            return TSK_ERR;
        }
    }

    return TSK_OK;
}

/**
 * \internal
 * Use a file name directory entry corresponding to the exFAT equivalent of
 * an inode to populate the TSK_FS_META object of a TSK_FS_FILE object.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_inum Address of the inode.
 * @param [in] a_dentries One or more directory entries.
 * @param a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_inode(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, EXFATFS_DENTRY_SET *a_dentries, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_file_name_inode";
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentries != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)(&a_dentries->dentries[0]);
    assert(dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME ||
           dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME);

    if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_file->meta, 
        (UTF16*)dentry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH,
        a_inum, "file name segment") == TSKconversionOK) {
        return TSK_OK;
    }
    else {
        return TSK_COR;
    }
}

/**
 * \internal
 * Initialize the members of a TSK_FS_META object before copying the contents
 * of an an inode consisting of one or more raw exFAT directry entries into it. 
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in] a_inum Address of the inode.
 * @param [in] a_is_alloc Allocation status of the sector that contains the
*  inode.
 * @param [in, out] a_fs_file Generic file with generic inode structure to 
 * initialize.
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_inode_copy_init(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_inode_copy_init";
    TSK_FS_META *fs_meta = NULL;
    int8_t ret_val = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    fs_meta = a_fs_file->meta;

    /* Record allocation status and the inode address. */
    fs_meta->flags = a_is_alloc ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC;
    fs_meta->addr = a_inum;

    /* As for FATXX, make regular file the default type. */
    fs_meta->type = TSK_FS_META_TYPE_REG;

    /* As for FATXX, mark everything as executable. */
    fs_meta->mode = (TSK_FS_META_MODE_ENUM)(TSK_FS_META_MODE_IXUSR | TSK_FS_META_MODE_IXGRP |
        TSK_FS_META_MODE_IXOTH);

    /* There is no notion of links in exFAT, just deleted or not deleted. 
     * With not deleted being equivalent to having one link, set nlink to 1
     * here so that it will be set for static things like the allocation 
     * bitmap. The code for file inodes can reset or unset it appropriately. */
    fs_meta->nlink = 1;

    /* Initialize size to zero. The code for particular inode types will 
     * fill in another value, if appropriate. */
    fs_meta->size = 0;

    /* Default values for time stamp metadata. The code for file inodes will 
     * fill in actual time stamp data. */
    fs_meta->mtime = 0;
    fs_meta->mtime_nano = 0;
    fs_meta->atime = 0;
    fs_meta->atime_nano = 0;
    fs_meta->ctime = 0;
    fs_meta->ctime_nano = 0;
    fs_meta->crtime = 0;
    fs_meta->crtime_nano = 0;

    /* Metadata that does not exist in exFAT. */
    fs_meta->uid = 0;
    fs_meta->gid = 0;
    fs_meta->seq = 0;

    /* Allocate space for a name. */
    if (fs_meta->name2 == NULL) {
        if ((fs_meta->name2 = (TSK_FS_META_NAME_LIST*)tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 1;
        }
        fs_meta->name2->next = NULL;
    }

    /* Allocate space for saving the cluster address of the first cluster 
     * of file inodes, including allocation bitmaps and upcase tables. */
    if (fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((fs_meta =
                tsk_fs_meta_realloc(fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }

    /* Mark the generic attribute list as not in use (in the generic file model
     * attributes are containers for data or metadata). Population of this 
     * stuff is done on demand (lazy look up). */
    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    return 0;
}

/**
 * \internal
 * Use one or more directory entries corresponding to the exFAT equivalent of
 * an inode to populate the TSK_FS_META object of a TSK_FS_FILE object.
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in] a_dentries One or more directory entries.
 * @param [in] a_inum Address of the inode.
 * @param [in] a_is_alloc Allocation status of the inode.
 * @param [in, out] a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM
exfatfs_copy_inode(FATFS_INFO *a_fatfs, EXFATFS_DENTRY_SET *a_dentries, 
    TSK_INUM_T a_inum, uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_copy_inode";

    assert(a_fatfs != NULL);
    assert(a_dentries != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    if (exfatfs_inode_copy_init(a_fatfs, a_inum, a_is_alloc, a_fs_file)) {
        return TSK_ERR;
    }

    switch (a_dentries->dentries[0].data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_copy_vol_label_inode(a_fatfs, a_inum, a_dentries, a_fs_file);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_VOLUME_GUID_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_copy_alloc_bitmap_inode(a_fatfs, a_dentries, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_copy_upcase_table_inode(a_fatfs, a_dentries, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_TEX_FAT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_ACT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
        return exfatfs_copy_file_inode(a_fatfs, a_dentries, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
        return exfatfs_copy_file_name_inode(a_fatfs, a_inum, a_dentries, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
    default:
        /* Stream entries are copied in tandem with the corresponding file entry. */
        return TSK_ERR;
    }

    return TSK_OK;
}

/**
 * \internal
 * Given an inode address, load the corresponding directory entry and test
 * to see if it's an exFAT file stream directory entry.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param a_stream_entry_inum [in] The inode address associated with the 
 * supposed file stream entry.
 * @param a_sector_is_alloc [in] The allocation status of the sector that
 * contains the supposed file stream entry.
 * @param a_file_dentry_type [in] The companion file entry type, 
 * deleted or not.
 * @param a_dentry [in, out] A directory entry structure. The stream 
 * entry, if found, will be loaded into it.
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_load_and_test_file_stream_dentry(FATFS_INFO *a_fatfs, 
    TSK_INUM_T a_stream_entry_inum, uint8_t a_sector_is_alloc, 
    EXFATFS_DIR_ENTRY_TYPE_ENUM a_file_dentry_type,
    FATFS_DENTRY *a_dentry)
{
    EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_stream_entry_inum));
    assert(a_dentry != NULL);

    if (fatfs_dentry_load(a_fatfs, a_dentry, a_stream_entry_inum) == 0) {
        /* Is the next entry likely a stream entry? */
        dentry_type = exfatfs_is_dentry(a_fatfs, a_dentry, a_sector_is_alloc);

        /* If it is and its not deleted/deleted status matches that of the
            * file entry, call it good. */
        if ((a_file_dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE && 
             dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) ||
            (a_file_dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE &&
             dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM)) {
            return 0;
        }
    }

    /* Did not find the file stream entry. */
    memset((void*)a_dentry, 0, sizeof(FATFS_DENTRY));
    return 1;
}

/**
 * \internal
 * Given an exFAT file directory entry, try to find the corresponding file
 * stream directory entry.
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in] a_file_entry_inum The inode address associated with the file 
 * entry.
 * @param [in] a_sector The address of the sector where the file entry was 
 * found.
 * @param [in] a_sector_is_alloc The allocation status of the sector.
 * @param [in] a_file_dentry_type The file entry type, deleted or not.
 * @param [in, out] a_dentry_set A directory entry set with the file entry 
 * as the first entry. The stream entry, if found, will be loaded into the
 * second entry in the set.
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_load_file_stream_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_file_entry_inum, 
    TSK_DADDR_T a_sector, uint8_t a_sector_is_alloc,  
    EXFATFS_DIR_ENTRY_TYPE_ENUM a_file_dentry_type,
    EXFATFS_DENTRY_SET *a_dentry_set)
{
    const char *func_name = "exfatfs_load_file_stream_dentry";
    TSK_INUM_T stream_entry_inum = 0;
    TSK_DADDR_T cluster = 0;
    TSK_DADDR_T cluster_base_sector = 0;
    TSK_DADDR_T last_entry_offset = 0;
    TSK_DADDR_T file_entry_offset = 0;
    EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
    TSK_DADDR_T next_cluster = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_file_entry_inum));
    assert(a_dentry_set != NULL);

    /* Check for the most common case first - the file stream entry is located
     * immediately after the file entry. This should be true for any file 
     * entry for a non-deleted file in an allocated cluster, provided that 
     * the entry is not the last 32 bytes of the cluster. Even then, if the
     * directory is not fragmented, the stream entry will still follow the
     * file entry. Finally, if the file entry is for a deleted file and it was
     * found in an unallocated cluster, the only viable place to look for the
     * stream entry is in the bytes following the file entry. */
    stream_entry_inum = a_file_entry_inum + 1;
    if (fatfs_is_inum_in_range(a_fatfs, stream_entry_inum)) {
        if (exfatfs_load_and_test_file_stream_dentry(a_fatfs, 
            stream_entry_inum, a_sector_is_alloc, 
            a_file_dentry_type, 
            &(a_dentry_set->dentries[1])) == 0) {
            /* Found it. */
            return 0;
        }
    }

    /* If the stream entry was not found immediately following the file entry
     * and the cluster is allocated, it is possible that the file entry was the
     * last thirty two bytes of a cluster in a fragmented directory. In this
     * case, the FAT can be consulted to see if there is a next cluster. If 
     * so, the stream entry may be the first 32 bytes of that cluster. */
    if (a_sector_is_alloc) {
        /* Calculate the byte offset of the last possible directory entry in 
         * the current cluster. */
        cluster = FATFS_SECT_2_CLUST(a_fatfs, a_sector);
        cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, cluster); 
        last_entry_offset = (cluster_base_sector * a_fatfs->ssize) + 
            (a_fatfs->csize * a_fatfs->ssize) - sizeof(FATFS_DENTRY);   

        /* Get the byte offset of the file entry. */
        file_entry_offset = FATFS_INODE_2_OFF(a_fatfs, a_file_entry_inum);

        if (file_entry_offset == last_entry_offset) {
            /* The file entry is the last in its cluster. Look up the next
             * cluster. */
            if ((fatfs_getFAT(a_fatfs, cluster, &next_cluster) == 0) &&
                (next_cluster != 0)) {
                /* Found the next cluster in the FAT, so get its first sector
                 * and the inode address of the first bytes of the sector. */
                cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, cluster); 
                stream_entry_inum = FATFS_SECT_2_INODE(a_fatfs, 
                    cluster_base_sector);

                if (!fatfs_is_inum_in_range(a_fatfs, stream_entry_inum)) {
                    if (exfatfs_load_and_test_file_stream_dentry(a_fatfs, 
                        stream_entry_inum, a_sector_is_alloc, 
                        a_file_dentry_type, 
                        &(a_dentry_set->dentries[1])) == 0) {
                        /* Found it. */
                        return 0;
                    }
                }
            }
        }
    }

    /* Did not find the file stream entry. */
    return 1;
}

/**
 * \internal
 * Read in the bytes from an exFAT file system that correspond to the exFAT 
 * equivalent of an inode and use them to populate the TSK_FS_META object of
 * a TSK_FS_FILE object.
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in, out] a_fs_file The TSK_FS_FILE object.
 * @param [in] a_inum Inode address.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file, 
    TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_inode_lookup";
    TSK_DADDR_T sector = 0;
    int8_t sect_is_alloc = 0;
    EXFATFS_DENTRY_SET dentry_set;
    uint64_t inode_offset = 0;
    TSK_DADDR_T cluster_base_sector = 0;
    TSK_INUM_T next_inum = 0;
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
    TSK_RETVAL_ENUM copy_result = TSK_OK;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_file, "a_fs_file", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_file->meta, "a_fs_file->meta", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_file->fs_info, "a_fs_file->fs_info", func_name) ||
        !fatfs_is_inum_arg_in_range(a_fatfs, a_inum, func_name)) {
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

    /* Check the allocation status of the sector. This status will be used
     * not only as metadata to be reported, but also as a way to choose
     * between the basic or in-depth version of the tests (below) that 
     * determine whether or not the bytes corrresponding to the inode are 
     * likely to be a directory entry. Note that in other places in the code 
     * information about whether or not the sector that contains the inode is
     * part of a folder is used to select the test. Here, that information is 
     * not available, so the test here is less reliable and may result in some 
     * false positives. */
    sect_is_alloc = fatfs_is_sectalloc(a_fatfs, sector);
    if (sect_is_alloc == -1) {
        return 1;
    }

    /* Load the bytes at the inode address. */
    memset((void*)&dentry_set, 0, sizeof(FATFS_DENTRY) * 2);
    if (fatfs_dentry_load(a_fatfs, &dentry_set.dentries[0], a_inum)) {
        return 1;
    }

    /* Try typing the bytes as a directory entry.*/
    dentry_type = exfatfs_is_dentry(a_fatfs, &dentry_set.dentries[0], sect_is_alloc);

    /* For the purposes of inode lookup, the file and file stream entries that
     * begin a file entry set (a file entry, a file stream antry, and 1-17 
     * file name entries) are mapped to a single inode. Thus, 1) file stream 
     * entries are not treated as independent inodes and 2) when a file entry
     * is found, the companion file stream entry needs to be read in, too. */
    if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_NONE ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM) {
        /* Report not an inode. */
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM " is not an inode", func_name, 
            a_inum);
        return 1;
    }
    else if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE ||
             dentry_type == EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE) {
        /* Read in the file stream entry. If not successful, at least
         * return the file entry metadata. */
        exfatfs_load_file_stream_dentry(a_fatfs, a_inum, sector, sect_is_alloc, 
            dentry_type, &dentry_set);
    }
    else {
        /* The entry is one of the one entry, one inode types. */
        if (fatfs_dentry_load(a_fatfs, &dentry_set.dentries[0], a_inum)) {
            return 1;
        }
    }

    /* Populate the TSK_FS_META object. */
    copy_result = exfatfs_copy_inode(a_fatfs, &dentry_set, a_inum, 
        sect_is_alloc, a_fs_file); 
    if (copy_result == TSK_OK) {
        return 0;
    }
    else if (copy_result == TSK_COR) {
        /* If there was a Unicode conversion error on a string, but the rest 
         * of the inode metadata is probably o.k. Report the error, but also
         report a successful look up.*/
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

/**
 * \internal
 * Output file attributes for an exFAT directory entry/inode in 
 * human-readable form.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_inum Inode address associated with the directory entry.
 * @param [in] a_hFile Handle of the file to which to write.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
exfatfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum,  FILE *a_hFile)
{
    const char *func_name = "exfatfs_istat_attr_flags";
    FATFS_DENTRY dentry;
    EXFATFS_FILE_DIR_ENTRY *file_dentry = NULL;
    uint16_t attr_flags = 0;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_is_inum_arg_in_range(a_fatfs, a_inum, func_name)) {
        return 1; 
    }

    /* Load the bytes at the inode address. */
    if (fatfs_dentry_load(a_fatfs, (FATFS_DENTRY*)(&dentry), a_inum)) {
        return 1; 
    }

    /* Print the attributes. */
    switch (dentry.data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        tsk_fprintf(a_hFile, "Volume Label\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        tsk_fprintf(a_hFile, "Volume GUID\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:     
        tsk_fprintf(a_hFile, "Allocation Bitmap\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:     
        tsk_fprintf(a_hFile, "Up-Case Table\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:     
        tsk_fprintf(a_hFile, "TexFAT\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        tsk_fprintf(a_hFile, "Access Control Table\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
        file_dentry = (EXFATFS_FILE_DIR_ENTRY*)&dentry;
        attr_flags = tsk_getu16(a_fatfs->fs_info.endian, file_dentry->attrs);

        if (attr_flags & FATFS_ATTR_DIRECTORY) {
            tsk_fprintf(a_hFile, "Directory");
        }
        else {
            tsk_fprintf(a_hFile, "File");
        }

        if (attr_flags & FATFS_ATTR_READONLY) {
            tsk_fprintf(a_hFile, ", Read Only");
        }

        if (attr_flags & FATFS_ATTR_HIDDEN) {
            tsk_fprintf(a_hFile, ", Hidden");
        }

        if (attr_flags & FATFS_ATTR_SYSTEM) {
            tsk_fprintf(a_hFile, ", System");
        }

        if (attr_flags & FATFS_ATTR_ARCHIVE) {
            tsk_fprintf(a_hFile, ", Archive");
        }

        tsk_fprintf(a_hFile, "\n");

        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
        tsk_fprintf(a_hFile, "File Stream\n"); 
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
        tsk_fprintf(a_hFile, "File Name\n");
        break;
    default:
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " is not an exFAT directory entry", func_name, a_inum);
        return 1;
    }

    return 0;
}