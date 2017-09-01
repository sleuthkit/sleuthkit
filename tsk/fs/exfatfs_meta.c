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
 * Checks whether a specified cluster is allocated according to the allocation 
 * bitmap of an exFAT file system. 
 *
 * @param [in] a_fatfs A FATFS_INFO struct representing an exFAT file system.
 * @param [in] a_cluster_addr The cluster address of the cluster to check. 
 * @return 1 if the cluster is allocated, 0 if the cluster is not allocated, 
 * or -1 if an error occurs.
 */
int8_t 
exfatfs_is_cluster_alloc(FATFS_INFO *a_fatfs, TSK_DADDR_T a_cluster_addr)
{
    const char *func_name = "exfatfs_is_clust_alloc";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSK_DADDR_T bitmap_byte_offset = 0;
    uint8_t bitmap_byte;
    ssize_t bytes_read = 0;

    assert(a_fatfs != NULL);
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name)) {
        return -1;
    }

    assert((a_cluster_addr >= FATFS_FIRST_CLUSTER_ADDR) && (a_cluster_addr <= a_fatfs->lastclust));
    if ((a_cluster_addr < FATFS_FIRST_CLUSTER_ADDR) || (a_cluster_addr > a_fatfs->lastclust)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: cluster address %" PRIuINUM " out of range", func_name, a_cluster_addr);
        return -1;
    }

     /* Normalize the cluster address. */
    a_cluster_addr = a_cluster_addr - FATFS_FIRST_CLUSTER_ADDR;

    /* Determine the offset of the byte in the allocation bitmap that contains
     * the bit for the specified cluster. */
    bitmap_byte_offset = (a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap * a_fatfs->ssize) + (a_cluster_addr / 8);

    /* Read the byte. */
    bytes_read = tsk_fs_read(fs, bitmap_byte_offset, (char*)&bitmap_byte, 1);
    if (bytes_read != 1) {
        if (bytes_read >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("%s: failed to read bitmap byte at offset %" PRIuINUM "", func_name, bitmap_byte_offset); 
        return -1;
    }

    /* Check the bit that corresponds to the specified cluster. Note that this
     * computation does not yield 0 or 1. */
    if (bitmap_byte & (1 << (a_cluster_addr % 8))) {
        return 1;
    }
    else {
        return 0;
    }
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT volume label
 * directory entry.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @returns 1 if the directory entry buffer likely contains a volume label 
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_vol_label_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc)
{
    const char *func_name = "exfatfs_is_vol_label_dentry";
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    uint8_t i = 0;
    
    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL) {
        return 0;
    }

    /* There should be a single volume label directory entry at the
     * beginning of the root directory, so check the allocation status, if 
     * known, of the cluster from which the buffer was filled. */
    if (a_cluster_is_alloc == FATFS_DATA_UNIT_ALLOC_STATUS_UNALLOC) {
        return 0;
    }

    if(exfatfs_get_alloc_status_from_type(dentry->entry_type) == 1){
        /* There is supposed to be a label, check its length. */
        if ((dentry->volume_label_length_chars < 1) || (dentry->volume_label_length_chars > EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR)) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: incorrect volume label length\n", func_name);
            }
            return 0;
        }
    }
    else {
        /* There is supposed to be no label, check for a zero in the length
         * field. */
        if (dentry->volume_label_length_chars != 0x00) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: volume label length non-zero for no label entry\n", func_name);
            }
            return 0;
        }

        /* Every byte of the UTF-16 volume label string should be 0. */
        for (i = 0; i < EXFATFS_MAX_VOLUME_LABEL_LEN_BYTE; ++i) {
            if (dentry->volume_label[i] != 0x00) {
                if (tsk_verbose) {
                    fprintf(stderr, "%s: non-zero byte in label for no label entry\n", func_name);
                }
                return 0;
            }
        }
    }

    return 1;
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT volume GUID
 * directory entry.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @returns 1 if the directory entry buffer likely contains a volume GUID 
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_vol_guid_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status)
{
    const char *func_name = "exfatfs_is_vol_guid_dentry";
    EXFATFS_VOL_GUID_DIR_ENTRY *dentry = (EXFATFS_VOL_GUID_DIR_ENTRY*)a_dentry;
    
    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID) {
        return 0;
    }

    /* There is not enough data in a volume GUID directory entry to test
     * anything but the entry type byte. However, a volume GUID directory 
     * entry should be in allocated space, so check the allocation status, if
     * known, of the cluster from which the buffer was filled to reduce false
     * positives. */
    return ((a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_ALLOC) ||
            (a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN));
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT allocation bitmap
 * directory entry. The test will be more reliable if an optional FATFS_INFO 
 * struct representing the file system is provided.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @param [in] a_fatfs A FATFS_INFO struct representing an exFAT file system,
 * may be NULL.
 * @returns 1 if the directory entry buffer likely contains an allocation 
 * bitmap directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_alloc_bitmap_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status, FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_is_alloc_bitmap_dentry";
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_bitmap = 0;
    uint64_t length_of_alloc_bitmap_in_bytes = 0;

    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP) {
        return 0;
    }

    /* There should be a single allocation bitmap directory entry near the the
     * beginning of the root directory, so check the allocation status, if 
     * known, of the cluster from which the buffer was filled. */
    if (a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_UNALLOC) {
        return 0;
    }

    if (a_fatfs != NULL) {
        /* The length of the allocation bitmap should be consistent with the 
         * number of clusters in the data area as specified in the volume boot
         * record. */
        length_of_alloc_bitmap_in_bytes = tsk_getu64(a_fatfs->fs_info.endian, dentry->length_of_alloc_bitmap_in_bytes);
        if (length_of_alloc_bitmap_in_bytes != (a_fatfs->clustcnt + 7) / 8) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: bitmap length incorrect\n", func_name);
            }
            return 0;
        }

        /* The first cluster of the bit map should be within the data area.
         * It is usually in the first cluster. */
        first_cluster_of_bitmap = tsk_getu32(a_fatfs->fs_info.endian, dentry->first_cluster_of_bitmap);
        if ((first_cluster_of_bitmap < EXFATFS_FIRST_CLUSTER) ||
            (first_cluster_of_bitmap > a_fatfs->lastclust)) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
            }
            return 0;
        }
        
        /* The first cluster of the allocation bitmap should be allocated (the 
         * other conditions allow this function to be safely used to look for
         * the allocation bitmap during FATFS_INFO initialization, before a 
         * cluster allocation is possible). */
        if ((a_fatfs->EXFATFS_INFO.first_sector_of_alloc_bitmap > 0) &&
            (a_fatfs->EXFATFS_INFO.length_of_alloc_bitmap_in_bytes > 0) &&
            (exfatfs_is_cluster_alloc(a_fatfs, (TSK_DADDR_T)first_cluster_of_bitmap) != 1)) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster of allocation bitmap not allocated\n", func_name);
            }
            return 0;
        }
    }

    return 1;
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT upcase table
 * directory entry. The test will be more reliable if an optional FATFS_INFO 
 * struct representing the file system is provided.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @param [in] a_fatfs A FATFS_INFO struct representing an exFAT file system,
 * may be NULL.
 * @returns 1 if the directory entry buffer likely contains an upcase table 
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_upcase_table_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status, FATFS_INFO *a_fatfs)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    uint64_t table_size = 0;
    uint32_t first_cluster_of_table = 0;

    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE) {
        return 0;
    }

    /* There should be a single upcase table directory entry near the the
     * beginning of the root directory, so check the allocation status, if 
     * known, of the cluster from which the buffer was filled. */
    if (a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_UNALLOC) {
        return 0;
    }

    if (a_fatfs != NULL) {
        /* Check the size of the table. */
        table_size = tsk_getu64(a_fatfs->fs_info.endian, dentry->table_length_in_bytes);
        if (table_size == 0) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: table size is zero\n", func_name);
            }
            return 0;
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
            return 0;
        }

        /* Is the address of the first cluster in range? */
        first_cluster_of_table = tsk_getu32(a_fatfs->fs_info.endian, dentry->first_cluster_of_table);
        if ((first_cluster_of_table < EXFATFS_FIRST_CLUSTER) ||
            (first_cluster_of_table > a_fatfs->lastclust)) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster not in cluster heap\n", func_name);
            }
            return 0;
        }

        /* The first cluster of the table should be allocated. */
        if (exfatfs_is_cluster_alloc(a_fatfs, (TSK_DADDR_T)first_cluster_of_table) != 1) {
            if (tsk_verbose) {
                fprintf(stderr, 
                    "%s: first cluster of table not allocated\n", func_name);
            }
            return 0;
        }
    }

    return 1;
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT TexFAT directory
 * entry.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @returns 1 if the directory entry buffer likely contains a TexFAT directory
 * entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_texfat_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status)
{
    const char *func_name = "exfatfs_is_texfat_dentry";
    EXFATFS_TEXFAT_DIR_ENTRY *dentry = (EXFATFS_TEXFAT_DIR_ENTRY*)a_dentry;
    
    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_TEXFAT) {
        return 0;
    }

    /* There is not enough data in a TexFAT directory entry to test anything
     * but the entry type byte. However, a TexFAT directory entry should be in 
     * allocated space, so check the allocation status, if known, of the 
     * cluster from which the buffer was filled to reduce false positives. */
    return ((a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_ALLOC) ||
            (a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN));
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT access control 
 * table directory entry.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_alloc_status The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @returns 1 if the directory entry buffer likely contains an access control
 * table entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_access_ctrl_table_dentry(FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_alloc_status)
{
    const char *func_name = "exfatfs_is_texfat_dentry";
    EXFATFS_TEXFAT_DIR_ENTRY *dentry = (EXFATFS_TEXFAT_DIR_ENTRY*)a_dentry;
    
    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_TEXFAT) {
        return 0;
    }

    /* There is not enough data in an access control table directory entry to 
     * test anything but the entry type byte. However, an access control table
     * directory entry should be in allocated space, so check the allocation 
     * status, if known, of the cluster from which the buffer was filled to 
     * reduce false positives. */
    return ((a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_ALLOC) ||
            (a_alloc_status == FATFS_DATA_UNIT_ALLOC_STATUS_UNKNOWN));
}


/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT file directory 
 * entry. The test will be more reliable if an optional TSK_ENDIAN_ENUM value 
 * is known. This function was split into two parts so that the main 
 * test can be run without a FATFS_INFO object.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_fatfs A FATFS_INFO struct representing an exFAT file system,
 * may be NULL.
 * @returns 1 if the directory entry buffer likely contains a file directory 
 * entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_file_dentry(FATFS_DENTRY *a_dentry, FATFS_INFO *a_fatfs)
{
    if (a_fatfs != NULL) {
        TSK_FS_INFO *fs = &(a_fatfs->fs_info);
        return exfatfs_is_file_dentry_standalone(a_dentry, fs->endian);
    }
    else {
        return exfatfs_is_file_dentry_standalone(a_dentry, TSK_UNKNOWN_ENDIAN);
    }

}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT file directory 
 * entry. The test will be more reliable if an optional TSK_ENDIAN_ENUM value 
 * is known. This version of the function can be called without a TSK_FS_INFO
 * object.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_endian Endianness of the file system
 * @returns 1 if the directory entry buffer likely contains a file directory 
 * entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_file_dentry_standalone(FATFS_DENTRY *a_dentry, TSK_ENDIAN_ENUM a_endian)
{
    const char *func_name = "exfatfs_is_file_dentry";
    EXFATFS_FILE_DIR_ENTRY *dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_FILE){ 
        return 0;
    }

    /* A file directory entry is the first entry of a file directory entry set
     * consisting of a file directory entry followed by a file stream directory
     * entry and from 1 to 17 file name directory entries. The file stream and
     * file name entries are called secondary entries. */
    if (dentry->secondary_entries_count < EXFATFS_MIN_FILE_SECONDARY_DENTRIES_COUNT ||
        dentry->secondary_entries_count > EXFATFS_MAX_FILE_SECONDARY_DENTRIES_COUNT) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: secondary entries count out of range\n", 
                func_name);
        }
        return 0;
    }

    if (a_endian != TSK_UNKNOWN_ENDIAN) {  

        /* Make sure the time stamps aren't all zeros. */
        if ((tsk_getu16(a_endian, dentry->modified_date) == 0) &&
            (tsk_getu16(a_endian, dentry->modified_time) == 0) &&
            (dentry->modified_time_tenths_of_sec == 0) && 
            (tsk_getu16(a_endian, dentry->created_date) == 0) &&
            (tsk_getu16(a_endian, dentry->created_time) == 0) &&
            (dentry->created_time_tenths_of_sec == 0) && 
            (tsk_getu16(a_endian, dentry->accessed_date) == 0) &&
            (tsk_getu16(a_endian, dentry->accessed_time) == 0)) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: time stamps all zero\n", 
                    func_name);
            }
            return 0;
        }
    }

    return 1;
}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT file stream 
 * directory entry. The test will be more reliable if an optional FATFS_INFO 
 * struct representing the file system is provided. This function was 
 * split into two parts so that the main test can be run 
 * without a FATFS_INFO object.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_fatfs A FATFS_INFO struct representing an exFAT file system,
 * may be NULL.
 * @returns 1 if the directory entry buffer likely contains a file stream 
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_file_stream_dentry(FATFS_DENTRY *a_dentry, FATFS_INFO *a_fatfs)
{
    TSK_FS_INFO *fs = NULL;

    uint64_t cluster_heap_size = 0;

    if (a_fatfs != NULL) {
        fs = &(a_fatfs->fs_info);

        /* Calculate the size of the cluster heap. The cluster heap size 
         * is computed by multiplying the cluster size 
         * by the number of sectors in a cluster and then 
         * multiplying by the number of bytes in a sector (the last operation 
         * is optimized as a left shift by the base 2 log of sector size). */
        cluster_heap_size = (a_fatfs->clustcnt * a_fatfs->csize) << a_fatfs->ssize_sh;

        return exfatfs_is_file_stream_dentry_standalone(a_dentry, fs->endian, cluster_heap_size, a_fatfs->lastclust);
    }
    else{
        return exfatfs_is_file_stream_dentry_standalone(a_dentry, TSK_UNKNOWN_ENDIAN, 0, 0);
    }

}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT file stream 
 * directory entry. The test will be more reliable if the optional endianness
 * and cluster information are used. This version of the function can be 
 * called without a TSK_FS_INFO object.
 * 
 * The endianness must be known to run all of the extended tests. The other 
 * parameters can be set to zero if unknown and the function will run whichever
 * tests are possible with the given information.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_endian Endianness of the file system
 * @param [in] a_cluster_heap_size Size of the cluster heap (in bytes)
 * @param [in] a_last_cluster Last cluster in the file system
 * @returns 1 if the directory entry buffer likely contains a file stream 
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_file_stream_dentry_standalone(FATFS_DENTRY *a_dentry, TSK_ENDIAN_ENUM a_endian,
    uint64_t a_cluster_heap_size, TSK_DADDR_T a_last_cluster)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry;
    uint64_t file_size = 0;
    uint32_t first_cluster = 0;

    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* Check the entry type byte. */
    if (exfatfs_get_enum_from_type(dentry->entry_type) != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) { 
        return 0;
    }

   if (a_endian != TSK_UNKNOWN_ENDIAN) { 

        /* Check the size. */
        file_size = tsk_getu64(a_endian, dentry->data_length);
        if (file_size > 0) {
            /* Is the file size less than the size of the cluster heap 
             * (data area)? The cluster heap size is computed by multiplying the
             * cluster size by the number of sectors in a cluster and then 
             * multiplying by the number of bytes in a sector (the last operation 
             * is optimized as a left shift by the base 2 log of sector size). */
            if(a_cluster_heap_size > 0){
                if (file_size > a_cluster_heap_size) {
                    if (tsk_verbose) {
                        fprintf(stderr, "%s: file size too big\n", func_name);
                    }
                    return 0;
                }
            }

            /* Is the address of the first cluster in range? */
            first_cluster = tsk_getu32(a_endian, dentry->first_cluster_addr);
            if ((first_cluster < EXFATFS_FIRST_CLUSTER) ||
                ((a_last_cluster > 0) && (first_cluster > a_last_cluster))) {
                if (tsk_verbose) {
                    fprintf(stderr, 
                        "%s: first cluster not in cluster heap\n", func_name);
                }
                return 0;
            }
        }
   }
   return 1;

}

/**
 * \internal
 * Determine whether the contents of a buffer may be an exFAT file name 
 * directory entry.
 *
 * @param [in] a_dentry A directory entry buffer.
 * @returns 1 if the directory entry buffer likely contains an file name
 * directory entry, 0 otherwise. 
 */
uint8_t
exfatfs_is_file_name_dentry(FATFS_DENTRY *a_dentry)
{
    const char *func_name = "exfatfs_is_file_name_dentry";
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry;
    
    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    /* There is not enough data in a file name directory entry
     * to test anything but the entry type byte. */
    return (exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME);
}


/**
 * \internal
 * Determine whether a buffer likely contains a directory entry.
 * For the most reliable results, request the in-depth test.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_dentry Buffer that may contain a directory entry.
 * @param [in] a_cluster_is_alloc The allocation status, possibly unknown, of the 
 * cluster from which the buffer was filled. 
 * @param [in] a_do_basic_tests_only Whether to do basic or in-depth testing. 
 * @return 1 if the buffer likely contains a directory entry, 0 otherwise
 */
uint8_t
exfatfs_is_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, FATFS_DATA_UNIT_ALLOC_STATUS_ENUM a_cluster_is_alloc, uint8_t a_do_basic_tests_only)
{
    const char *func_name = "exfatfs_is_dentry";

    assert(a_dentry != NULL);
    if (fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 0;
    }

    switch (exfatfs_get_enum_from_type(a_dentry->data[0]))
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
        return exfatfs_is_vol_label_dentry(a_dentry, a_cluster_is_alloc);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        return exfatfs_is_vol_guid_dentry(a_dentry, a_cluster_is_alloc);
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_is_alloc_bitmap_dentry(a_dentry, a_cluster_is_alloc, a_fatfs);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_is_upcase_table_dentry(a_dentry, a_cluster_is_alloc, a_fatfs);
    case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
        return exfatfs_is_texfat_dentry(a_dentry, a_cluster_is_alloc);
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        return exfatfs_is_access_ctrl_table_dentry(a_dentry, a_cluster_is_alloc);
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
        return exfatfs_is_file_dentry(a_dentry, a_fatfs);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
        return exfatfs_is_file_stream_dentry(a_dentry, a_fatfs);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
        return exfatfs_is_file_name_dentry(a_dentry);
    default:
        return 0;
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
            fs_meta->size,
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
 * @param [in] a_dentry A volume label directory entry.
 * @param a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_inode(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, TSK_FS_FILE *a_fs_file)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL);

    /* If there is a volume label, copy it to the name field of the 
     * TSK_FS_META structure. */
    if (exfatfs_get_alloc_status_from_type(dentry->entry_type) == 1) {
        if (fatfs_utf16_inode_str_2_utf8(a_fatfs, (UTF16*)dentry->volume_label, (size_t)dentry->volume_label_length_chars,
            (UTF8*)a_fs_file->meta->name2->name, sizeof(a_fs_file->meta->name2->name), a_inum, "volume label") != TSKconversionOK) {
            return TSK_COR;
        }
    }
    else {
        strcpy(a_fs_file->meta->name2->name, EXFATFS_EMPTY_VOLUME_LABEL_DENTRY_NAME);
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
 * @param [in] a_dentry An allocation bitmap directory entry.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_alloc_bitmap_inode(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, TSK_FS_FILE *a_fs_file)
{
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_dentry;
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP);

    /* Set the file name to a descriptive pseudo file name. */
    strcpy(a_fs_file->meta->name2->name, EXFATFS_ALLOC_BITMAP_DENTRY_NAME);

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
 * @param [in] a_dentry An upcase table directory entry.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_upcase_table_inode(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, TSK_FS_FILE *a_fs_file)
{
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(a_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE);

    strcpy(a_fs_file->meta->name2->name, EXFATFS_UPCASE_TABLE_DENTRY_NAME);

    /* Set the size of the Up-Case table and the address of its 
     * first cluster. */((TSK_DADDR_T*)a_fs_file->meta->content_ptr)[0] = tsk_getu32(a_fatfs->fs_info.endian, dentry->first_cluster_of_table);
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
 * Given an inode address, load the corresponding directory entry and test
 * to see if it's an exFAT file stream directory entry.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param a_stream_entry_inum [in] The inode address associated with the 
 * supposed file stream entry.
 * @param a_sector_is_alloc [in] The allocation status of the sector that
 * contains the supposed file stream entry.
 * @param a_file_dentry_type [in] The companion file entry type, 
 * i.e., deleted or not.
 * @param a_dentry [in, out] A directory entry structure. The stream 
 * entry, if found, will be loaded into it.
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_load_file_stream_dentry(FATFS_INFO *a_fatfs, 
    TSK_INUM_T a_stream_entry_inum, uint8_t a_sector_is_alloc, 
    EXFATFS_DIR_ENTRY_TYPE a_file_dentry_type,
    FATFS_DENTRY *a_dentry)
{
    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_stream_entry_inum));
    assert(a_dentry != NULL);

    if (fatfs_dentry_load(a_fatfs, a_dentry, a_stream_entry_inum) == 0 &&
        exfatfs_is_dentry(a_fatfs, a_dentry, (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)a_sector_is_alloc, a_sector_is_alloc)) {
        /* If the bytes at the specified inode address are a file stream entry
         * with the same allocation status as the file entry, report success. */
        if((exfatfs_get_alloc_status_from_type(a_file_dentry_type) == exfatfs_get_alloc_status_from_type(a_dentry->data[0])) &&
            (exfatfs_get_enum_from_type(a_file_dentry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE) &&
            (exfatfs_get_enum_from_type(a_dentry->data[0]) == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM)) {
            return 0;
        }
    }

    memset((void*)a_dentry, 0, sizeof(FATFS_DENTRY));
    return 1;
}

/**
 * \internal
 * Given an exFAT directory entry, try to find the corresponding file
 * stream directory or file name directory entry that follows it and
 * return the inum.
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in] a_current_entry_inum The inode address associated with the current 
 * entry.
 * @param [in] a_file_dentry The file entry type (only use deleted or not)
 * @param [in] a_next_dentry_type The type of the dentry we're searching for
 * @param [out] a_next_inum The inode of the next stream/file name directory entry will be stored here (if found)
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_next_dentry_inum(FATFS_INFO *a_fatfs, TSK_INUM_T a_current_entry_inum, 
    EXFATFS_FILE_DIR_ENTRY *a_file_dentry, EXFATFS_DIR_ENTRY_TYPE_ENUM a_next_dentry_type,
	TSK_INUM_T * a_next_inum)
{
    int8_t alloc_check_ret_val = 0;
    uint8_t cluster_is_alloc = 0;
    TSK_DADDR_T sector = 0; 
    TSK_DADDR_T cluster = 0;
    TSK_DADDR_T cluster_base_sector = 0;
    TSK_DADDR_T last_entry_offset = 0;
    TSK_DADDR_T file_entry_offset = 0;
    TSK_DADDR_T next_cluster = 0;
	FATFS_DENTRY temp_dentry;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_current_entry_inum));
    assert(a_file_dentry != NULL);
        
	/* Only look for file stream and file name directory entries */
	if((a_next_dentry_type != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) &&
		(a_next_dentry_type != EXFATFS_DIR_ENTRY_TYPE_FILE_NAME)){
			return FATFS_FAIL;
	}

    sector = FATFS_INODE_2_SECT(a_fatfs, a_current_entry_inum);
    cluster = FATFS_SECT_2_CLUST(a_fatfs, sector);
    alloc_check_ret_val = exfatfs_is_cluster_alloc(a_fatfs, cluster);
    if (alloc_check_ret_val != -1) {
        cluster_is_alloc = (uint8_t)alloc_check_ret_val;
    }
    else {
        return FATFS_FAIL;
    }

    /* Check for the most common case first - the file stream/name entry is located
     * immediately after the specified one. This should always be true for any 
     * in-use file entry in an allocated cluster that is not the last entry in
     * the cluster. It will also be true if the previous entry is the last entry in 
     * the cluster and the directory that contains the file is not fragmented - 
     * the stream/name entry will simply be the first entry of the next cluster. 
     * Finally, if the previous entry is not in-use and was found in an unallocated 
     * sector, the only viable place to look for the next entry is in the 
     * bytes following the file entry, since there is no FAT chain to 
     * consult. */
    *a_next_inum = a_current_entry_inum + 1;
    if (fatfs_inum_is_in_range(a_fatfs, *a_next_inum)) {
		if(fatfs_dentry_load(a_fatfs, &temp_dentry, *a_next_inum) == 0){
			if(a_next_dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM){
				if(exfatfs_is_file_stream_dentry(&temp_dentry, a_fatfs)){
					return FATFS_OK;
				}
			}
			else if(a_next_dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME){
				if (exfatfs_is_file_name_dentry(&temp_dentry)){
					return FATFS_OK;
				}
			}
		}
    }

    /* If the stream/name entry was not found immediately following the file entry
     * and the cluster is allocated, it is possible that the previous entry was the
     * last entry of a cluster in a fragmented directory. In this
     * case, the FAT can be consulted to see if there is a next cluster. If 
     * so, the stream/name entry may be the first entry of that cluster. */
    if (cluster_is_alloc) {
        /* Calculate the byte offset of the last possible directory entry in 
         * the current cluster. */
        cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, cluster); 
        last_entry_offset = (cluster_base_sector * a_fatfs->ssize) + 
            (a_fatfs->csize * a_fatfs->ssize) - sizeof(FATFS_DENTRY);   

        /* Get the byte offset of the file entry. Note that FATFS_INODE_2_OFF
         * gives the offset relative to start of a sector. */
        file_entry_offset = (sector * a_fatfs->ssize) + 
            FATFS_INODE_2_OFF(a_fatfs, a_current_entry_inum);

        if (file_entry_offset == last_entry_offset) {
            /* The file entry is the last in its cluster. Look up the next
             * cluster. */
            if ((fatfs_getFAT(a_fatfs, cluster, &next_cluster) == 0) &&
                (next_cluster != 0)) {
                /* Found the next cluster in the FAT, so get its first sector
                 * and the inode address of the first entry of the sector. */
                cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, next_cluster); 
                *a_next_inum = FATFS_SECT_2_INODE(a_fatfs, 
                    cluster_base_sector);

                if (fatfs_inum_is_in_range(a_fatfs, *a_next_inum)) {
					if(fatfs_dentry_load(a_fatfs, &temp_dentry, *a_next_inum) == 0){
						if(a_next_dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM){
							if(exfatfs_is_file_stream_dentry(&temp_dentry, a_fatfs)){
								return FATFS_OK;
							}
						}
						else if(a_next_dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME){
							if (exfatfs_is_file_name_dentry(&temp_dentry)){
								return FATFS_OK;
							}
						}
					}
                }
            }
        }
    }

    /* Did not find the file stream/name entry. */
    return FATFS_FAIL;
}


/**
 * \internal
 * Use a a file and a file stream directory entry corresponding to the exFAT 
 * equivalent of an inode to populate the TSK_FS_META object of a TSK_FS_FILE 
 * object.
 *
 * @param a_fatfs [in] Source file system for the directory entries.
 * @param [in] a_inum Address of the inode. 
 * @param [in] a_dentry A file directory entry.
 * @param [in] a_is_alloc Allocation status of the sector that contains the
 * file directory entry.
 * @param a_fs_file [in, out] Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_inode(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_file_dentry, uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    TSK_FS_INFO *fs = NULL;
    TSK_FS_META *fs_meta =  NULL;
    EXFATFS_FILE_DIR_ENTRY *file_dentry = (EXFATFS_FILE_DIR_ENTRY*)a_file_dentry;
    EXFATFS_FILE_STREAM_DIR_ENTRY stream_dentry;
    uint32_t mode = 0;
	TSK_INUM_T stream_inum;
	TSK_INUM_T name_inum;
	TSK_INUM_T prev_inum;
    uint8_t name_bytes_written;
	int name_index;
	uint8_t bytes_to_copy;
	FATFS_DENTRY temp_dentry;
	char utf16_name[512];

    assert(a_fatfs != NULL);
    assert(a_file_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);
    assert(exfatfs_get_enum_from_type(file_dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE);

    fs = &(a_fatfs->fs_info);
    fs_meta = a_fs_file->meta;

    /* Determine whether the file is a regular file or directory. */
    if (file_dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        fs_meta->type = TSK_FS_META_TYPE_DIR;
    }
    else {
        fs_meta->type = TSK_FS_META_TYPE_REG;
    }

    /* Add mode flags corresponding to file attribute flags. */
    mode = fs_meta->mode; 
    if ((file_dentry->attrs[0] & FATFS_ATTR_READONLY) == 0) {
        mode |=
            (TSK_FS_META_MODE_IRUSR | TSK_FS_META_MODE_IRGRP |
            TSK_FS_META_MODE_IROTH);
    }
    if ((file_dentry->attrs[0] & FATFS_ATTR_HIDDEN) == 0) {
        mode |=
            (TSK_FS_META_MODE_IWUSR | TSK_FS_META_MODE_IWGRP |
            TSK_FS_META_MODE_IWOTH);
    }
    fs_meta->mode = (TSK_FS_META_MODE_ENUM)mode;

    /* There is no notion of links in exFAT, just deleted or not deleted. 
     * If the file is not deleted, treat this as having one link. */
    fs_meta->nlink = (exfatfs_get_alloc_status_from_type(file_dentry->entry_type) == 0) ? 0 : 1;

    /* Copy the last modified time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, file_dentry->modified_date))) {
        fs_meta->mtime =
            fatfs_dos_2_unix_time(tsk_getu16(fs->endian, file_dentry->modified_date),
                tsk_getu16(fs->endian, file_dentry->modified_time), 
                file_dentry->modified_time_tenths_of_sec);
        fs_meta->mtime_nano = fatfs_dos_2_nanosec(file_dentry->modified_time_tenths_of_sec);
    }
    else {
        fs_meta->mtime = 0;
        fs_meta->mtime_nano = 0;
    }

    /* Copy the last accessed time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, file_dentry->accessed_date))) {
        fs_meta->atime =
            fatfs_dos_2_unix_time(tsk_getu16(fs->endian, file_dentry->accessed_date), 
                tsk_getu16(fs->endian, file_dentry->accessed_time), 0);
    }
    else {
        fs_meta->atime = 0;
    }
    fs_meta->atime_nano = 0;

    /* exFAT does not have a last changed time. */
    fs_meta->ctime = 0;
    fs_meta->ctime_nano = 0;

    /* Copy the created time, converted to UNIX date format. */
    if (FATFS_ISDATE(tsk_getu16(fs->endian, file_dentry->created_date))) {
        fs_meta->crtime =
            fatfs_dos_2_unix_time(tsk_getu16(fs->endian, file_dentry->created_date),
                tsk_getu16(fs->endian, file_dentry->created_time), 
                file_dentry->created_time_tenths_of_sec);
        fs_meta->crtime_nano = fatfs_dos_2_nanosec(file_dentry->created_time_tenths_of_sec);
    }
    else {
        fs_meta->crtime = 0;
        fs_meta->crtime_nano = 0;
    }

    /* Attempt to load the file stream entry that goes with this file entry. 
     * If not successful, at least the file entry meta data will be returned. */
	if(exfatfs_next_dentry_inum(a_fatfs, a_inum, file_dentry, EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM, &stream_inum)){
		return TSK_OK;
	}

	if (exfatfs_load_file_stream_dentry(a_fatfs, stream_inum, a_is_alloc, 
        file_dentry->entry_type, (FATFS_DENTRY *)(&stream_dentry)) ) {
			return TSK_OK;
	}

    /* Set the size of the file and the address of its first cluster. */
    ((TSK_DADDR_T*)a_fs_file->meta->content_ptr)[0] = 
        tsk_getu32(a_fatfs->fs_info.endian, stream_dentry.first_cluster_addr);
    fs_meta->size = tsk_getu64(fs->endian, stream_dentry.data_length);

    /* Set the allocation status using both the allocation status of the 
     * sector that contains the directory entries and the entry type 
     * settings - essentially a "belt and suspenders" check. */
    if ((a_is_alloc) &&
        (exfatfs_get_alloc_status_from_type(file_dentry->entry_type) == 1) &&
        (exfatfs_get_alloc_status_from_type(stream_dentry.entry_type) == 1)) {
        a_fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;

        /* If the FAT chain bit of the secondary flags of the stream entry is set,
         * the file is not fragmented and there is no FAT chain to walk. If the 
         * file is not deleted, do an eager load instead of a lazy load of its 
         * data run. */
        if ((stream_dentry.flags & EXFATFS_INVALID_FAT_CHAIN_MASK) &&
            (exfatfs_make_contiguous_data_run(a_fs_file))) {
            return TSK_ERR;
        }
    }
    else {
        a_fs_file->meta->flags = TSK_FS_META_FLAG_UNALLOC;
    }

	/* Attempt to load the file name entry(entries) that go with this file entry
	 * First copy all UTF16 data into a single buffer
	 * If not successful, return what we have to this point with no error */
	memset(utf16_name, 0, sizeof(utf16_name));
    name_bytes_written = 0;
	prev_inum = stream_inum;
	for(name_index = 1; name_index < file_dentry->secondary_entries_count;name_index++){
		if(exfatfs_next_dentry_inum(a_fatfs, prev_inum, file_dentry, EXFATFS_DIR_ENTRY_TYPE_FILE_NAME, &name_inum)){
			/* Try to save what we've got (if we found at least one file name dentry) */
			if(name_index > 1){
				if(fatfs_utf16_inode_str_2_utf8(a_fatfs, (UTF16 *)utf16_name, name_bytes_written / 2,
					(UTF8*)a_fs_file->meta->name2->name, sizeof(a_fs_file->meta->name2->name), a_inum, "file name (partial)") != TSKconversionOK){
						return TSK_OK; /* Don't want to disregard valid data read earlier */
				}
			}
			return TSK_OK;
		}
		fatfs_dentry_load(a_fatfs, &temp_dentry, name_inum);
		if(stream_dentry.file_name_length_UTF16_chars * 2 - name_bytes_written > EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_BYTES){
            bytes_to_copy = EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_BYTES;
		}
		else{
            bytes_to_copy = stream_dentry.file_name_length_UTF16_chars * 2 - name_bytes_written;
		}
        memcpy(utf16_name + name_bytes_written, &(temp_dentry.data[2]), bytes_to_copy);

		prev_inum = name_inum;
        name_bytes_written += bytes_to_copy;
	}

	/* Copy the file name segment. */
	if(fatfs_utf16_inode_str_2_utf8(a_fatfs, (UTF16 *)utf16_name, name_bytes_written / 2,
		(UTF8*)a_fs_file->meta->name2->name, sizeof(a_fs_file->meta->name2->name), a_inum, "file name") != TSKconversionOK){
			return TSK_OK; /* Don't want to disregard valid data read earlier */
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
 * @param [in] a_is_alloc Allocation status of the sector that contains the
 * inode.
 * @param [in] a_dentry A file name directory entry.
 * @param a_fs_file Generic file with generic inode structure (TSK_FS_META).
 * @return TSK_RETVAL_ENUM.  
 */
static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_inode(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_dentry, uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry;
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME);

    /* Set the allocation status using both the allocation status of the 
     * sector that contains the directory entries and the entry type 
     * settings - essentially a "belt and suspenders" check. */
    if ((a_is_alloc) &&
        (exfatfs_get_alloc_status_from_type(dentry->entry_type) == 1)) {
        a_fs_file->meta->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;
    }
    else {
        a_fs_file->meta->flags = TSK_FS_META_FLAG_UNALLOC;
    }

    /* Copy the file name segment. */
    if (fatfs_utf16_inode_str_2_utf8(a_fatfs, (UTF16*)dentry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_CHARS, 
        (UTF8*)a_fs_file->meta->name2->name, sizeof(a_fs_file->meta->name2->name), a_inum, "file name segment") != TSKconversionOK) {
        return TSK_COR;
    }
    return TSK_OK;
}

/**
 * \internal
 * Initialize the members of a TSK_FS_META object before copying the contents
 * of an an inode consisting of one or more raw exFAT directory entries into it.
 *
 * @param [in] a_fatfs Source file system for the directory entries.
 * @param [in] a_inum Address of the inode.
 * @param [in] a_is_alloc Allocation status of the sector that contains the
 * inode.
 * @param [in, out] a_fs_file Generic file with generic inode structure to 
 * initialize.
 * @return 0 on success, 1 on failure, per TSK convention
 */
static uint8_t
exfatfs_inode_copy_init(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    TSK_FS_META *fs_meta = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);

    fs_meta = a_fs_file->meta;
    fs_meta->addr = a_inum;

    /* Set the allocation status based on the cluster allocation status. File 
     * entry set entries may change this. */
    a_fs_file->meta->flags = a_is_alloc ? TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED : TSK_FS_META_FLAG_UNALLOC;

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
    fs_meta->name2->name[0] = '\0';

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
 * @param [in] a_inum Address of the inode.
 * @param [in] a_dentry A directory entry.
 * @param [in] a_is_alloc Allocation status of the inode.
 * @param [in, out] a_fs_file Generic file object with a generic inode 
 * metadata structure.
 * @return TSK_RETVAL_ENUM.  
 */
TSK_RETVAL_ENUM
exfatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_dentry, uint8_t a_is_alloc, TSK_FS_FILE *a_fs_file)
{
    const char *func_name = "exfatfs_dinode_copy";

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_fs_file != NULL);
    assert(a_fs_file->meta != NULL);
    assert(a_fs_file->fs_info != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file->meta, "a_fs_file->meta", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file->fs_info, "a_fs_file->fs_info", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
        return TSK_ERR;
    }

    if (exfatfs_inode_copy_init(a_fatfs, a_inum, a_is_alloc, a_fs_file)) {
        return TSK_ERR;
    }

    switch (exfatfs_get_enum_from_type(a_dentry->data[0]))
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
        return exfatfs_copy_vol_label_inode(a_fatfs, a_inum, a_dentry, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_VOLUME_GUID_DENTRY_NAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_copy_alloc_bitmap_inode(a_fatfs, a_dentry, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_copy_upcase_table_inode(a_fatfs, a_dentry, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_TEX_FAT_DENTRY_NAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        strcpy(a_fs_file->meta->name2->name, EXFATFS_ACT_DENTRY_NAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
        return exfatfs_copy_file_inode(a_fatfs, a_inum, a_dentry, a_is_alloc, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
        return exfatfs_copy_file_name_inode(a_fatfs, a_inum, a_dentry, a_is_alloc, a_fs_file);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    default:
        /* Stream entries are copied in tandem with the corresponding file entry. */
        return TSK_ERR;
    }

    return TSK_OK;
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
 * @param [in, out] The stream entry, if found, will be loaded into the
 * this generic directory entry structure.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
exfatfs_find_file_stream_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_file_entry_inum, 
    TSK_DADDR_T a_sector, uint8_t a_sector_is_alloc,  
    EXFATFS_DIR_ENTRY_TYPE a_file_dentry_type,
    FATFS_DENTRY *a_stream_dentry)
{
    const char *func_name = "exfatfs_find_file_stream_dentry";
    TSK_INUM_T stream_entry_inum = 0;
    TSK_DADDR_T cluster = 0;
    TSK_DADDR_T cluster_base_sector = 0;
    TSK_DADDR_T last_entry_offset = 0;
    TSK_DADDR_T file_entry_offset = 0;
    TSK_DADDR_T next_cluster = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_file_entry_inum));
    assert(a_stream_dentry != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_stream_dentry, "a_stream_dentry", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_file_entry_inum, func_name)) {
        return FATFS_FAIL;
    }
        
    /* Check for the most common case first - the file stream entry is located
     * immediately after the file entry. This should always be true for any 
     * in-use file entry in an allocated cluster that is not the last entry in
     * the cluster. It will also be true if the file entry is the last entry in 
     * the cluster and the directory that contains the file is not fragmented - 
     * the stream entry will simply be the first entry of the next cluster. 
     * Finally, if the file entry is not in-use and was found in an unallocated 
     * sector, the only viable place to look for the stream entry is in the 
     * bytes following the file entry, since there is no FAT chain to 
     * consult. */
    stream_entry_inum = a_file_entry_inum + 1;
    if (fatfs_inum_is_in_range(a_fatfs, stream_entry_inum)) {
        if (exfatfs_load_file_stream_dentry(a_fatfs, 
            stream_entry_inum, a_sector_is_alloc, 
            a_file_dentry_type, 
            a_stream_dentry) == 0) {
            /* Found it. */
            return FATFS_OK;
        }
    }

    /* If the stream entry was not found immediately following the file entry
     * and the cluster is allocated, it is possible that the file entry was the
     * last entry of a cluster in a fragmented directory. In this
     * case, the FAT can be consulted to see if there is a next cluster. If 
     * so, the stream entry may be the first entry of that cluster. */
    if (a_sector_is_alloc) {
        /* Calculate the byte offset of the last possible directory entry in 
         * the current cluster. */
        cluster = FATFS_SECT_2_CLUST(a_fatfs, a_sector);
        cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, cluster); 
        last_entry_offset = (cluster_base_sector * a_fatfs->ssize) + 
            (a_fatfs->csize * a_fatfs->ssize) - sizeof(FATFS_DENTRY);   

        /* Get the byte offset of the file entry. Note that FATFS_INODE_2_OFF
         * gices the offset relative to start of a sector. */
        file_entry_offset = (a_sector * a_fatfs->ssize) + 
            FATFS_INODE_2_OFF(a_fatfs, a_file_entry_inum);

        if (file_entry_offset == last_entry_offset) {
            /* The file entry is the last in its cluster. Look up the next
             * cluster. */
            if ((fatfs_getFAT(a_fatfs, cluster, &next_cluster) == 0) &&
                (next_cluster != 0)) {
                /* Found the next cluster in the FAT, so get its first sector
                 * and the inode address of the first entry of the sector. */
                cluster_base_sector = FATFS_CLUST_2_SECT(a_fatfs, next_cluster); 
                stream_entry_inum = FATFS_SECT_2_INODE(a_fatfs, 
                    cluster_base_sector);

                if (fatfs_inum_is_in_range(a_fatfs, stream_entry_inum)) {
                    if (exfatfs_load_file_stream_dentry(a_fatfs, 
                        stream_entry_inum, a_sector_is_alloc, 
                        a_file_dentry_type, 
                        a_stream_dentry) == 0) {
                        /* Found it. */
                        return FATFS_OK;
                    }
                }
            }
        }
    }

    /* Did not find the file stream entry. */
    return FATFS_FAIL;
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
    FATFS_DENTRY dentry;
    //FATFS_DENTRY stream_dentry;
    //FATFS_DENTRY *secondary_dentry = NULL;
    EXFATFS_DIR_ENTRY_TYPE dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
    TSK_RETVAL_ENUM copy_result = TSK_OK;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file, "a_fs_file", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file->meta, "a_fs_file->meta", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_file->fs_info, "a_fs_file->fs_info", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
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
     * not only as meta data to be reported, but also as a way to choose
     * between the basic or in-depth version of the tests (below) that 
     * determine whether or not the bytes corresponding to the inode are 
     * likely to be a directory entry. Note that in other places in the code 
     * information about whether or not the sector that contains the inode is
     * part of a folder is used to select the test. Here, that information is 
     * not available, so the test here is less reliable and may result in some 
     * false positives. */
    sect_is_alloc = fatfs_is_sectalloc(a_fatfs, sector);
    if (sect_is_alloc == -1) {
        return 1;
    }

    /* Load the bytes at the specified inode address. */
    memset((void*)&dentry, 0, sizeof(FATFS_DENTRY));
    if (fatfs_dentry_load(a_fatfs, &dentry, a_inum)) {
        return 1;
    }

    /* Try typing the bytes as a directory entry.*/
    if (exfatfs_is_dentry(a_fatfs, &dentry, (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)sect_is_alloc, sect_is_alloc)) {
        dentry_type = (EXFATFS_DIR_ENTRY_TYPE)dentry.data[0];
    }
    else {
        return 1;
    }

    /* For the purposes of inode lookup, the file and file stream entries 
     * that begin a file entry set are mapped to a single inode. Thus,  
     * file stream entries are not treated as independent inodes. */
    if (exfatfs_get_enum_from_type(dentry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM " is not an inode", func_name, 
            a_inum);
        return 1;
    }

    /* Populate the TSK_FS_META object of the TSK_FS_FILE object. */
    copy_result = exfatfs_dinode_copy(a_fatfs, a_inum, &dentry, sect_is_alloc, a_fs_file); 
    if (copy_result == TSK_OK) {
        return 0;
    }
    else if (copy_result == TSK_COR) {
        /* There was a Unicode conversion error on a string, but the rest 
         * of the inode meta data is probably o.k., so report the error (if in 
         * verbose mode), but also report a successful look up.*/
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
 * Outputs file attributes for an exFAT directory entry/inode in 
 * human-readable form.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_inum Inode address associated with the directory entry.
 * @param [in] a_hFile Handle of a file to which to write.
 * @return 0 on success, 1 on failure, per TSK convention
 */
uint8_t
exfatfs_istat_attr_flags(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum,  FILE *a_hFile)
{
    const char *func_name = "exfatfs_istat_attr_flags";
    FATFS_DENTRY dentry;
    EXFATFS_FILE_DIR_ENTRY *file_dentry = NULL;
    uint16_t attr_flags = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_hFile != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name)) {
        return FATFS_FAIL; 
    }

    /* Load the bytes at the given inode address. */
    if (fatfs_dentry_load(a_fatfs, (FATFS_DENTRY*)(&dentry), a_inum)) {
        return FATFS_FAIL; 
    }

    /* Print the attributes. */
    switch (exfatfs_get_enum_from_type(dentry.data[0]))
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
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
    case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:     
        tsk_fprintf(a_hFile, "TexFAT\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        tsk_fprintf(a_hFile, "Access Control Table\n");
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
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
        tsk_fprintf(a_hFile, "File Stream\n"); 
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
        tsk_fprintf(a_hFile, "File Name\n");
        break;
    default:
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: Inode %" PRIuINUM
            " is not an exFAT directory entry", func_name, a_inum);
        return FATFS_FAIL;
    }

    return FATFS_OK;
}

/**
 * \internal
 * Determine whether an exFAT directory entry should be included in an inode
 *  walk.
 *
 * @param [in] a_fatfs Source file system for the directory entry.
 * @param [in] a_inum Inode address associated with the directory entry.
 * @param [in] a_dentry A directory entry buffer.
 * @param [in] a_selection_flags The inode selection falgs for the inode walk.
 * @param [in] a_cluster_is_alloc The allocation status of the cluster that
 * contains the directory entry.
 * @return 1 if the entry should be skipped, 0 otherwise
 */
uint8_t
exfatfs_inode_walk_should_skip_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, 
    FATFS_DENTRY *a_dentry, unsigned int a_selection_flags, 
    int a_cluster_is_alloc)
{
    const char *func_name = "exfatfs_inode_walk_should_skip_dentry";
    unsigned int dentry_flags = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_inum_is_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        !fatfs_inum_arg_is_in_range(a_fatfs, a_inum, func_name) ||
        fatfs_ptr_arg_is_null(a_dentry, "a_dentry", func_name)) {
        return 1; 
    }

    /* Skip file stream and file name entries. For inode walks, these entries
     * are handled with the file entry with which they are associated in a file
     * entry set. */
    if (exfatfs_get_enum_from_type(a_dentry->data[0]) == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM ||
        exfatfs_get_enum_from_type(a_dentry->data[0]) == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME) {
        return 1;
    }

    /* Assign an allocation status to the entry. Allocation status is 
     * determined first by the allocation status of the cluster that contains
     * the entry, then by the allocated status of the entry. */
    if ((a_cluster_is_alloc) && (exfatfs_get_alloc_status_from_type(a_dentry->data[0]) == 1)) {
        dentry_flags = TSK_FS_META_FLAG_ALLOC;
    }
    else {
        dentry_flags = TSK_FS_META_FLAG_UNALLOC;
    }

    /* Does the allocation status of the entry match that of the inode 
     * selection flags? */
    if ((a_selection_flags & dentry_flags) != dentry_flags) {
        return 1;
    }

    /* If the inode selection flags call for only processing orphan files, 
     * check whether or not this inode is in list of non-orphan files found via
     * name walk. */
    if ((dentry_flags & TSK_FS_META_FLAG_UNALLOC) &&
        (a_selection_flags & TSK_FS_META_FLAG_ORPHAN) &&
        (tsk_fs_dir_find_inum_named(&(a_fatfs->fs_info), a_inum))) {
        return 1;
    }

    return 0;
}


/**
 * \internal
 * Returns the allocation status of a dir entry given its
 * dir entry type byte (stored in the high bit)
 *
 * @param [in] a_dir_entry_type Entry type byte
 * @return 0 if unused, 1 if used
 */
uint8_t 
exfatfs_get_alloc_status_from_type(EXFATFS_DIR_ENTRY_TYPE a_dir_entry_type)
{
    return (a_dir_entry_type >> 7);
}


/**
 * \internal
 * Returns the directory type enum from the given entry type byte
 * (Comes from the low 7 bits)
 *
 * @param [in] a_dir_entry_type
 * @return Enum for this type
 */
EXFATFS_DIR_ENTRY_TYPE_ENUM 
exfatfs_get_enum_from_type(EXFATFS_DIR_ENTRY_TYPE a_dir_entry_type){
    return ((EXFATFS_DIR_ENTRY_TYPE_ENUM)(a_dir_entry_type & 0x7f));
}
