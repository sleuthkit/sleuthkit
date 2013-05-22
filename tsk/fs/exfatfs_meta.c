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

    tsk_error_reset();

     /* Subtract 2 from the cluster address since cluster #2 is 
      * the first cluster. */
    cluster_addr = a_cluster_addr - 2;

    /* Determine the offset of the byte in the allocation bitmap that contains
     * the bit for the specified cluster. */
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

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    uint8_t i = 0;
    
    if (!a_do_basic_test_only) {
        /* There is not enough data in a volume label directory entry for an 
         * in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE; // RJCTODO: Is this the right choice?
    }

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

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    if (!a_do_basic_test_only) {
        /* There is not enough data in a volume GUID directory entry for an
         * in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE; // RJCTODO: Is this the right choice?
    }

    return EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID;
}

// RJCTODO: Add function header comment
enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_alloc_bitmap_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_bitmap = 0;
    uint64_t length_of_alloc_bitmap_in_bytes = 0;

    if (!a_do_basic_test_only) {
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

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_table = 0;

    if (!a_do_basic_test_only) {
        /* There is not enough data in an UP-Case table directory entry
         * for an in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE; // RJCTODO: Is this the right choice?
    }

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

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    if (!a_do_basic_test_only) {
        /* There is not enough data in a UP-TexFAT directory entry
         * for an in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE; // RJCTODO: Is this the right choice?
    }

    return EXFATFS_DIR_ENTRY_TYPE_TEX_FAT;
}

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    if (!a_do_basic_test_only) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE; // RJCTODO: Is this the right choice?
    }

    return EXFATFS_DIR_ENTRY_TYPE_ACT;
}

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *file_dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    if (!a_do_basic_test_only == 0)
    {
        // RJCTODO: Check MAC times
    }

    // RJCTODO: Consider using additional tests similar to bulk extractor tests, e.g., sanity check attributes

    /* The MAC times should not be all zero. */ 
    //RJCTODO: Is this legitimate? 
    if ((tsk_getu16(fs->endian, file_dentry->mtime) == 0) &&
        (tsk_getu16(fs->endian, file_dentry->atime) == 0) &&
        (tsk_getu16(fs->endian, file_dentry->ctime) == 0))
    {
        if (tsk_verbose) {
            fprintf(stderr, "%s: MAC times all zero\n", func_name);
        }
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    return EXFATFS_DIR_ENTRY_TYPE_FILE;
}

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    if (!a_do_basic_test_only) {
        // RJCTODO: Validate this entry
    }

    // RJCTODO: Validate this entry

    return EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM;
}

// RJCTODO: Add function header comment
static enum EXFATFS_DIR_ENTRY_TYPE_ENUM
exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_do_basic_test_only)
{
    if (!a_do_basic_test_only) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    // RJCTODO: Make sure allocation possible bit is not set. Invalid FAT chain bit should be set.
    // CAn this be used for other entries?

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

    if (a_fatfs == NULL) {
        assert(a_fatfs != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_fatfs argument is NULL", func_name);
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }

    if (a_dentry == NULL) {
        assert(a_fatfs != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_dentry argument is NULL", func_name);
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
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
        return exfatfs_is_file_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        return exfatfs_is_file_stream_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_is_file_name_dentry(a_fatfs, a_dentry, a_do_basic_test_only);
    default:
        return EXFATFS_DIR_ENTRY_TYPE_NONE;
    }
}

// RJCTODO: Add function header comment
static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_inode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode, TSK_INUM_T a_inum)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)(&a_inode->primary_dentry);

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

// RJCTODO: Add function header comment
static TSK_RETVAL_ENUM 
exfatfs_copy_file_inode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode, TSK_INUM_T a_inum) // RJCTODO: What is this inum for?
{
    const char *func_name = "exfatfs_copy_file_inode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *file_dentry = (EXFATFS_FILE_DIR_ENTRY*)(&a_inode->primary_dentry);
    EXFATFS_FILE_STREAM_DIR_ENTRY *stream_dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)(&a_inode->secondary_dentry);

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name)) {
        return TSK_ERR;
    }

    if ((file_dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_FILE) ||
        (stream_dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM)) { // RJCTODO: Also handle deleted
            // RJCTODO: At least assert
            return TSK_ERR;
    }

    if (file_dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        a_fs_meta->type = TSK_FS_META_TYPE_DIR;
    }
    else {
        a_fs_meta->type = TSK_FS_META_TYPE_REG;
    }

    /* There is no notion of link in exFAT, just deleted or not. */
    a_fs_meta->nlink = (file_dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED) ? 0 : 1;


    a_fs_meta->size = tsk_getu64(fs->endian, stream_dentry->data_length); // RJCTODO: What about the valid data length?

    // RJCTODO: Correct? More to do?

    /* If these are valid dates, then convert to a unix date format */
    //if (FATFS_ISDATE(tsk_getu16(fs->endian, file_dentry->mtime))) { //RJCTO: time should be changed to date
    //    a_fs_meta->mtime =
    //        dos2unixtime(tsk_getu16(fs->endian, a_dentry->mtime),
    //        tsk_getu16(fs->endian, a_dentry->wtime), 0);
    //}
    //else {
    //    a_fs_meta->mtime = 0;
    //}
    //a_fs_meta->mtime_nano = 0;

    //if (FATFS_ISDATE(tsk_getu16(fs->endian, a_dentry->adate)))
    //    fs_meta->atime =
    //        dos2unixtime(tsk_getu16(fs->endian, a_dentry->adate), 0, 0);
    //else
    //    fs_meta->atime = 0;
    //fs_meta->atime_nano = 0;

    ///* cdate is the creation date in FAT and there is no change,
    //    * so we just put in into change and set create to 0.  The other
    //    * front-end code knows how to handle it and display it
    //    */
    //if (FATFS_ISDATE(tsk_getu16(fs->endian, a_dentry->cdate))) {
    //    fs_meta->crtime =
    //        dos2unixtime(tsk_getu16(fs->endian, a_dentry->cdate),
    //        tsk_getu16(fs->endian, a_dentry->ctime), a_dentry->ctimeten);
    //    fs_meta->crtime_nano = dos2nanosec(a_dentry->ctimeten);
    //}
    //else {
    //    fs_meta->crtime = 0;
    //    fs_meta->crtime_nano = 0;
    //}

    //// FAT does not have a changed time
    //fs_meta->ctime = 0;
    //fs_meta->ctime_nano = 0;


    return TSK_OK;
}

// RJCTODO: Add function header comment
static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_inode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, EXFATFS_INODE *a_inode, TSK_INUM_T a_inum) // RJCTODO: What is this inum for?
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)(&a_inode->primary_dentry);

    a_fs_meta->type = TSK_FS_META_TYPE_REG;

    if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dentry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH, a_inum, "file name segment") == TSKconversionOK) {
        return TSK_OK;
    }
    else {
        return TSK_COR;
    }
}

// RJCTODO: Add function header comment
// RJCTODO: Consider using this for FATXX as well.
static uint8_t
exfatfs_inode_copy_init(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_inode_copy_init";
    int8_t ret_val = 0;

    if ((fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name))) {
        return TSK_ERR;
    }

    /* Use the allocation status of the sector to determine if the inode is
     * allocated or not. NOTE: This is more reliable than checking the 
     * "in use" bit of the directory entry.*/
    ret_val = fatfs_is_sectalloc(a_fatfs, a_sect);
    if (ret_val != -1) {
        a_fs_meta->flags = ret_val == 1 ? TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC;
    }
    else {
        return 0;
    }

    a_fs_meta->addr = a_inum;

    a_fs_meta->type = TSK_FS_META_TYPE_VIRT; // RJCTODO: Is this reasonable? Should it be TSK_FS_META_TYPE_UNDEF instead?
    // RJCTODO: mode is as at allocation of struct...ok? Use new mode?

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

    if (a_fs_meta->content_len < FATFS_FILE_CONTENT_LEN) {
        if ((a_fs_meta =
                tsk_fs_meta_realloc(a_fs_meta,
                    FATFS_FILE_CONTENT_LEN)) == NULL) {
            return 0;
        }
    }

    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }

    if (a_fs_meta->name2 == NULL) {
        if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST*)tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            return 0;
        }
        a_fs_meta->name2->next = NULL;
    }

    return 1;
}

//RJCTODO: Is this comment still accurate?
/**
    * \internal
    * Copy the contents of a raw directry entry into a TSK_FS_INFO structure.
    *
    * @param a_fatfs File system that directory entry is from.
    * @param a_fs_meta Generic inode structure to copy data into.
    * @param a_dentry Generic directory entry to copy data from.
    * @param a_sect Sector address where directory entry is from -- used
    * to determine allocation status.
    * @param a_inum Address of the inode.
    * @return 1 on error and 0 on success.  Errors should only occur for
    * Unicode conversion problems and when this occurs the name will be
    * NULL terminated (but with unknown contents).
    */
TSK_RETVAL_ENUM
exfatfs_inode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
    EXFATFS_INODE *a_inode, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_inode_copy";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    if ((fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name)) ||
        (fatfs_is_ptr_arg_null(a_inode, "a_inode", func_name))) {
        return TSK_ERR;
    }

    if (!exfatfs_inode_copy_init(a_fatfs, a_fs_meta, a_sect, a_inum)) {
        return TSK_ERR;
    }

    //RJCTODO: May not support copying all directory entries as inodes?
    //RCJTODO: Using names for inodes or not?
    switch (a_inode->primary_dentry.data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_copy_vol_label_inode(a_fatfs, a_fs_meta, a_inode, a_inum);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        strcpy(a_fs_meta->name2->name, EXFATFS_VOLUME_GUID_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        strcpy(a_fs_meta->name2->name, EXFATFS_ALLOC_BITMAP_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        strcpy(a_fs_meta->name2->name, EXFATFS_UPCASE_TABLE_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        strcpy(a_fs_meta->name2->name, EXFATFS_TEX_FAT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        strcpy(a_fs_meta->name2->name, EXFATFS_ACT_VIRT_FILENAME);
        return TSK_OK;
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
        return exfatfs_copy_file_inode(a_fatfs, a_fs_meta, a_inode, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_copy_file_name_inode(a_fatfs, a_fs_meta, a_inode, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        // RJCTODO: May want to do more here
    default:
        return TSK_ERR;
    }

    return TSK_OK;
}

// RJCTODO: Add function header comment
uint8_t 
exfatfs_inode_lookup(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, 
    TSK_INUM_T a_inum, TSK_DADDR_T a_sect, uint8_t a_do_basic_test)
{
    const char *func_name = "exfatfs_inode_lookup";
    TSK_RETVAL_ENUM copy_result = TSK_OK;
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs;
    EXFATFS_INODE inode; 
    enum EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

    if (fatfs_dentry_load(fs, &(inode.primary_dentry), a_inum) != 0) {
        // RJCTODO: Report error
        return 1;
    }

    dentry_type = exfatfs_is_dentry(a_fatfs, &(inode.primary_dentry), a_do_basic_test);

    /* Non-directory entries are naturally not reported. However, neither are
     * file stream directory entries. They are handled in tandem with the
     * corresponding file entry. */
    if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_NONE ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM ||
        dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: %" PRIuINUM
            " is not an inode", func_name, a_inum);
        return 1;
    }

    if (dentry_type == EXFATFS_DIR_ENTRY_TYPE_FILE) //RJCTODO: Also handle deleted
    {
        if (fatfs_dentry_load(fs, &(inode.secondary_dentry), a_inum + 1) != 0) {
            // RJCTODO: Report error
            return 1;
        }

        dentry_type = exfatfs_is_dentry(a_fatfs, &(inode.secondary_dentry), a_do_basic_test);

        if (dentry_type != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM) { //RJCTODO: Also handle deleted
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
            tsk_error_set_errstr("%s: %" PRIuINUM
                " is not an inode", func_name, a_inum);
            return 1;
        }
    }

    copy_result = exfatfs_inode_copy(a_fatfs, a_fs_meta, &inode, a_sect, 
        a_inum);
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
exfatfs_istat_attrs(TSK_FS_INFO *a_fs, TSK_INUM_T a_inum,  FILE *a_hFile)
{
    const char *func_name = "exfatfs_istat_attrs";
    FATFS_DENTRY dentry;
    EXFATFS_FILE_DIR_ENTRY *file_dentry = NULL;

    if (fatfs_is_ptr_arg_null(a_fs, "a_fs", func_name) ||
        fatfs_is_ptr_arg_null(a_hFile, "a_hFile", func_name) ||
        !fatfs_is_inum_in_range(a_fs, a_inum, func_name)) {
        // RJCTODO: Report error, diff function return type?
        return; 
    }

    if (fatfs_dentry_load(a_fs, (FATFS_DENTRY*)(&dentry), a_inum) != 0) {
        // RJCTODO: Report error, diff function return type?
        return; 
    }

    switch (dentry.data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
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
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        tsk_fprintf(a_hFile, "File Stream\n"); 
        // RJCTODO: Want to print secondary flags? I think so...
        break;
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        tsk_fprintf(a_hFile, "File Name\n");
    default:
        // RJCTODO: Do an error here?
        break;
    }
}