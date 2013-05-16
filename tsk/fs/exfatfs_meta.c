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
 * \file exfatfs.c
 * Contains the internal TSK exFAT file system code to handle metadata 
 * category processing. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

static uint8_t
exfatfs_is_vol_label_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;

    if (!a_basic) {
        /* There is not enough data in a volume label directory entry for an 
         * in-depth test. */
         return 0; // RJCTODO: Is this the right choice?
    }

    /* The character count should not exceed the maximum length of the volume 
     * label. */
    if (dentry->utf16_char_count > EXFATFS_MAX_VOLUME_LABEL_LEN)
    {
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_vol_guid_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in a volume GUID directory entry for an
         * in-depth test. */
         return 0; // RJCTODO: Is this the right choice?
    }

    return 1;
}

uint8_t
exfatfs_is_alloc_bitmap_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_alloc_bitmap_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_ALLOC_BITMAP_DIR_ENTRY *dentry = (EXFATFS_ALLOC_BITMAP_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_bitmap = 0;
    uint64_t length_of_alloc_bitmap_in_bytes = 0;

    if (!a_basic) {
        /* The length of the allocation bitmap should be consistent with the 
         * number of clusters in the data area as specified in the volume boot
         * record. */
        length_of_alloc_bitmap_in_bytes = tsk_getu64(fs->endian, dentry->length_of_alloc_bitmap_in_bytes);
        if (length_of_alloc_bitmap_in_bytes != (a_fatfs->clustcnt + 7) / 8) {
            if (tsk_verbose) {
                fprintf(stderr, "%s: bitmap length incorrect\n", func_name);
            }
            return 0;
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
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_upcase_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_upcase_table_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_UPCASE_TABLE_DIR_ENTRY *dentry = (EXFATFS_UPCASE_TABLE_DIR_ENTRY*)a_dentry;
    uint32_t first_cluster_of_table = 0;

    if (!a_basic) {
        /* There is not enough data in an UP-Case table directory entry
         * for an in-depth test. */
         return 0; // RJCTODO: Is this the right choice?
    }

    /* The first cluster of the Up-Case table should be within the 
     * data area. */
    first_cluster_of_table = tsk_getu32(fs->endian, dentry->first_cluster_of_table);
    if ((first_cluster_of_table < EXFATFS_FIRST_CLUSTER) ||
        (first_cluster_of_table > a_fatfs->lastclust)) {
        if (tsk_verbose) {
            fprintf(stderr, "%s: first cluster not in cluster heap\n", func_name);
        }
        return 0;
    }

    return 1;
}

static uint8_t
exfatfs_is_tex_fat_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in a UP-TexFAT directory entry
         * for an in-depth test. */
         return 0; // RJCTODO: Is this the right choice?
    }

    return 1;
}

static uint8_t
exfatfs_is_access_ctrl_table_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return 0; // RJCTODO: Is this the right choice?
    }

    return 1;
}

static uint8_t
exfatfs_is_file_stream_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_file_stream_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);

    if (!a_basic) {
        // RJCTODO: Validate this entry
    }

    // RJCTODO: Validate this entry

    return 1;
}

static uint8_t
exfatfs_is_file_name_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    if (!a_basic) {
        /* There is not enough data in an access control table directory entry
         * for an in-depth test. */
         return 0;
    }

    // RJCTODO: Make sure allocation possible bit is not set. Invalid FAT chain bit should be set.
    // CAn this be used for other entries?

    return 1;
}

static uint8_t
exfatfs_is_file_dentry(FATFS_INFO *a_fatfs, FATFS_DENTRY *a_dentry, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_file_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *file_dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    if (!a_basic == 0)
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
        return 0;
    }

    return 1;
}

/**
 * \internal
 * Determines whether a buffer likely contains a directory entry.
 * For the most reliable results, request the in-depth test.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_buf Buffer that may contain a directory entry.
 * @param a_basic 1 if only basic tests should be performed. 
 * @return 1 if likely directory entry found, 0 if not
 */
uint8_t
exfatfs_is_dentry(FATFS_INFO *a_fatfs, char *a_buf, uint8_t a_basic)
{
    const char *func_name = "exfatfs_is_dentry";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    FATFS_DENTRY *dentry = (FATFS_DENTRY*)a_buf; 

    if (a_fatfs == NULL) {
        assert(a_fatfs != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_fatfs argument is NULL", func_name);
        return 0;
    }

    if (a_buf == NULL) {
        assert(a_fatfs != NULL);
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: a_buf argument is NULL", func_name);
        return 0;
    }

    switch (dentry->data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_is_vol_label_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
        return exfatfs_is_vol_guid_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
        return exfatfs_is_alloc_bitmap_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
        return exfatfs_is_upcase_table_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
        return exfatfs_is_tex_fat_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_ACT:
        return exfatfs_is_access_ctrl_table_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_DELETED:
        return exfatfs_is_file_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        return exfatfs_is_file_stream_dentry(a_fatfs, dentry, a_basic);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_is_file_name_dentry(a_fatfs, dentry, a_basic);
    default:
        return 0;
    }
}

//RCJTODO: Using names for inodes or not?
static TSK_RETVAL_ENUM 
exfatfs_copy_vol_label_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, char *a_buf, TSK_INUM_T a_inum)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_buf;

    if (dentry->entry_type != EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY) {
        if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dentry->volume_label, dentry->utf16_char_count, a_inum, "volume label") == TSKconversionOK) {
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

static TSK_RETVAL_ENUM 
exfatfs_copy_file_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, char *a_buf, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_file_dinode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_DIR_ENTRY *dentry = (EXFATFS_FILE_DIR_ENTRY*)a_buf;

    // RJCTODO: Implement

    return TSK_OK;
}

static TSK_RETVAL_ENUM 
exfatfs_copy_file_stream_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, char *a_buf, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_copy_file_stream_dinode";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_buf;

    // RJCTODO: Implement

    return TSK_OK;
}

static TSK_RETVAL_ENUM 
exfatfs_copy_file_name_dinode(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, char *a_buf, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_buf;

    if (fatfs_copy_utf16_str_2_meta_name(a_fatfs, a_fs_meta, (UTF16*)dentry->utf16_name_chars, EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH, a_inum, "file name segment") == TSKconversionOK) {
        return TSK_OK;
    }
    else {
        return TSK_COR;
    }
}

// RJCTODO: Consider using this for FATXX as well.
static uint8_t
exfatfs_dinode_copy_init(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_dinode_copy_init";
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
    // RJCTODO: mode is as at allocation of struct...

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

    // RJCTODO: Is this the right choice?
    if (a_fs_meta->name2 != NULL) {
        free(a_fs_meta->name2);
        a_fs_meta->name2 = NULL;
    }

    //if (a_fs_meta->name2 == NULL) {
    //    if ((a_fs_meta->name2 = (TSK_FS_META_NAME_LIST*)tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
    //        return 0;
    //    }
    //    a_fs_meta->name2->next = NULL;
    //}

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
exfatfs_dinode_copy(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta,
    char *a_buf, TSK_DADDR_T a_sect, TSK_INUM_T a_inum)
{
    const char *func_name = "exfatfs_dinode_copy";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    FATFS_DENTRY *dentry = (FATFS_DENTRY*)a_buf; 

    if ((fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name)) ||
        (fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name)) ||
        (fatfs_is_ptr_arg_null(a_buf, "a_buf", func_name))) {
        return TSK_ERR;
    }

    if (!exfatfs_dinode_copy_init(a_fatfs, a_fs_meta, a_sect, a_inum)) {
        return TSK_ERR;
    }

    //RJCTODO: May not support copying all directory entries as inodes?
    //RCJTODO: Using names for inodes or not?
    switch (dentry->data[0])
    {
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
    case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
        return exfatfs_copy_vol_label_dinode(a_fatfs, a_fs_meta, a_buf, a_inum);
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
        return exfatfs_copy_file_dinode(a_fatfs, a_fs_meta, a_buf, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM_DELETED:
        return exfatfs_copy_file_stream_dinode(a_fatfs, a_fs_meta, a_buf, a_inum);
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
    case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME_DELETED:
        return exfatfs_copy_file_name_dinode(a_fatfs, a_fs_meta, a_buf, a_inum);
    default:
        return TSK_ERR;
    }

    return TSK_OK;
}

extern uint8_t
exfatfs_copy_inode_if_valid(FATFS_INFO *a_fatfs, TSK_FS_FILE *a_fs_file, 
    TSK_DADDR_T sect, TSK_INUM_T inum, 
    char *a_buf, uint8_t do_basic_validity_test)
{
    // RJCTODO
    return 1;
}
