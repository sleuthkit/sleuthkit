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
 * \file exfatfs_dent.c
 * Contains the internal TSK exFAT file system code to handle name category 
 * processing. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

/**
 * \internal
 * \struct
 * Bundles a TSK_FS_NAME object and a TSK_FS_DIR object with additional data 
 * required when assembling a name from file directory entry set. If the
 * TSK_FS_NAME is successfully populated, it is added to the TSK_FS_DIR.
 */
typedef struct {
    FATFS_INFO *fatfs;
    int8_t sector_is_allocated;
    EXFATFS_DIR_ENTRY_TYPE last_dentry_type;
    uint8_t expected_secondary_entry_count;
    uint8_t actual_secondary_entry_count;
    uint16_t expected_check_sum;
    uint8_t expected_name_length_utf16_chars;     /* Name length (in characters) as reported by the file stream dentry */
    uint8_t current_file_name_length_utf16_chars; /* Number of UTF16 name characters read in so far */
    uint8_t file_name_utf16[(EXFATFS_MAX_FILE_NAME_LENGTH_UTF16_CHARS + 1) * 2];  /* The UTF16 characters read in so far*/
    size_t actual_name_length_utf8_bytes;  /* Length of the UTF8 version of the name (stored in fs_name) */
    TSK_FS_NAME *fs_name;
    TSK_FS_DIR *fs_dir;
} EXFATFS_FS_NAME_INFO;

/**
 * \internal
 * Reset the fields of a EXFATFS_FS_NAME_INFO to their initialized state. This
 * allows for reuse of the object.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_reset_name_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);

    a_name_info->last_dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
    a_name_info->expected_secondary_entry_count = 0;
    a_name_info->actual_secondary_entry_count = 0;
    a_name_info->expected_check_sum = 0;
    a_name_info->expected_name_length_utf16_chars = 0;
    a_name_info->current_file_name_length_utf16_chars = 0;
    a_name_info->file_name_utf16[0] = '\0';
    a_name_info->actual_name_length_utf8_bytes = 0;
    a_name_info->fs_name->name[0] = '\0';
    a_name_info->fs_name->meta_addr = 0;
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
    a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
}

/**
 * \internal
 * Add the TSK_FS_NAME object of an EXFATFS_FS_NAME_INFO object to its
 * TSK_FS_DIR object and reset the fields of a EXFATFS_FS_NAME_INFO to their
 * initialized state. This allows for reuse of the object.
 * The conversion from UTF16 to UTF8 happens here if needed.
 *
 * @param a_name_info The name info object.
 */
static void
exfatfs_add_name_to_dir_and_reset_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);

    /* If the name has not been converted to UTF8 yet, do it now */
    if ((strlen(a_name_info->fs_name->name) == 0) && 
        (a_name_info->current_file_name_length_utf16_chars > 0)) {

        /* Convert the UTF16 name to UTF8 */
        if (fatfs_utf16_inode_str_2_utf8(a_name_info->fatfs,
            (UTF16*)a_name_info->file_name_utf16, a_name_info->current_file_name_length_utf16_chars,
            (UTF8*)a_name_info->fs_name->name, a_name_info->fs_name->name_size,
            a_name_info->fs_name->meta_addr, "file name segment") != TSKconversionOK) {

            /* It might be that we have a partial name, so we want to
             * continue regardless of the result here */
        }
    }
       
    /* If the parsing of the directory entry or directory entry set produced
    * a name, add the TSK_FS_NAME object to the TSK_FS_DIR object. */
    if (strlen(a_name_info->fs_name->name) > 0) {
        tsk_fs_dir_add(a_name_info->fs_dir, a_name_info->fs_name);
    }

    exfatfs_reset_name_info(a_name_info);
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a file
 * directory entry. Since this is the beginning of a new name, the name
 * previously stored on the EXFATFS_FS_NAME_INFO, if any, is saved.
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_DIR_ENTRY *dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));
    
    /* Starting parse of a new name, so save the current name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    /* Set the current entry type. This is used to check the sequence and 
     * in-use state of the entries in the set. */
    a_name_info->last_dentry_type = (EXFATFS_DIR_ENTRY_TYPE)dentry->entry_type;

    /* The number of secondary entries and the check sum for the entry set are
     * stored in the file entry. */
    a_name_info->expected_secondary_entry_count = 
        dentry->secondary_entries_count;
    a_name_info->expected_check_sum = 
        tsk_getu16(a_name_info->fatfs->fs_info.endian, dentry->check_sum);
    
    /* The file type (regular file, directory) is stored in the file entry. */
    if (dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_DIR;
    }
    else {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;
    }
   
    /* If the in-use bit of the type byte is not set, the entry set is for a 
     * deleted or renamed file. However, trust and verify - to be marked as 
     * allocated, the inode must also be in an allocated sector. */
    if (a_name_info->sector_is_allocated && exfatfs_get_alloc_status_from_type(dentry->entry_type)) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;    
    }
    else {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;    
    }

    /* Make the inum of the file entry the inode address for the entry set. */
    a_name_info->fs_name->meta_addr = a_inum;
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a file
 * stream directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file stream directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_stream_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    if(exfatfs_get_enum_from_type(a_name_info->last_dentry_type) != EXFATFS_DIR_ENTRY_TYPE_FILE){
        /* A file stream entry must follow a file entry, so this entry is a
         * false positive or there is corruption. Save the current name, 
         * if any, and ignore this buffer. */ 
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    if(exfatfs_get_alloc_status_from_type(a_name_info->last_dentry_type) !=
        exfatfs_get_alloc_status_from_type(dentry->entry_type)){
        /* The in-use bits of all of the entries in an entry set should be 
         * same, so this entry is a false positive or there is corruption. 
         * Save the current name, if any, and ignore this buffer. */ 
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    /* Set the current entry type. This is used to check the sequence and 
     * in-use state of the entries in the set. */
    a_name_info->last_dentry_type = 
        (EXFATFS_DIR_ENTRY_TYPE)dentry->entry_type;

    /* The file stream entry contains the length of the file name. */
    a_name_info->expected_name_length_utf16_chars = dentry->file_name_length_UTF16_chars;

    /* If all of the secondary entries for the set are present, save the name,
     * if any. Note that if this condition is satisfied here, the directory is
     * corrupted or this is a degenerate case - there should be at least one 
     * file name entry in a directory entry set. */
    ++a_name_info->actual_secondary_entry_count;
    if (a_name_info->actual_secondary_entry_count == 
        a_name_info->expected_secondary_entry_count) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a file
 * name directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a file name directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_file_name_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry;
    uint8_t num_utf16_chars_to_copy = 0;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_FILE_NAME);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    if (exfatfs_get_enum_from_type(a_name_info->last_dentry_type) != EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM &&
        exfatfs_get_enum_from_type(a_name_info->last_dentry_type) != EXFATFS_DIR_ENTRY_TYPE_FILE_NAME) {
        /* A file name entry must follow a stream or name entry, so this entry is
         * is a false positive or there is corruption. Save the current name,
         * if any, and ignore this buffer. */
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    if (exfatfs_get_alloc_status_from_type(a_name_info->last_dentry_type) !=
        exfatfs_get_alloc_status_from_type(dentry->entry_type)) {
        /* The in-use bits of all of the entries in an entry set should be
         * same, so this entry is a false positive or there is corruption.
         * Save the current name, if any, and ignore this buffer. */
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
        return;
    }

    /* Set the current entry type. This is used to check the sequence and
     * in-use state of the entries in the set. */
    a_name_info->last_dentry_type =
        (EXFATFS_DIR_ENTRY_TYPE)dentry->entry_type;

    /* Determine how many name chars remain according to the name length from
     * the file stream entry and how many chars can be obtained from this
     * name entry. */
    num_utf16_chars_to_copy = a_name_info->expected_name_length_utf16_chars - a_name_info->current_file_name_length_utf16_chars;
    if (num_utf16_chars_to_copy > EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_CHARS) {
        num_utf16_chars_to_copy = EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH_UTF16_CHARS;
    }

    /* Copy two bytes per character */
    if (num_utf16_chars_to_copy <= EXFATFS_MAX_FILE_NAME_LENGTH_UTF16_CHARS - a_name_info->current_file_name_length_utf16_chars) {
        memcpy(&a_name_info->file_name_utf16[(a_name_info->current_file_name_length_utf16_chars * 2)], dentry->utf16_name_chars, num_utf16_chars_to_copy * 2);
        a_name_info->current_file_name_length_utf16_chars += num_utf16_chars_to_copy;
    }

    /* If all of the secondary entries for the set are present, save the name,
     * if any. */
    ++a_name_info->actual_secondary_entry_count;
    if (a_name_info->actual_secondary_entry_count == 
        a_name_info->expected_secondary_entry_count) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a volume
 * label directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a volume label directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_vol_label_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    EXFATFS_VOL_LABEL_DIR_ENTRY *dentry = (EXFATFS_VOL_LABEL_DIR_ENTRY*)a_dentry;
    const char *tag = " (Volume Label Entry)";
    size_t tag_length = 0;

    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(dentry != NULL);
    assert(exfatfs_get_enum_from_type(dentry->entry_type) == EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    /* Starting parse of a new name, save the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    /* Set the current entry type. This is used to check the sequence and 
     * in-use state of the entries in the set. */
    a_name_info->last_dentry_type = 
        (EXFATFS_DIR_ENTRY_TYPE)dentry->entry_type;

    /* The volume label is supposed to be a max of 11 characters. In practice it is
     * sometimes possible to extend the name into the reserved area, making the 
     * maximum 15 characters, which is what is stored in EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR. */
    if (dentry->volume_label_length_chars > EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR) {
        dentry->volume_label_length_chars = EXFATFS_MAX_VOLUME_LABEL_LEN_CHAR;
    }

    if(exfatfs_get_alloc_status_from_type(dentry->entry_type) == 1){
        if (fatfs_utf16_inode_str_2_utf8(a_name_info->fatfs, 
            (UTF16*)dentry->volume_label, (size_t)dentry->volume_label_length_chars,
            (UTF8*)a_name_info->fs_name->name, a_name_info->fs_name->name_size,
            a_inum, "volume label") != TSKconversionOK) {
            /* Discard whatever was written by the failed conversion. */
            exfatfs_reset_name_info(a_name_info);
            return;
        }
    }
    else {
        strcpy(a_name_info->fs_name->name, EXFATFS_EMPTY_VOLUME_LABEL_DENTRY_NAME);
    }

    a_name_info->actual_name_length_utf8_bytes = strlen(a_name_info->fs_name->name);

    tag_length = strlen(tag);
    if (a_name_info->actual_name_length_utf8_bytes + tag_length <
        FATFS_MAXNAMLEN_UTF8) {
        strcat(a_name_info->fs_name->name, tag);
    }

    /* Record the inum associated with this name. */
    a_name_info->fs_name->meta_addr =  a_inum;

    /* Not a directory. */
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;

    if (a_name_info->sector_is_allocated) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;    
    }

    /* Save the volume label. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);
}

/**
 * \internal
 * Populates an EXFATFS_FS_NAME_INFO object with data parsed from a 
 * special file directory entry. 
 *
 * @param a_name_info The name info object.
 * @param a_dentry A buffer containing a special file directory entry.
 * @param a_inum The inode address associated with the directory entry.
 */
static void
exfats_parse_special_file_dentry(EXFATFS_FS_NAME_INFO *a_name_info, FATFS_DENTRY *a_dentry, TSK_INUM_T a_inum)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fatfs != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_name->name != NULL);
    assert(a_name_info->fs_name->name_size == FATFS_MAXNAMLEN_UTF8);
    assert(a_name_info->fs_dir != NULL);
    assert(a_dentry != NULL);
    assert(fatfs_inum_is_in_range(a_name_info->fatfs, a_inum));

    /* Starting parse of a new name, save the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    /* Record the inum associated with this name. */
    a_name_info->fs_name->meta_addr = a_inum;

    /* Set the current entry type. This is used to check the sequence and 
     * in-use state of the entries in the set. */
    a_name_info->last_dentry_type = 
        (EXFATFS_DIR_ENTRY_TYPE)a_dentry->data[0];

    switch (exfatfs_get_enum_from_type(a_dentry->data[0])) {
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            strcpy(a_name_info->fs_name->name, EXFATFS_VOLUME_GUID_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            strcpy(a_name_info->fs_name->name, EXFATFS_ALLOC_BITMAP_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            strcpy(a_name_info->fs_name->name, EXFATFS_UPCASE_TABLE_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
            strcpy(a_name_info->fs_name->name, EXFATFS_TEX_FAT_DENTRY_NAME);
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ACT:
            strcpy(a_name_info->fs_name->name, EXFATFS_ACT_DENTRY_NAME);
            break;

        // listed so that we don't get compile warnings
        case EXFATFS_DIR_ENTRY_TYPE_NONE:
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
        case EXFATFS_DIR_ENTRY_TYPE_FILE:
        case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
        case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
        default:
            a_name_info->fs_name->name[0] = '\0';
            break;
    }

    /* Not a directory. */
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;

    if (a_name_info->sector_is_allocated) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;    
    }

    /* Save the virtual file name. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);
}

/**
 * \internal
 * Parse a buffer containing the contents of a directory and add TSK_FS_NAME 
 * objects for each named file found to the TSK_FS_DIR representation of the 
 * directory.
 *
 * @param a_fatfs File system information structure for file system that
 * contains the directory.
 * @param a_fs_dir Directory structure into to which parsed file metadata will
 * be added.
 * @param a_buf Buffer that contains the directory contents.
 * @param a_buf_len Length of buffer in bytes (must be a multiple of sector
*  size).
 * @param a_sector_addrs Array where each element is the original address of
 * the corresponding sector in a_buf (size of array is number of sectors in
 * the directory).
 * @return TSK_RETVAL_ENUM
*/
TSK_RETVAL_ENUM
exfatfs_dent_parse_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
    TSK_OFF_T a_buf_len, TSK_DADDR_T *a_sector_addrs)
{
    const char *func_name = "exfatfs_parse_directory_buf";
    TSK_FS_INFO *fs = NULL;
    TSK_OFF_T num_sectors = 0;
    TSK_OFF_T sector_index = 0;
    TSK_INUM_T base_inum_of_sector = 0;
    EXFATFS_FS_NAME_INFO name_info;
    TSK_OFF_T dentry_index = 0;
    FATFS_DENTRY *dentry = NULL;
    int entries_count = 0;
    int invalid_entries_count = 0;
    uint8_t is_corrupt_dir = 0;

    tsk_error_reset();
    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_ptr_arg_is_null(a_fs_dir, "a_fs_dir", func_name) ||
        fatfs_ptr_arg_is_null(a_buf, "a_buf", func_name) ||
        fatfs_ptr_arg_is_null(a_sector_addrs, "a_sector_addrs", func_name)) {
        return TSK_ERR; 
    }

    assert(a_buf_len > 0);
    if (a_buf_len < 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: invalid buffer length", func_name);
        return TSK_ERR; 
    }

    fs = (TSK_FS_INFO*)a_fatfs;

    memset((void*)&name_info, 0, sizeof(EXFATFS_FS_NAME_INFO));
    name_info.fatfs = a_fatfs;
    if ((name_info.fs_name = tsk_fs_name_alloc(FATFS_MAXNAMLEN_UTF8, 0)) == NULL) {
        return TSK_ERR;
    }
    name_info.fs_name->name[0] = '\0';
    name_info.fs_dir = a_fs_dir;

    /* Loop through the sectors in the buffer. */ 
    dentry = (FATFS_DENTRY*)a_buf;
    num_sectors = a_buf_len / a_fatfs->ssize;
    for (sector_index = 0; sector_index < num_sectors; ++sector_index) {
        /* Convert the address of the current sector into an inode address. */
        base_inum_of_sector = 
            FATFS_SECT_2_INODE(a_fatfs, a_sector_addrs[sector_index]);
        if (base_inum_of_sector > fs->last_inum) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr("%s: inode address for sector address %" 
                PRIuDADDR " at addresses array index %" PRIuDADDR 
                " is too large", func_name, base_inum_of_sector, sector_index);
            tsk_fs_name_free(name_info.fs_name);
            return TSK_COR;
        }

        if (tsk_verbose) {
            tsk_fprintf(stderr,"%s: Parsing sector %" PRIuDADDR " for dir %" 
                PRIuINUM "\n", func_name, a_sector_addrs[sector_index], a_fs_dir->addr);
        }

        /* Get the allocation status of the current sector. */
        if ((name_info.sector_is_allocated = 
            fatfs_is_sectalloc(a_fatfs, a_sector_addrs[sector_index])) == -1) {
            if (tsk_verbose) {
                tsk_fprintf(stderr, 
                    "%s: Error looking up allocation status of sector : %"
                    PRIuDADDR "\n", func_name, a_sector_addrs[sector_index]);
                tsk_error_print(stderr);
            }
            tsk_error_reset();
            continue;
        }

        /* Loop through the putative directory entries in the current sector. */
        for (dentry_index = 0; dentry_index < a_fatfs->dentry_cnt_se; ++dentry_index, ++dentry) {
            FATFS_DENTRY *current_dentry = dentry;
            TSK_INUM_T current_inum = base_inum_of_sector + dentry_index;
            EXFATFS_DIR_ENTRY_TYPE dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

            ++entries_count;

            if (!fatfs_inum_is_in_range(a_fatfs, current_inum)) {
                tsk_fs_name_free(name_info.fs_name);
                return TSK_ERR;
            }

            if (exfatfs_is_dentry(a_fatfs, current_dentry, 
                (FATFS_DATA_UNIT_ALLOC_STATUS_ENUM)name_info.sector_is_allocated, 
                (uint8_t)(!is_corrupt_dir && name_info.sector_is_allocated))) {
                dentry_type = (EXFATFS_DIR_ENTRY_TYPE)current_dentry->data[0];
            }
            else {
                dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;
            }

            switch(exfatfs_get_enum_from_type(dentry_type)) {
            case EXFATFS_DIR_ENTRY_TYPE_FILE:
                exfats_parse_file_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
                exfats_parse_file_stream_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
                exfats_parse_file_name_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
                exfats_parse_vol_label_dentry(&name_info, current_dentry, current_inum);
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            case EXFATFS_DIR_ENTRY_TYPE_TEXFAT:
            case EXFATFS_DIR_ENTRY_TYPE_ACT:
                exfats_parse_special_file_dentry(&name_info, current_dentry, current_inum);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_NONE:
            default:
                ++invalid_entries_count;
                if (entries_count == 4 && invalid_entries_count == 4) {
                    /* If the first four putative entries in the buffer are not
                     * entries, set the corrupt directory flag to make entry tests
                     * more in-depth, even for allocated sectors. */
                    is_corrupt_dir = 1;
                }

                /* Starting parse of a new name, save the previous name, 
                 * if any. */
                exfatfs_add_name_to_dir_and_reset_info(&name_info);

                break;
            }
        }
    }

     /* Save the last parsed name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(&name_info);
    tsk_fs_name_free(name_info.fs_name);

    return TSK_OK;
}
