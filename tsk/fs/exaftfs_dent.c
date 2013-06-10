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
 * Contains the internal TSK exFAT file system code to handle name 
 * category processing. 
 */

#include "tsk_exfatfs.h" /* Include first to make sure it stands alone. */
#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

/**
 * /Internal
 * Bundles a TSK_FS_NAME object and a TSK_FS_DIR object with additional data 
 * required when assembling a name from file directory entry set.
 */
typedef struct {
    int8_t sector_is_allocated;
    uint8_t in_use;
    uint8_t expected_secondary_entry_count;
    uint8_t actual_secondary_entry_count;
    uint16_t expected_check_sum;
    uint16_t actual_check_sum;
    uint8_t utf16_name_length;
    uint8_t utf16_chars_found;
    TSK_FS_NAME *fs_name;
    TSK_FS_DIR *fs_dir;
} 
EXFATFS_FS_NAME_INFO;

// RJCTODO: comment
static void
exfatfs_reset_name_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    a_name_info->in_use = 0;
    a_name_info->expected_secondary_entry_count = 0;
    a_name_info->actual_secondary_entry_count = 0;
    a_name_info->expected_check_sum = 0;
    a_name_info->actual_check_sum = 0;
    memset((void*)a_name_info->fs_name->name, 0, a_name_info->fs_name->name_size);
    a_name_info->fs_name->meta_addr = 0;
    a_name_info->fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
    a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
}

// RJCTODO: comment
static void
exfatfs_add_name_to_dir_and_reset_info(EXFATFS_FS_NAME_INFO *a_name_info)
{
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    /* If the parsing of the directory entry or directory entry set produced
     * a name, add the TSK_FS_NAME object to the TSK_FS_DIR object. */
    if (a_name_info->fs_name->name_size > 0) {
        tsk_fs_dir_add(a_name_info->fs_dir, a_name_info->fs_name);
    }

    exfatfs_reset_name_info(a_name_info);
}

// RJCTODO: Comment
static void
exfats_parse_file_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, EXFATFS_FS_NAME_INFO *a_name_info)
{
    const char *func_name = "exfats_parse_file_dentry";
    EXFATFS_FILE_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);
    
    /* Starting parse of a new name, save the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry; 
    a_name_info->in_use = dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE ? 1 : 0;
    a_name_info->expected_secondary_entry_count = dentry->secondary_entries_count;
    a_name_info->expected_check_sum = tsk_getu16(a_fatfs->fs_info.endian, dentry->check_sum);
    
    a_name_info->fs_name->meta_addr = a_inum;

    if (dentry->attrs[0] & FATFS_ATTR_DIRECTORY) {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_DIR;
    }
    else {
        a_name_info->fs_name->type = TSK_FS_NAME_TYPE_REG;
    }
   
    if (a_name_info->sector_is_allocated && a_name_info->in_use) {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;    
    }
    else {
        a_name_info->fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;    
    }

    // RJCTODO: Update checksum.
}

// RJCTODO: Comment
static void
exfats_parse_file_stream_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, EXFATFS_FS_NAME_INFO *a_name_info)
{
    const char *func_name = "exfats_parse_file_stream_dentry"; // RJCTODO: May not need this
    EXFATFS_FILE_STREAM_DIR_ENTRY *dentry = NULL;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    dentry = (EXFATFS_FILE_STREAM_DIR_ENTRY*)a_dentry; 

    // RJCTODO: Is it necessary to compare the in-use bit of the secondary entries to the in-use bit of the file entry?
    // What about a file stream entry with no preceding file entry?

    a_name_info->utf16_name_length = dentry->file_name_length;

    ++a_name_info->actual_secondary_entry_count;
    // RJCTODO: Update checksum. 
    if (a_name_info->actual_secondary_entry_count == a_name_info->expected_secondary_entry_count) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}

// RJCTODO: Comment
static void
exfats_parse_file_name_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, EXFATFS_FS_NAME_INFO *a_name_info)
{
    const char *func_name = "exfats_parse_file_name_dentry"; // RJCTODO: May not need this
    EXFATFS_FILE_NAME_DIR_ENTRY *dentry = NULL;
    uint8_t utf16_chars_to_copy_cnt = 0;

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    dentry = (EXFATFS_FILE_NAME_DIR_ENTRY*)a_dentry; 

    // RJCTODO: Is it necessary to compare the in-use bit of the secondary entries to the in-use bit of the file entry?
    // What about a file name entry with no preceding file or file stream entry?

    if (a_name_info->utf16_chars_found < a_name_info->utf16_name_length) {
        utf16_chars_to_copy_cnt = a_name_info->utf16_name_length - a_name_info->utf16_chars_found;
        if (utf16_chars_to_copy_cnt > EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH) {
            utf16_chars_to_copy_cnt = EXFATFS_MAX_FILE_NAME_SEGMENT_LENGTH;
        }
    
        if (fatfs_strcopy_utf16_2_utf8(a_fatfs, (UTF16*)dentry->utf16_name_chars, utf16_chars_to_copy_cnt, (UTF8*)a_name_info->fs_name->name, EXFATFS_MAX_NAME_LEN_UTF8, a_inum, "file name segment") == TSKconversionOK) {
        }

        a_name_info->utf16_chars_found += utf16_chars_to_copy_cnt;
    }

    ++a_name_info->actual_secondary_entry_count;
    // RJCTODO: Update checksum. 
    if (a_name_info->actual_secondary_entry_count == a_name_info->expected_secondary_entry_count) {
        exfatfs_add_name_to_dir_and_reset_info(a_name_info);
    }
}
 
// RJCTODO: Comment
static void
exfats_parse_stand_alone_dentry(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, EXFATFS_FS_NAME_INFO *a_name_info)
{
    const char *func_name = "exfats_parse_stand_alone_dentry"; // RJCTODO: May not need this

    assert(a_fatfs != NULL);
    assert(fatfs_is_inum_in_range(a_fatfs, a_inum));
    assert(a_dentry != NULL);
    assert(a_name_info != NULL);
    assert(a_name_info->fs_name != NULL);
    assert(a_name_info->fs_dir != NULL);

    /* Starting parse of a new name, save the previous name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(a_name_info);

    switch (a_dentry->data[0]) {
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
            // RJCTODO: Write this function
                 //fs_name->name[a] = '\0';
                ///* Append a string to show it is a label */
                //if (a + 22 < FATFS_MAXNAMLEN_UTF8) {
                //    const char *volstr = " (Volume Label Entry)";
                //    strncat(fs_name->name, volstr,
                //        FATFS_MAXNAMLEN_UTF8 - a);
                //}
           break;
        case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            strcpy(a_name_info->fs_name->name, EXFATFS_VOLUME_GUID_VIRT_FILENAME);
            a_name_info->fs_name->name_size = strlen(EXFATFS_VOLUME_GUID_VIRT_FILENAME); 
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            strcpy(a_name_info->fs_name->name, EXFATFS_ALLOC_BITMAP_VIRT_FILENAME);
            a_name_info->fs_name->name_size = strlen(EXFATFS_ALLOC_BITMAP_VIRT_FILENAME); 
            break;
        case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            strcpy(a_name_info->fs_name->name, EXFATFS_UPCASE_TABLE_VIRT_FILENAME);
            a_name_info->fs_name->name_size = strlen(EXFATFS_UPCASE_TABLE_VIRT_FILENAME); 
            break;
        case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
            strcpy(a_name_info->fs_name->name, EXFATFS_TEX_FAT_VIRT_FILENAME);
            a_name_info->fs_name->name_size = strlen(EXFATFS_TEX_FAT_VIRT_FILENAME); 
            break;
        case EXFATFS_DIR_ENTRY_TYPE_ACT:
            strcpy(a_name_info->fs_name->name, EXFATFS_ACT_VIRT_FILENAME);
            a_name_info->fs_name->name_size = strlen(EXFATFS_ACT_VIRT_FILENAME); 
            break;
    }
}

/**
 * /internal
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
exfatfs_parse_directory_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
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
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_dir, "a_fs_dir", func_name) ||
        fatfs_is_ptr_arg_null(a_buf, "a_buf", func_name) ||
        fatfs_is_ptr_arg_null(a_sector_addrs, "a_sector_addrs", func_name)) {
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
    if ((name_info.fs_name = tsk_fs_name_alloc(EXFATFS_MAX_NAME_LEN_UTF8, 0)) == NULL) {
        return TSK_ERR;
    }

//    fs_name.fs_name->par_addr = a_inum; // RJCTODO: Does this need to be set here?

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
            EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

            ++entries_count;

            dentry_type = exfatfs_is_dentry(a_fatfs, current_dentry, 
                (!is_corrupt_dir && name_info.sector_is_allocated)); 

            switch (dentry_type) {
            case EXFATFS_DIR_ENTRY_TYPE_FILE:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
                exfats_parse_file_dentry(a_fatfs, current_inum, current_dentry, &name_info);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
                exfats_parse_file_stream_dentry(a_fatfs, current_inum, current_dentry, &name_info);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
                exfats_parse_file_name_dentry(a_fatfs, current_inum, current_dentry, &name_info);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
            case EXFATFS_DIR_ENTRY_TYPE_ACT:
                exfats_parse_stand_alone_dentry(a_fatfs, current_inum, current_dentry, &name_info);                 
                break;
            case EXFATFS_DIR_ENTRY_TYPE_NONE:
                ++invalid_entries_count;
                if (entries_count == 4 && invalid_entries_count == 4) {
                    /* If the first four putative entries in the buffer are not
                     * entries, set the corrupt directory flag to make entry tests
                     * more in-depth, even for allocated sectors. */
                    is_corrupt_dir = 1;
                }

                // RJCTODO: Probably need to do an output here...
                continue; // RJCTODO: Does this have the right effect here?
                break;
            default:
                // RJCTODO: What to do here, anything?
                break;
            }
        }
    }

     /* Save the last parsed name, if any. */
    exfatfs_add_name_to_dir_and_reset_info(&name_info);
    tsk_fs_name_free(name_info.fs_name);

    return TSK_OK;
}