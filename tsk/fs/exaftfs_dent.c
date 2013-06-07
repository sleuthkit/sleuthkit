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

typedef struct {
    TSK_INUM_T inum;
    uint8_t in_use;
    uint8_t is_dir;
    uint8_t *name_utf16_bytes;
    uint8_t name_length;
    uint8_t expected_secondary_entry_count;
    uint8_t actual_secondary_entry_count;
    uint16_t expected_check_sum;
    uint16_t actual_check_sum;
} EXFATFS_FILE_DENTRY_SET_INFO;

void
exfats_add_file_dentry(TSK_INUM_T a_inum, FATFS_DENTRY *a_dentry, EXFATFS_FILE_DENTRY_SET_INFO *dentry_set)
{
    const char *func_name = "exfats_parse_directory_entries_buf";
    EXFATFS_FILE_DIR_ENTRY *dentry = NULL;

    assert(a_dentry != NULL);
    assert(dentry_set != NULL);

    dentry = (EXFATFS_FILE_DIR_ENTRY*)a_dentry; 
    dentry_set->inum = a_inum;
    dentry_set->in_use = dentry->entry_type == EXFATFS_DIR_ENTRY_TYPE_FILE ? 1 : 0;
    dentry_set->is_dir = (dentry->attrs[0] & FATFS_ATTR_DIRECTORY);
}

void
exfats_parse_dentries_buf()
{
    const char *func_name = "exfats_parse_directory_entries_buf";

}

// RJCTODO: Correct comment
/**
 * /internal
 * Process the contents of a directory and add them to FS_DIR.
 *
 * @param a_fatfs File system information structure for file system that
 * contains the directory.
 * @param a_fs_dir Directory structure to store the files in.
 * @param list_seen List of directory inodes that have been seen thus far in
 * directory walking (can be a pointer to a NULL pointer on first call).
 * @param buf Buffer that contains the directory contents.
 * @param len Length of buffer in bytes (must be a multiple of sector size)
 * @param addrs Array where each element is the original address of the
 * corresponding block in buf (size of array is number of blocks in directory).
 * @return TSK_RETVAL_ENUM
*/
TSK_RETVAL_ENUM
exfatfs_parse_directory_buf(FATFS_INFO *a_fatfs, TSK_FS_DIR *a_fs_dir, char *a_buf,
    TSK_OFF_T a_buf_len, TSK_DADDR_T *a_sector_addrs)
{
    const char *func_name = "exfatfs_parse_directory_buf";
    TSK_FS_INFO *fs = NULL;
    TSK_FS_NAME *fs_name = NULL;
    TSK_OFF_T num_sectors = 0;
    TSK_OFF_T sector_index = 0;
    TSK_INUM_T base_inum_of_sector = 0;
    int8_t sector_is_alloc = 0;
    EXFATFS_FILE_DENTRY_SET_INFO dentry_set_info;
    TSK_OFF_T dentry_index = 0;
    FATFS_DENTRY *dentry = NULL;

    tsk_error_reset();
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_dir, "a_fs_dir", func_name) ||
        fatfs_is_ptr_arg_null(a_buf, "a_buf", func_name) ||
        fatfs_is_ptr_arg_null(a_sector_addrs, "a_sector_addrs", func_name)) {
        return TSK_ERR; 
    }

    fs = (TSK_FS_INFO*)a_fatfs;
    memset((void*)&dentry_set_info, 0, sizeof(EXFATFS_FILE_DENTRY_SET_INFO));
    dentry = (FATFS_DENTRY*)a_buf;

    if ((fs_name = tsk_fs_name_alloc(EXFATFS_MAX_NAME_LEN_UTF8, 0)) == NULL) {
        return TSK_ERR;
    }

    /* Loop through the sectors in the buffer. */ 
    num_sectors = a_buf_len / a_fatfs->ssize;
    for (sector_index = 0; sector_index < num_sectors; ++sector_index) {
        /* Convert the address of the current sector into an inode address. */
        base_inum_of_sector = 
            FATFS_SECT_2_INODE(a_fatfs, a_sector_addrs[sector_index]);
        if (base_inum_of_sector > fs->last_inum) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("fatfs_parse: inode address is too large");
            tsk_fs_name_free(fs_name);
            return TSK_COR;
        }

        if (tsk_verbose) {
            tsk_fprintf(stderr,"%s: Parsing sector %" PRIuDADDR " for dir %" 
                PRIuINUM "\n", func_name, a_sector_addrs[sector_index], a_fs_dir->addr);
        }

        /* Get the allocation status of the current sector. */
        if ((sector_is_alloc = fatfs_is_sectalloc(a_fatfs, a_sector_addrs[sector_index])) == -1) {
            if (tsk_verbose) {
                tsk_fprintf(stderr,
                    "%s: Error looking up sector allocation: %"
                    PRIuDADDR "\n", func_name, a_sector_addrs[sector_index]);
                tsk_error_print(stderr);
            }
            tsk_error_reset();
            continue;
        }

        /* Loop through the putative directory entries in the current sector. */
        for (dentry_index = 0; dentry_index < a_fatfs->dentry_cnt_se; ++dentry_index, ++dentry) {
            FATFS_DENTRY *current_dentry = dentry;
            TSK_INUM_T current_inode = base_inum_of_sector + dentry_index;
            EXFATFS_DIR_ENTRY_TYPE_ENUM dentry_type = EXFATFS_DIR_ENTRY_TYPE_NONE;

            //entrySeenCount++;

            dentry_type = exfatfs_is_dentry(a_fatfs, current_dentry, sector_is_alloc); //RJCTODO: Change data type of third param
            switch (dentry_type) {
            case EXFATFS_DIR_ENTRY_TYPE_FILE:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE:
                // RJCTODO: Get the secondary count and start collecting the data
                // from the parts. Perhaps this should all be in another loop?
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_STREAM:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_STREAM:
                // RJCTODO: Update state and collect data
                break;
            case EXFATFS_DIR_ENTRY_TYPE_FILE_NAME:
            case EXFATFS_DIR_ENTRY_TYPE_DELETED_FILE_NAME:
                // RJCTODO: If found the last file name entry, the fs_name structure can be populated and stored.
                break;
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL:
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_LABEL_EMPTY:
            case EXFATFS_DIR_ENTRY_TYPE_VOLUME_GUID:
            case EXFATFS_DIR_ENTRY_TYPE_ALLOC_BITMAP:
            case EXFATFS_DIR_ENTRY_TYPE_UPCASE_TABLE:
            case EXFATFS_DIR_ENTRY_TYPE_TEX_FAT:
            case EXFATFS_DIR_ENTRY_TYPE_ACT:
                // RJCTODO: Ignore? Save volume label? Save virtual file names?
                break;
            case EXFATFS_DIR_ENTRY_TYPE_NONE:
                // RJCTODO: Need special handling like in FATXX
                continue; // RJCTODO: Does this have the right effect here?
                break;
            default:
                // RJCTODO: At least assert
                break;
            }



            //if (0 == fatxxfs_is_dentry(fatfs, (FATFS_DENTRY*)dep,
            //    ((isCorruptDir == 0) && (sectalloc)) ? 1 : 0)) {
            //        if (tsk_verbose)
            //            tsk_fprintf(stderr,
            //            "fatfs_dent_parse_buf: Entry %u is invalid\n",
            //            idx);
            //        entryInvalidCount++;
            //        // RJCTODO: What does this mean?
            //        /* If we have seen four entries and all of them are corrupt,
            //        * then test every remaining entry in this folder -- 
            //        * even if the sector is allocated. The scenario is one
            //        * where we are processing a cluster that is allocated
            //        * to a file and we happen to get some data that matches
            //        * every now and then. */
            //        if ((entrySeenCount == 4) && (entryInvalidCount == 4)) {
            //            isCorruptDir = 1;
            //        }
            //        continue;
            //}

        }
    }

    tsk_fs_name_free(fs_name);

    return TSK_OK;
}