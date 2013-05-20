/*
** The Sleuth Kit
**
** Copyright (c) 2013 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file fatfs_utils.c
 * Contains utility functions for processing FAT file systems. 
 */

#include "tsk_fs_i.h"
#include "tsk_fatfs.h"
#include <assert.h>

uint8_t
fatfs_is_ptr_arg_null(void *ptr, const char *param_name, const char *func_name)
{
    assert(ptr != NULL);
    if (ptr == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: %s argument is NULL", param_name, func_name);
        return 1;
    }
    return 0;
}

uint8_t
fatfs_is_inum_in_range(TSK_FS_INFO *a_fs, TSK_INUM_T a_inum, const char *func_name)
{
    if ((a_inum < a_fs->first_inum)
        || (a_inum > a_fs->last_inum - FATFS_NUM_SPECFILE)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("%s: address: %" PRIuINUM, func_name, a_inum);
        return 0;
    }              
    return 1;
}

TSKConversionResult
fatfs_copy_utf16_str_2_meta_name(FATFS_INFO *a_fatfs, TSK_FS_META *a_fs_meta, UTF16 *src, uint8_t src_len, TSK_INUM_T a_inum, const char *a_desc)
{
    const char *func_name = "exfatfs_copy_utf16_str_2_meta_name";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSKConversionResult conv_result = TSKconversionOK;
    UTF8 *dest = NULL;
    UTF8 *dest_end = NULL;
    uint32_t i = 0;

    /* Validate the function arguments. */
    if (fatfs_is_ptr_arg_null(a_fatfs, "a_fatfs", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta, "a_fs_meta", func_name) ||
        fatfs_is_ptr_arg_null(a_fs_meta->name2, "a_fs_meta->name2", func_name)) {
        return TSKsourceIllegal; // RJCTODO: This may be less than ideal...
    }

    dest = (UTF8*)a_fs_meta->name2->name;
    dest_end = (UTF8*)((uintptr_t)a_fs_meta->name2->name + sizeof(a_fs_meta->name2->name));
    conv_result = tsk_UTF16toUTF8(fs->endian, (const UTF16**)&src, (UTF16*)&src[src_len], &dest, dest_end, TSKlenientConversion);
    if (conv_result == TSKconversionOK) {
        /* Make sure the result is NULL-terminated. */
        if ((uintptr_t) dest > (uintptr_t) a_fs_meta->name2->name + sizeof(a_fs_meta->name2->name)) {
            a_fs_meta->name2->name[sizeof(a_fs_meta->name2->name) - 1] = '\0';
        }
        else {
            *dest = '\0';
        }
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNICODE);
        tsk_error_set_errstr("%s: Error converting %s for inum %d from UTF16 to UTF8: %d", func_name, a_desc, a_inum, conv_result);
        *dest = '\0';
    }

    /* Clean up non-ASCII because we are copying it into a buffer that is 
     * supposed to be UTF-8 andwe don't know what encoding it is actually in 
     * or if it is simply junk. */
    fatfs_cleanup_ascii(a_fs_meta->name2->name);

    /* Clean up name to remove control characters */
    i = 0;
    while (a_fs_meta->name2->name[i] != '\0') {
        if (TSK_IS_CNTRL(a_fs_meta->name2->name[i]))
            a_fs_meta->name2->name[i] = '^';
        i++;
    }

    return conv_result;
}

/** 
 * Cleans up a char string so that it is only ASCII. We do this
 * before we copy something into a TSK buffer that is supposed 
 * to be UTF-8.  If it is not ASCII and it is from a single-byte
 * data structure, then we we clean it up because we dont' know
 * what the actual encoding is (or if it is corrupt). 
 * @param name Name to cleanup
 */
void
fatfs_cleanup_ascii(char *name)
{
    int i;
    for (i = 0; name[i] != '\0'; i++) {
        if ((unsigned char) (name[i]) > 0x7e) {
            name[i] = '^';
        }
    }
}