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
fatfs_is_inum_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs; 

    if ((a_inum < fs->first_inum) || (a_inum > fs->last_inum)) {
        return 0;
    }
    return 1;
}

uint8_t
fatfs_is_ptr_arg_null(void *ptr, const char *param_name, const char *func_name)
{
    assert(ptr != NULL);
    if (ptr == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: %s argument is NULL", param_name, func_name);
        return 1;
    }
    return 0;
}

uint8_t
fatfs_is_inum_arg_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, const char *func_name)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs; 

    if (!fatfs_is_inum_in_range(a_fatfs, a_inum)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("%s: invalid inode address: %" PRIuINUM, func_name, a_inum);
        return 0;
    }              
    return 1;
}

/*
** Convert the DOS time to the UNIX version
**
** UNIX stores the time in seconds from 1970 in UTC
** FAT dates are the actual date with the year relative to 1980
**
*/
time_t
dos2unixtime(uint16_t date, uint16_t time, uint8_t timetens)
{
    struct tm tm1;
    time_t ret;

    if (date == 0)
        return 0;

    memset(&tm1, 0, sizeof(struct tm));

    tm1.tm_sec = ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2;
    if ((tm1.tm_sec < 0) || (tm1.tm_sec > 60))
        tm1.tm_sec = 0;
    // the ctimetens value has a range of 0 to 199
    if (timetens > 100)
        tm1.tm_sec++;

    tm1.tm_min = ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT);
    if ((tm1.tm_min < 0) || (tm1.tm_min > 59))
        tm1.tm_min = 0;

    tm1.tm_hour = ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT);
    if ((tm1.tm_hour < 0) || (tm1.tm_hour > 23))
        tm1.tm_hour = 0;

    tm1.tm_mday = ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT);
    if ((tm1.tm_mday < 1) || (tm1.tm_mday > 31))
        tm1.tm_mday = 0;

    tm1.tm_mon = ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1;
    if ((tm1.tm_mon < 0) || (tm1.tm_mon > 11))
        tm1.tm_mon = 0;

    /* There is a limit to the year because the UNIX time value is
     * a 32-bit value
     * the maximum UNIX time is Tue Jan 19 03:14:07 2038
     */
    tm1.tm_year = ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80;
    if ((tm1.tm_year < 0) || (tm1.tm_year > 137))
        tm1.tm_year = 0;

    /* set the daylight savings variable to -1 so that mktime() figures
     * it out */
    tm1.tm_isdst = -1;

    ret = mktime(&tm1);

    if (ret < 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "dos2unixtime: Error running mktime() on: %d:%d:%d %d/%d/%d\n",
                ((time & FATFS_HOUR_MASK) >> FATFS_HOUR_SHIFT),
                ((time & FATFS_MIN_MASK) >> FATFS_MIN_SHIFT),
                ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2,
                ((date & FATFS_MON_MASK) >> FATFS_MON_SHIFT) - 1,
                ((date & FATFS_DAY_MASK) >> FATFS_DAY_SHIFT),
                ((date & FATFS_YEAR_MASK) >> FATFS_YEAR_SHIFT) + 80);
        return 0;
    }

    return ret;
}

/* timetens is number of tenths of a second for a 2 second range (values 0 to 199) */
uint32_t
dos2nanosec(uint8_t timetens)
{
    timetens %= 100;
    return timetens * 10000000;
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
     * supposed to be UTF-8 and we don't know what encoding it is actually in 
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