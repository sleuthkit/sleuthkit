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

/**
 * \internal
 * Tests whether a pointer argument is set to NULL. If the pointer is NULL,
 * sets a TSK_ERR_FS_ARG error with an error message that includes a parameter
 * name and a function name supplied by the caller.
 *
 * @param a_ptr The pointer to test for NULL.
 * @param a_param_name The name of the parameter for which the pointer was
 * passed as an argument.
 * @param a_func_name The name of the function for which a_param is a 
 * parameter.
 * @return Returns 1 if the pointer is NULL, 0 otherwise.
 */
uint8_t
fatfs_ptr_arg_is_null(void *a_ptr, const char *a_param_name, const char *a_func_name)
{
    const char *func_name = "fatfs_ptr_arg_is_null";

    assert(a_param_name != NULL);
    assert(a_func_name != NULL);

    if (a_ptr == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        if ((a_param_name != NULL) && (a_func_name != NULL)) { 
            tsk_error_set_errstr("%s: %s is NULL", a_param_name, a_func_name);
        }
        else {
            tsk_error_set_errstr("%s: NULL pointer", func_name);
        }

        return 1;
    }

    return 0;
}

/**
 * \internal
 * Tests whether an inode address is in the range of valid inode addresses for
 * a given file system.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_inum An inode address. 
 * @return Returns 1 if the address is in range, 0 otherwise.
 */
uint8_t
fatfs_inum_is_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum)
{
    const char *func_name = "fatfs_inum_is_in_range";
    TSK_FS_INFO *fs = (TSK_FS_INFO*)a_fatfs; 

    assert(a_fatfs != NULL);

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name)) {
        return 0;
    }

    if ((a_inum < fs->first_inum) || (a_inum > fs->last_inum)) {
        return 0;
    }

    return 1;
}

/**
 * \internal
 * Tests whether an inode address argument is in the range of valid inode
 * addresses for a given file system. If the address is out of range,
 * sets a TSK_ERR_FS_ARG error with an error message that includes the inode
 * address and a function name supplied by the caller.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_inum An inode address. 
 * @param a_func_name The name of the function that received the inode address 
 * as an argument.
 * @return Returns 1 if the address is in range, 0 otherwise.
 */
uint8_t
fatfs_inum_arg_is_in_range(FATFS_INFO *a_fatfs, TSK_INUM_T a_inum, const char *a_func_name)
{
    const char *func_name = "fatfs_inum_arg_is_in_range";

    assert(a_fatfs != NULL);
    assert(a_func_name != NULL);

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name)) {
        return 0;
    }

    if (!fatfs_inum_is_in_range(a_fatfs, a_inum)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        if (a_func_name != NULL) {
            tsk_error_set_errstr("%s: inode address: %" PRIuINUM " out of range", a_func_name, a_inum);
        }
        else {
            tsk_error_set_errstr("%s: inode address: %" PRIuINUM " out of range", func_name, a_inum);
        }

        return 0;
    }              
    return 1;
}

/**
 * \internal
 * Convert a DOS time stamp into a UNIX time stamp. A DOS time stamp consists
 * of a date with the year specified as an offset from 1980. A UNIX time stamp
 * is seconds since January 1, 1970 in UTC.
 *
 * @param date Date part of a DOS time stamp.
 * @param time Time part of a DOS time stamp. 
 * @param timetens Tenths of seconds part of a DOS time stamp, range is 0-199.
 * @return A UNIX time stamp.
 */
time_t
fatfs_dos_2_unix_time(uint16_t date, uint16_t time, uint8_t timetens)
{
    struct tm tm1;
    time_t ret;

    if (date == 0)
        return 0;

    memset(&tm1, 0, sizeof(struct tm));

    tm1.tm_sec = ((time & FATFS_SEC_MASK) >> FATFS_SEC_SHIFT) * 2;
    if ((tm1.tm_sec < 0) || (tm1.tm_sec > 60))
        tm1.tm_sec = 0;

    /* The ctimetens value has a range of 0 to 199 */
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
     * the maximum UNIX time is Tue Jan 19 03:14:07 2038 */
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
                "fatfs_dos_2_unix_time: Error running mktime() on: %d:%d:%d %d/%d/%d\n",
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

/**
 * \internal
 * Converts the tenths of seconds part a DOS time stamp into nanoseconds.
 * of a date with the year specified as an offset from 1980. A UNIX time stamp
 * is seconds since January 1, 1970 in UTC.
 *
 * @param timetens Tenths of seconds part of a DOS time stamp, range is 0-199.
 * @return A duration in nanoseconds.
 */
uint32_t
fatfs_dos_2_nanosec(uint8_t timetens)
{
    timetens %= 100;
    return timetens * 10000000;
}

/** 
 * \internal
 * Cleans up a string so that it contains only ASCII characters. Useful when
 *
 * @param name The string
 */
void
fatfs_cleanup_ascii(char *str)
{
    const char *func_name = "fatfs_cleanup_ascii";

    assert(str != NULL);

    if (!fatfs_ptr_arg_is_null(str, "str", func_name)) {
        int i;
        for (i = 0; str[i] != '\0'; i++) {
            if ((unsigned char) (str[i]) > 0x7e) {
                str[i] = '^';
            }
        }
    }
}

/**
 * \internal
 * Converts a UTF-16 string from an inode into a null-terminated UTF-8 string. If the 
 * conversion fails, sets a TSK_ERR_FS_UNICODE error with an error message 
 * that includes the inode address and a description of the UTF-16 string
 * supplied by the caller.
 *
 * Unlike tsk_UTF16toUTF8, a_src and a_dest will not be updated to point 
 * to where the conversion stopped reading/writing.
 *
 * @param a_fatfs Generic FAT file system info structure.
 * @param a_src The UTF-16 string to convert.
 * @param a_src_len The number of UTF16 items in a_src.
 * @param a_dest The buffer for the UTF-8 string.
 * @param a_dest_len The number of bytes in a_dest.
 * @param a_inum The address of the source inode, used if an error message is
 * generated.
 * @param a_desc A description of the source string, used if an error message 
 * is generated.
 * @return TSKConversionResult.
 */
TSKConversionResult
fatfs_utf16_inode_str_2_utf8(FATFS_INFO *a_fatfs, UTF16 *a_src, size_t a_src_len, UTF8 *a_dest, size_t a_dest_len, TSK_INUM_T a_inum, const char *a_desc)
{
    const char *func_name = "fatfs_copy_utf16_str";
    TSK_FS_INFO *fs = &(a_fatfs->fs_info);
    TSKConversionResult conv_result = TSKconversionOK;
    UTF8* dest_start;
    UTF8* dest_end;
    
    assert(a_fatfs != NULL);
    assert(a_src != NULL);
    assert(a_src_len > 0);
    assert(a_dest != NULL);
    assert(a_dest_len > 0);
    assert(a_desc != NULL);

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_fatfs", func_name)) {
        return TSKsourceIllegal; 
    }

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_src", func_name)) {
        return TSKsourceExhausted; 
    }

    if (a_src_len <= 0) {
        return TSKsourceExhausted; 
    }

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_dest", func_name)) {
        return TSKtargetExhausted; 
    }

    if (a_dest_len <= 0) {
        return TSKtargetExhausted; 
    }

    if (fatfs_ptr_arg_is_null(a_fatfs, "a_desc", func_name)) {
        return TSKsourceIllegal; 
    }

    /* Do the conversion. Note that a_dest and a_src will point to where the conversion
     * stopped reading/writing. */
    dest_start = a_dest;
    dest_end = (UTF8*)&a_dest[a_dest_len];
    conv_result = tsk_UTF16toUTF8(fs->endian, (const UTF16**)&a_src, (UTF16*)&a_src[a_src_len], &a_dest, dest_end, TSKlenientConversion);

    if (conv_result != TSKconversionOK) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_UNICODE);
        tsk_error_set_errstr("%s: Error converting %s for inum %"PRIuINUM" from UTF16 to UTF8: %d", func_name, a_desc, a_inum, conv_result);
        *a_dest = '\0';
        return conv_result;
    }

    /* Make sure the result is NULL-terminated. */
    if((uintptr_t)a_dest >= (uintptr_t)dest_end)
        dest_start[a_dest_len - 1] = '\0';
    else
        *a_dest = '\0';

    return conv_result;
}
