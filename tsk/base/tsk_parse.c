/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All Rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */
#include "tsk_base_i.h"


/**
 * \file tsk_parse.c
 * Contains code to parse specific types of data from
 * the command line
 */

/**
 * \ingroup baselib
 * Parse a TSK_TCHAR block address string.
 * Note that the cnt\@size format is no longer supported.
 * Set the device sector size in img_open to set the block size.
 *
 * @param [in] a_offset_str The string version of the offset
 * @return -1 on error or block offset on success
 */
TSK_OFF_T
tsk_parse_offset(const TSK_TCHAR * a_offset_str)
{
    TSK_TCHAR offset_lcl[64], *offset_lcl_p;
    TSK_DADDR_T num_blk;
    TSK_TCHAR *cp;

    if (a_offset_str == NULL) {
        return 0;
    }
    if (TSTRLEN(a_offset_str) > 63) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OFFSET);
        tsk_error_set_errstr("tsk_parse: offset string is too long: %"
            PRIttocTSK, a_offset_str);
        return -1;
    }

    /* Make a local copy */
    TSTRNCPY(offset_lcl, a_offset_str, 64);
    offset_lcl_p = offset_lcl;

    /* Check for the old x@y setup */
    if (TSTRCHR(offset_lcl_p, '@') != NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OFFSET);
        tsk_error_set_errstr
            ("tsk_parse: offset string format no longer supported.  Use -b to specify sector size: %"
            PRIttocTSK, a_offset_str);
        return -1;
    }

    offset_lcl_p = offset_lcl;

    /* remove leading 0s */
    while ((offset_lcl_p[0] != '\0') && (offset_lcl_p[0] == '0'))
        offset_lcl_p++;

    num_blk = 0;
    if (offset_lcl_p[0] != '\0') {
        num_blk = TSTRTOULL(offset_lcl_p, &cp, 0);
        if (*cp || *cp == *offset_lcl_p) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_IMG_OFFSET);
            tsk_error_set_errstr("tsk_parse: invalid image offset: %"
                PRIttocTSK, offset_lcl_p);
            return -1;
        }
    }

    return num_blk;
}




/**
 * \ingroup baselib
 * Parse a TSK_TCHAR string of a partition byte offset and the
 * integer version of it.
 *
 * @param [in] a_pnum_str The string version of the address
 * @param [out] a_pnum The parsed integer version of the address
 * @return 1 on error and 0 on success
 */
int
tsk_parse_pnum(const TSK_TCHAR * a_pnum_str, TSK_PNUM_T * a_pnum)
{
    TSK_TCHAR *cp;

    if (a_pnum_str == NULL) {
        return 0;
    }

    *a_pnum = TSTRTOUL(a_pnum_str, &cp, 0);
    if (*cp || *cp == *a_pnum_str) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_IMG_OFFSET);
        tsk_error_set_errstr("tsk_parse: invalid partition address: %"
            PRIttocTSK, a_pnum_str);
        return 1;
    }

    return 0;
}
