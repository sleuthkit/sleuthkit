/*
 * The Sleuth Kit 
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All Rights reserved
 *
 *  This software is distributed under the Common Public License 1.0
 */
#include "tsk_fs_i.h"


/**
 * \file fs_parse.c
 * Contains code to parse specific types of data from 
 * the command line
 */


/**
 * \ingroup fslib
 * Parse a TSK_TCHAR string of an inode, type, and id pair (not all parts
 * need to be there).  This assumes the string is either:
 * INUM, INUM-TYPE, or INUM-TYPE-ID.  Return the values in integer form. 
 *
 * @param [in] str Input string to parse
 * @param [out] inum Pointer to location where inode can be stored.
 * @param [out] type Pointer to location where type can be stored (or NULL)
 * @param [out] type_used Pointer to location where the value can be set
 * to 1 if the type was set (to differentiate between meanings of 0) (or NULL).
 * @param [out] id Pointer to location where id can be stored (or NULL)
 * @param [out] id_used Pointer to location where the value can be set
 * to 1 if the id was set (to differentiate between meanings of 0) (or NULL).
 *
 * @return 1 on error or if not an inode and 0 on success
 */
int
tsk_fs_parse_inum(const TSK_TCHAR * str, TSK_INUM_T * inum,
    TSK_FS_ATTR_TYPE_ENUM * type, uint8_t * type_used, uint16_t * id,
    uint8_t * id_used)
{
    TSK_TCHAR *cp;
    TSK_TCHAR *tdash = NULL;
    TSK_TCHAR *tmpstr;

    if (*str == 0)
        return 1;

    if (type)
        *type = TSK_FS_ATTR_TYPE_DEFAULT;
    if (type_used)
        *type_used = 0;
    if (id)
        *id = TSK_FS_ATTR_ID_DEFAULT;
    if (id_used)
        *id_used = 0;

    /* Make a copy of the input string */
    tmpstr =
        (TSK_TCHAR *) tsk_malloc((TSTRLEN(str) + 1) * sizeof(TSK_TCHAR));
    if (tmpstr == NULL)
        return 1;

    TSTRNCPY(tmpstr, str, TSTRLEN(str) + 1);

    if ((tdash = TSTRCHR(tmpstr, _TSK_T('-'))) != NULL) {
        *tdash = '\0';
        tdash++;
    }

    *inum = TSTRTOULL(tmpstr, &cp, 10);
    if (*cp || *cp == *tmpstr) {
        free(tmpstr);
        return 1;
    }

    // if there was a dash, verify what follows is numbers
    if (tdash) {
        TSK_TCHAR *idash = NULL;
        uint32_t ttmp;

        if ((idash = TSTRCHR(tdash, _TSK_T('-'))) != NULL) {
            *idash = '\0';
            idash++;
        }

        ttmp = (uint32_t) TSTRTOUL(tdash, &cp, 10);
        if (*cp || *cp == *tdash) {
            free(tmpstr);
            return 1;
        }

        if (type != NULL) {
            *type = ttmp;
            if (type_used)
                *type_used = 1;
        }

        // if there was a dash after type, verify it is a number after it
        if (idash) {
            uint16_t itmp;

            itmp = (uint16_t) TSTRTOUL(idash, &cp, 0);
            if (*cp || *cp == *idash) {
                free(tmpstr);
                return 1;
            }

            if (id)
                *id = itmp;
            if (id_used)
                *id_used = 1;
        }
    }

    free(tmpstr);
    return 0;
}
