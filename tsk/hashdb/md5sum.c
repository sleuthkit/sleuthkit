/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2003-2014 Brian Carrier.  All rights reserved
*
*
* This software is distributed under the Common Public License 1.0
*/

/**
* \file md5sum.c
* Contains the MD5sum hash database specific extraction and printing routines.
*/

#include "tsk_hashdb_i.h"

#define STR_EMPTY ""

/**
* Test the file to see if it is a md5sum database
*
* @param hFile File handle to hash database
*
* @return 1 if md5sum and 0 if not
*/
uint8_t
    md5sum_test(FILE * hFile)
{
    char buf[TSK_HDB_MAXLEN];

    fseeko(hFile, 0, SEEK_SET);
    if (NULL == fgets(buf, TSK_HDB_MAXLEN, hFile))
        return 0;

    if (strlen(buf) < TSK_HDB_HTYPE_MD5_LEN)
        return 0;

    if ((buf[0] == 'M') && (buf[1] == 'D') &&
        (buf[2] == '5') && (buf[3] == ' ') && (buf[4] == '(')) {
            return 1;
    }

    if ((isxdigit((int) buf[0]))
        && (isxdigit((int) buf[TSK_HDB_HTYPE_MD5_LEN - 1]))
        && (isspace((int) buf[TSK_HDB_HTYPE_MD5_LEN]))) {
            return 1;
    }

    return 0;
}

TSK_HDB_INFO *md5sum_open(FILE *hDb, const TSK_TCHAR *db_path)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = NULL;

    // get the basic binary-search info struct
    hdb_binsrch_info = hdb_binsrch_open(hDb, db_path);
    if (NULL == hdb_binsrch_info) {
        return NULL;
    }

    // overwrite with more specific methods
    hdb_binsrch_info->base.db_type = TSK_HDB_DBTYPE_MD5SUM_ID;
    hdb_binsrch_info->get_entry = md5sum_getentry;
    hdb_binsrch_info->base.make_index = md5sum_makeindex;

    return (TSK_HDB_INFO*)hdb_binsrch_info;    
}

/**
* Given a line of text from an MD5sum database, return pointers
* to the start start of the name and MD5 hash values (original 
* string will have NULL values in it).
*
* @param [in]Input string from database -- THIS WILL BE MODIFIED
* @param [out] Will contain a pointer to MD5 value in input string
* @param [out] Will contain a pointer to name value in input string (input could be NULL)
*
* @return 1 on error and 0 on success
*/
static uint8_t
    md5sum_parse_md5(char *str, char **md5, char **name)
{
    char *ptr;

    if (strlen(str) < TSK_HDB_HTYPE_MD5_LEN + 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
            "md5sum_parse_md5: String is too short: %s", str);
        return 1;
    }

    /* Format of: MD5      NAME  or even just the MD5 value */
    if ((isxdigit((int) str[0]))
        && (isxdigit((int) str[TSK_HDB_HTYPE_MD5_LEN - 1]))
        && (isspace((int) str[TSK_HDB_HTYPE_MD5_LEN]))) {
            unsigned int i;
            size_t len = strlen(str);

            if (md5 != NULL) {
                *md5 = &str[0];
            }
            i = TSK_HDB_HTYPE_MD5_LEN;
            str[i++] = '\0';

            /* Just the MD5 values */
            if (i >= len) {
                if (name != NULL) {
                    *name = STR_EMPTY;
                }
                return 0;
            }

            while ((i < len) && ((str[i] == ' ') || (str[i] == '\t'))) {
                i++;
            }

            if ((len == i) || (str[i] == '\n')) {
                return 0;
            }

            if (str[i] == '*') {
                i++;
            }

            if (name != NULL) {
                *name = &str[i];
            }
            ptr = &str[i];

            if (ptr[strlen(ptr) - 1] == '\n')
                ptr[strlen(ptr) - 1] = '\0';
    }

    /* Format of: MD5 (NAME) = MD5 */
    else if ((str[0] == 'M') && (str[1] == 'D') &&
        (str[2] == '5') && (str[3] == ' ') && (str[4] == '(')) {

            ptr = &str[5];

            if (name != NULL) {
                *name = ptr;
            }

            if (NULL == (ptr = strchr(ptr, ')'))) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                    "md5sum_parse_md5: Missing ) in name: %s", str);
                return 1;
            }
            *ptr = '\0';
            ptr++;


            if (4 + TSK_HDB_HTYPE_MD5_LEN > strlen(ptr)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                    "md5sum_parse_md5: Invalid MD5 value: %s", ptr);
                return 1;
            }

            if ((*(ptr) != ' ') || (*(++ptr) != '=') ||
                (*(++ptr) != ' ') || (!isxdigit((int) *(++ptr))) ||
                (ptr[TSK_HDB_HTYPE_MD5_LEN] != '\n')) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                    tsk_error_set_errstr(
                        "md5sum_parse_md5: Invalid hash value %s", ptr);
                    return 1;
            }

            *md5 = ptr;
            ptr[TSK_HDB_HTYPE_MD5_LEN] = '\0';
    }

    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
            "md5sum_parse_md5: Invalid md5sum format in file: %s\n",
            str);
        return 1;
    }

    return 0;
}

/**
* Process the database to create a sorted index of it. Consecutive
* entries with the same hash value are not added to the index, but
* will be found during lookup.
*
* @param hdb_info_base Hash database to make index of.
* @param dbtype Type of hash database (should always be TSK_HDB_DBTYPE_MD5SUM_STR)
*
* @return 1 on error and 0 on success.
*/
uint8_t
    md5sum_makeindex(TSK_HDB_INFO *hdb_info_base, TSK_TCHAR * dbtype)
{
    TSK_HDB_BINSRCH_INFO *hdb_info = (TSK_HDB_BINSRCH_INFO*)hdb_info_base;
    int i;
    char buf[TSK_HDB_MAXLEN];
    char *hash = NULL, phash[TSK_HDB_HTYPE_MD5_LEN + 1];
    TSK_OFF_T offset = 0;
    int db_cnt = 0, idx_cnt = 0, ig_cnt = 0;
    size_t len;

    /* Initialize the TSK index file */
    if (hdb_binsrch_idx_initialize(hdb_info, dbtype)) {
        tsk_error_set_errstr2( "md5sum_makeindex");
        return 1;
    }

    /* Status */
    if (tsk_verbose)
        TFPRINTF(stderr, _TSK_T("Extracting Data from Database (%s)\n"),
        hdb_info->base.db_fname);

    /* Allocate a buffer for the previous hash value */
    memset(phash, '0', TSK_HDB_HTYPE_MD5_LEN + 1);

    /* read the file and add to the index */
    fseek(hdb_info->hDb, 0, SEEK_SET);
    for (i = 0; NULL != fgets(buf, TSK_HDB_MAXLEN, hdb_info->hDb);
        offset += (TSK_OFF_T) len, i++) {

            len = strlen(buf);

            /* Parse each line */
            if (md5sum_parse_md5(buf, &hash, NULL)) {
                ig_cnt++;
                continue;
            }
            db_cnt++;

            /* We only want to add one of each hash to the index */
            if (memcmp(hash, phash, TSK_HDB_HTYPE_MD5_LEN) == 0) {
                continue;
            }

            /* Add the entry to the index */
            if (hdb_binsrch_idx_add_entry_str(hdb_info, hash, offset)) {
                tsk_error_set_errstr2( "md5sum_makeindex");
                return 1;
            }

            idx_cnt++;

            /* Set the previous has value */
            strncpy(phash, hash, TSK_HDB_HTYPE_MD5_LEN + 1);
    }

    if (idx_cnt > 0) {

        if (tsk_verbose) {
            fprintf(stderr, "  Valid Database Entries: %d\n", db_cnt);
            fprintf(stderr,
                "  Invalid Database Entries (headers or errors): %d\n",
                ig_cnt);
            fprintf(stderr, "  Index File Entries %s: %d\n",
                (idx_cnt == db_cnt) ? "" : "(optimized)", idx_cnt);
        }

        /* Close and sort the index */
        if (hdb_binsrch_idx_finalize(hdb_info)) {
            tsk_error_set_errstr2( "md5sum_makeindex");
            return 1;
        }
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
            "md5sum_makeindex: No valid entries found in database");
        return 1;
    }

    return 0;
}

/**
* Find the corresponding name at a
* given offset.  The offset was likely determined from the index.
* The entries in the DB following the one specified are also processed
* if they have the same hash value and their name is different. 
* The callback is called for each entry. 
*
* @param hdb_info Hash database to get data from
* @param hash MD5 hash value that was searched for
* @param offset Byte offset where hash value should be located in db_file
* @param flags (not used)
* @param action Callback used for each entry found in lookup
* @param cb_ptr Pointer to data passed to callback
*
* @return 1 on error and 0 on succuss
*/
uint8_t
    md5sum_getentry(TSK_HDB_INFO * hdb_info, const char *hash,
    TSK_OFF_T offset, TSK_HDB_FLAG_ENUM flags,
    TSK_HDB_LOOKUP_FN action, void *cb_ptr)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info;
    char buf[TSK_HDB_MAXLEN], *name, *ptr = NULL, pname[TSK_HDB_MAXLEN];
    int found = 0;

    if (tsk_verbose)
        fprintf(stderr,
        "md5sum_getentry: Lookup up hash %s at offset %" PRIuOFF
        "\n", hash, offset);

    if (strlen(hash) != TSK_HDB_HTYPE_MD5_LEN) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "md5sum_getentry: Invalid hash value: %s", hash);
        return 1;
    }

    memset(pname, '0', TSK_HDB_MAXLEN);

    /* Loop so that we can find multiple occurrences of the same hash */
    while (1) {
        size_t len;

        if (0 != fseeko(hdb_binsrch_info->hDb, offset, SEEK_SET)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                "md5sum_getentry: Error seeking to get file name: %lu",
                (unsigned long) offset);
            return 1;
        }

        if (NULL == fgets(buf, TSK_HDB_MAXLEN, hdb_binsrch_info->hDb)) {
            if (feof(hdb_binsrch_info->hDb)) {
                break;
            }
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                "md5sum_getentry: Error reading database");
            return 1;
        }

        len = strlen(buf);
        if (len < TSK_HDB_HTYPE_MD5_LEN) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                "md5sum_getentry: Invalid entry in database (too short): %s",
                buf);
            return 1;
        }

        if (md5sum_parse_md5(buf, &ptr, &name)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                "md5sum_getentry: Invalid entry in database: %s",
                buf);
            return 1;
        }

        /* Is this the one that we want? */
        if (0 != strcasecmp(ptr, hash)) {
            break;
        }

        if (strcmp(name, pname) != 0) {
            int retval;
            retval = action(hdb_info, hash, name, cb_ptr);
            if (retval == TSK_WALK_ERROR) {
                return 1;
            }
            else if (retval == TSK_WALK_STOP) {
                return 0;
            }
            found = 1;
            strncpy(pname, name, TSK_HDB_MAXLEN);
        }

        /* Advance to the next row */
        offset += len;
    }

    if (found == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "md5sum_getentry: Hash not found in file at offset: %lu",
            (unsigned long) offset);
        return 1;
    }

    return 0;
}
