/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "tsk_hashdb_i.h"

/**
 * \file hk_index.c
 * Contains functions to read and process hash keeper database files
 */

/**
 * Test the file to see if it is a hashkeeper database
 *
 * @param hFile File handle to hash database
 *
 * @return 1 if hk and 0 if not
 */
uint8_t
hk_test(FILE * hFile)
{
    char buf[TSK_HDB_MAXLEN];
    int cnt = 0;
    char *ptr;

    fseek(hFile, 0, SEEK_SET);

    // read in header line
    if (NULL == fgets(buf, TSK_HDB_MAXLEN, hFile))
        return 0;

    if (strlen(buf) < 150) 
        return 0;

    ptr = buf;
    
    // "file_id","hashset_id","file_name","directory","hash","file_size","date_modified","time_modified","time_zone","comments","date_accessed","time_accessed"
    
    if (strncmp(ptr, "\"file_id\"", strlen("\"file_id\"")) != 0)
        return 0;

    /* Cycle through the line looking at the fields in between the commas */
    while (NULL != (ptr = strchr(ptr, ','))) {
        cnt++;

        if (cnt == 1) {
            if (strncmp(ptr, ",\"hashset_id\"", strlen(",\"hashset_id\"")) != 0)
                return 0;
        }
        else if (cnt == 2) {
            if (strncmp(ptr, ",\"file_name\"", strlen(",\"file_name\"")) != 0)
                return 0;
        }
        else if (cnt == 3) {
            if (strncmp(ptr, ",\"directory\"", strlen(",\"directory\"")) != 0)
                return 0;
        }
        else if (cnt == 4) {
            if (strncmp(ptr, ",\"hash\"", strlen(",\"hash\"")) != 0)
                return 0;
        }
        else {
            break;
        }
        ptr++;
    }
    return 1;
}

/**
 * Set the database name into HDB_INFO
 *
 * @param hdb_info File handle to hash database
 */
void
hk_name(TSK_HDB_INFO * hdb_info)
{
    tsk_hdb_name_from_path(hdb_info);
}

/**
 * Give a line from a hash keeper database, parse out the
 * MD5 (and other) text.  NOTE that this will add NULL values
 * to the input text. 
 *
 * @param str [in] String to parse
 * @param md5 [out] Pointer to a pointer, which will be assigned to the MD5 text in original string
 * @param name [in] Poiner to buffer where name can be copied into (can be NULL)
 * @param n_len [in] Length of name buffer
 * @param other [in] Pointer to buffer where extended data should be copied to (can be NULL)
 * @param o_len [in] Length of other buffer
 */
static int
hk_parse_md5(char *str, char **md5, char *name, int n_len,
             char *other, int o_len)
{
    char *ptr = str;
    char *file = NULL, *dir = NULL, *file_id = NULL, *hash_id = NULL;
    int cnt = 0;

    if ((str == NULL) || (strlen(str) < TSK_HDB_HTYPE_MD5_LEN))
        return 1;

    if ((md5 == NULL) && (name == NULL) && (other == NULL))
        return 0;

    /*
     * 0 file_id
     * 1 hashset_id
     * 2 file_name
     * 3 directory
     * 4 hash
     * 5 file_size
     * 6 date_modified
     * 7 time modified
     * 8 time_zone
     * 9 comments
     * 10 date_accessed
     * 11 time_accessed
     */

    /* Assign the file_id if we are looking for it */
    if (other != NULL) {
        file_id = ptr;
    }

    while (NULL != (ptr = strchr(ptr, ','))) {
        cnt++;

        /* End of file_id, begin hash_id */
        if ((cnt == 1) && (other != NULL)) {
            *ptr = '\0';
            ptr++;
            hash_id = ptr;

        }
        /* End of hash_id, begin name */
        else if (cnt == 2) {

            /* Finish the 'other' stuff */
            if (other != NULL) {
                *ptr = '\0';
                snprintf(other, o_len, "Hash ID: %s  File ID: %s",
                         hash_id, file_id);
            }

            /* Are we done? */
            if ((name == NULL) && (md5 == NULL))
                return 0;

            /* get the pointer to the name */
            if (name) {
                if (ptr[1] != '"')
                    return 1;

                file = &ptr[2];
                /* We utilize the other loop code to find the end of
                 * the name */
            }
        }
        /* end of the name, begin directory - which may not exist */
        else if ((cnt == 3) && (name != NULL)) {

            /* finish up the name */
            if (ptr[-1] != '"')
                return 1;

            ptr[-1] = '\0';

            /* get the directory start, if it exists */
            if (ptr[1] == '"') {
                dir = &ptr[2];
            }
            else {
                dir = NULL;
            }
        }
        /* end of directory, begin MD5 value */
        else if (cnt == 4) {

            /* Copy the name into the buffer */
            if (name != NULL) {
                name[0] = '\0';
                if (dir) {
                    /* finish up the dir */
                    if (ptr[-1] != '"')
                        return 1;

                    ptr[-1] = '\0';

                    strncpy(name, dir, n_len);
                    strncat(name, "\\", n_len);
                }
                if (file) {
                    strncat(name, file, n_len);
                }
                else {
                    return 1;
                }
            }

            if (md5 == NULL)
                return 0;

            /* Do a length check and more sanity checks */
            if ((strlen(ptr) < 2 + TSK_HDB_HTYPE_MD5_LEN)
                || (ptr[1] != '"')
                || (ptr[2 + TSK_HDB_HTYPE_MD5_LEN] != '"')) {
                return 1;
            }

            ptr = &ptr[2];
            ptr[TSK_HDB_HTYPE_MD5_LEN] = '\0';

            *md5 = ptr;

            /* Final sanity check */
            if (NULL != strchr(ptr, ',')) {
                return 1;
            }

            return 0;
        }

        /* If the next field is in quotes then we need to skip to the
         * next quote and ignore any ',' in there
         */
        if (ptr[1] == '"') {
            if (NULL == (ptr = strchr(&ptr[2], '"'))) {
                return 1;
            }
        }
        else {
            ptr++;
        }
    }

    return 1;
}


/**
 * Process the database to create a sorted index of it. Consecutive
 * entries with the same hash value are not added to the index, but
 * will be found during lookup.
 *
 * @param hdb_info Hash database to make index of
 * @param dbtype Text of database type (should always be TSK_HDB_DBTYPE_HK_STR)
 *
 * @return 1 on error and 0 on success.
 */
uint8_t
hk_makeindex(TSK_HDB_INFO * hdb_info, TSK_TCHAR * dbtype)
{
    int i;
    size_t len = 0;
    char buf[TSK_HDB_MAXLEN];
    char *hash = NULL, phash[TSK_HDB_HTYPE_MD5_LEN + 1];
    TSK_OFF_T offset = 0;
    int db_cnt = 0, idx_cnt = 0, ig_cnt = 0;

    if (tsk_hdb_idxinitialize(hdb_info, dbtype)) {
        tsk_error_set_errstr2( "hk_makeindex");
        return 1;
    }

    /* Status */
    if (tsk_verbose)
        TFPRINTF(stderr, _TSK_T("Extracting Data from Database (%s)\n"),
                 hdb_info->db_fname);

    /* Allocate a buffer to hold the previous hash values */
    memset(phash, '0', TSK_HDB_HTYPE_MD5_LEN + 1);

    /* read each line of the file */
    fseek(hdb_info->hDb, 0, SEEK_SET);
    for (i = 0; NULL != fgets(buf, TSK_HDB_MAXLEN, hdb_info->hDb);
         offset += (TSK_OFF_T) len, i++) {

        // skip the header line
        if (i == 0) {
            ig_cnt++;
            continue;
        }
        
        len = strlen(buf);

        /* Parse each line to get the MD5 value */
        if (hk_parse_md5(buf, &hash, NULL, 0, NULL, 0)) {
            ig_cnt++;
            continue;
        }
        db_cnt++;

        /* If this entry is for the same hash value as the last entry,
         * the skip it -- we'll look for it during lookup */
        if (memcmp(hash, phash, TSK_HDB_HTYPE_MD5_LEN) == 0) {
            continue;
        }

        /* Add the entry to the index */
        if (tsk_hdb_idxaddentry(hdb_info, hash, offset)) {
            tsk_error_set_errstr2( "hk_makeindex");
            return 1;
        }

        idx_cnt++;

        /* Set the previous hash value */
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

        /* Finish the index making process */
        if (tsk_hdb_idxfinalize(hdb_info)) {
            tsk_error_set_errstr2( "hk_makeindex");
            return 1;
        }
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "hk_makeindex: No valid entries found in database");
        return 1;
    }

    return 0;
}


/**
 * Find the corresponding name at the
 * given offset.  The offset was likely determined from the index.
 * The entries in the DB following the one specified are also processed
 * if they have the same hash value and their name is different. 
 * The callback is called for each entry. 
 *
 * Note: This routine assumes that &hdb_info->lock is locked by the caller.
 *
 * @param hdb_info Data base to get data from.
 * @param hash MD5 hash value that was searched for
 * @param offset Byte offset where hash value should be located in db_file
 * @param flags 
 * @param action Callback used for each entry found in lookup
 * @param cb_ptr Pointer to data passed to callback
 *
 * @return 1 on error and 0 on success
 */
uint8_t
hk_getentry(TSK_HDB_INFO * hdb_info, const char *hash, TSK_OFF_T offset,
            TSK_HDB_FLAG_ENUM flags,
            TSK_HDB_LOOKUP_FN action, void *cb_ptr)
{
    char buf[TSK_HDB_MAXLEN], name[TSK_HDB_MAXLEN], *ptr =
        NULL, pname[TSK_HDB_MAXLEN], other[TSK_HDB_MAXLEN];
    int found = 0;

    if (tsk_verbose)
        fprintf(stderr,
                "hk_getentry: Lookup up hash %s at offset %" PRIuOFF "\n",
                hash, offset);

    if (strlen(hash) != TSK_HDB_HTYPE_MD5_LEN) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hk_getentry: Invalid hash value: %s", hash);
        return 1;
    }

    memset(pname, '0', TSK_HDB_MAXLEN);

    /* Loop so that we can find multiple occurances of the same hash */
    while (1) {
        size_t len;

        if (0 != fseeko(hdb_info->hDb, offset, SEEK_SET)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                     "hk_getentry: Error seeking to get file name: %lu",
                     (unsigned long) offset);
            return 1;
        }

        if (NULL ==
            fgets(hdb_info->idx_lbuf, TSK_HDB_MAXLEN, hdb_info->hDb)) {
            if (feof(hdb_info->hDb)) {
                break;
            }
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                     "hk_getentry: Error reading database");
            return 1;
        }

        len = strlen(buf);
        if (len < TSK_HDB_HTYPE_MD5_LEN) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "hk_getentry: Invalid entry in database (too short): %s",
                     buf);
            return 1;
        }

        if (hk_parse_md5(buf, &ptr, name, TSK_HDB_MAXLEN,
                         ((flags & TSK_HDB_FLAG_EXT) ? other : NULL),
                         ((flags & TSK_HDB_FLAG_EXT) ? TSK_HDB_MAXLEN :
                          0))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "hk_getentry: Invalid entry in database: %s", buf);
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
            //if (flags & FLAG_EXT)
            //      printf("%s\t%s\t(%s)\n", hash, name, other);
            //  else
            //      printf("%s\t%s\n", hash, name);

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
                 "hk_getentry: Hash not found in file at offset: %lu",
                 (unsigned long) offset);
        return 1;
    }

    return 0;
}
