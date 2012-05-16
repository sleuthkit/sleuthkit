/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_hashdb_i.h"

/**
 * \file nsrl_index.c
 * NSRL specific functions to read the database.
 */

 /**
  * Version of NSRL Database
  */
enum TSK_HDB_NSRL_FORM_ENUM {
    TSK_HDB_NSRL_FORM1 = (1 << 0),      ///< Version 1
    TSK_HDB_NSRL_FORM2 = (1 << 1)       ///< Version 2
};
typedef enum TSK_HDB_NSRL_FORM_ENUM TSK_HDB_NSRL_FORM_ENUM;


/**
 * Analyze the header line of the database to determine the version of NSRL
 *
 * @param str line from the database file
 *
 * @return version or -1 on error
 */
static int
get_format_ver(char *str)
{

/*
 "SHA-1","FileName","FileSize","ProductCode","OpSystemCode","MD4","MD5","CRC32","SpecialCode"
*/
    if ((str[9] == 'F') && (str[20] == 'F') && (str[24] == 'S') &&
        (str[31] == 'P') && (str[45] == 'O'))
        return TSK_HDB_NSRL_FORM1;

/*
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","Specia
lCode"
*/
    else if ((str[9] == 'M') && (str[15] == 'C') && (str[23] == 'F') &&
             (str[34] == 'F') && (str[45] == 'P'))
        return TSK_HDB_NSRL_FORM2;

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
    tsk_error_set_errstr(
             "nsrl: Unknown header format: %s\n", str);
    return -1;
}

/**
 * Test the file to see if it is an NSRL database
 *
 * @param hFile File handle to hash database
 *
 * @return 1 if NSRL and 0 if not
 */
uint8_t
nsrl_test(FILE * hFile)
{
    char buf[TSK_HDB_MAXLEN];

    fseeko(hFile, 0, SEEK_SET);
    if (NULL == fgets(buf, TSK_HDB_MAXLEN, hFile))
        return 0;

    if (strlen(buf) < 45)
        return 0;

    // Basic checks in first field
    if ((buf[0] != '"') || (buf[1] != 'S') || (buf[2] != 'H') ||
        (buf[3] != 'A') || (buf[4] != '-') || (buf[5] != '1') ||
        (buf[6] != '"'))
        return 0;

    if (-1 == get_format_ver(buf))
        return 0;

    return 1;
}

/**
 * Set db_name using information from this database type
 *
 * @param hdb_info the hash database object
 */
void
nsrl_name(TSK_HDB_INFO * hdb_info)
{
    tsk_hdb_name_from_path(hdb_info);
}

/**
 * Perform a basic check on a string to see if it starts with quotes
 * and contains a possible SHA-1 value
 *
 * @param x string to test
 * @return 1 if NSRL and 0 if not
 */
#define is_valid_nsrl(x) \
	( (strlen((x)) > TSK_HDB_HTYPE_SHA1_LEN + 4) && \
	((x)[0] == '"') && ((x)[TSK_HDB_HTYPE_SHA1_LEN + 1] == '"') && \
	((x)[TSK_HDB_HTYPE_SHA1_LEN + 2] == ',') && ((x)[TSK_HDB_HTYPE_SHA1_LEN + 3] == '"') )


/**
 * Parse a line from the NSRL database and set pointers to the SHA1 and Name.  This will modify
 * the input text by adding NULL values!
 *
 * @param str String to parse
 * @param sha1 Pointer to a pointer that will contain location of SHA1 in original text
 * @param name Pointer to a pointer that will contain location of the name in original text
 * @param ver Version of NSRL we are parsing
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
nsrl_parse_sha1(char *str, char **sha1, char **name, int ver)
{
    char *ptr = NULL;

    /* Sanity check */
    if (is_valid_nsrl(str) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "nsrl_parse_sha1: Invalid string to parse: %s", str);
        return 1;
    }

    /* Do they want the hash? */
    if (sha1 != NULL) {
        /* set the hash pointer to just the SHA value (past the ") */
        ptr = &str[1];
        ptr[TSK_HDB_HTYPE_SHA1_LEN] = '\0';

        /* Final sanity check to make sure there are no ',' in hash */
        if (NULL != strchr(ptr, ',')) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "nsrl_parse_sha1: Invalid string to parse (commas after SHA1): %s",
                     ptr);
            return 1;
        }

        /* Assign the argument if it is not NULL */
        *sha1 = ptr;
    }

    /* Do they want the name? */
    if (name != NULL) {
        if (ver == TSK_HDB_NSRL_FORM1) {
            /* Extract out the name  - the field after SHA1 */
            ptr = &str[TSK_HDB_HTYPE_SHA1_LEN + 4];     // 4 = 3 " and 1 ,
            *name = ptr;

            if (NULL == (ptr = strchr(ptr, ','))) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_parse_sha1: Invalid string to parse (commas after name): %s",
                         ptr);
                return 1;
            }

            /* Seek back to cover the final " */
            ptr[-1] = '\0';
        }
        else if (ver == TSK_HDB_NSRL_FORM2) {
            /* Extract out the name  - the field after SHA1, MD5, and CRC */
            ptr =
                &str[1 + TSK_HDB_HTYPE_SHA1_LEN + 3 +
                     TSK_HDB_HTYPE_MD5_LEN + 3 + TSK_HDB_HTYPE_CRC32_LEN +
                     3];
            *name = ptr;

            if (NULL == (ptr = strchr(ptr, ','))) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_parse_sha1: Invalid string to parse (commas after name): %s",
                         ptr);
                return 1;
            }

            /* Seek back to cover the final " */
            ptr[-1] = '\0';
        }
    }

    return 0;
}

/**
 * Parse a line from the NSRL database and set pointers to the MD5 and Name.  This will modify
 * the input text by adding NULL values!
 *
 * @param str String to parse
 * @param md5 Pointer to a pointer that will contain location of MD5 in original text
 * @param name Pointer to a pointer that will contain location of the name in original text
 * @param ver Version of NSRL we are parsing
 *
 * @return 1 on error and 0 on success
 */
static uint8_t
nsrl_parse_md5(char *str, char **md5, char **name, int ver)
{
    char *ptr = NULL;
    int cnt = 0;

    /* Sanity check */
    if (is_valid_nsrl(str) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "nsrl_parse_md5: Invalid string to parse: %s", str);
        return 1;
    }

    if ((md5 == NULL) && (name == NULL))
        return 0;

    if (ver == TSK_HDB_NSRL_FORM1) {
        ptr = str;

        /* Cycle through the fields to extract name and MD5
         *
         * 1. before name
         * 2. before size
         * 3. before prod code
         * 4. before OS
         * 5. before MD4
         * 6. before MD5
         */
        cnt = 0;
        while (NULL != (ptr = strchr(ptr, ','))) {
            cnt++;

            /* Begining of the name */
            if ((cnt == 1) && (name != NULL)) {
                *name = &ptr[2];
                /* We utilize the other loop code to find the end of
                 * the name */
            }
            /* end of the name */
            else if ((cnt == 2) && (name != NULL)) {
                if (ptr[-1] != '"') {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                    tsk_error_set_errstr(
                             "nsrl_parse_md5: Missing Quote after name: %s",
                             (char *) name);
                    return 1;
                }

                ptr[-1] = '\0';

                if (md5 == NULL)
                    return 0;
            }
            /* MD5 value */
            else if ((cnt == 6) && (md5 != NULL)) {
                /* Do a length check and more sanity checks */
                if ((strlen(ptr) < 2 + TSK_HDB_HTYPE_MD5_LEN)
                    || (ptr[1] != '"')
                    || (ptr[2 + TSK_HDB_HTYPE_MD5_LEN] != '"')) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                    tsk_error_set_errstr(
                             "nsrl_parse_md5: Invalid MD5 value: %s", ptr);
                    return 1;
                }

                ptr = &ptr[2];
                ptr[TSK_HDB_HTYPE_MD5_LEN] = '\0';

                *md5 = ptr;

                /* Final sanity check */
                if (NULL != strchr(ptr, ',')) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                    tsk_error_set_errstr(
                             "nsrl_parse_md5: Missing comma after MD5: %s",
                             (char *) md5);
                    return 1;
                }

                return 0;
            }

            /* If the next field is in quotes then we need to skip to the
             * next quote and ignore any ',' in there
             */
            if (ptr[1] == '"') {
                if (NULL == (ptr = strchr(&ptr[2], '"'))) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                    tsk_error_set_errstr(
                             "nsrl_parse_md5: Error advancing past quote");
                    return 1;
                }
            }
            else {
                ptr++;
            }
        }
    }
    else if (ver == TSK_HDB_NSRL_FORM2) {
        /* Do they want the hash? */
        if (md5 != NULL) {
            /* set the hash pointer to just the MD5 value (past the SHA1") */
            ptr = &str[1 + TSK_HDB_HTYPE_SHA1_LEN + 3];
            ptr[TSK_HDB_HTYPE_MD5_LEN] = '\0';

            /* Final sanity check to make sure there are no ',' in hash */
            if (NULL != strchr(ptr, ',')) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_parse_md5: Comma in MD5 value: %s", ptr);
                return 1;
            }
            *md5 = ptr;
        }

        /* do they want the name */
        if (name != NULL) {
            /* Extract out the name  - the field after SHA1, MD5, and CRC */
            ptr =
                &str[1 + TSK_HDB_HTYPE_SHA1_LEN + 3 +
                     TSK_HDB_HTYPE_MD5_LEN + 3 + TSK_HDB_HTYPE_CRC32_LEN +
                     3];
            *name = ptr;

            if (NULL == (ptr = strchr(ptr, ','))) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_parse_md5: Missing comma after name: %s",
                         (char *) name);
                return 1;
            }

            /* Seek back to cover the final " */
            ptr -= 1;
            *ptr = '\0';
        }
        return 0;
    }
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
             "nsrl_parse_md5: Invalid version: %d\n", ver);
    return 1;
}




/**
 * Process the database to create a sorted index of it. Consecutive
 * entries with the same hash value are not added to the index, but
 * will be found during lookup.
 *
 * @param hdb_info Hash database to make index of.
 * @param dbtype Type of database 
 *
 * @return 1 on error and 0 on success.
 */
uint8_t
nsrl_makeindex(TSK_HDB_INFO * hdb_info, TSK_TCHAR * dbtype)
{
    size_t i, len;
    char buf[TSK_HDB_MAXLEN];
    char *hash = NULL, phash[TSK_HDB_HTYPE_SHA1_LEN + 1];
    TSK_OFF_T offset = 0;
    int ver = 0;
    int db_cnt = 0, idx_cnt = 0, ig_cnt = 0;

    if (tsk_hdb_idxinitialize(hdb_info, dbtype)) {
        tsk_error_set_errstr2( "nsrl_makeindex");
        return 1;
    }

    /* Status */
    if (tsk_verbose)
        TFPRINTF(stderr, _TSK_T("Extracting Data from Database (%s)\n"),
                 hdb_info->db_fname);

    /* Allocate a buffer for the previous hash value */
    memset(phash, '0', TSK_HDB_HTYPE_SHA1_LEN + 1);

    /* read the file */
    fseek(hdb_info->hDb, 0, SEEK_SET);
    for (i = 0; NULL != fgets(buf, TSK_HDB_MAXLEN, hdb_info->hDb);
         offset += len, i++) {

        len = strlen(buf);

        /* Get the version of the database on the first time around */
        if (i == 0) {
            if ((ver = get_format_ver(buf)) == -1) {
                return 1;
            }
            ig_cnt++;
            continue;
        }

        /* Parse the line */
        if (hdb_info->hash_type & TSK_HDB_HTYPE_SHA1_ID) {
            if (nsrl_parse_sha1(buf, &hash, NULL, ver)) {
                ig_cnt++;
                continue;
            }
        }
        else if (hdb_info->hash_type & TSK_HDB_HTYPE_MD5_ID) {
            if (nsrl_parse_md5(buf, &hash, NULL, ver)) {
                ig_cnt++;
                continue;
            }
        }

        db_cnt++;

        /* We only want to add one of each hash to the index */
        if (memcmp(hash, phash, hdb_info->hash_len) == 0) {
            continue;
        }

        /* Add the entry to the index */
        if (tsk_hdb_idxaddentry(hdb_info, hash, offset)) {
            tsk_error_set_errstr2( "nsrl_makeindex");
            return 1;
        }

        idx_cnt++;

        /* Set the previous has value */
        strncpy(phash, hash, hdb_info->hash_len + 1);
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
        if (tsk_hdb_idxfinalize(hdb_info)) {
            tsk_error_set_errstr2( "nsrl_makeindex");
            return 1;
        }
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "nsrl_makeindex: No valid entries found in database");
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
 * @param hdb_info Database to get data from.
 * @param hash MD5/SHA-1 hash value that was searched for
 * @param offset Byte offset where hash value should be located in db_file
 * @param flags (not used)
 * @param action Callback used for each entry found in lookup
 * @param cb_ptr Pointer to data passed to callback
 *
 * @return 1 on error and 0 on success
 */
uint8_t
nsrl_getentry(TSK_HDB_INFO * hdb_info, const char *hash, TSK_OFF_T offset,
              TSK_HDB_FLAG_ENUM flags,
              TSK_HDB_LOOKUP_FN action, void *cb_ptr)
{
    char buf[TSK_HDB_MAXLEN], *name, *cur_hash, pname[TSK_HDB_MAXLEN];
    int found = 0;
    int ver;

    if (tsk_verbose)
        fprintf(stderr,
                "nsrl_getentry: Lookup up hash %s at offset %" PRIuOFF
                "\n", hash, offset);

    if ((hdb_info->hash_type == TSK_HDB_HTYPE_MD5_ID)
        && (strlen(hash) != TSK_HDB_HTYPE_MD5_LEN)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "nsrl_getentry: Invalid hash value (expected to be MD5): %s\n",
                 hash);
        return 1;
    }
    else if ((hdb_info->hash_type == TSK_HDB_HTYPE_SHA1_ID)
             && (strlen(hash) != TSK_HDB_HTYPE_SHA1_LEN)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "nsrl_getentry: Invalid hash value (expected to be SHA1): %s\n",
                 hash);
        return 1;
    }

    /* read the header line ... -- this should be done only once... */
    fseeko(hdb_info->hDb, 0, SEEK_SET);
    if (NULL == fgets(buf, TSK_HDB_MAXLEN, hdb_info->hDb)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READDB);
        tsk_error_set_errstr(
                 "nsrl_getentry: Error reading NSRLFile.txt header\n");
        return 1;
    }

    if ((ver = get_format_ver(buf)) == -1) {
        tsk_error_set_errstr2( "nsrl_getentry");
        return 1;
    }

    memset(pname, '0', TSK_HDB_MAXLEN);

    /* Loop so that we can find consecutive occurances of the same hash */
    while (1) {
        size_t len;

        if (0 != fseeko(hdb_info->hDb, offset, SEEK_SET)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                     "nsrl_getentry: Error seeking to get file name: %lu",
                     (unsigned long) offset);
            return 1;
        }

        if (NULL == fgets(buf, TSK_HDB_MAXLEN, hdb_info->hDb)) {
            if (feof(hdb_info->hDb))
                break;

            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READDB);
            tsk_error_set_errstr(
                     "nsrl_getentry: Error reading database");
            return 1;
        }

        len = strlen(buf);
        if (len < TSK_HDB_HTYPE_SHA1_LEN + 5) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "nsrl_getentry: Invalid entry in database (too short): %s",
                     buf);
            return 1;
        }

        /* Which field are we looking for */
        if (hdb_info->hash_type == TSK_HDB_HTYPE_SHA1_ID) {
            if (nsrl_parse_sha1(buf, &cur_hash, &name, ver)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_getentry: Invalid entry in database: %s",
                         buf);
                return 1;
            }
        }
        else if (hdb_info->hash_type == TSK_HDB_HTYPE_MD5_ID) {
            if (nsrl_parse_md5(buf, &cur_hash, &name, ver)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                         "nsrl_getentry: Invalid entry in database: %s",
                         buf);
                return 1;
            }
        }

        /* Verify that this is the hash we are looking for */
        if (0 != strcasecmp(cur_hash, hash)) {
            break;
        }

        /* Check if this is the same name as the previous entry */
        if (strcmp(name, pname) != 0) {
            int retval;
            retval = action(hdb_info, hash, name, cb_ptr);
            if (retval == TSK_WALK_STOP)
                return 0;
            else if (retval == TSK_WALK_ERROR)
                return 1;

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
                 "nsrl_getentry: Hash not found in file at offset: %lu",
                 (unsigned long) offset);
        return 1;
    }

    return 0;
}
