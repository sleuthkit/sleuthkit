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
 * \file tm_lookup.c
 * Contains the generic hash database creation and lookup code.
 */

/**
 * Open the index structure for the given hash db
 */
TSK_IDX_INFO *
tsk_idx_open(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    TSK_IDX_INFO * idx_info;
    size_t flen;
    const int header_size = 16;
    char header[header_size];
    FILE * idx = NULL;

    if (hdb_info->idx_info != NULL) {
        return hdb_info->idx_info;
    }

    if ((idx_info =
         (TSK_IDX_INFO *) tsk_malloc(sizeof(TSK_IDX_INFO))) == NULL) {
        return NULL;
    }

    hdb_info->idx_info = idx_info;

    /* Make the name for the index file */
    flen = TSTRLEN(hdb_info->db_fname) + 32;
    idx_info->idx_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (idx_info->idx_fname == NULL) {
        free(idx_info);
        return NULL;
    }

    /* Get hash type specific information */
    switch (htype) {
        case TSK_HDB_HTYPE_MD5_ID:
            hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(htype);
            hdb_info->hash_len = TSK_HDB_HTYPE_MD5_LEN;
            TSNPRINTF(idx_info->idx_fname, flen,
                    _TSK_T("%s") _TSK_T(".kdb"),
                    hdb_info->db_fname);
            break;
        case TSK_HDB_HTYPE_SHA1_ID:
            hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(htype);
            hdb_info->hash_len = TSK_HDB_HTYPE_SHA1_LEN;
            TSNPRINTF(idx_info->idx_fname, flen,
                    _TSK_T("%s-%") _TSK_T(".kdb"),
                    hdb_info->db_fname, TSK_HDB_HTYPE_SHA1_STR);
            break;
        default:
            free(idx_info);
            return NULL;
    }


#if 0
    /* Verify the index exists, get its size, and open it */
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        DWORD szLow, szHi;

        if (-1 == GetFileAttributes(idx_info->idx_fname)) {
            tsk_release_lock(&idx_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error finding index file: %"PRIttocTSK,
                    idx_info->idx_fname);
            free(idx_info);
            return NULL;
        }

        if ((hWin = CreateFile(idx_info->idx_fname, GENERIC_READ,
                        FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
                INVALID_HANDLE_VALUE) {
            tsk_release_lock(&idx_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error opening index file: %"PRIttocTSK,
                    idx_info->idx_fname);
            free(idx_info);
            return NULL;
        }
        idx =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
    }
#else
    {
        idx = fopen(idx_info->idx_fname, "r");
    }
#endif
#endif

    if (NULL != idx)
    {
        if(NULL == fread(header, header_size, 1, idx)) {
            idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;
        } else if (strncmp(header,
                    IDX_SQLITE_V1_HEADER,
                    strlen(IDX_SQLITE_V1_HEADER)) == 0) {
            idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;
        } else if (strncmp(header,
                    IDX_PLAIN_TXT_HEADER,
                    strlen(IDX_PLAIN_TXT_HEADER)) == 0) {
            idx_info->index_type = TSK_HDB_ITYPE_PLAIN_TXT;
        } else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "hdb_setupindex: Unrecognized header format: %s\n",
                    idx_info->idx_fname);
            free(idx_info);
            return NULL;
        }
    } else {
        idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;
    }

    switch (idx_info->index_type) {
        case TSK_HDB_ITYPE_SQLITE_V1:
            idx_info->open = sqlite_v1_open;
            idx_info->close = sqlite_v1_close;
            idx_info->initialize = sqlite_v1_initialize;
            idx_info->addentry = sqlite_v1_addentry;
            idx_info->addentry_bin = sqlite_v1_addentry_bin;
            idx_info->finalize = sqlite_v1_finalize;
            idx_info->lookup_str = sqlite_v1_lookup_str;
            idx_info->lookup_raw = sqlite_v1_lookup_raw;
            break;
        case TSK_HDB_ITYPE_PLAIN_TXT:
            idx_info->open = plain_txt_open;
            idx_info->close = plain_txt_close;
            idx_info->initialize = plain_txt_initialize;
            idx_info->addentry = plain_txt_addentry;
            idx_info->addentry_bin = plain_txt_addentry_bin;
            idx_info->finalize = plain_txt_finalize;
            idx_info->lookup_str = plain_txt_lookup_str;
            idx_info->lookup_raw = plain_txt_lookup_raw;
            break;
        default:
            free(idx_info);
            return NULL;
    }

    if (idx_info->open(hdb_info, idx_info, htype) == 0) {
        return idx_info;
    }

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
             "Error setting up idx_info struct: %d\n", htype);
    free(idx_info);
    return NULL;
}


/**
 * Set up the internal index structures
 * @return 0 if already set up or if setup successful, 1 otherwise
 */
uint8_t
hdb_setupindex(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    if (hdb_info->idx_info != NULL) {
        return 0;
    }

    hdb_info->idx_info = tsk_idx_open(hdb_info, htype);


    if (hdb_info->idx_info != NULL) {
        return 0;
    }

    return 1;
}


/** Initialize the TSK hash DB index file. This creates the intermediate file,
 * which will have entries added to it.
 *
 * @param hdb_info Hash database state structure
 * @param htype String of index type to create
 *
 * @return 1 on error and 0 on success
 *
 */
uint8_t
tsk_hdb_idxinitialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
    char dbtmp[32];
    int i;


    /* Use the string of the index/hash type to figure out some
     * settings */

    // convert to char -- cheating way to deal with WCHARs..
    for (i = 0; i < 31 && htype[i] != '\0'; i++) {
        dbtmp[i] = (char) htype[i];
    }
    dbtmp[i] = '\0';

    if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_MD5_STR) == 0) {

        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hdb_info->hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_SHA1_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hdb_info->hash_type = TSK_HDB_HTYPE_SHA1_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_MD5SUM_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_MD5SUM_ID);
            return 1;
        }
        hdb_info->hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_HK_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_HK_ID);
            return 1;
        }
        hdb_info->hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_ENCASE_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_ENCASE_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_ENCASE_ID);
            return 1;
        }
        hdb_info->hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_idxinitialize: Unknown database type request: %s",
                 dbtmp);
        return 1;
    }

    /* Setup the internal hash information */
    if (hdb_setupindex(hdb_info, hdb_info->hash_type)) {
        return 1;
    }

    /* Call htype-specific initialize function */
	return hdb_info->idx_info->initialize(hdb_info, htype);
}

/**
 * Add a string entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue String of hash value to add
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxaddentry(TSK_HDB_INFO * hdb_info, char *hvalue,
                    TSK_OFF_T offset)
{
    return hdb_info->idx_info->addentry(hdb_info, hvalue, offset);
}

/**
 * Add a binary entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue Array of integers of hash value to add
 * @param hlen Number of bytes in hvalue
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxaddentry_bin(TSK_HDB_INFO * hdb_info, unsigned char *hvalue, int hlen,
                    TSK_OFF_T offset)
{
    return hdb_info->idx_info->addentry_bin(hdb_info, hvalue, hlen, offset);
}

/**
 * Finalize index creation process by sorting the index and removing the
 * intermediate temp file.
 *
 * @param hdb_info Hash database state info structure.
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxfinalize(TSK_HDB_INFO * hdb_info)
{
    return hdb_info->idx_info->finalize(hdb_info);
}




/**
 * \ingroup hashdblib
 * Search the index for a text/ASCII hash value
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Hash value to search for (NULL terminated string)
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
tsk_hdb_lookup_str(TSK_HDB_INFO * hdb_info, const char *hash,
                   TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action,
                   void *ptr)
{
    uint8_t htype;

    /* Sanity checks on the hash input */
    if (strlen(hash) == TSK_HDB_HTYPE_MD5_LEN) {
        htype = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strlen(hash) == TSK_HDB_HTYPE_SHA1_LEN) {
        htype = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "hdb_lookup_str: Invalid hash length: %s", hash);
        return -1;
    }

    if (hdb_setupindex(hdb_info, htype)) {
        return -1;
    }

	return hdb_info->idx_info->lookup_str(hdb_info, hash, flags, action, ptr);
			
}

/**
 * \ingroup hashdblib
 * Search the index for the given hash value given (in binary form).
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Array with binary hash value to search for
 * @param len Number of bytes in binary hash value
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
tsk_hdb_lookup_raw(TSK_HDB_INFO * hdb_info, uint8_t * hash, uint8_t len,
                   TSK_HDB_FLAG_ENUM flags,
                   TSK_HDB_LOOKUP_FN action, void *ptr)
{
    uint8_t htype;

    /* Sanity checks on the hash input */
    if (len/2 == TSK_HDB_HTYPE_MD5_LEN) {
        htype = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (len/2 == TSK_HDB_HTYPE_SHA1_LEN) {
        htype = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "hdb_lookup_raw: Invalid hash length: %s", hash);
        return -1;
    }

    if (hdb_setupindex(hdb_info, htype)) {
        return -1;
    }

	return hdb_info->idx_info->lookup_raw(hdb_info, hash, len, flags, action, ptr);
}

/**
 * \ingroup hashdblib
 * Determine if the open hash database has an index.
 *
 * @param hdb_info Hash database to consider
 * @param htype Hash type that index should be of
 *
 * @return 1 if index exists and 0 if not
 */
uint8_t
tsk_hdb_hasindex(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    /* Check if the index is already open, and 
     * try to open it if not */
    if (tsk_idx_open(hdb_info, htype))
        return 0;
    else
        return 1;
}


/**
 * \ingroup hashdblib
 * Open a hash database. 
 *
 * @param db_file Path to database (even if only an index exists).
 * @param flags Flags for opening the database.  
 *
 * @return Poiner to hash database state structure or NULL on error
 */
TSK_HDB_INFO *
tsk_hdb_open(TSK_TCHAR * db_file, TSK_HDB_OPEN_ENUM flags)
{
    TSK_HDB_INFO *hdb_info;
    size_t flen;
    FILE *hDb;
    uint8_t dbtype = 0;

    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        /* Open the database file */
#ifdef TSK_WIN32
        {
            HANDLE hWin;

            if ((hWin = CreateFile(db_file, GENERIC_READ,
                                   FILE_SHARE_READ, 0, OPEN_EXISTING, 0,
                                   0)) == INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                         "hdb_open: Error opening database file: %S",
                         db_file);
                return NULL;
            }
            hDb =
                _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
            if (hDb == NULL) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                         "hdb_open: Error converting Windows handle to C handle");
                return NULL;
            }
        }
#else
        if (NULL == (hDb = fopen(db_file, "r"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                     "hdb_open: Error opening database file: %s", db_file);
            return NULL;
        }
#endif

        /* Try to figure out what type of DB it is */
        if (nsrl_test(hDb)) {
            dbtype = TSK_HDB_DBTYPE_NSRL_ID;
        }
        if (md5sum_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (MD5sum)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_MD5SUM_ID;
        }
        if (encase_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (EnCase)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_ENCASE_ID;
        }
        if (hk_test(hDb)) {
            if (dbtype != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                         "hdb_open: Error determining DB type (HK)");
                return NULL;
            }
            dbtype = TSK_HDB_DBTYPE_HK_ID;
        }
        if (dbtype == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "hdb_open: Error determining DB type");
            return NULL;
        }
        fseeko(hDb, 0, SEEK_SET);
    }
    else {
        dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
        hDb = NULL;
    }

    if ((hdb_info =
         (TSK_HDB_INFO *) tsk_malloc(sizeof(TSK_HDB_INFO))) == NULL)
        return NULL;

    hdb_info->hDb = hDb;

    /* Copy the database name into the structure */
    flen = TSTRLEN(db_file) + 8;        // + 32;

    hdb_info->db_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_info->db_fname == NULL) {
        free(hdb_info);
        return NULL;
    }
    TSTRNCPY(hdb_info->db_fname, db_file, flen);

    
    hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(0);
    hdb_info->hash_len = 0;
    hdb_info->idx_info = NULL;

    /* Get database specific information */
    hdb_info->db_type = static_cast<TSK_HDB_DBTYPE_ENUM>(dbtype);
    switch (dbtype) {
        case TSK_HDB_DBTYPE_NSRL_ID:
            nsrl_name(hdb_info);
            hdb_info->getentry = nsrl_getentry;
            hdb_info->makeindex = nsrl_makeindex;
            break;

        case TSK_HDB_DBTYPE_MD5SUM_ID:
            md5sum_name(hdb_info);
            hdb_info->getentry = md5sum_getentry;
            hdb_info->makeindex = md5sum_makeindex;
            break;

        case TSK_HDB_DBTYPE_ENCASE_ID:
            encase_name(hdb_info);
            hdb_info->getentry = encase_getentry;
            hdb_info->makeindex = encase_makeindex;
            break;

        case TSK_HDB_DBTYPE_HK_ID:
            hk_name(hdb_info);
            hdb_info->getentry = hk_getentry;
            hdb_info->makeindex = hk_makeindex;
            break;

        case TSK_HDB_DBTYPE_IDXONLY_ID:
            idxonly_name(hdb_info);
            hdb_info->getentry = idxonly_getentry;
            hdb_info->makeindex = idxonly_makeindex;
            break;

        default:
            return NULL;
    }


    return hdb_info;
}

/**
 * \ingroup hashdblib
 * Close an open hash index
 *
 * @param idx_info index to close
 */
void tsk_idx_close(TSK_IDX_INFO * idx_info)
{
    if (idx_info->idx_fname) {
        free(idx_info->idx_fname);
    }

    idx_info->close(idx_info);
}

/**
 * \ingroup hashdblib
 * Close an open hash database.
 *
 * @param hdb_info database to close
 */
void
tsk_hdb_close(TSK_HDB_INFO * hdb_info)
{
    if (hdb_info->db_fname)
        free(hdb_info->db_fname);

    if (hdb_info->hDb)
        fclose(hdb_info->hDb);

    if (hdb_info->idx_info) {
        tsk_idx_close(hdb_info->idx_info);
    }

    tsk_deinit_lock(&hdb_info->idx_info->lock);

    free(hdb_info);
}

/**
 * \ingroup hashdblib
 * Create an index for an open hash database.
 * @param a_hdb_info Open hash database to index
 * @param a_type Text of hash database type
 * @returns 1 on error
 */
uint8_t
tsk_hdb_makeindex(TSK_HDB_INFO * a_hdb_info, TSK_TCHAR * a_type)
{
    return a_hdb_info->makeindex(a_hdb_info, a_type);
}

/**
 * Set db_name to the name of the database file
 *
 * @param hdb_info the hash database object
 */
void
tsk_hdb_name_from_path(TSK_HDB_INFO * hdb_info)
{
#ifdef TSK_WIN32
    const char PATH_CHAR = '\\';
#else
    const char PATH_CHAR = '/';
#endif
    TSK_TCHAR * begin;
    TSK_TCHAR * end;
    int i;

    hdb_info->db_name[0] = '\0';

    begin = TSTRRCHR(hdb_info->db_fname, PATH_CHAR);
#ifdef TSK_WIN32
    // cygwin can have forward slashes, so try that too on Windows
    if (!begin) {
        begin = TSTRRCHR(hdb_info->db_fname, '/');
    }
#endif

    if (!begin) {
        begin = hdb_info->db_fname;
    }
    else {
        // unlikely since this means that the dbname is "/"
        if (TSTRLEN(begin) == 1)
            return;
        else
            begin++;
    }

    // end points to the byte after the last one we want to use
    if ((TSTRLEN(hdb_info->db_fname) > 4) && (TSTRICMP(&hdb_info->db_fname[TSTRLEN(hdb_info->db_fname)-4], _TSK_T(".idx")) == 0)) 
        end = &hdb_info->db_fname[TSTRLEN(hdb_info->db_fname)-4];
    else
        end = begin + TSTRLEN(begin);
        

    // @@@ TODO: Use TskUTF16_to_UTF8 to properly convert for Windows
    for(i = 0; i < (end-begin); i++)
    {
        hdb_info->db_name[i] = (char) begin[i];
    }

    hdb_info->db_name[i] = '\0';
}
