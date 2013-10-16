/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2013 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 */

#include "tsk_hashdb_i.h"


/**
 * \file hdb_index.cpp
 * Contains the code to make indexes for databases.
 */


/**
 * Open a file and return a handle to it.
 */
static FILE *
tsk_idx_open_file(TSK_TCHAR *idx_fname)
{
    if (idx_fname == NULL) {
        return NULL;
    }

    FILE * idx = NULL;

#ifdef TSK_WIN32
    {
        HANDLE hWin;
        //DWORD szLow, szHi;

        if (-1 == GetFileAttributes(idx_fname)) {
            //tsk_release_lock(&idx_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "tsk_idx_open_file: Error finding index file: %"PRIttocTSK,
                    idx_fname);
            return NULL;
        }

        if ((hWin = CreateFile(idx_fname, GENERIC_READ,
                        FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
                INVALID_HANDLE_VALUE) {
            //tsk_release_lock(&idx_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "tsk_idx_open_file: Error opening index file: %"PRIttocTSK,
                    idx_fname);
            return NULL;
        }

        idx = _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
    }
#else
    {
        idx = fopen(idx_fname, "r");
    }
#endif

    return idx;
}


/**
 * Open an index for the given hash db
 * We only create kdb (SQLite) files, but can open old indexes.
 * @return NULL on error, TSK_IDX_INFO instance on success
 */
// @@@ htype should be enum
static TSK_IDX_INFO *
tsk_idx_open(TSK_HDB_INFO * hdb_info, uint8_t htype, uint8_t create)
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
        // @@@ ERROR INFO NEEDED
        return NULL;
    }

    /* Get hash type specific information */
    switch (htype) {
        case TSK_HDB_HTYPE_MD5_ID:
            hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(htype);
            hdb_info->hash_len = TSK_HDB_HTYPE_MD5_LEN;
            break;
        case TSK_HDB_HTYPE_SHA1_ID:
            hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(htype);
            hdb_info->hash_len = TSK_HDB_HTYPE_SHA1_LEN;
            break;
        default:
            free(idx_info);
            // @@@ ERROR INFO NEEDED
            return NULL;
    }


    // Verify the new SQLITE index exists, get its size, and open it for header reading
    TSNPRINTF(idx_info->idx_fname, flen,
            _TSK_T("%s.kdb"), hdb_info->db_fname);
    if (((idx = tsk_idx_open_file(idx_info->idx_fname)) == NULL) && (create == 0)) {

        // Try opening an old format index file

        // Change the filename to the old format
        switch (htype) {
            case TSK_HDB_HTYPE_MD5_ID:
                TSNPRINTF(idx_info->idx_fname, flen,
                          _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                          hdb_info->db_fname, TSK_HDB_HTYPE_MD5_STR);
                break;
            case TSK_HDB_HTYPE_SHA1_ID:
                TSNPRINTF(idx_info->idx_fname, flen,
                          _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                          hdb_info->db_fname, TSK_HDB_HTYPE_SHA1_STR);
                break;
        }

        idx = tsk_idx_open_file(idx_info->idx_fname);

        if (!idx) {
            free(idx_info);
            // @@@ ERROR NEEDED
            return NULL;
        }
        
        if (1 != fread(header, header_size, 1, idx)) {
            ///@@@ ERROR
            return NULL;
        }
        else if (strncmp(header,
                           IDX_PLAIN_TXT_HEADER,
                           strlen(IDX_PLAIN_TXT_HEADER)) == 0) {
            idx_info->index_type = TSK_HDB_ITYPE_PLAIN_TXT;
            idx_info->open = plain_txt_open;
            idx_info->close = plain_txt_close;
            idx_info->initialize = plain_txt_initialize;
            idx_info->addentry = plain_txt_addentry;
            idx_info->addentry_bin = plain_txt_addentry_bin;
            idx_info->finalize = plain_txt_finalize;
            idx_info->lookup_str = plain_txt_lookup_str;
            idx_info->lookup_raw = plain_txt_lookup_raw;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                                 "tsk_idx_open: Unrecognized header format: %s\n",
                                 idx_info->idx_fname);
            free(idx_info);
            return NULL;
        }
    }
    // kdb extension
    else {
        if (idx) {
            if (1 != fread(header, header_size, 1, idx)) {
                ///@todo should this actually be an error?
                idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;
            }
            else if (strncmp(header,
                        IDX_SQLITE_V1_HEADER,
                        strlen(IDX_SQLITE_V1_HEADER)) == 0) {
                idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;
            }
            else {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_MISSING);
                tsk_error_set_errstr(
                        "tsk_idx_open: Unrecognized header format: %s\n",
                        idx_info->idx_fname);
                free(idx_info);
                return NULL;
            }
        }

        idx_info->open = sqlite_v1_open;
        idx_info->close = sqlite_v1_close;
        idx_info->initialize = sqlite_v1_initialize;
        idx_info->addentry = sqlite_v1_addentry;
        idx_info->addentry_bin = sqlite_v1_addentry_bin;
        idx_info->finalize = sqlite_v1_finalize;
        idx_info->lookup_str = sqlite_v1_lookup_str;
        idx_info->lookup_raw = sqlite_v1_lookup_raw;
    }

    // Open
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
 * Ensures that the index is already opened or can be opened. 
 * @param hdb_info Database handle
 * @param htype TSK_HDB_HTYPE_ENUM value
 * @param 
 * @return 0 if already set up or if setup successful, 1 otherwise
 */
uint8_t
hdb_setupindex(TSK_HDB_INFO * hdb_info, uint8_t htype, uint8_t create)
{
    // Lock for lazy load of idx_info and lazy alloc of idx_lbuf.
    tsk_take_lock(&hdb_info->lock);

    // already opened
    if (hdb_info->idx_info != NULL) {
        tsk_release_lock(&hdb_info->lock);
        return 0;
    }

    hdb_info->idx_info = tsk_idx_open(hdb_info, htype, create);

    if (hdb_info->idx_info != NULL) {
        tsk_release_lock(&hdb_info->lock);
        return 0;
    }

    tsk_release_lock(&hdb_info->lock);
    return 1;
}


/** 
 * Creates and initialize a new TSK hash DB index file.
 *
 * @param hdb_info Hash database state structure
 * @param a_dbtype String of index type to create
 *
 * @return 1 on error and 0 on success
 */
uint8_t
tsk_hdb_idxinitialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * a_dbtype)
{
    char dbtmp[32];
    int i;
    bool create = true; //create new file if it doesn't already exist

    /* Use the string of the index/hash type to figure out some
     * settings */

    // convert to char -- cheating way to deal with WCHARs..
    for (i = 0; i < 31 && a_dbtype[i] != '\0'; i++) {
        dbtmp[i] = (char) a_dbtype[i];
    }
    dbtmp[i] = '\0';

    // MD5 index for NSRL file
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
    // SHA1 index for NSRL file
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
    if (hdb_setupindex(hdb_info, hdb_info->hash_type, create)) {
        return 1;
    }

    /* Call db-specific initialize function */
	return hdb_info->idx_info->initialize(hdb_info, a_dbtype);
}

/**
 * Add a string hash entry to the index
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
 * Add a binary hash entry to the index
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
 * Finalize index creation process.
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
    if (hdb_setupindex(hdb_info, htype, false)) {
        return 0;
    } else {
        return 1;
    }
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
