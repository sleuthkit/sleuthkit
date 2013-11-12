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


static void
tsk_idx_close_file(FILE * idx)
{
    if (idx == NULL) {
        return;
    }

    // fclose should work on all platforms:
    if (fclose(idx) != 0) {
        tsk_error_set_errstr2("tsk_idx_close_file: Error closing index file object.");
    }
}

/**
 * Update the hash type. New indices can handle multiple hash types, so hash
 * type is now dependent on what the client is doing (e.g. lookup md5).
 * @return 1 on error, 0 on success
 */
static int
hdb_update_htype(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
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
            return 1;
    }
    return 0;
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

    if (hdb_update_htype(hdb_info, htype) == 1) {
        free(idx_info);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_MISSING);
        tsk_error_set_errstr(
            "tsk_idx_open: Unknown hash type: %d\n",
            (int)htype);
        return NULL;
    }

    // Verify the new SQLite index exists, get its size, and open it for header reading
    
    // Set SQLite index filename

    // Do not auto-add .kdb extension if we are creating a blank kdb file.
    bool newBlank = (create == 1) && (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID);
    
    // Check if it already has a .kdb extension
    TSK_TCHAR * c;
    c = TSTRRCHR(hdb_info->db_fname, _TSK_T('.'));    
    if (newBlank || ((c != NULL) && (TSTRLEN(c) >= 4)
        && (TSTRCMP(c, _TSK_T(".kdb")) == 0))) {

        TSTRNCPY(idx_info->idx_fname, hdb_info->db_fname, TSTRLEN(hdb_info->db_fname));
    } else {
        TSNPRINTF(idx_info->idx_fname, flen,
            _TSK_T("%s.kdb"), hdb_info->db_fname);
    }
    
    if (((idx = tsk_idx_open_file(idx_info->idx_fname)) == NULL) && (create == 0)) {

        // Try opening an old format index file

        // Clear index filename
        free(idx_info->idx_fname);
        idx_info->idx_fname = (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
        if (idx_info->idx_fname == NULL) {
            free(idx_info);
            // @@@ ERROR INFO NEEDED
            return NULL;
        }

        // Check if it already has an .idx extension
        TSK_TCHAR * c;
        c = TSTRRCHR(hdb_info->db_fname, _TSK_T('.'));    
        if ((c != NULL) && (TSTRLEN(c) >= 4)
            && (TSTRCMP(c, _TSK_T(".idx")) == 0)) {

            // Use given db filename as the index filename
            TSTRNCPY(idx_info->idx_fname, hdb_info->db_fname, TSTRLEN(hdb_info->db_fname));
        } else {
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
        }

        idx = tsk_idx_open_file(idx_info->idx_fname);

        if (!idx) {
            free(idx_info);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr( "tsk_idx_open: Error opening index file");
            return NULL;
        }
        
        if (1 != fread(header, header_size, 1, idx)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                "tsk_idx_open: Error reading header: %"PRIttocTSK,
                idx_info->idx_fname);
            return NULL;
        }
        else if (strncmp(header,
                           IDX_BINSRCH_HEADER,
                           strlen(IDX_BINSRCH_HEADER)) == 0) {
            idx_info->index_type = TSK_HDB_ITYPE_BINSRCH;
            idx_info->open = binsrch_open;
            idx_info->close = binsrch_close;
            idx_info->initialize = binsrch_initialize;
            idx_info->addentry = binsrch_addentry;
            idx_info->addentry_bin = binsrch_addentry_bin;
            idx_info->finalize = binsrch_finalize;
            idx_info->lookup_str = binsrch_lookup_str;
            idx_info->lookup_raw = binsrch_lookup_raw;
            idx_info->get_properties = binsrch_get_properties;
        }
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                "tsk_idx_open: Unrecognized header format: %"PRIttocTSK,
                idx_info->idx_fname);
            free(idx_info);
            return NULL;
        }
    }
    // kdb extension
    else {
        ///@todo should we require the header check here?
        if (idx) {
            if (1 != fread(header, header_size, 1, idx)) {
                ///@todo should this actually be an error?                
            }
            
            if (strncmp(header,
                        IDX_SQLITE_V1_HEADER,
                        strlen(IDX_SQLITE_V1_HEADER)) != 0) {

                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_MISSING);
                tsk_error_set_errstr(
                        "tsk_idx_open: Unrecognized header format: %"PRIttocTSK,
                        idx_info->idx_fname);
                tsk_idx_close_file(idx);
                free(idx_info);                
                return NULL;
            }
        }
        
        idx_info->index_type = TSK_HDB_ITYPE_SQLITE_V1;

        idx_info->open = sqlite_v1_open;
        idx_info->close = sqlite_v1_close;
        idx_info->initialize = sqlite_v1_initialize;
        idx_info->addentry = sqlite_v1_addentry;
        idx_info->addentry_bin = sqlite_v1_addentry_bin;
        idx_info->finalize = sqlite_v1_finalize;
        idx_info->lookup_str = sqlite_v1_lookup_str;
        idx_info->lookup_raw = sqlite_v1_lookup_raw;
        idx_info->get_properties = sqlite_v1_get_properties;
    }

    tsk_idx_close_file(idx);

    // Open
    if (idx_info->open(hdb_info, idx_info, htype) == 0) {
        // Set the properties such as updateable
        if (create == 1) {
            if (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID) {
                idx_info->updateable = 1;
            } else {
                idx_info->updateable = 0;
            }
        } else {
            idx_info->get_properties(hdb_info);
        }

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
        // update htype
        hdb_update_htype(hdb_info, htype);

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
    uint8_t create = 1; //create new file if it doesn't already exist

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
        if ((hdb_info->db_type != TSK_HDB_DBTYPE_MD5SUM_ID) && (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
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
    ///@todo change this function to not call hdb_setupindex

    if (hdb_setupindex(hdb_info, htype, 0) == 0) {
        return 1;
    } else {
        return 0;
    }

    return 0;
}

/**
 * \ingroup hashdblib
 * Setup the index if the open hash database has one.
 * 
 *
 * @param hdb_info Hash database to consider
 * @param htype Hash type that index should be of
 *
 * @return 1 if index exists / was setup; 0 if not / failed
 */
uint8_t
tsk_hdb_idxsetup(TSK_HDB_INFO * hdb_info, uint8_t htype)
{
    /* Check if the index is already open, and 
     * try to open it if not */
    if (hdb_setupindex(hdb_info, htype, 0) == 0) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * \ingroup hashdblib
 * Clear, setup, init, and make a fresh index.
 *  
 * @param hdb_info Hash database to consider
 * @param htype Hash type that index should be of
 *
 * @return 1 if index exists / was setup; 0 if not / failed
 */
uint8_t
tsk_hdb_regenerate_index(TSK_HDB_INFO * hdb_info, TSK_TCHAR * db_type)
{
    // blow away the existing index info
    //tsk_take_lock(&hdb_info->lock);
    tsk_idx_close(hdb_info->idx_info);
    free(hdb_info->idx_info);
    hdb_info->idx_info = NULL;
    //tsk_release_lock(&hdb_info->lock);

    if (hdb_setupindex(hdb_info, hdb_info->hash_type, 1) == 0) {
        /* Call db-specific initialize function */
	    if (hdb_info->idx_info->initialize(hdb_info, db_type)) {
            return 0;
        }

        if (tsk_hdb_makeindex(hdb_info, db_type)) {
            return 0;
        }
        return 1;
    } else {
        return 0;
    }


}

/**
 * \ingroup hashdblib
 * Test for index only (legacy)
 * Assumes that the db was opened using the TSK_HDB_OPEN_TRY option.
 *
 * @param hdb_info Hash database to consider
 *
 * @return 1 if there is only a legacy index AND no db, 0 otherwise
 */
uint8_t
tsk_hdb_is_idxonly(TSK_HDB_INFO * hdb_info)
{
    if (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID) {
        return (hdb_info->idx_info->index_type == TSK_HDB_ITYPE_BINSRCH) ? 1 : 0;
    } else {
        return 0;
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
 * \ingroup hashdblib
 * Create an empty index.
 * @param db_file Filename. For a new index from scratch, the db name == idx name.
 * @returns NULL on error
 */
TSK_HDB_INFO *
tsk_hdb_new(TSK_TCHAR * db_file)
{
    TSK_HDB_OPEN_ENUM flags = TSK_HDB_OPEN_IDXONLY;
    TSK_HDB_INFO * hdb_info = tsk_hdb_open(db_file, flags);
    if (hdb_info != NULL) {
        TSK_TCHAR * dbtype = NULL; //ignored for IDX only
        if (hdb_info->makeindex(hdb_info, dbtype) != 0) {
            tsk_hdb_close(hdb_info);
            hdb_info = NULL;
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CREATE);
            tsk_error_set_errstr("tsk_hdb_new: making new index failed");
        } else {
            if (tsk_hdb_idxfinalize(hdb_info) != 0) {
                tsk_hdb_close(hdb_info);
                hdb_info = NULL;
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_WRITE);
                tsk_error_set_errstr("tsk_hdb_new: finalizing new index failed");
            }
        }    
    }
    return hdb_info;
}

/**
 * \ingroup hashdblib
 * Add a binary hash entry to the index
 *
 * @param hdb_info the hash database object
 * @param filename Name of the file that was hashed (can be null)
 * @param md5 Text of MD5 hash (can be null)
 * @param sha1 Text of SHA1 hash (can be null)
 * @param sha256 Text of SHA256 hash (can be null)
 * @return 1 on error, 0 on success, -1 if not updateable
 */
int8_t
tsk_hdb_add_str(TSK_HDB_INFO * hdb_info, 
                const TSK_TCHAR * filename, 
                const char * md5, 
                const char * sha1, 
                const char * sha256)
{
    if(hdb_info == NULL) {
        tsk_error_set_errstr2("tsk_hdb_add_str: null hdb_info");
        return 1;
    } else {
        uint8_t htype = TSK_HDB_HTYPE_MD5_ID;
        if (hdb_setupindex(hdb_info, htype, 0)) {
            return 1;
        }

        if(hdb_info->idx_info->updateable == 1) {
            ///@todo also allow use of other htypes
            char * hvalue = (char *)md5;

            // @todo Could set up a polymorphic mechanism like with finalize() but
            // we know it's going to be sqlite in this function.
            if (sqlite_v1_begin(hdb_info) == 1) {
                tsk_error_set_errstr2("tsk_hdb_add_str: sqlite_v1_begin failed");
                return 1;
            }

            // Attempt to add a new row to the hash index
            TSK_OFF_T offset = 0; //not needed since there might not be an original DB
            if (tsk_hdb_idxaddentry(hdb_info, hvalue, offset) != 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_WRITE);
                tsk_error_set_errstr("tsk_hdb_add_str: adding entry failed");
                return 1;            
            } else {
                // Close the index
                if (tsk_hdb_idxfinalize(hdb_info) != 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_HDB_WRITE);
                    tsk_error_set_errstr("tsk_hdb_add_str: finalizing index failed");
                    return 1;
                }  
                return 0;
            }
        } else {
            return -1;
        }
    }
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
