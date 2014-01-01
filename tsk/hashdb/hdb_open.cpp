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

#ifdef TSK_WIN32
#include <share.h>
#endif

/**
 * \file hdb_open.c
 * Contains the code to open and close all supported hash database types.
 */

static uint8_t hdb_file_exists(TSK_TCHAR *file_path)
{
    // RJCTODO: Is there a TSK error for this? Use an assert?
    if (NULL == file_path) {
        return NULL;
    }

#ifdef TSK_WIN32
    return (GetFileAttributes(file_path) == INVALID_FILE_ATTRIBUTES) ? 0 : 1;
#else
    struct stat sb;
    return (stat(idx_info->idx_fname, &sb) < 0) ? 0 : 1;
#endif
}

static FILE *open_db_file(TSK_TCHAR *file_path) // RJCTODO: Change name to include hdb for sake of error messages
{
    // RJCTODO: Is there a TSK error for this? Use an assert?
    if (NULL == file_path) {
        return NULL;
    }

    FILE *file = NULL;

#ifdef TSK_WIN32
    int fd;
    if (_wsopen_s(&fd, file_path, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("open_db_file: Error opening file: %"PRIttocTSK, file_path);
        return NULL;
    }
    file = _wfdopen(fd, L"rb");
#else
    if (NULL == (file = fopen(file_path, "r"))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("open_db_file: Error opening file: %s", file_path); // RJCTODO: Is this correct?
        return NULL;
    }
#endif

    return file;
}

/**
 * \ingroup hashdblib
 * Creates a new hash database. 
 * @param file_path Path for database to create.
 * @return 0 on success, 1 otherwise
 */
uint8_t 
tsk_hdb_create(TSK_TCHAR *file_path)
{
    // RJCTODO: Is there a TSK error for this? Use an assert?
    if (NULL ==  file_path) {
        return NULL;
    }

    // RJCTODO: Should there be enforcement of the .kdb extension here (or in hfind)? Or is that strictly an Autopsy thing?

    return sqlite_hdb_create_db(file_path); 
}

/**
 * \ingroup hashdblib
 * Opens an existing hash database. 
 * @param file_path Path to database or database index file.
 * @param flags Flags for opening the database.  
 * @return Pointer to a struct representing the hash database or NULL on error.
 */
TSK_HDB_INFO *
tsk_hdb_open(TSK_TCHAR *file_path, TSK_HDB_OPEN_ENUM flags)
{
    // RJCTODO: Is there a TSK error for this? Use an assert?
    if (NULL ==  file_path) {
        return NULL;
    }

    // If the caller has not explicitly specified that the supplied file path 
    // is a plain text index file able to be used for simple lookups in the 
    // absence of the original database file, inspect the file and figure out 
    // what type of hash datbase is to be opened. Otherwise, trust the caller
    // and proceed.
    TSK_TCHAR *db_path = NULL;
    TSK_TCHAR *idx_path = NULL;
    FILE *hDb = NULL;
    TSK_HDB_DBTYPE_ENUM dbtype = TSK_HDB_DBTYPE_INVALID_ID;
    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        TSK_TCHAR *ext = TSTRRCHR(file_path, _TSK_T('.'));    
        if ((ext != NULL) && (TSTRLEN(ext) >= 4) && (TSTRCMP(ext, _TSK_T(".idx")) == 0)) {
            // The path has a .idx extension. It is likely that it is an index
            // file. Copy it as such.
            size_t flen = TSTRLEN(file_path) + 8; // RJCTODO: Check this change from 32 (change was in DF code) with Brian; was change in older code? Put + 8 this in open funcs
            TSK_TCHAR *idx_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
            if (NULL == idx_path) {
                return NULL;
            }

            // Strip it off and look for a database file in the same location
            // as the index file.
            TSK_TCHAR *db_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
            if (NULL == db_path) {
                free(idx_path);
                return NULL;
            }
            TSTRNCPY(db_path, file_path, (ext - file_path));

            // If the database file does not exist, treat the index file as an 
            // index only database.
            if (!hdb_file_exists(db_path)) {
                free(db_path);
                db_path = NULL;
                dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
            }
        }
        else {
            // The given path does not appear to be an index path.
            size_t flen = TSTRLEN(file_path);
            TSK_TCHAR *idx_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
            if (NULL == idx_path) {
                return NULL;
            }
            TSTRNCPY(db_path, file_path, flen);
        }

        if ((TSK_HDB_DBTYPE_IDXONLY_ID != dbtype) && (NULL != db_path)) {
            // Open the database file.            
            hDb = open_db_file(db_path);
            if (NULL == hDb) {
                free(db_path);
                if (NULL != idx_path) {
                    free(idx_path);
                }
                return NULL;
            }

            // Determine the type of the database file
            TSK_HDB_INFO *hdb_info = NULL;
            if (TSK_HDB_DBTYPE_IDXONLY_ID != dbtype) {
                if (sqlite3_test(hDb)) {
                    dbtype = TSK_HDB_DBTYPE_SQLITE_ID;
                } 
                else {
                    // Try each supported text database type.
                    // Only one of the tests should succeed. 
                    if (nsrl_test(hDb)) {
                        dbtype = TSK_HDB_DBTYPE_NSRL_ID;
                    }

                    if (md5sum_test(hDb)) {
                        if (dbtype != TSK_HDB_DBTYPE_INVALID_ID) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                            tsk_error_set_errstr(
                                        "hdb_open: Error determining DB type (MD5sum)");
                            return NULL;
                        }
                        dbtype = TSK_HDB_DBTYPE_MD5SUM_ID;
                    }

                    if (encase_test(hDb)) {
                        if (dbtype != TSK_HDB_DBTYPE_INVALID_ID) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                            tsk_error_set_errstr(
                                        "hdb_open: Error determining DB type (EnCase)");
                            return NULL;
                        }
                        dbtype = TSK_HDB_DBTYPE_ENCASE_ID;
                    }

                    if (hk_test(hDb)) {
                        if (dbtype != TSK_HDB_DBTYPE_INVALID_ID) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                            tsk_error_set_errstr(
                                        "hdb_open: Error determining DB type (HK)");
                            return NULL;
                        }
                        dbtype = TSK_HDB_DBTYPE_HK_ID;
                    }

                    if (dbtype == TSK_HDB_DBTYPE_INVALID_ID) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                        tsk_error_set_errstr(
                                    "hdb_open: Error determining DB type");
                        return NULL;
                    }

                    fseeko(hDb, 0, SEEK_SET);
                }
            }
        }
    }
    else {
        size_t flen = TSTRLEN(file_path) + 8; // RJCTODO: Check this change from 32 (change was in DF code) with Brian; was change in older code? Put + 8 this in open funcs
        TSK_TCHAR *idx_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
        if (NULL == idx_path) {
            return NULL;
        }
        dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
    }

    TSK_HDB_INFO *hdb_info = NULL;
    switch (dbtype) {
        case TSK_HDB_DBTYPE_NSRL_ID:
            hdb_info = nsrl_open(hDb, db_path, idx_path);
            break;
        case TSK_HDB_DBTYPE_MD5SUM_ID:
            break;
        case TSK_HDB_DBTYPE_ENCASE_ID:
            break;
        case TSK_HDB_DBTYPE_HK_ID:
            break;
        case TSK_HDB_DBTYPE_IDXONLY_ID:
            break;
        case TSK_HDB_DBTYPE_SQLITE_ID: 
            if (hDb) {
                fclose(hDb);
            }
            hdb_info = sqlite_hdb_open(db_path);
            break;
        default:
            if (db_path) {
                free(db_path);
            }
            if (idx_path) {
                free(idx_path);
            }
    }

    if (!hdb_info) {
        if (db_path) {
            free(db_path);
        }

        if (idx_path) {
            free(idx_path);
        }
    }

    return hdb_info;
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
    // RJCTODO: Need close function
    //if (hdb_info->db_fname) {
    //    free(hdb_info->db_fname);
    //}

    //if (hdb_info->hDb) {
    //    fclose(hdb_info->hDb);
    //}

    //if (hdb_info->idx_info) {
    //    tsk_idx_close(hdb_info->idx_info);
    //    // RJCTODO: Looks like a leak here
    //}

    //tsk_deinit_lock(&hdb_info->lock);

    //free(hdb_info);
}
