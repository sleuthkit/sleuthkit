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

static FILE *open_db_file(TSK_TCHAR *file_path) 
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

    // Allocate space for saving the hash database path.
    size_t flen = TSTRLEN(file_path) + 8; // RJCTODO: Check this change from 32 (change was in DF code) with Brian; was change in older code? Put this in open funcs
    TSK_TCHAR *db_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (NULL == db_path) {
        return NULL;
    }

    FILE *hDb = NULL;
    TSK_HDB_DBTYPE_ENUM dbtype = TSK_HDB_DBTYPE_INVALID_ID;
    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        // The caller has not explicitly specified that the supplied file path is
        // a plain text index file able to be used for simple lookups in the absence 
        // of the original database file. Is this actually the case?
        TSK_TCHAR *ext = TSTRRCHR(file_path, _TSK_T('.'));    
        if ((ext != NULL) && (TSTRLEN(ext) >= 4) && (TSTRCMP(ext, _TSK_T(".idx")) == 0)) {
            // The path has a .idx extension. Strip it off and look for a
            // database file in the same location as the index file.
            TSTRNCPY(db_path, file_path, (ext - file_path));
#ifdef TSK_WIN32
            if (GetFileAttributes(db_path) == INVALID_FILE_ATTRIBUTES) {
                // No such database file exists. Use the index file path as the database path
                // and mark the database as index only.
                memset(db_path, 0, flen); 
                TSTRNCPY(db_path, file_path, flen);
                dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
            }
#else
            struct stat sb;
            if (stat(idx_info->idx_fname, &sb) < 0) {
                // No such database file exists. Use the index file path as the database path
                // and mark the database as index only.
                memset(db_path, 0, flen); 
                TSTRNCPY(db_path, file_path, flen);
                dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
            }
#endif
        }
        else {
            // The given path does not appear to be an index path.
            TSTRNCPY(db_path, file_path, flen);
        }

        hDb = open_db_file(db_path);
        if (NULL == hDb) {
            free(db_path);
            return NULL;
        }

        // Determine the type of the database file, if it is not an index only.
        TSK_HDB_INFO *hdb_info = NULL;
        if (TSK_HDB_DBTYPE_IDXONLY_ID != dbtype) {
            if (sqlite3_test(hDb)) {
                hdb_info = sqlite_hdb_open(db_path);
                dbtype = TSK_HDB_DBTYPE_SQLITE_ID;
            } 
            else {
                // Try each supported text database type.
                // Only one of the tests should succeed; if this is not the case
                // report an error.
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
    else {
        // The caller has explicitly specified that the supplied file path is
        // a plain text index file able to be used for simple lookups in the absence 
        // of the original database file. 
        TSTRNCPY(db_path, file_path, flen);
        hDb = open_db_file(db_path);
        if (NULL == hDb) {
            free(db_path);
            return NULL;
        }
        dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
    }

    //// Allocate a struct to represent this hash database.
    //TSK_HDB_INFO *hdb_info = NULL;
    //if ((hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO))) == NULL) {
    //    return NULL;
    //}

    //// RJCTODO: Call the specific create fuunctions here

    //// Save the database file handle. 
    //// RJCTODO: Make the struct member a void*
    //if (TSK_HDB_DBTYPE_SQLITE_ID == dbtype) {
    //    fclose(hDb);
    //    sqlite3 *db = sqlite_hdb_open_db(db_path);
    //    if (NULL != db) {
    //        hdb_info->hDb = hDb;
    //    }
    //    else {
    //        free(db_path);
    //        free(hdb_info);
    //        return NULL;
    //    }
    //}
    //else {
    //    hdb_info->hDb = hDb;
    //}

    // Save the database file path. In the case of an index only database, this will actually
    // be the index file standing in for the original text file database.
    //hdb_info->db_fname = db_path;
    
    // Initialize the lock used for thread safety.
    tsk_init_lock(&hdb_info->lock);

    // Initialize members to be set later to "not set".
    hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(0); // RJCTODO: Why is this set later? Seems this will be a problem for SQLite...
    hdb_info->hash_len = 0; // RJCTODO: Why is this set later?  Seems this will be a problem for SQLite...
    hdb_info->idx_info = NULL;

    // Set members that depend on the hash database type. 
    //hdb_info->db_type = static_cast<TSK_HDB_DBTYPE_ENUM>(dbtype);
    //switch (dbtype) {
    //    case TSK_HDB_DBTYPE_NSRL_ID:
    //        nsrl_name(hdb_info);
    //        hdb_info->getentry = nsrl_getentry;
    //        hdb_info->makeindex = nsrl_makeindex;
    //        hdb_info->add_comment = NULL; // RJCTODO: Consider making no-ops for these
    //        hdb_info->add_filename = NULL;
    //        break;

    //    case TSK_HDB_DBTYPE_MD5SUM_ID:
    //        md5sum_name(hdb_info);
    //        hdb_info->getentry = md5sum_getentry;
    //        hdb_info->makeindex = md5sum_makeindex;
    //        hdb_info->add_comment = NULL;
    //        hdb_info->add_filename = NULL;
    //        break;

    //    case TSK_HDB_DBTYPE_ENCASE_ID:
    //        encase_name(hdb_info);
    //        hdb_info->getentry = encase_getentry;
    //        hdb_info->makeindex = encase_makeindex;
    //        hdb_info->add_comment = NULL;
    //        hdb_info->add_filename = NULL;
    //        break;

    //    case TSK_HDB_DBTYPE_HK_ID:
    //        hk_name(hdb_info);
    //        hdb_info->getentry = hk_getentry;
    //        hdb_info->makeindex = hk_makeindex;
    //        hdb_info->add_comment = NULL;
    //        hdb_info->add_filename = NULL;
    //        break;

    //    case TSK_HDB_DBTYPE_IDXONLY_ID:
    //        idxonly_name(hdb_info);
    //        hdb_info->getentry = idxonly_getentry;
    //        hdb_info->makeindex = idxonly_makeindex;
    //        hdb_info->add_comment = NULL;
    //        hdb_info->add_filename = NULL;
    //        break;

    //    case TSK_HDB_DBTYPE_SQLITE_ID: 
    //        sqlite_hdb_set_db_name(hdb_info);
    //        hdb_info->getentry = sqlite_hdb_get_entry;
    //        hdb_info->makeindex = sqlite_hdb_make_index;
    //        hdb_info->add_comment = sqlite_v1_addcomment;
    //        hdb_info->add_filename = sqlite_v1_addfilename;
    //        break;

    //    default:
    //        free(hdb_info->db_fname);
    //        free(hdb_info);
    //        hdb_info = NULL;
    //}

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
    if (hdb_info->db_fname) {
        free(hdb_info->db_fname);
    }

    if (hdb_info->hDb) {
        fclose(hdb_info->hDb);
    }

    if (hdb_info->idx_info) {
        tsk_idx_close(hdb_info->idx_info);
        // RJCTODO: Looks like a leak here
    }

    tsk_deinit_lock(&hdb_info->lock);

    free(hdb_info);
}
