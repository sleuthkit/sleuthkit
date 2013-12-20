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

/**
 * \ingroup hashdblib
 * Creates a new hash database. 
 *
 * @param db_file_path Path to database to create.
 * @return 0 on success, 1 otherwise // RJCTODO
 */
TSK_HDB_INFO * 
tsk_hdb_create_db(TSK_TCHAR *db_file_path)
{
    if (sqlite_hdb_create_db(db_file_path) == 1) {
        return NULL;
    }

    return tsk_hdb_open(db_file_path, TSK_HDB_OPEN_NONE); // RJCTODO: Consider checking the dbType here to be sure it is SQLite
}

/**
 * \ingroup hashdblib
 * Open an existing hash database. 
 *
 * @param db_file Path to database (even if only an index exists, in which case db path should still be listed).
 * @param flags Flags for opening the database.  
 *
 * @return Pointer to hash database state structure or NULL on error
 */
TSK_HDB_INFO *
tsk_hdb_open(TSK_TCHAR * db_file, TSK_HDB_OPEN_ENUM flags)
{
    TSK_HDB_INFO *hdb_info = NULL;
    size_t flen = 0;
    FILE *hDb = NULL;
    uint8_t dbtype = TSK_HDB_DBTYPE_INVALID_ID;

    // Determine the database type.
    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        // The caller has not explicitly specified that the supplied file path is
        // a plain text index file able to be used for simple lookups in the absence 
        // of the original database file. Open the file to determine its type.
#ifdef TSK_WIN32
        int fd;
        if (_wsopen_s(&fd, db_file, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "open_index_file: Error opening index file: %"PRIttocTSK,
                    db_file);
            return NULL;
        }

        hDb = _wfdopen(fd, L"rb");
#else
        if (NULL == (hDb = fopen(db_file, "r"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                     "hdb_open: Error opening database file: %s", db_file);
            return NULL;
        }
#endif

        if (sqlite3_test(hDb)) {
            dbtype = TSK_HDB_DBTYPE_SQLITE_ID;

            // Close the database file because it will be re-opened with SQLite when the
            // "index" is opened. Even though there is no separate index file as is the 
            // case with the text database types, the SQLite handle will be treated as
            // an index file since all lookups go through the "index" first.
            fclose(hDb);
            hDb = NULL; 
        } 
        else {
            // Try each supported text database type.
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
    }
    else {
        // The caller has explicitly specified that the supplied file path is
        // a plain text index file able to be used for simple lookups in the absence 
        // of the original database file. 
        dbtype = TSK_HDB_DBTYPE_IDXONLY_ID;
        hDb = NULL;
    }

    // Allocate the struct that will represent this database.
    if ((hdb_info = (TSK_HDB_INFO*)tsk_malloc(sizeof(TSK_HDB_INFO))) == NULL) {
        return NULL;
    }

    // Save the file handle. If the database is index only or an RDBMS, the handle will be
    // null, indicating that there is no separate text file from which data can be fetched.
    hdb_info->hDb = hDb;

    // Save the database file path. In the case of an index only database, this will actually
    // be the index file standing in for the original text file database.
    flen = TSTRLEN(db_file) + 32;
    hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_info->db_fname == NULL) {
        free(hdb_info);
        return NULL;
    }
    TSTRNCPY(hdb_info->db_fname, db_file, flen);
    
    // Initialize lock.
    tsk_init_lock(&hdb_info->lock);

    // Initialize members to be set later to "not set".
    hdb_info->hash_type = static_cast<TSK_HDB_HTYPE_ENUM>(0); // RJCTODO: Why is this set later?
    hdb_info->hash_len = 0; // RJCTODO: Why is this set later?
    hdb_info->idx_info = NULL;

    // Set members that depend on the hash database type. 
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

        case TSK_HDB_DBTYPE_SQLITE_ID: 
            sqlite_hdb_set_db_name(hdb_info);
            hdb_info->getentry = sqlite_hdb_get_entry;
            hdb_info->makeindex = sqlite_hdb_make_index;
            break;

        default:
            free(hdb_info);
            hdb_info = NULL;
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
    if (hdb_info->db_fname) {
        free(hdb_info->db_fname);
    }

    if (hdb_info->hDb) {
        fclose(hdb_info->hDb);
    }

    if (hdb_info->idx_info) {
        tsk_idx_close(hdb_info->idx_info);
    }

    tsk_deinit_lock(&hdb_info->lock);

    free(hdb_info);
}
