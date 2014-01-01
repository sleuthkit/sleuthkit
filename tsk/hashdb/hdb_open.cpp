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
#include <assert.h>

#ifdef TSK_WIN32
#include <share.h>
#endif

/**
 * \file hdb_open.c
 * Contains the code to open and close all supported hash database types.
 */

static uint8_t 
hdb_file_exists(TSK_TCHAR *file_path)
{
#ifdef TSK_WIN32
    return (GetFileAttributes(file_path) == INVALID_FILE_ATTRIBUTES) ? 0 : 1;
#else
    struct stat sb;
    return (stat(idx_info->idx_fname, &sb) < 0) ? 0 : 1;
#endif
}

static FILE *
hdb_open_file(TSK_TCHAR *file_path)
{
    FILE *file = NULL;
    int fd = 0;

    assert(NULL != file_path);

#ifdef TSK_WIN32
    if (_wsopen_s(&fd, file_path, _O_RDONLY | _O_BINARY, _SH_DENYNO, 0)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("hdb_open_file: Error opening file: %"PRIttocTSK, file_path); // RJCTODO: Is this correct formatting?
        return NULL;
    }
    file = _wfdopen(fd, L"rb");
#else
    // RJCTODO: Is this correct handling of TSK_TCHAR?
    if (NULL == (file = fopen(file_path, "r"))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("hdb_open_file: Error opening file: %s", file_path); 
        return NULL;
    }
#endif

    return file;
}

static TSK_HDB_DBTYPE_ENUM
hdb_determine_db_type(FILE *hDb, const TSK_TCHAR *db_path)
{
    const char *func_name = "hdb_determine_db_type";
    TSK_HDB_DBTYPE_ENUM db_type = TSK_HDB_DBTYPE_INVALID_ID;

    assert(NULL != hDb);
    assert(NULL != db_path);

    if (sqlite3_test(hDb)) {
        fseeko(hDb, 0, SEEK_SET);
        return TSK_HDB_DBTYPE_SQLITE_ID;
    }

    // Try each supported text database type for a more positive identification.
    // Only one of the tests should succeed. 
    fseeko(hDb, 0, SEEK_SET);
    if (nsrl_test(hDb)) {
        db_type = TSK_HDB_DBTYPE_NSRL_ID;
    }
    fseeko(hDb, 0, SEEK_SET);
    if (md5sum_test(hDb)) {
        if (db_type != TSK_HDB_DBTYPE_INVALID_ID) {
            fseeko(hDb, 0, SEEK_SET);
            return TSK_HDB_DBTYPE_INVALID_ID;
        }
        db_type = TSK_HDB_DBTYPE_MD5SUM_ID;
    }
    fseeko(hDb, 0, SEEK_SET);
    if (encase_test(hDb)) {
        if (db_type != TSK_HDB_DBTYPE_INVALID_ID) {
            fseeko(hDb, 0, SEEK_SET);
            return TSK_HDB_DBTYPE_INVALID_ID;
        }
        db_type = TSK_HDB_DBTYPE_ENCASE_ID;
    }
    fseeko(hDb, 0, SEEK_SET);
    if (hk_test(hDb)) {
        if (db_type != TSK_HDB_DBTYPE_INVALID_ID) {
            fseeko(hDb, 0, SEEK_SET);
            return TSK_HDB_DBTYPE_INVALID_ID;
        }
        db_type = TSK_HDB_DBTYPE_HK_ID;
    }

    fseeko(hDb, 0, SEEK_SET);
    return db_type;
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
    assert(NULL != file_path);
    if (NULL ==  file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_INVALID_PARAM);
        tsk_error_set_errstr("tsk_hdb_create: NULL file path");
        return NULL;
    }

    // RJCTODO: Should there be enforcement of the .kdb extension here (or in hfind)? Or is that strictly an Autopsy thing?
    // At present, only SQLite hash databases can be created by TSK. 
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
tsk_hdb_open(const TSK_TCHAR *file_path, TSK_HDB_OPEN_ENUM flags)
{
    const char *func_name = "tsk_hdb_create";
    size_t flen = 0;
    TSK_TCHAR *db_path = NULL;
    TSK_TCHAR *idx_path = NULL;
    FILE *hDb = NULL;
    TSK_HDB_DBTYPE_ENUM db_type = TSK_HDB_DBTYPE_INVALID_ID;
    TSK_HDB_INFO *hdb_info = NULL;

    assert(NULL != file_path);
    if (NULL ==  file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_INVALID_PARAM);
        tsk_error_set_errstr("%s: NULL file path", func_name);
        return NULL;
    }

    // Allocate memory for saving the database and index paths.
    flen = TSTRLEN(file_path) + 8; // RJCTODO: Check this change from 32 (change was in DF code) with Brian; was change in older code? What is the point, anyway?
    db_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (NULL == db_path) {
        free(idx_path);
        return NULL;
    }
    idx_path = (TSK_TCHAR*)tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (NULL == idx_path) {
        return NULL;
    }

    // Determine the database type and set the paths.
    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        // The open flags do not explicitly specify that the supplied file 
        // path is for an index file that can be used for simple lookups in 
        // the absence of the original database file. Therefore, determine 
        // what type of hash database is to be opened. The first thing to
        // do is determine whether the file is indeed an index file.
        TSK_TCHAR *ext = TSTRRCHR((TSK_TCHAR*)file_path, _TSK_T('.'));    
        if ((ext != NULL) && (TSTRLEN(ext) >= 4) && (TSTRCMP(ext, _TSK_T(".idx")) == 0)) {
            // The path has a .idx extension, the only extension currently
            // used for TSK hash database index files. It is most likely an
            // an index file.
            TSTRNCPY(idx_path, file_path, flen);

            // Strip the extension from the index path and look for a database 
            // file in the same directory as the index file.
            TSTRNCPY(db_path, file_path, (ext - file_path));
            if (!hdb_file_exists(db_path)) {
                // If the database file does not exist, treat the index file as an 
                // index only database.
                free(db_path);
                db_path = NULL;
                db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
            }
        }
        else {
            // The given path appears to be a database path.
            TSTRNCPY(db_path, file_path, flen);
            free(idx_path);
            idx_path = NULL;
        }

        // Since the database is not an index only, determine its type by
        // inspecting the contents of the file.
        if ((TSK_HDB_DBTYPE_IDXONLY_ID != db_type) && (NULL != db_path)) {
            hDb = hdb_open_file(db_path);
            if (NULL == hDb) {
                free(db_path);
                if (NULL != idx_path) {
                    free(idx_path);
                }
                return NULL;
            }

            db_type = hdb_determine_db_type(hDb, db_path);
            if (TSK_HDB_DBTYPE_INVALID_ID == db_type) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr("%s: Error determining hash database type of PRIttocTSK", func_name, db_path);

                if (db_path) {
                    free(db_path);
                }

                if (idx_path) {
                    free(idx_path);
                }

                return NULL;
            }
        }
    }
    else {
        // The open flags explicitly specify that the supplied file 
        // path is for an index file that can be used for simple lookups in 
        // the absence of the original database file.
        TSTRNCPY(idx_path, file_path, flen);
        free(db_path);
        db_path = NULL;
        db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
    }

    switch (db_type) {
        case TSK_HDB_DBTYPE_NSRL_ID:
            hdb_info = nsrl_open(hDb, db_path);
            break;
        case TSK_HDB_DBTYPE_MD5SUM_ID:
            hdb_info = md5sum_open(hDb, db_path);
            break;
        case TSK_HDB_DBTYPE_ENCASE_ID:
            hdb_info = encase_open(hDb, db_path);
            break;
        case TSK_HDB_DBTYPE_HK_ID:
            hdb_info = hk_open(hDb, db_path);
            break;
        case TSK_HDB_DBTYPE_IDXONLY_ID:
            if (hDb) {
                fclose(hDb);
            }
            hdb_info = idxonly_open(idx_path);
            break;
        case TSK_HDB_DBTYPE_SQLITE_ID: 
            if (hDb) {
                fclose(hDb);
            }
            hdb_info = sqlite_hdb_open(db_path);
            break;
        default:
            assert(0);
    }

    if (db_path) {
        free(db_path);
    }

    if (idx_path) {
        free(idx_path);
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
