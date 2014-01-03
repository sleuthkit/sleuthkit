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
tsk_hdb_open(TSK_TCHAR *file_path, TSK_HDB_OPEN_ENUM flags)
{
    const char *func_name = "tsk_hdb_create";
    TSK_TCHAR *db_path = NULL; // The given file path may not be the database path.
    FILE *hDb = NULL;
    TSK_HDB_DBTYPE_ENUM db_type = TSK_HDB_DBTYPE_INVALID_ID;
    TSK_HDB_INFO *hdb_info = NULL;

    assert(NULL != file_path);
    if (NULL == file_path) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_INVALID_PARAM); // RJCTODO: COnsider changing this to INVALID_PATH
        tsk_error_set_errstr("%s: NULL file path", func_name);
        return NULL;
    }

    // Deduce the database path and type using the given file path and the 
    // open flags (the TSK_HDB_OPEN_IDXONLY flag may have been set to 
    // explicitly specify that the given file path is for an index file that
    // can be used for lookups in the absence of the original database file). 
    if ((flags & TSK_HDB_OPEN_IDXONLY) == 0) {
        TSK_TCHAR *ext = TSTRRCHR(file_path, _TSK_T('.'));    
        if ((NULL != ext) && (TSTRLEN(ext) >= 4) && (TSTRCMP(ext, _TSK_T(".idx")) == 0)) {
            // The file path has a .idx extension, the only extension currently
            // used for TSK hash database index files. Strip off the extension 
            // and look for a database file in the same directory as the index
            // file, per TSK convention.
            db_path = (TSK_TCHAR*)tsk_malloc(TSTRLEN(file_path) * sizeof(TSK_TCHAR));
            if (NULL == db_path) {
                return NULL;
            }
            TSTRNCPY(db_path, file_path, (ext - file_path));
            if (!hdb_file_exists(db_path)) {
                // If the database file does not exist, the index path *is* the
                // database path.
                free(db_path);
                db_path = NULL;
                db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
            }
        }

        // Since the database is not index only, determine its type by
        // inspecting the contents of the file.
        if ((TSK_HDB_DBTYPE_IDXONLY_ID != db_type)) {
            hDb = hdb_open_file((NULL != db_path) ? db_path : file_path);
            if (NULL == hDb) {
                if (NULL != db_path) {
                    free(db_path);
                }
                return NULL;
            }

            db_type = hdb_determine_db_type(hDb, (NULL != db_path) ? db_path : file_path);
            if (TSK_HDB_DBTYPE_INVALID_ID == db_type) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr("%s: Error determining hash database type of PRIttocTSK", func_name, (NULL != db_path) ? db_path : file_path);
                if (NULL != db_path) {
                    free(db_path);
                }
                return NULL;
            }
        }
    }
    else {
        db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
    }

    switch (db_type) {
        case TSK_HDB_DBTYPE_NSRL_ID:
            hdb_info = nsrl_open(hDb, (NULL != db_path) ? db_path : file_path);
            break;
        case TSK_HDB_DBTYPE_MD5SUM_ID:
            hdb_info = md5sum_open(hDb, (NULL != db_path) ? db_path : file_path);
            break;
        case TSK_HDB_DBTYPE_ENCASE_ID:
            hdb_info = encase_open(hDb, (NULL != db_path) ? db_path : file_path);
            break;
        case TSK_HDB_DBTYPE_HK_ID:
            hdb_info = hk_open(hDb, (NULL != db_path) ? db_path : file_path);
            break;
        case TSK_HDB_DBTYPE_IDXONLY_ID:
            hdb_info = idxonly_open((NULL != db_path) ? db_path : file_path);
            break;
        case TSK_HDB_DBTYPE_SQLITE_ID: 
            if (hDb) {
                fclose(hDb);
            }
            hdb_info = sqlite_hdb_open((NULL != db_path) ? db_path : file_path);
            break;
        default:
            assert(0);
    }

    if (NULL != db_path) {
        free(db_path);
    }

    return hdb_info;
}

/**
 * \ingroup hashdblib
 * RJCTODO: Comment
 */
uint8_t
tsk_set_index_params(TSK_HDB_INFO *hdb_info, TSK_HDB_DBTYPE_ENUM hash_type)
{
    return hdb_info->set_index_params(hdb_info, hash_type); 
}

/**
 * \ingroup hashdblib
 * Closes an open hash database.
 * @param hdb_info database to close
 */
void
tsk_hdb_close(TSK_HDB_INFO * hdb_info)
{
    hdb_info->close_db(hdb_info);
}
