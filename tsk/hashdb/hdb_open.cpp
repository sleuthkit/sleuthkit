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
 * \file hdb_open.c
 * Contains the generic hash database creation and lookup code.
 */



/**
 * \ingroup hashdblib
 * Open an existing hash database. 
 *
 * @param db_file Path to database (even if only an index exists, in which case db path should still be listed).
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

    // Initialize mutex (or critical section) obj
    tsk_init_lock(&hdb_info->lock);

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

    tsk_deinit_lock(&hdb_info->lock);

    free(hdb_info);
}
