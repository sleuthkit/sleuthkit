/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2014 Brian Carrier.  All rights reserved
*
*
* This software is distributed under the Common Public License 1.0
*/

#include "tsk_hashdb_i.h"

/**
* \file hdb_base.c
* "Base" functions for hash databases. Many are no-ops / stubs
*/

/**
* \ingroup hashdblib
* Sets hash database name in hdb_info based on database file path. 
* @param hdb_info Struct representation of an open hash database.
*/
void 
    hdb_base_db_name_from_path(TSK_HDB_INFO *hdb_info)
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

    // @@@ This only works for file names with Latin characters. It may need
    // to be fixed some day. Leave it be for now. 
    for(i = 0; i < (end-begin); i++)
    {
        hdb_info->db_name[i] = (char) begin[i];
    }

    hdb_info->db_name[i] = '\0';
}

/**
* \ingroup hashdblib
* \internal
* Initializes TSK_HDB_INFO struct with "base class" method pointers and basic
* setup of values.  
* @param hdb_info Allocated struct to initialize.
* @param db_path 
* @return 0 on success, 1 on failure.
*/
uint8_t 
    hdb_info_base_open(TSK_HDB_INFO *hdb_info, const TSK_TCHAR *db_path)
{
    // copy the database path into the struct
    size_t path_len = TSTRLEN(db_path); 
    hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
    if (!hdb_info->db_fname) {
        return 1;
    }
    TSTRNCPY(hdb_info->db_fname, db_path, path_len);

    // set the name based on path
    hdb_base_db_name_from_path(hdb_info);

    hdb_info->db_type = TSK_HDB_DBTYPE_INVALID_ID;
    tsk_init_lock(&hdb_info->lock);

    hdb_info->transaction_in_progress = 0;

    hdb_info->get_db_path = hdb_base_get_db_path;
    hdb_info->get_display_name = hdb_base_get_display_name;
    hdb_info->uses_external_indexes = hdb_base_uses_external_indexes;
    hdb_info->get_index_path = hdb_base_get_index_path;
    hdb_info->has_index = hdb_base_has_index; 
    hdb_info->make_index = hdb_base_make_index;
    hdb_info->open_index = hdb_base_open_index;
    hdb_info->lookup_str = hdb_base_lookup_str;
    hdb_info->lookup_raw = hdb_base_lookup_bin;
    hdb_info->lookup_verbose_str = hdb_base_lookup_verbose_str;
    hdb_info->accepts_updates = hdb_base_accepts_updates;
    hdb_info->add_entry = hdb_base_add_entry;
    hdb_info->begin_transaction = hdb_base_begin_transaction;
    hdb_info->commit_transaction = hdb_base_commit_transaction;
    hdb_info->rollback_transaction = hdb_base_rollback_transaction;
    hdb_info->close_db = hdb_info_base_close;

    return 0;
}

const TSK_TCHAR *
    hdb_base_get_db_path(TSK_HDB_INFO *hdb_info)
{
    // The "base class" assumption is that the hash database is implemented
    // as a user-accessible file (e.g., it is a SQLite database or a text-
    // format database). In the future, it may become necessary to accomodate
    // connection strings.
    return hdb_info->db_fname;
}

const char *
    hdb_base_get_display_name(TSK_HDB_INFO *hdb_info)
{
    return hdb_info->db_name;
}

uint8_t
    hdb_base_uses_external_indexes()
{
    // The "base class" assumption is that the hash database does not use
    // user-accessible external index files (e.g., it is a relational
    // database).
    return 0;
}

const TSK_TCHAR*
    hdb_base_get_index_path(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    // The "base class" assumption is that the hash database does not have
    // user-accessible external index files (e.g., it is a relational
    // database). It follows that the hash database path and index path are 
    // the same, assuming that the hash database is implemented
    // as a user-accessible file (e.g., it is a SQLite database). 
    return hdb_info->db_fname;
}

uint8_t
    hdb_base_has_index(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    // The "base class" assumption is that the hash database does not have
    // user-accessible external index files (e.g., it is a relational database). 
    // It follows that the hash database has an index as soon as it is created. 
    // This implementation of this function also says that look ups for all hash 
    // algorithm types are supported.
    return 1;
}

uint8_t 
    hdb_base_make_index(TSK_HDB_INFO *hdb_info, TSK_TCHAR *htype)
{
    // The "base class" assumption is that the hash database does not have
    // user-accessible external index files (e.g., it is a relational
    // database). It follows that the hash database has an index upon creation.
    // Make this a no-op by simply returning the success code.
    return 0;
}

uint8_t
    hdb_base_open_index(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    // The "base class" assumption is that the hash database does not use
    // user-accessible external index files (e.g., it is a relational
    // database). It follows that the hash database has an index when it is
    // created and it is already "open". Make this a no-op by simply returning
    // the success code.
    return 0;
}

int8_t
    hdb_base_lookup_str(TSK_HDB_INFO *hdb_info, const char *hash, TSK_HDB_FLAG_ENUM flag, TSK_HDB_LOOKUP_FN callback, void *data)
{
    // This function always needs an "override" by "derived classes."
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_lookup_str: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

int8_t
    hdb_base_lookup_bin(TSK_HDB_INFO *hdb_info, uint8_t *hash, uint8_t hash_len, TSK_HDB_FLAG_ENUM flag, TSK_HDB_LOOKUP_FN callback, void *data)
{
    // This function always needs an "override" by "derived classes."
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_lookup_bin: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

int8_t
    hdb_base_lookup_verbose_str(TSK_HDB_INFO *hdb_info, const char *hash, void *result)
{
    // This function always needs an "override" by "derived classes."
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_lookup_verbose_str: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

uint8_t
    hdb_base_accepts_updates()
{
    // The "base class" assumption is that the database accepts updates (e.g.,
    // it is a relational database and there is a "derived class override" of 
    // add_entry() function that does INSERTs).
    return 1;
}

uint8_t
    hdb_base_add_entry(TSK_HDB_INFO *hdb_info, const char *file_name, const char *md5, const char *sha1, const char *sha2_256, const char *comment)
{
    // This function needs an "override" by "derived classes" unless there is an 
    // "override" of the accepts_updates function that returns 0 (false).
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_add_entry: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

uint8_t hdb_base_begin_transaction(TSK_HDB_INFO *hdb_info)
{
    // This function needs an "override" by "derived classes" unless there is an 
    // "override" of the accepts_updates function that returns 0 (false).
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_begin_transaction: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

uint8_t hdb_base_commit_transaction(TSK_HDB_INFO *hdb_info)
{
    // This function needs an "override" by "derived classes" unless there is an 
    // "override" of the accepts_updates function that returns 0 (false).
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_commit_transaction: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

uint8_t hdb_base_rollback_transaction(TSK_HDB_INFO *hdb_info)
{
    // This function needs an "override" by "derived classes" unless there is an 
    // "override" of the accepts_updates function that returns 0 (false).
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_UNSUPFUNC);
    tsk_error_set_errstr("hdb_base_rollback_transaction: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

/**
* \ingroup hashdblib
* De-initializes struct representation of a hash database.
* @param hdb_info Struct representation of a hash database.
* @return 0 on success, 1 on failure.
*/
void hdb_info_base_close(TSK_HDB_INFO *hdb_info)
{
    if (NULL == hdb_info) {
        return;
    }

    if (hdb_info->db_fname) {
        free(hdb_info->db_fname);
        hdb_info->db_fname = NULL;
    }

    tsk_deinit_lock(&hdb_info->lock);
}
