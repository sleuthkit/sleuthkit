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
 * "Base" functions for hash databases. Many are no-ops.
 */

/**
 * \ingroup hashdblib
 * Sets hash database file name from file path.
 * @param hdb_info Struct representation of a hash database.
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

    // @@@ TODO: Use TskUTF16_to_UTF8 to properly convert for Windows
    for(i = 0; i < (end-begin); i++)
    {
        hdb_info->db_name[i] = (char) begin[i];
    }

    hdb_info->db_name[i] = '\0';
}

/**
 * \ingroup hashdblib
 * \internal
 * Initializes struct representation of a hash database.
 * @param hdb_info Struct representation of a hash database.
 * @return 0 on sucess, 1 on failure.
 */
uint8_t hdb_info_base_open(TSK_HDB_INFO *hdb_info, const TSK_TCHAR *db_path)
{
    size_t path_len = TSTRLEN(db_path); 
    hdb_info->db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
    if (!hdb_info->db_fname) {
        return 1;
    }
    TSTRNCPY(hdb_info->db_fname, db_path, path_len);
    hdb_base_db_name_from_path(hdb_info);

    hdb_info->db_type = TSK_HDB_DBTYPE_INVALID_ID;
    tsk_init_lock(&hdb_info->lock);

    hdb_info->get_db_path = hdb_base_get_db_path;
    hdb_info->get_db_name = hdb_base_get_db_name;
    hdb_info->uses_external_indexes = hdb_base_uses_external_indexes;
    hdb_info->get_index_path = hdb_base_get_index_path;
    hdb_info->has_index = hdb_base_has_index; 
    hdb_info->make_index = hdb_base_make_index;
    hdb_info->open_index = hdb_base_open_index;
    hdb_info->lookup_str = hdb_base_lookup_str;
    hdb_info->lookup_raw = hdb_base_lookup_bin;
    hdb_info->has_verbose_lookup = hdb_base_supports_verbose_lookup;
    hdb_info->lookup_verbose_str = hdb_base_lookup_verbose_str;
    hdb_info->accepts_updates = hdb_base_accepts_updates;
    hdb_info->add_entry = hdb_base_add_entry;
    hdb_info->close_db = hdb_info_base_close;

    return 0;
}

const TSK_TCHAR *hdb_base_get_db_path(TSK_HDB_INFO *hdb_info)
{
    return hdb_info->db_fname;
}

const char *hdb_base_get_db_name(TSK_HDB_INFO *hdb_info)
{
    return hdb_info->db_name;
}

uint8_t
hdb_base_uses_external_indexes()
{
    return 0;
}

const TSK_TCHAR*
hdb_base_get_index_path(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG); // RJCTODO: Could use dedicated NOT_IMPL or NO_SUPPORT enum member for this sort of thing in the "base" functions
    tsk_error_set_errstr("hdb_base_get_index_path: get index path not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return NULL;
}

uint8_t
hdb_base_has_index(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    return 0;
}

uint8_t hdb_base_make_index(TSK_HDB_INFO *hdb_info, TSK_TCHAR *htype)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_make_index: operationnot supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

uint8_t
hdb_base_open_index(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_open_index: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

int8_t
hdb_base_lookup_str(TSK_HDB_INFO *hdb_info, const char *hash, TSK_HDB_FLAG_ENUM flag, TSK_HDB_LOOKUP_FN callback, void *data)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_lookup_str: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

int8_t
hdb_base_lookup_bin(TSK_HDB_INFO *hdb_info, uint8_t *hash, uint8_t hash_len, TSK_HDB_FLAG_ENUM flag, TSK_HDB_LOOKUP_FN callback, void *data)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_lookup_bin: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

uint8_t
hdb_base_supports_verbose_lookup(TSK_HDB_INFO *hdb_info)
{
    return 0;
}

int8_t
hdb_base_lookup_verbose_str(TSK_HDB_INFO *hdb_info, const char *hash, void **result)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_lookup_verbose_str: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return -1;
}

uint8_t
hdb_base_accepts_updates()
{
    return 0;
}

uint8_t
hdb_base_add_entry(TSK_HDB_INFO *hdb_info, const char *file_name, const char *md5, const char *sha1, const char *sha2_256, const char *comment)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr("hdb_base_add_entry: operation not supported for hdb_info->db_type=%u", hdb_info->db_type);
    return 1;
}

/**
 * \ingroup hashdblib
 * De-initializes struct representation of a hash database.
 * @param hdb_info Struct representation of a hash database.
 * @return 0 on sucess, 1 on failure.
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
