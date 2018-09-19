/*
* The Sleuth Kit
*
* Brian Carrier [carrier <at> sleuthkit [dot] org]
* Copyright (c) 2007-2014 Brian Carrier.  All rights reserved
*
* This software is distributed under the Common Public License 1.0
*/

/**
* \file idxonly.c
* Contains the dummy functions that are used when only an index is used for lookups and the 
* original database is gone. 
*/

#include "tsk_hashdb_i.h"

/**
* Set db_name using information from this database type
*
* @param hdb_info the hash database object
* @returns 1 on error
*/
static uint8_t 
    idxonly_name(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info)
{
    FILE * hFile;
    char buf[TSK_HDB_NAME_MAXLEN];
    char *bufptr = buf;
    size_t i = 0;

    // Try to get the database name from the index file.
    memset(hdb_binsrch_info->base.db_name, '\0', TSK_HDB_NAME_MAXLEN);

    if (hdb_binsrch_info->hIdx == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("idxonly_name: Index is not open");
        return 1;
    }

    hFile = hdb_binsrch_info->hIdx;
    fseeko(hFile, 0, 0);
    if(NULL == fgets(buf, TSK_HDB_NAME_MAXLEN, hFile) ||
        NULL == fgets(buf, TSK_HDB_NAME_MAXLEN, hFile) ||
        strncmp(buf,
        TSK_HDB_IDX_HEAD_NAME_STR,
        strlen(TSK_HDB_IDX_HEAD_NAME_STR)) != 0) {
            if (tsk_verbose)
                fprintf(stderr,
                "Failed to read name from index; using file name instead");
            hdb_base_db_name_from_path((TSK_HDB_INFO*)hdb_binsrch_info);
            return 1;
    }
    bufptr = strchr(buf, '|');
    bufptr++;
    while(bufptr[i] != '\r' && bufptr[i] != '\n' && i < strlen(bufptr))
    {
        hdb_binsrch_info->base.db_name[i] = bufptr[i];
        i++;
    }
    return 0;
}

/**
 * @param db_path Path to DB, which probably does not exist. But it gets passed in because we need
 *   it in a bunch of places. 
 * @param idx_path Path to index file (should be superset of db_path)
 */
TSK_HDB_INFO *idxonly_open(const TSK_TCHAR *db_path, const TSK_TCHAR *idx_path)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = NULL;
    TSK_TCHAR *ext;
    TSK_HDB_HTYPE_ENUM htype;

    hdb_binsrch_info = hdb_binsrch_open(NULL, db_path);
    if (NULL == hdb_binsrch_info) {
        return NULL;
    }

    hdb_binsrch_info->base.db_type = TSK_HDB_DBTYPE_IDXONLY_ID;

    // open the index
    ext = TSTRRCHR(idx_path, _TSK_T('-'));
    if (ext == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("idxonly_open: invalid file name (no extension): %" PRIttocTSK, idx_path);
        return NULL;
    }
    else if ((TSTRLEN(ext) == 8) && (TSTRICMP(ext, _TSK_T("-md5.idx")) == 0)) {
        htype = TSK_HDB_HTYPE_MD5_ID;
    }
    else if ((TSTRLEN(ext) == 9) && (TSTRICMP(ext, _TSK_T("-sha1.idx")) == 0)) {
        htype = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("idxonly_open: invalid file name (unknown extension): %" PRIttocTSK, idx_path);
        return NULL;
    }
    
    if (hdb_binsrch_open_idx((TSK_HDB_INFO*)hdb_binsrch_info, htype)) {
        return NULL;
    }

    if (idxonly_name(hdb_binsrch_info)) {
        hdb_binsrch_close((TSK_HDB_INFO*)hdb_binsrch_info);
        return NULL;
    }

    hdb_binsrch_info->base.get_db_path = idxonly_get_db_path;
    hdb_binsrch_info->get_entry = idxonly_getentry;

    // Before returning, do one final check that we'll be able to open
    // the index file
    if (hdb_binsrch_open_idx((TSK_HDB_INFO*)hdb_binsrch_info, hdb_binsrch_info->hash_type)) {
        hdb_binsrch_close((TSK_HDB_INFO*)hdb_binsrch_info);
        return NULL;
    }

    return (TSK_HDB_INFO*)hdb_binsrch_info;    
}

const TSK_TCHAR *
    idxonly_get_db_path(TSK_HDB_INFO *hdb_info)
{
    // The database path member of the TSK_HDB_INFO is filled in, but that is
    // just for the sake of the common index file name construction algorithm.
    return NULL;
}

uint8_t
    idxonly_getentry(TSK_HDB_INFO * hdb_info, const char *hash,
    TSK_OFF_T offset, TSK_HDB_FLAG_ENUM flags,
    TSK_HDB_LOOKUP_FN action, void *cb_ptr)
{
    if (!(flags & TSK_HDB_FLAG_QUICK) && (NULL != action)) {
        action(hdb_info, hash, NULL, cb_ptr);
    }
    return 0;
}
