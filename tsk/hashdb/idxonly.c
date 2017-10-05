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
*/
static void
    idxonly_name(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info)
{
    FILE * hFile;
    char buf[TSK_HDB_NAME_MAXLEN];
    char *bufptr = buf;
    size_t i = 0;

    memset(hdb_binsrch_info->base.db_name, '\0', TSK_HDB_NAME_MAXLEN);

    // Currently only supporting md5 and sha1 index files. Try to get the
    // database name from the index file.
    if(hdb_binsrch_open_idx((TSK_HDB_INFO*)hdb_binsrch_info, TSK_HDB_HTYPE_MD5_ID)) {
        if(hdb_binsrch_open_idx((TSK_HDB_INFO*)hdb_binsrch_info, TSK_HDB_HTYPE_SHA1_ID)) {
            if (tsk_verbose)
                fprintf(stderr,
                "Failed to get name from index (index does not exist); using file name instead");
            hdb_base_db_name_from_path((TSK_HDB_INFO*)hdb_binsrch_info);
            return;
        }
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
            return;
    }
    bufptr = strchr(buf, '|');
    bufptr++;
    while(bufptr[i] != '\r' && bufptr[i] != '\n' && i < strlen(bufptr))
    {
        hdb_binsrch_info->base.db_name[i] = bufptr[i];
        i++;
    }
}

TSK_HDB_INFO *idxonly_open(const TSK_TCHAR *db_path)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = NULL;
    hdb_binsrch_info = hdb_binsrch_open(NULL, db_path);
    if (NULL == hdb_binsrch_info) {
        return NULL;
    }

    hdb_binsrch_info->base.db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
    idxonly_name(hdb_binsrch_info);
    hdb_binsrch_info->base.get_db_path = idxonly_get_db_path;
    hdb_binsrch_info->get_entry = idxonly_getentry;

    // Before returning, do one final check that we'll be able to open
    // the index file
    if (hdb_binsrch_open_idx(hdb_binsrch_info, hdb_binsrch_info->hash_type)) {
        hdb_binsrch_close(hdb_binsrch_info);
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
