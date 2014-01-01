/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2007-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file idxonly_index.c
 * Contains the dummy functions that are used when only an index is used for lookups and the 
 * original database is gone. 
 */

#include "tsk_hashdb_i.h"

/**
 * Set db_name using information from this database type
 *
 * @param hdb_info the hash database object
 */
void
idxonly_name(TSK_HDB_INFO * hdb_info)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx;
    FILE * hFile;
    char buf[TSK_HDB_NAME_MAXLEN];
    char *bufptr = buf;
    size_t i = 0;
    memset(idx_info->base.db_name, '\0', TSK_HDB_NAME_MAXLEN);

    if(tsk_hdb_idxsetup(hdb_info, TSK_HDB_HTYPE_MD5_ID) == 0) {
        if (tsk_verbose)
            fprintf(stderr,
                "Failed to get name from index (index does not exist); using file name instead");
        tsk_hdb_name_from_path(hdb_info);
        return;
    }

    hFile = idx_info->hIdx;
    fseeko(hFile, 0, 0);
    if(NULL == fgets(buf, TSK_HDB_NAME_MAXLEN, hFile) ||
        NULL == fgets(buf, TSK_HDB_NAME_MAXLEN, hFile) ||
        strncmp(buf,
                TSK_HDB_IDX_HEAD_NAME_STR,
                strlen(TSK_HDB_IDX_HEAD_NAME_STR)) != 0) {
        if (tsk_verbose)
            fprintf(stderr,
                "Failed to read name from index; using file name instead");
        tsk_hdb_name_from_path(hdb_info);
        return;
    }
    bufptr = strchr(buf, '|');
    bufptr++;
    while(bufptr[i] != '\r' && bufptr[i] != '\n' && i < strlen(bufptr))
    {
        idx_info->base.db_name[i] = bufptr[i];
        i++;
    }
}

/**
 * This function creates an empty
 *
 * @param hdb_info Hash database to make index of.
 * @param dbtype Type of hash database. Ignored for IDX only.
 *
 * @return 1 on error and 0 on success.
 */
uint8_t
idxonly_makeindex(TSK_HDB_INFO * hdb_info, TSK_TCHAR * dbtype)
{
    //tsk_error_reset();
    //tsk_error_set_errno(TSK_ERR_HDB_ARG);
    //tsk_error_set_errstr(
    //         "idxonly_makeindex: Make index not supported when INDEX ONLY option is used");

    ///@temporary until we exorcise all the htype conditionals out
    TSK_TCHAR dbtype_default[1024];
    TSNPRINTF(dbtype_default, 1024, _TSK_T("%") PRIcTSK, TSK_HDB_DBTYPE_MD5SUM_STR);

    /* Initialize the TSK index file */
    if (tsk_hdb_idxinitialize(hdb_info, dbtype_default)) {
        tsk_error_set_errstr2( "idxonly_makeindex");
        return 1;
    }

    return 0;
}

/**
 * This function should find the corresponding name at a
 * given offset.  In this case though, we do not have the original database,
 * so just make an error...
 *
 * @param hdb_info Hash database to get data from
 * @param hash MD5 hash value that was searched for
 * @param offset Byte offset where hash value should be located in db_file
 * @param flags (not used)
 * @param action Callback used for each entry found in lookup
 * @param cb_ptr Pointer to data passed to callback
 *
 * @return 1 on error and 0 on succuss
 */
uint8_t
idxonly_getentry(TSK_HDB_INFO * hdb_info, const char *hash,
                 TSK_OFF_T offset, TSK_HDB_FLAG_ENUM flags,
                 TSK_HDB_LOOKUP_FN action, void *cb_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
             "idxonly_getentry: Not supported when INDEX ONLY option is used");
    return 1;
}

TSK_HDB_INFO *idxonly_open(TSK_TCHAR *db_path)
{
    size_t path_len = 0;
    TSK_TEXT_HDB_INFO *hdb_info = NULL;

    if ((hdb_info = (TSK_TEXT_HDB_INFO*)tsk_malloc(sizeof(TSK_TEXT_HDB_INFO))) == NULL) {
        return NULL;
    }

    path_len = TSTRLEN(db_path);
    hdb_info->base.db_fname = (TSK_TCHAR*)tsk_malloc((path_len + 1) * sizeof(TSK_TCHAR));
    if (NULL == hdb_info->base.db_fname) {
        free(hdb_info);
        return NULL;
    }
    TSTRNCPY(hdb_info->base.db_fname, db_path, path_len);

    // Initialize the lock used for thread safety.
    tsk_init_lock(&hdb_info->base.lock);

    // Initialize members to be set later to "not set".
    hdb_info->base.hash_type = TSK_HDB_HTYPE_INVALID_ID; // RJCTODO: Why is this set later? Seems this will be a problem for SQLite...
    hdb_info->base.hash_len = 0; // RJCTODO: Why is this set later?  Seems this will be a problem for SQLite...
    hdb_info->idx = NULL;

    hdb_info->base.db_type = TSK_HDB_DBTYPE_IDXONLY_ID;
    hdb_info->base.updateable = 0;
    idxonly_name((TSK_HDB_INFO*)hdb_info);
    hdb_info->getentry = idxonly_getentry;
    hdb_info->base.makeindex = idxonly_makeindex;
    hdb_info->base.add_comment = NULL; // RJCTODO: Consider making no-ops for these or moving them
    hdb_info->base.add_filename = NULL; // RJCTODO: Consider making no-ops for these or moving them

    return (TSK_HDB_INFO*)hdb_info;
}

