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
#include "tsk_hash_info.h"

/**
* \file binsrch_index.cpp
* Functions common to all text hash databases (i.e. NSRL, HashKeeper, EnCase, etc.).
* Examples include index management and index-based lookup.
*/

// A mapping of initial hash digits to offsets in the index file is used to
// set the initial bounds of the binary search of the index file that is done
// for lookups. The mapping is from the first three digits (three nibbles) of 
// the hash, so there are 2 ^ 12 or 4096 possible entries.
static const size_t IDX_IDX_ENTRY_COUNT = 4096;
static const size_t IDX_IDX_SIZE = IDX_IDX_ENTRY_COUNT * sizeof(uint64_t);
#if defined( __BORLANDC__ ) && ( __BORLANDC__ < 0x0560 )
static const uint64_t IDX_IDX_ENTRY_NOT_SET = 0xFFFFFFFFFFFFFFFFUL;
#else
static const uint64_t IDX_IDX_ENTRY_NOT_SET = 0xFFFFFFFFFFFFFFFFULL;
#endif


/**
 * Called by the various text-based databases to setup the TSK_HDB_BINSRCH_INFO struct.
 * This will setup the basic function pointers, that will be overwritten by the more
 * specific methods. 
 */
TSK_HDB_BINSRCH_INFO *hdb_binsrch_open(FILE *hDb, const TSK_TCHAR *db_path)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = NULL;

    if ((hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)tsk_malloc(sizeof(TSK_HDB_BINSRCH_INFO))) == NULL) {
        return NULL;
    }

    // Do basic initialization of hdb_binsrch_info
    if (hdb_info_base_open((TSK_HDB_INFO*)hdb_binsrch_info, db_path)) {
        return NULL;
    }

    // override basic settings with basic text settings
    hdb_binsrch_info->hDb = hDb; 
    hdb_binsrch_info->base.uses_external_indexes = hdb_binsrch_uses_external_indexes;
    hdb_binsrch_info->base.get_index_path = hdb_binsrch_get_index_path;
    hdb_binsrch_info->base.has_index = hdb_binsrch_has_index;
    hdb_binsrch_info->base.open_index = hdb_binsrch_open_idx;
    hdb_binsrch_info->base.lookup_str = hdb_binsrch_lookup_str;
    hdb_binsrch_info->base.lookup_raw = hdb_binsrch_lookup_bin;
    hdb_binsrch_info->base.lookup_verbose_str = hdb_binsrch_lookup_verbose_str;
    hdb_binsrch_info->base.accepts_updates = hdb_binsrch_accepts_updates;
    hdb_binsrch_info->base.close_db = hdb_binsrch_close;

    // The database type and function pointers will need to be set 
    // by the "derived class" caller these things vary by database type.
    hdb_binsrch_info->base.db_type = TSK_HDB_DBTYPE_INVALID_ID;
    hdb_binsrch_info->base.make_index = NULL;
    hdb_binsrch_info->get_entry = NULL;

    // Some text hash database types support indexes for more than one hash 
    // type, so setting the hash type and length are deferred until the desired 
    // index is created/opened.
    hdb_binsrch_info->hash_type = TSK_HDB_HTYPE_INVALID_ID; 
    hdb_binsrch_info->hash_len = 0; 

    return hdb_binsrch_info;    
}

/** \internal
* Setup the hash-type specific information (such as length, index entry
* sizes, index name etc.) in the HDB_INFO structure.
*
* @param hdb_info Structure to fill in.
* @param htype Hash type being used
* @return 1 on error and 0 on success
*/
static uint8_t
    hdb_binsrch_idx_init_hash_type_info(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info, TSK_HDB_HTYPE_ENUM htype)
{
    if (hdb_binsrch_info->hash_type != TSK_HDB_HTYPE_INVALID_ID) {
        return 0;
    }

    /* Make the name for the index file */
    size_t flen = TSTRLEN(hdb_binsrch_info->base.db_fname) + 32;
    hdb_binsrch_info->idx_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_binsrch_info->idx_fname == NULL) {
        return 1;
    }

    /* Make the name for the index of the index file */
    hdb_binsrch_info->idx_idx_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_binsrch_info->idx_idx_fname == NULL) {
        return 1;
    }

    /* Set hash type specific information */
    switch (htype) {
    case TSK_HDB_HTYPE_MD5_ID:
        hdb_binsrch_info->hash_type = htype;
        hdb_binsrch_info->hash_len = TSK_HDB_HTYPE_MD5_LEN;
        TSNPRINTF(hdb_binsrch_info->idx_fname, flen,
            _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
            hdb_binsrch_info->base.db_fname, TSK_HDB_HTYPE_MD5_STR);
        TSNPRINTF(hdb_binsrch_info->idx_idx_fname, flen,
            _TSK_T("%s-%") PRIcTSK _TSK_T(".idx2"),
            hdb_binsrch_info->base.db_fname, TSK_HDB_HTYPE_MD5_STR);
        return 0;
    case TSK_HDB_HTYPE_SHA1_ID:
        hdb_binsrch_info->hash_type = htype;
        hdb_binsrch_info->hash_len = TSK_HDB_HTYPE_SHA1_LEN;
        TSNPRINTF(hdb_binsrch_info->idx_fname, flen,
            _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
            hdb_binsrch_info->base.db_fname, TSK_HDB_HTYPE_SHA1_STR);
        TSNPRINTF(hdb_binsrch_info->idx_idx_fname, flen,
            _TSK_T("%s-%") PRIcTSK _TSK_T(".idx2"),
            hdb_binsrch_info->base.db_fname, TSK_HDB_HTYPE_SHA1_STR);
        return 0;

        // listed to prevent compiler warnings
    case TSK_HDB_HTYPE_INVALID_ID:
    case TSK_HDB_HTYPE_SHA2_256_ID:
    default:
        break;
    }

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
        "hdb_binsrch_idx_init_hash_type_info: Invalid hash type as argument: %d", htype);
    return 1;
}

uint8_t
    hdb_binsrch_uses_external_indexes()
{
    return 1;
}

const TSK_TCHAR*
    hdb_binsrch_get_index_path(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    if (hdb_binsrch_open_idx(hdb_info, htype)) {
        return NULL;
    }
    else {
        TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info;
        return hdb_binsrch_info->idx_fname;
    }
}

uint8_t
    hdb_binsrch_has_index(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    if (hdb_binsrch_open_idx(hdb_info, htype)) {
        return 0;
    }
    else {
        return 1;
    }
}

static uint8_t
    hdb_binsrch_load_index_offsets(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info) 
{
    const char *func_name = "hdb_binsrch_load_index_offsets";

    if (!hdb_binsrch_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("%s: TSK_HDB_BINSRCH_INFO* is NULL", func_name);
        return 1;
    }

    if (!hdb_binsrch_info->idx_idx_fname) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("%s: hdb_binsrch_info->idx_idx_fname is NULL", func_name);
        return 1;
    }

    // Attempt to open the file that contains the index of the index.
    // For older text-format hash databases, this additional index may 
    // not exist, and that's o.k., lookups will just be slower.
    FILE *idx_idx_file = NULL;
    TSK_OFF_T idx_idx_size = 0;
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        if (-1 == GetFileAttributes(hdb_binsrch_info->idx_idx_fname)) {
            // The file does not exist. Not a problem.
            return 0;
        }

        if ((hWin = CreateFile(hdb_binsrch_info->idx_idx_fname, GENERIC_READ,
            FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
            INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                    "%s: error opening index of index: %" PRIttocTSK" - %d",
                    func_name, hdb_binsrch_info->idx_idx_fname, (int)GetLastError());
                return 1;
        }

        idx_idx_file =_fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "rb");
        if (!idx_idx_file) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "%s: error converting file handle from Windows to C for: %" PRIttocTSK, 
                func_name, hdb_binsrch_info->idx_idx_fname);
            return 1;
        }

        DWORD szHi = 0;
        DWORD szLow = GetFileSize(hWin, &szHi);
        if (szLow == 0xffffffff) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "%s: error getting size of index of index file: %" PRIttocTSK" - %d",
                func_name, hdb_binsrch_info->idx_idx_fname, (int)GetLastError());
            return 1;
        }
        idx_idx_size = szLow | ((uint64_t) szHi << 32);
    }
#else
    {
        struct stat sb;
        if (stat(hdb_binsrch_info->idx_idx_fname, &sb) < 0) {
            // The file does not exist. Not a problem.
            return 0;
        }
        idx_idx_size = sb.st_size;

        if (NULL == (idx_idx_file = fopen(hdb_binsrch_info->idx_idx_fname, "rb"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "%s: error opening index of index: %" PRIttocTSK,
                func_name, hdb_binsrch_info->idx_idx_fname);
            return 1;
        }
    }
#endif

    // Read the stored mapping of initial hash digits to offsets in the index file
    // into memory. The mapping is for the first three digits of the hashes 
    // (three nibbles), so there are 2 ^ 12 or 4096 possible entries.
    if (IDX_IDX_SIZE != idx_idx_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("%s: index of index is wrong size", func_name);
        return 1;
    }

    hdb_binsrch_info->idx_offsets = (uint64_t*)tsk_malloc(IDX_IDX_SIZE);
    if (NULL == hdb_binsrch_info->idx_offsets) {
        return 1;
    }

    if (1 != fread((void*)hdb_binsrch_info->idx_offsets, IDX_IDX_SIZE, 1, idx_idx_file)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_OPEN);
        tsk_error_set_errstr("%s: error reading index of index", func_name);
        return 1;
    }
    fclose(idx_idx_file);

    return 0;
}

/** \internal
* Setup the internal variables to read an index. This
* opens the index and sets the needed size information.
*
* @param hdb_info Hash database to analyze
* @param hash The hash type that was used to make the index.
*
* @return 1 on error and 0 on success
*/
static uint8_t 
    hdb_binsrch_open_idx_file(TSK_HDB_INFO *hdb_info_base, TSK_HDB_HTYPE_ENUM htype)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info_base; 
    char head[TSK_HDB_MAXLEN];
    char head2[TSK_HDB_MAXLEN];
    char *ptr;

    if ((htype != TSK_HDB_HTYPE_MD5_ID)
        && (htype != TSK_HDB_HTYPE_SHA1_ID)) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Invalid hash type : %d", htype);
            return 1;
    }

    if (hdb_binsrch_idx_init_hash_type_info(hdb_binsrch_info, htype)) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        return 1;
    }

    /* Verify the index exists, get its size, and open it */
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        DWORD szLow, szHi;

        if (-1 == GetFileAttributes(hdb_binsrch_info->idx_fname)) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error finding index file: %" PRIttocTSK,
                hdb_binsrch_info->idx_fname);
            return 1;
        }

        if ((hWin = CreateFile(hdb_binsrch_info->idx_fname, GENERIC_READ,
            FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
            INVALID_HANDLE_VALUE) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_OPEN);
                tsk_error_set_errstr(
                    "hdb_binsrch_open_idx: Error opening index file: %" PRIttocTSK,
                    hdb_binsrch_info->idx_fname);
                return 1;
        }
        hdb_binsrch_info->hIdx =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
        if (hdb_binsrch_info->hIdx == NULL) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error converting Windows handle to C handle");
            return 1;
        }

        szLow = GetFileSize(hWin, &szHi);
        if (szLow == 0xffffffff) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error getting size of index file: %" PRIttocTSK" - %d",
                hdb_binsrch_info->idx_fname, (int)GetLastError());
            return 1;
        }
        hdb_binsrch_info->idx_size = szLow | ((uint64_t) szHi << 32);
    }

#else
    {
        struct stat sb;
        if (stat(hdb_binsrch_info->idx_fname, &sb) < 0) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error finding index file: %s",
                hdb_binsrch_info->idx_fname);
            return 1;
        }
        hdb_binsrch_info->idx_size = sb.st_size;

        if (NULL == (hdb_binsrch_info->hIdx = fopen(hdb_binsrch_info->idx_fname, "r"))) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error opening index file: %s",
                hdb_binsrch_info->idx_fname);
            return 1;
        }
    }
#endif

    /* Do some testing on the first line */
    if (NULL == fgets(head, TSK_HDB_MAXLEN, hdb_binsrch_info->hIdx)) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
            "hdb_binsrch_open_idx_file: Header line of index file");
        return 1;
    }

    if (strncmp(head, TSK_HDB_IDX_HEAD_TYPE_STR, strlen(TSK_HDB_IDX_HEAD_TYPE_STR))
        != 0) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Invalid index file: Missing header line");
            return 1;
    }

    /* Do some testing on the second line */
    if (NULL == fgets(head2, TSK_HDB_MAXLEN, hdb_binsrch_info->hIdx)) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
            "hdb_binsrch_open_idx_file: Error reading line 2 of index file");
        return 1;
    }

    /* Set the offset to the start of the index entries */
    if (strncmp(head2, TSK_HDB_IDX_HEAD_NAME_STR, strlen(TSK_HDB_IDX_HEAD_NAME_STR))
        != 0) {
            hdb_binsrch_info->idx_off = (uint16_t) (strlen(head));
    } else {
        hdb_binsrch_info->idx_off = (uint16_t) (strlen(head) + strlen(head2));
    }


    /* Skip the pipe symbol */
    ptr = &head[strlen(TSK_HDB_IDX_HEAD_TYPE_STR) + 1];

    /* Set the line length consistent with the hash type and the newline representation in the file.*/
    hdb_binsrch_info->idx_llen = TSK_HDB_IDX_LEN(htype);
    ptr[strlen(ptr) - 1] = '\0';
    if ((ptr[strlen(ptr) - 1] == 10) || (ptr[strlen(ptr) - 1] == 13)) {
        ptr[strlen(ptr) - 1] = '\0';
        hdb_binsrch_info->idx_llen++;
    }

    /* Verify the header value in the index */
    if (strcmp(ptr, TSK_HDB_DBTYPE_NSRL_STR) == 0) {
        if ((hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_NSRL_ID) &&
            (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                    "hdb_binsrch_open_idx_file: DB detected as %s, index type has NSRL",
                    ptr);
                return 1;
        }
    }
    else if (strcmp(ptr, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if ((hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_MD5SUM_ID) &&
            (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                    "hdb_binsrch_open_idx_file: DB detected as %s, index type has MD5SUM",
                    ptr);
                return 1;
        }
    }
    else if (strcmp(ptr, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if ((hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_HK_ID) &&
            (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                    "hdb_binsrch_open_idx_file: DB detected as %s, index type has hashkeeper",
                    ptr);
                return 1;
        }
    }
    else if (strcmp(ptr, TSK_HDB_DBTYPE_ENCASE_STR) == 0) {
        if ((hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_ENCASE_ID) &&
            (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
                tsk_error_set_errstr(
                    "hdb_binsrch_open_idx_file: DB detected as %s, index type has EnCase",
                    ptr);
                return 1;
        }
    }
    else if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_IDXONLY_ID) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
        tsk_error_set_errstr(
            "hdb_binsrch_open_idx_file: Unknown Database Type in index header: %s",
            ptr);
        return 1;
    }

    /* Do some sanity checking */
    if (((hdb_binsrch_info->idx_size - hdb_binsrch_info->idx_off) % hdb_binsrch_info->idx_llen) !=
        0) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                "hdb_binsrch_open_idx_file: Error, size of index file is not a multiple of row size");
            return 1;
    }

    /* allocate a buffer for a row */
    if ((hdb_binsrch_info->idx_lbuf = (char*)tsk_malloc(hdb_binsrch_info->idx_llen + 1)) == NULL) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        return 1;
    }

    return 0;
}

/** \internal
* Opens and index file and loads the index of the index file into memory.
*
* @param hdb_info Hash database to analyze
* @param hash The hash type that was used to make the index.
*
* @return 1 on error and 0 on success
*/
uint8_t
    hdb_binsrch_open_idx(TSK_HDB_INFO *hdb_info_base, TSK_HDB_HTYPE_ENUM htype)
{
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info_base; 

    // Lock for lazy load of hIdx and lazy alloc of idx_lbuf.
    tsk_take_lock(&hdb_binsrch_info->base.lock);

    // if it is already open, bail out
    if (hdb_binsrch_info->hIdx != NULL) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        return 0;
    }

    if (hdb_binsrch_open_idx_file(hdb_info_base, htype))
    {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("hdb_binsrch_open_idx: unable to open index file");
        return 1;
    }

    /* To speed up lookups, a mapping of the first three bytes of a hash to
     * an offset in the index file will be loaded into memory, if available. */
    if (hdb_binsrch_load_index_offsets(hdb_binsrch_info)) {
        tsk_release_lock(&hdb_binsrch_info->base.lock);
        return 1;
    }

    tsk_release_lock(&hdb_binsrch_info->base.lock);

    return 0;
}

/** Initialize the TSK hash DB index file. This creates the intermediate file,
* which will have entries added to it.  This file must be sorted before the 
* process is finished.
*
* @param hdb_binsrch_info Hash database state structure
* @param htype String of index type to create
*
* @return 1 on error and 0 on success
*
*/
uint8_t
    hdb_binsrch_idx_initialize(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info, TSK_TCHAR *htype)
{
    const char *func_name = "hdb_binsrch_idx_init";
    TSK_HDB_HTYPE_ENUM hash_type = TSK_HDB_HTYPE_INVALID_ID;
    size_t flen = 0;
    char dbtmp[32];
    int i = 0;

    /* Use the string of the index/hash type to figure out some
    * settings */

    // convert to char -- cheating way to deal with WCHARs..
    for (i = 0; i < 31 && htype[i] != '\0'; i++) {
        dbtmp[i] = (char) htype[i];
    }
    dbtmp[i] = '\0';

    if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_MD5_STR) == 0) {

        if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: database detected as: %d index creation as: %d",
                func_name, hdb_binsrch_info->base.db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_SHA1_STR) == 0) {
        if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: database detected as: %d index creation as: %d",
                func_name, hdb_binsrch_info->base.db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        hash_type = TSK_HDB_HTYPE_SHA1_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_MD5SUM_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: database detected as: %d index creation as: %d",
                func_name, hdb_binsrch_info->base.db_type, TSK_HDB_DBTYPE_MD5SUM_ID);
            return 1;
        }
        hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_HK_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: database detected as: %d index creation as: %d",
                func_name, hdb_binsrch_info->base.db_type, TSK_HDB_DBTYPE_HK_ID);
            return 1;
        }
        hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_ENCASE_STR) == 0) {
        if (hdb_binsrch_info->base.db_type != TSK_HDB_DBTYPE_ENCASE_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: database detected as: %d index creation as: %d",
                func_name, hdb_binsrch_info->base.db_type, TSK_HDB_DBTYPE_ENCASE_ID);
            return 1;
        }
        hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "%s: Unknown database/hash type request: %s",
            func_name, dbtmp);
        return 1;
    }

    /* Setup the internal hash information */
    if (hdb_binsrch_idx_init_hash_type_info(hdb_binsrch_info, hash_type)) {
        return 1;
    }

    /* Make the name for the unsorted intermediate index file */
    flen = TSTRLEN(hdb_binsrch_info->base.db_fname) + 32;
    hdb_binsrch_info->uns_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_binsrch_info->uns_fname == NULL) {
        return 1;
    }
    TSNPRINTF(hdb_binsrch_info->uns_fname, flen,
        _TSK_T("%s-%") PRIcTSK _TSK_T("-ns.idx"), hdb_binsrch_info->base.db_fname,
        TSK_HDB_HTYPE_STR(hdb_binsrch_info->hash_type));


    /* Create temp unsorted file of offsets */
#ifdef TSK_WIN32
    {
        HANDLE hWin;

        if ((hWin = CreateFile(hdb_binsrch_info->uns_fname, GENERIC_WRITE,
            0, 0, CREATE_ALWAYS, 0, 0)) ==
            INVALID_HANDLE_VALUE) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CREATE);
                tsk_error_set_errstr(
                    "%s: %" PRIttocTSK" GetFileSize: %d",
                    func_name, hdb_binsrch_info->uns_fname, (int)GetLastError());
                return 1;
        }

        hdb_binsrch_info->hIdxTmp =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_WRONLY), "wb");
        if (hdb_binsrch_info->hIdxTmp == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "%s: Error converting Windows handle to C handle", func_name);
            return 1;
        }
    }
#else
    if (NULL == (hdb_binsrch_info->hIdxTmp = fopen(hdb_binsrch_info->uns_fname, "w"))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CREATE);
        tsk_error_set_errstr(
            "%s: Error creating temp index file: %s",
            func_name, hdb_binsrch_info->uns_fname);
        return 1;
    }
#endif

    /* Print the header */
    fprintf(hdb_binsrch_info->hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_NAME_STR,
        hdb_binsrch_info->base.db_name);
    switch (hdb_binsrch_info->base.db_type) {
    case TSK_HDB_DBTYPE_NSRL_ID:
        fprintf(hdb_binsrch_info->hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_NSRL_STR);
        break;
    case TSK_HDB_DBTYPE_MD5SUM_ID:
        fprintf(hdb_binsrch_info->hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_MD5SUM_STR);
        break;
    case TSK_HDB_DBTYPE_HK_ID:
        fprintf(hdb_binsrch_info->hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_HK_STR);
        break;
    case TSK_HDB_DBTYPE_ENCASE_ID:
        fprintf(hdb_binsrch_info->hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_ENCASE_STR);
        break;
        /* Used to stop warning messages about missing enum value */
    case TSK_HDB_DBTYPE_IDXONLY_ID:
    default:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CREATE);
        tsk_error_set_errstr("%s: Invalid db type", func_name);
        return 1;
    }

    return 0;
}

/**
* Add a string entry to the intermediate index file.
*
* @param hdb_binsrch_info Hash database state info
* @param hvalue String of hash value to add
* @param offset Byte offset of hash entry in original database.
* @return 1 on error and 0 on success
*/
uint8_t
    hdb_binsrch_idx_add_entry_str(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info, char *hvalue, TSK_OFF_T offset)
{
    int i;

    // make the hashes all upper case
    for (i = 0; hvalue[i] != '\0'; i++) {
        if (islower((int) hvalue[i]))
            fprintf(hdb_binsrch_info->hIdxTmp, "%c", toupper((int) hvalue[i]));
        else
            fprintf(hdb_binsrch_info->hIdxTmp, "%c", hvalue[i]);
    }

    /* Print the entry to the unsorted index file */
    fprintf(hdb_binsrch_info->hIdxTmp, "|%.16llu\n", (unsigned long long) offset);

    return 0;
}

/**
* Add a binary entry to the intermediate index file.
*
* @param hdb_binsrch_info Hash database state info
* @param hvalue Array of integers of hash value to add
* @param hlen Number of bytes in hvalue
* @param offset Byte offset of hash entry in original database.
* @return 1 on error and 0 on success
*/
uint8_t
    hdb_binsrch_idx_add_entry_bin(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info, unsigned char *hvalue, int hlen, TSK_OFF_T offset)
{
    int i;

    for (i = 0; i < hlen; i++) {
        fprintf(hdb_binsrch_info->hIdxTmp, "%02X", hvalue[i]);
    }

    /* Print the entry to the unsorted index file */
    fprintf(hdb_binsrch_info->hIdxTmp, "|%.16llu\n", (unsigned long long) offset);

    return 0;
}

static uint8_t
    hdb_binsrch_make_idx_idx(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info)
{
    const char *func_name = "hdb_binsrch_make_idx_idx";

    if (!hdb_binsrch_info) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("%s: TSK_HDB_BINSRCH_INFO* is NULL", func_name);
        return 1;
    }

    if (!hdb_binsrch_info->idx_idx_fname) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("%s: hdb_binsrch_info->idx_idx_fname is NULL", func_name);
        return 1;
    }

    // Open the index file. This will read past the header, so the file
    // pointer will be positioned at the offset of the first hash line
    // in the index file. 
    if (hdb_binsrch_open_idx_file(&(hdb_binsrch_info->base), hdb_binsrch_info->hash_type)) {
        // error message was already set.
        return 1;
    }

    // Create the file for the index of the index file.
    FILE *idx_idx_file = NULL;
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        if ((hWin = CreateFile(hdb_binsrch_info->idx_idx_fname, GENERIC_WRITE,
            0, 0, CREATE_ALWAYS, 0, 0)) == INVALID_HANDLE_VALUE) {
                int winErrNo = (int)GetLastError();
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CREATE);
                tsk_error_set_errstr(
                    "%s: error creating index of index file %" PRIttocTSK" - %d)",
                    func_name, hdb_binsrch_info->idx_idx_fname, winErrNo);
                return 1;
        }

        idx_idx_file =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_WRONLY), "wb");
        if (idx_idx_file == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                "%s: error converting file handle from Windows to C for: %" PRIttocTSK, 
                func_name, hdb_binsrch_info->idx_idx_fname);
            return 1;
        }
    }
#else
    if (NULL == (idx_idx_file = fopen(hdb_binsrch_info->idx_idx_fname, "wb"))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CREATE);
        tsk_error_set_errstr(
            "%s: error creating index of index file %" PRIttocTSK,
            func_name, hdb_binsrch_info->idx_idx_fname);
        return 1;
    }
#endif

    // Allocate an array to hold the starting offsets in the index file for each 
    // set of hashes with identical initial (3) nibbles.
    hdb_binsrch_info->idx_offsets = (uint64_t*)tsk_malloc(IDX_IDX_SIZE);
    if (NULL == hdb_binsrch_info->idx_offsets) {
        return 1;
    }
    memset(hdb_binsrch_info->idx_offsets, 0xFF, IDX_IDX_SIZE);

    // Populate the array. Note that the index is sorted, so the first
    // occurence of any nibble indicates the starting offset for the
    // corresponding set.
    TSK_OFF_T idx_off = hdb_binsrch_info->idx_off;
    char digits[4];
    digits[3] = '\0';
    long int offsets_idx = 0;
    while (fgets(hdb_binsrch_info->idx_lbuf, (int)hdb_binsrch_info->idx_llen + 1, hdb_binsrch_info->hIdx)) {
        strncpy(digits, hdb_binsrch_info->idx_lbuf, 3);		
        offsets_idx = strtol(digits, NULL, 16);
        if (hdb_binsrch_info->idx_offsets[offsets_idx] == IDX_IDX_ENTRY_NOT_SET) {
            hdb_binsrch_info->idx_offsets[offsets_idx] = idx_off;
        }
        idx_off += hdb_binsrch_info->idx_llen;
    }

    // Write the array to the index of the index file so that it 
    // can be reloaded into memory the next time the index is opened.
    uint8_t ret_val = (1 == fwrite((const void*)hdb_binsrch_info->idx_offsets, IDX_IDX_SIZE, 1, idx_idx_file)) ? 0 : 1; 
    fclose(idx_idx_file);

    return ret_val;
}

/**
* Finalize index creation process by sorting the index and removing the
* intermediate temp file.
*
* @param hdb_binsrch_info Hash database state info structure.
* @return 1 on error and 0 on success
*/
uint8_t
    hdb_binsrch_idx_finalize(TSK_HDB_BINSRCH_INFO *hdb_binsrch_info)
{
    /* Close the unsorted file */
    fclose(hdb_binsrch_info->hIdxTmp);
    hdb_binsrch_info->hIdxTmp = NULL;

    /* Close the existing index if it is open, and unset the old index file data. */
    if (hdb_binsrch_info->hIdx) {
        fclose(hdb_binsrch_info->hIdx);
        hdb_binsrch_info->hIdx = NULL;
    }
    hdb_binsrch_info->idx_size = 0;
    hdb_binsrch_info->idx_off = 0;
    hdb_binsrch_info->idx_llen = 0;
    if (hdb_binsrch_info->idx_lbuf != NULL)
    {
        free(hdb_binsrch_info->idx_lbuf);
        hdb_binsrch_info->idx_lbuf = NULL;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hdb_idxfinalize: Sorting index\n");

#ifdef TSK_WIN32
    wchar_t buf[TSK_HDB_MAXLEN];
    /// @@ Expand this to be SYSTEM_ROOT -- GetWindowsDirectory()
    wchar_t *sys32 = _TSK_T("C:\\WINDOWS\\System32\\sort.exe");
    DWORD stat;
    STARTUPINFO myStartInfo;
    PROCESS_INFORMATION pinfo;

    stat = GetFileAttributes(sys32);
    if ((stat != -1) && ((stat & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
        TSNPRINTF(buf, TSK_HDB_MAXLEN, _TSK_T("%s /o \"%s\" \"%s\""),
            sys32, hdb_binsrch_info->idx_fname, hdb_binsrch_info->uns_fname);
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_MISSING);
        tsk_error_set_errstr("Cannot find sort executable");
        return 1;
    }

    GetStartupInfo(&myStartInfo);

    if (FALSE ==
        CreateProcess(NULL, buf, NULL, NULL, FALSE, 0, NULL, NULL,
        &myStartInfo, &pinfo)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_PROC);
            tsk_error_set_errstr(
                "Error starting sorting index file using %S", buf);
            return 1;
    }

    if (WAIT_FAILED == WaitForSingleObject(pinfo.hProcess, INFINITE)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_PROC);
        tsk_error_set_errstr(
            "Error (waiting) sorting index file using %S", buf);
        return 1;
    }

    if (FALSE == DeleteFile(hdb_binsrch_info->uns_fname)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_DELETE);
        tsk_error_set_errstr(
            "Error deleting temp file: %d", (int)GetLastError());
        return 1;
    }

    // verify it was created
    stat = GetFileAttributes(hdb_binsrch_info->idx_fname);
    if (stat == -1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_PROC);
        tsk_error_set_errstr("hdb_binsrch_finalize: sorted file not created");
        return 1;
    }

#else
    char buf[TSK_HDB_MAXLEN];
    const char *root = "/bin/sort";
    const char *usr = "/usr/bin/sort";
    const char *local = "/usr/local/bin/sort";
    struct stat stats;

    if (0 == stat(local, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o %s %s", local,
            hdb_binsrch_info->idx_fname, hdb_binsrch_info->uns_fname);
    }
    else if (0 == stat(usr, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o \"%s\" \"%s\"",
            usr, hdb_binsrch_info->idx_fname, hdb_binsrch_info->uns_fname);
    }
    else if (0 == stat(root, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o \"%s\" \"%s\"",
            root, hdb_binsrch_info->idx_fname, hdb_binsrch_info->uns_fname);
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_MISSING);
        tsk_error_set_errstr("Cannot find sort executable");
        return 1;
    }

    if (0 != system(buf)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_PROC);
        tsk_error_set_errstr(
            "Error sorting index file using %s", buf);
        return 1;
    }

    unlink(hdb_binsrch_info->uns_fname);
    if (stat(hdb_binsrch_info->idx_fname, &stats)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_PROC);
        tsk_error_set_errstr("hdb_binsrch_finalize: sorted file not created");
        return 1;
    }
#endif

    // To speed up lookups, create a mapping of the first three bytes of a hash 
    // to an offset in the index file.	
    if (hdb_binsrch_make_idx_idx(hdb_binsrch_info)) {
        tsk_error_set_errstr2(
            "hdb_binsrch_idx_finalize: error creating index of index file");
        return 1;
    }

    return 0;
}

/**
* \ingroup hashdblib
* Search the index for a text/ASCII hash value
*
* @param hdb_info_base Open hash database (with index)
* @param hash Hash value to search for (NULL terminated string)
* @param flags Flags to use in lookup
* @param action Callback function to call for each hash db entry 
* (not called if QUICK flag is given)
* @param ptr Pointer to data to pass to each callback
*
* @return -1 on error, 0 if hash value not found, and 1 if value was found.
*/
int8_t
    hdb_binsrch_lookup_str(TSK_HDB_INFO * hdb_info_base, const char *hash,
    TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action,
    void *ptr)
{
    const char *func_name = "hdb_binsrch_lookup_str";
    TSK_HDB_BINSRCH_INFO *hdb_binsrch_info = (TSK_HDB_BINSRCH_INFO*)hdb_info_base; 
    TSK_OFF_T poffset;
    TSK_OFF_T up;               // Offset of the first byte past the upper limit that we are looking in
    TSK_OFF_T low;              // offset of the first byte of the lower limit that we are looking in
    int cmp;
    uint8_t wasFound = 0;
    size_t i;
    TSK_HDB_HTYPE_ENUM htype;
    char ucHash[TSK_HDB_HTYPE_SHA1_LEN + 1]; // Set to the longest hash length + 1

    /* Sanity checks on the hash input */
    if (strlen(hash) == TSK_HDB_HTYPE_MD5_LEN) {
        htype = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (strlen(hash) == TSK_HDB_HTYPE_SHA1_LEN) {
        htype = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "%s: Invalid hash length: %s", func_name, hash);
        return -1;
    }

    for (i = 0; i < strlen(hash); i++) {
        if (isxdigit((int) hash[i]) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: Invalid hash value (hex only): %s",
                func_name, hash);
            return -1;
        }
    }

    // verify the index is open
    if (hdb_binsrch_open_idx(hdb_info_base, htype))
        return -1;

    /* Sanity check */
    if (hdb_binsrch_info->hash_len != strlen(hash)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "%s: Hash passed is different size than expected (%d vs %Zd)",
            func_name, hdb_binsrch_info->hash_len, strlen(hash));
        return -1;
    }

    // Convert hash to uppercase
    for(i = 0;i < strlen(hash);i++){
        if(islower(hash[i])){
            ucHash[i] = toupper(hash[i]);
        }
        else{
            ucHash[i] = hash[i];
        }
    }
    ucHash[strlen(hash)] = '\0';

    // Do a lookup in the index of the index file. The index of the index file is
    // a mapping of the first three digits of a hash to the offset in the index
    // file of the first index entry of the possibly empty set of index entries 
    // for hashes with those initial digits.
    if (hdb_binsrch_info->idx_offsets) {
        // Convert the initial hash digits into an index into the index offsets.
        // This will give the offset into the index file for the set of hashes
        // that contains the sought hash.
        char digits[4];
        strncpy(digits, ucHash, 3);
        digits[3] = '\0';
        long int idx_idx_off = strtol(digits, NULL, 16);
        if ((idx_idx_off < 0) || (idx_idx_off > (long int)IDX_IDX_ENTRY_COUNT)) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                "%s: error finding index in secondary index for %s", func_name, ucHash);
            return -1;
        }

        // Determine the bounds for the binary search of the sorted index file.
        // The lower bound is the start of the set of entries that may contain
        // the sought hash. The upper bound is the offset one past the end
        // of that entry set, or EOF.
        low = hdb_binsrch_info->idx_offsets[idx_idx_off];
        if (IDX_IDX_ENTRY_NOT_SET != (uint64_t)low) {
            do {
                ++idx_idx_off;
                if (idx_idx_off == (long int)IDX_IDX_ENTRY_COUNT) {
                    // The set of hashes to search is the last set. Use the end of the index
                    // file as the upper bound for the binary search.
                    up = hdb_binsrch_info->idx_size;
                    break;
                }
                else {
                    up = hdb_binsrch_info->idx_offsets[idx_idx_off];
                }
            } while (IDX_IDX_ENTRY_NOT_SET == (uint64_t)up);
        }
        else {
            // Quick out - the hash does not map to an index offset.
            // It is not in the hash database.
            return 0;
        }
    }
    else {
        // There is no index for the index file. Search the entire file.
        low = hdb_binsrch_info->idx_off;
        up = hdb_binsrch_info->idx_size;
    }

    poffset = 0;

    // We have to lock access to idx_lbuf, but since we're in a loop,
    // I'm assuming one lock up front is better than many inside.
    tsk_take_lock(&hdb_binsrch_info->base.lock);

    while (1) {
        TSK_OFF_T offset;

        /* If top and bottom are the same, it's not there */
        if (up == low) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            return 0;
        }

        /* Get the middle of the windows that we are looking at */
        offset = rounddown(((up - low) / 2), hdb_binsrch_info->idx_llen);

        /* Sanity Check */
        if ((offset % hdb_binsrch_info->idx_llen) != 0) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                "hdb_lookup: Error, new offset is not a multiple of the line length");
            return -1;
        }

        /* The middle offset is relative to the low offset, so add them */
        offset += low;

        /* If we didn't move, then it's not there */
        if (poffset == offset) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            return 0;
        }

        /* Seek to the offset and read it */
        if (0 != fseeko(hdb_binsrch_info->hIdx, offset, SEEK_SET)) {
            tsk_release_lock(&hdb_binsrch_info->base.lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
            tsk_error_set_errstr(
                "hdb_lookup: Error seeking in search: %" PRIuOFF,
                offset);
            return -1;
        }

        if (NULL ==
            fgets(hdb_binsrch_info->idx_lbuf, (int) hdb_binsrch_info->idx_llen + 1,
            hdb_binsrch_info->hIdx)) {
                if (feof(hdb_binsrch_info->hIdx)) {
                    tsk_release_lock(&hdb_binsrch_info->base.lock);
                    return 0;
                }
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                tsk_error_set_errstr(
                    "Error reading index file: %lu",
                    (unsigned long) offset);
                return -1;
        }

        /* Sanity Check */
        if ((strlen(hdb_binsrch_info->idx_lbuf) < hdb_binsrch_info->idx_llen) ||
            (hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len] != '|')) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                tsk_error_set_errstr(
                    "Invalid line in index file: %lu (%s)",
                    (unsigned long) (offset / hdb_binsrch_info->idx_llen),
                    hdb_binsrch_info->idx_lbuf);
                return -1;
        }

        /* Set the delimiter to NULL so we can treat the hash as a string */
        hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len] = '\0';
        cmp = strcasecmp(hdb_binsrch_info->idx_lbuf, ucHash);

        /* The one we just read is too small, so set the new lower bound
        * at the start of the next row */
        if (cmp < 0) {
            low = offset + hdb_binsrch_info->idx_llen;
        }

        /* The one we just read is too big, so set the upper bound at this
        * entry */
        else if (cmp > 0) {
            up = offset;
        }

        /* We found it */
        else {
            wasFound = 1;

            if (flags & TSK_HDB_FLAG_QUICK) {
                tsk_release_lock(&hdb_binsrch_info->base.lock);
                return 1;
            }
            else {
                TSK_OFF_T tmpoff, db_off;

#ifdef TSK_WIN32
                db_off =
                    _atoi64(&hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len + 1]);
#else
                db_off =
                    strtoull(&hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len + 1],
                    NULL, 10);
#endif

                /* Print the one that we found first */
                if (hdb_binsrch_info->
                    get_entry(hdb_info_base, ucHash, db_off, flags, action, ptr)) {
                        tsk_release_lock(&hdb_binsrch_info->base.lock);
                        tsk_error_set_errstr2( "hdb_lookup");
                        return -1;
                }


                /* there could be additional entries both before and after
                * this entry - but we can restrict ourselves to the up
                * and low bounds from our previous hunting 
                */

                tmpoff = offset - hdb_binsrch_info->idx_llen;
                while (tmpoff >= low) {

                    /* Break if we are at the header */
                    if (tmpoff <= 0)
                        break;

                    if (0 != fseeko(hdb_binsrch_info->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_binsrch_info->base.lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                            "hdb_lookup: Error seeking for prev entries: %"
                            PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(hdb_binsrch_info->idx_lbuf,
                        (int) hdb_binsrch_info->idx_llen + 1,
                        hdb_binsrch_info->hIdx)) {
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                            tsk_error_set_errstr(
                                "Error reading index file (prev): %lu",
                                (unsigned long) tmpoff);
                            return -1;
                    }
                    else if (strlen(hdb_binsrch_info->idx_lbuf) <
                        hdb_binsrch_info->idx_llen) {
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                            tsk_error_set_errstr(
                                "Invalid index file line (prev): %lu",
                                (unsigned long) tmpoff);
                            return -1;
                    }

                    hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len] = '\0';
                    if (strcasecmp(hdb_binsrch_info->idx_lbuf, ucHash) != 0) {
                        break;
                    }

#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&hdb_binsrch_info->
                        idx_lbuf[hdb_binsrch_info->hash_len + 1]);
#else

                    db_off =
                        strtoull(&hdb_binsrch_info->
                        idx_lbuf[hdb_binsrch_info->hash_len + 1], NULL,
                        10);
#endif
                    if (hdb_binsrch_info->
                        get_entry(hdb_info_base, ucHash, db_off, flags, action,
                        ptr)) {
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            return -1;
                    }
                    tmpoff -= hdb_binsrch_info->idx_llen;
                }

                /* next entries */
                tmpoff = offset + hdb_binsrch_info->idx_llen;
                while (tmpoff < up) {

                    if (0 != fseeko(hdb_binsrch_info->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_binsrch_info->base.lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                            "hdb_lookup: Error seeking for next entries: %"
                            PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(hdb_binsrch_info->idx_lbuf,
                        (int) hdb_binsrch_info->idx_llen + 1,
                        hdb_binsrch_info->hIdx)) {
                            if (feof(hdb_binsrch_info->hIdx))
                                break;
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                            tsk_error_set_errstr(
                                "Error reading index file (next): %lu",
                                (unsigned long) tmpoff);
                            return -1;
                    }
                    else if (strlen(hdb_binsrch_info->idx_lbuf) <
                        hdb_binsrch_info->idx_llen) {
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                            tsk_error_set_errstr(
                                "Invalid index file line (next): %lu",
                                (unsigned long) tmpoff);
                            return -1;
                    }

                    hdb_binsrch_info->idx_lbuf[hdb_binsrch_info->hash_len] = '\0';
                    if (strcasecmp(hdb_binsrch_info->idx_lbuf, ucHash) != 0) {
                        break;
                    }
#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&hdb_binsrch_info->
                        idx_lbuf[hdb_binsrch_info->hash_len + 1]);
#else
                    db_off =
                        strtoull(&hdb_binsrch_info->
                        idx_lbuf[hdb_binsrch_info->hash_len + 1], NULL,
                        10);
#endif
                    if (hdb_binsrch_info->
                        get_entry(hdb_info_base, ucHash, db_off, flags, action,
                        ptr)) {
                            tsk_release_lock(&hdb_binsrch_info->base.lock);
                            return -1;
                    }

                    tmpoff += hdb_binsrch_info->idx_llen;
                }
            }
            break;
        }
        poffset = offset;
    }
    tsk_release_lock(&hdb_binsrch_info->base.lock);

    return wasFound;
}

/**
* \ingroup hashdblib
* Search the index for the given hash value given (in binary form).
*
* @param hdb_info Open hash database (with index)
* @param hash Array with binary hash value to search for
* @param len Number of bytes in binary hash value
* @param flags Flags to use in lookup
* @param action Callback function to call for each hash db entry 
* (not called if QUICK flag is given)
* @param ptr Pointer to data to pass to each callback
*
* @return -1 on error, 0 if hash value not found, and 1 if value was found.
*/
int8_t
    hdb_binsrch_lookup_bin(TSK_HDB_INFO * hdb_info, uint8_t * hash, uint8_t len,
    TSK_HDB_FLAG_ENUM flags,
    TSK_HDB_LOOKUP_FN action, void *ptr)
{
    char hashbuf[TSK_HDB_HTYPE_SHA1_LEN + 1];
    int i;
    static const char hex[] = "0123456789abcdef";

    if (2 * len > TSK_HDB_HTYPE_SHA1_LEN) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
            "tsk_hdb_lookup_raw: hash value too long\n");
        return -1;
    }

    for (i = 0; i < len; i++) {
        hashbuf[2 * i] = hex[(hash[i] >> 4) & 0xf];
        hashbuf[2 * i + 1] = hex[hash[i] & 0xf];
    }
    hashbuf[2 * len] = '\0';

    return tsk_hdb_lookup_str(hdb_info, hashbuf, flags, action, ptr);
}

/**
* \ingroup hashdblib
* \internal 
* Looks up a hash and any additional data associated with the hash in a 
* hash database.
* @param hdb_info_base A struct representing an open hash database.
* @param hash A hash value in string form.
* @param result A TskHashInfo struct to populate on success.
* @return -1 on error, 0 if hash value was not found, 1 if hash value
* was found.
*/
int8_t 
    hdb_binsrch_lookup_verbose_str(TSK_HDB_INFO *hdb_info_base, const char *hash, void *lookup_result)
{
    // Verify the length of the hash value argument.
    TSK_HDB_HTYPE_ENUM hash_type = TSK_HDB_HTYPE_INVALID_ID;
    size_t hash_len = strlen(hash);
    if (TSK_HDB_HTYPE_MD5_LEN == hash_len) {
        hash_type = TSK_HDB_HTYPE_MD5_ID;
    }
    else if (TSK_HDB_HTYPE_SHA1_LEN == hash_len) {
        hash_type = TSK_HDB_HTYPE_SHA1_ID;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr("hdb_binsrch_lookup_verbose_str: invalid hash, length incorrect: %s", hash);
        return -1;
    }

    // Due to a bug in the extended lookup code for text-format hash databases,
    // do a simple yes/no look up until the bug is fixed.
    int8_t ret_val = hdb_binsrch_lookup_str(hdb_info_base, hash, TSK_HDB_FLAG_QUICK, NULL, NULL);
    if (1 == ret_val) {
        TskHashInfo *result = static_cast<TskHashInfo*>(lookup_result);
        if (TSK_HDB_HTYPE_MD5_ID == hash_type) {
            result->hashMd5 = hash;
        }
        else {
            result->hashSha1 = hash;
        }
    }
    return ret_val; 
}

uint8_t
    hdb_binsrch_accepts_updates()
{
    return 0;
}

void
    hdb_binsrch_close(TSK_HDB_INFO *hdb_info_base) 
{
    TSK_HDB_BINSRCH_INFO *hdb_info = (TSK_HDB_BINSRCH_INFO*)hdb_info_base;

    if (hdb_info->hDb) {
        fclose(hdb_info->hDb);
        hdb_info->hDb = NULL;
    }

    if (hdb_info->idx_fname) {
        free(hdb_info->idx_fname);
        hdb_info->idx_fname = NULL;
    }

    if (hdb_info->hIdx) {
        fclose(hdb_info->hIdx);
        hdb_info->hIdx = NULL;
    }

    if (hdb_info->hIdxTmp) {
        fclose(hdb_info->hIdxTmp);
        hdb_info->hIdxTmp = NULL;
    }

    if (hdb_info->uns_fname) {
        free(hdb_info->uns_fname);
        hdb_info->uns_fname = NULL;
    }

    if (hdb_info->idx_lbuf) {
        free(hdb_info->idx_lbuf);
        hdb_info->idx_lbuf = NULL;
    }

    if (hdb_info->idx_offsets) {
        free(hdb_info->idx_offsets);
        hdb_info->idx_offsets = NULL;
    }

    hdb_info_base_close(hdb_info_base);

    free(hdb_info);
}
