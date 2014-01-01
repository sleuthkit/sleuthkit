/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2014 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "tsk_hashdb_i.h"

/**
 * \file binsrch_index.c
 * Contains functions for creating a binary search / ASCII index and 
 * looking up values in it. 
 */

// RJCTODO: Rename
/**
 * Setup the hash-type specific information (such as length, index entry
 * sizes, index name etc.) in the HDB_INFO structure.
 *
 * @param hdb_info Structure to fill in.
 * @param htype Hash type being used
 * @return 1 on error and 0 on success
 */
static uint8_t
hdb_setuphash(TSK_HDB_INFO *hdb_info, TSK_HDB_HTYPE_ENUM htype)
{

    size_t flen = 0;

    if (hdb_info->hash_type != 0) {
        return 0;
    }

    /* Make the name for the index file */
    flen = TSTRLEN(hdb_info->db_fname) + 32;
    hdb_info->idx_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (hdb_info->idx_fname == NULL) {
        return 1;
    }

    /* Get hash type specific information */
    switch (htype) {
    case TSK_HDB_HTYPE_MD5_ID:
        hdb_info->hash_type = htype;
        hdb_info->hash_len = TSK_HDB_HTYPE_MD5_LEN;
        hdb_info->idx_llen = TSK_HDB_IDX_LEN(htype);
        TSNPRINTF(hdb_info->idx_fname, flen,
                  _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                  hdb_info->db_fname, TSK_HDB_HTYPE_MD5_STR);
        return 0;
    case TSK_HDB_HTYPE_SHA1_ID:
        hdb_info->hash_type = htype;
        hdb_info->hash_len = TSK_HDB_HTYPE_SHA1_LEN;
        hdb_info->idx_llen = TSK_HDB_IDX_LEN(htype);
        TSNPRINTF(hdb_info->idx_fname, flen,
                  _TSK_T("%s-%") PRIcTSK _TSK_T(".idx"),
                  hdb_info->db_fname, TSK_HDB_HTYPE_SHA1_STR);
        return 0;
    }

    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_HDB_ARG);
    tsk_error_set_errstr(
             "hdb_setuphash: Invalid hash type as argument: %d", htype);
    return 1;
}

/** 
 * Initializes the TSK hash DB index file. This creates the intermediate file,
 * which will have entries added to it.  This file must be sorted before the 
 * process is finished.
 *
 * @param hdb_info Hash database state structure
 * @param htype String of index type to create
 *
 * @return 1 on error and 0 on success
 *
 */
uint8_t binsrch_initialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx; 
    FILE *hIdxTmp = idx_info->hIdxTmp;
    size_t flen;
    char dbtmp[32];
    int i;

    /* Use the string of the index/hash type to figure out some
     * settings */

    // convert to char -- cheating way to deal with WCHARs..
    for (i = 0; i < 31 && htype[i] != '\0'; i++) {
        dbtmp[i] = (char) htype[i];
    }
    dbtmp[i] = '\0';

    if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_MD5_STR) == 0) {

        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        //hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID); RJCTODO
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_NSRL_SHA1_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_NSRL_ID);
            return 1;
        }
        //hdb_setuphash(hdb_info, TSK_HDB_HTYPE_SHA1_ID); RJCTODO
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_MD5SUM_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_MD5SUM_ID);
            return 1;
        }
        //hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID); RJCTODO
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_HK_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_HK_ID);
            return 1;
        }
        //hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID); RJCTODO
    }
    else if (strcmp(dbtmp, TSK_HDB_DBTYPE_ENCASE_STR) == 0) {
        if (hdb_info->db_type != TSK_HDB_DBTYPE_ENCASE_ID) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: database detected as: %d index creation as: %d",
                     hdb_info->db_type, TSK_HDB_DBTYPE_ENCASE_ID);
            return 1;
        }
        //hdb_setuphash(hdb_info, TSK_HDB_HTYPE_MD5_ID); RJCTODO
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_idxinitialize: Unknown database type request: %s",
                 dbtmp);
        return 1;
    }

    /* Setup the internal hash information */
    //if (hdb_setuphash(hdb_info, hdb_info->hash_type)) { RJCTODO
    //    return 1;
    //}

    /* Make the name for the unsorted intermediate index file */
    flen = TSTRLEN(hdb_info->db_fname) + 32;
    idx_info->uns_fname =
        (TSK_TCHAR *) tsk_malloc(flen * sizeof(TSK_TCHAR));
    if (idx_info->uns_fname == NULL) {
        return 1;
    }
    TSNPRINTF(idx_info->uns_fname, flen,
              _TSK_T("%s-%") PRIcTSK _TSK_T("-ns.idx"), hdb_info->db_fname,
              TSK_HDB_HTYPE_STR(hdb_info->hash_type));


    /* Create temp unsorted file of offsets */
#ifdef TSK_WIN32
    {
        HANDLE hWin;

        if ((hWin = CreateFile(idx_info->uns_fname, GENERIC_WRITE,
                               0, 0, CREATE_ALWAYS, 0, 0)) ==
            INVALID_HANDLE_VALUE) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CREATE);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: %"PRIttocTSK" GetFileSize: %d",
                     idx_info->uns_fname, (int)GetLastError());
            return 1;
        }

        hIdxTmp =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_WRONLY), "wb");
        if (hIdxTmp == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                     "hdb_idxinitialize: Error converting Windows handle to C handle");
            free(hdb_info);
            return 1;
        }
    }
#else
    if (NULL == (hIdxTmp = fopen(text_hdb_info->uns_fname, "w"))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CREATE);
        tsk_error_set_errstr(
                 "Error creating temp index file: %s",
                 text_hdb_info->uns_fname);
        return 1;
    }
#endif

    /* Print the header */
    fprintf(hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_NAME_STR,
        idx_info->base.db_name);
    switch (hdb_info->db_type) {
    case TSK_HDB_DBTYPE_NSRL_ID:
       fprintf(hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_NSRL_STR);
        break;
    case TSK_HDB_DBTYPE_MD5SUM_ID:
        fprintf(hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_MD5SUM_STR);
        break;
    case TSK_HDB_DBTYPE_HK_ID:
        fprintf(hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_HK_STR);
        break;
    case TSK_HDB_DBTYPE_ENCASE_ID:
        fprintf(hIdxTmp, "%s|%s\n", TSK_HDB_IDX_HEAD_TYPE_STR,
            TSK_HDB_DBTYPE_ENCASE_STR);
        break;
        /* Used to stop warning messages about missing enum value */
    case TSK_HDB_DBTYPE_IDXONLY_ID:
    default:
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CREATE);
        tsk_error_set_errstr("idxinit: Invalid db type\n");
        return 1;
    }

    return 0;
}

/**
 * Add a string entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue String of hash value to add
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
    uint8_t
binsrch_addentry(TSK_HDB_INFO * hdb_info, char *hvalue,
        TSK_OFF_T offset)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx; 
    FILE *hIdxTmp = idx_info->hIdxTmp;
    int i = 0;

    // make the hashes all upper case
    for (i = 0; hvalue[i] != '\0'; i++) {
        if (islower((int) hvalue[i]))
            fprintf(hIdxTmp, "%c", toupper((int) hvalue[i]));
        else
            fprintf(hIdxTmp, "%c", hvalue[i]);
    }

    /* Print the entry to the unsorted index file */
    fprintf(hIdxTmp, "|%.16llu\n", (unsigned long long) offset);

    return 0;
}

/**
 * Add a binary entry to the intermediate index file.
 *
 * @param hdb_info Hash database state info
 * @param hvalue Array of integers of hash value to add
 * @param hlen Number of bytes in hvalue
 * @param offset Byte offset of hash entry in original database.
 * @return 1 on error and 0 on success
 */
    uint8_t
binsrch_addentry_bin(TSK_HDB_INFO * hdb_info, unsigned char *hvalue, int hlen,
        TSK_OFF_T offset)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx; 
    FILE *hIdxTmp = idx_info->hIdxTmp;
    int i = 0;

    for (i = 0; i < hlen; i++) {
        fprintf(hIdxTmp, "%02X", hvalue[i]);
    }

    /* Print the entry to the unsorted index file */
    fprintf(hIdxTmp, "|%.16llu\n", (unsigned long long) offset);

    return 0;
}

/**
 * Finalize index creation process by sorting the index and removing the
 * intermediate temp file.
 *
 * @param hdb_info Hash database state info structure.
 * @return 1 on error and 0 on success
 */
    uint8_t
binsrch_finalize(TSK_HDB_INFO * hdb_info)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx; 

#ifdef TSK_WIN32
    wchar_t buf[TSK_HDB_MAXLEN];
    /// @@ Expand this to be SYSTEM_ROOT -- GetWindowsDirectory()
    wchar_t *sys32 = _TSK_T("C:\\WINDOWS\\System32\\sort.exe");
    DWORD stat;
    STARTUPINFO myStartInfo;
    PROCESS_INFORMATION pinfo;

    /* Close the unsorted file */
    fclose(idx_info->hIdxTmp);
    idx_info->hIdxTmp = NULL;

    /* Close the existing index if it is open */
    if (idx_info->hIdx) {
        fclose(idx_info->hIdx);
        idx_info->hIdx = NULL;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hdb_idxfinalize: Sorting index\n");

    stat = GetFileAttributes(sys32);
    if ((stat != -1) && ((stat & FILE_ATTRIBUTE_DIRECTORY) == 0)) {
        TSNPRINTF(buf, TSK_HDB_MAXLEN, _TSK_T("%s /o \"%s\" \"%s\""),
                  sys32, text_hdb_info->idx_fname, idx_info->uns_fname);
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

    if (FALSE == DeleteFile(idx_info->uns_fname)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_DELETE);
        tsk_error_set_errstr(
                 "Error deleting temp file: %d", (int)GetLastError());
        return 1;
    }
#else
    char buf[TSK_HDB_MAXLEN];
    char *root = "/bin/sort";
    char *usr = "/usr/bin/sort";
    char *local = "/usr/local/bin/sort";
    struct stat stats;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hdb_idxfinalize: Sorting index\n");

    /* Close the unsorted file */
    fclose(idx_info->hIdxTmp);
    idx_info->hIdxTmp = NULL;

    /* Close the existing index if it is open */
    if (idx_info->hIdx) {
        fclose(idx_info->hIdx);
        idx_info->hIdx = NULL;
    }

    if (0 == stat(local, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o %s %s", local,
                 idx_info->idx_fname, idx_info->uns_fname);
    }
    else if (0 == stat(usr, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o \"%s\" \"%s\"",
                 usr, idx_info->idx_fname, idx_info->uns_fname);
    }
    else if (0 == stat(root, &stats)) {
        snprintf(buf, TSK_HDB_MAXLEN, "%s -o \"%s\" \"%s\"",
                 root, idx_info->idx_fname, idx_info->uns_fname);
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

    unlink(idx_info->uns_fname);
#endif

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
uint8_t
binsrch_open(TSK_HDB_INFO * hdb_info, TSK_HDB_HTYPE_ENUM htype)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = NULL;
    char head[TSK_HDB_MAXLEN];
    char head2[TSK_HDB_MAXLEN];
    char *ptr;

    if ((idx_info =
                (TSK_HDB_BINSRCH_IDX_INFO *) tsk_malloc
                (sizeof(TSK_HDB_BINSRCH_IDX_INFO))) == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "binsrch_open: Malloc error");
        return 1;
    }
    text_hdb_info->idx = (TSK_HDB_EXTERNAL_IDX_INFO*)idx_info;

    if ((htype != TSK_HDB_HTYPE_MD5_ID)
            && (htype != TSK_HDB_HTYPE_SHA1_ID)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "binsrch_open: Invalid hash type : %d", htype);
        return 1;
    }

    idx_info->idx_llen = TSK_HDB_IDX_LEN(htype);

    /* Verify the index exists, get its size, and open it */
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        DWORD szLow, szHi;

        if (-1 == GetFileAttributes(text_hdb_info->idx_fname)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "binsrch_open: Error finding index file: %"PRIttocTSK,
                    text_hdb_info->idx_fname);
            return 1;
        }

        if ((hWin = CreateFile(text_hdb_info->idx_fname, GENERIC_READ,
                        FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
                INVALID_HANDLE_VALUE) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "binsrch_open: Error opening index file: %"PRIttocTSK,
                    text_hdb_info->idx_fname);
            return 1;
        }
        idx_info->hIdx =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
        if (idx_info->hIdx == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "binsrch_open: Error converting Windows handle to C handle");
            return 1;
        }

        szLow = GetFileSize(hWin, &szHi);
        if (szLow == 0xffffffff) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "binsrch_open: Error getting size of index file: %"PRIttocTSK" - %d",
                    text_hdb_info->idx_fname, (int)GetLastError());
            return 1;
        }
        idx_info->idx_size = szLow | ((uint64_t) szHi << 32);
    }

#else
    {
        struct stat sb;
        if (stat(idx_info->idx_fname, &sb) < 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "binsrch_open: Error finding index file: %s",
                    idx_info->idx_fname);
            return 1;
        }
        idx_info->idx_size = sb.st_size;

        if (NULL == (idx_info->hIdx = fopen(idx_info->idx_fname, "r"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "binsrch_open: Error opening index file: %s",
                    idx_info->idx_fname);
            return 1;
        }
    }
#endif


    /* Do some testing on the first line */
    if (NULL == fgets(head, TSK_HDB_MAXLEN, idx_info->hIdx)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
                 "binsrch_open: Header line of index file");
        return 1;
    }

    if (strncmp(head, TSK_HDB_IDX_HEAD_TYPE_STR, strlen(TSK_HDB_IDX_HEAD_TYPE_STR))
        != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
        tsk_error_set_errstr(
                 "binsrch_open: Invalid index file: Missing header line");
        return 1;
    }

    /* Do some testing on the second line */
    if (NULL == fgets(head2, TSK_HDB_MAXLEN, idx_info->hIdx)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
                 "binsrch_open: Error reading line 2 of index file");
        return 1;
    }

    /* Set the offset to the start of the index entries */
    if (strncmp(head2, TSK_HDB_IDX_HEAD_NAME_STR, strlen(TSK_HDB_IDX_HEAD_NAME_STR))
        != 0) {
        idx_info->idx_off = (uint16_t) (strlen(head));
    } else {
        idx_info->idx_off = (uint16_t) (strlen(head) + strlen(head2));
    }


    /* Skip the space */
    ptr = &head[strlen(TSK_HDB_IDX_HEAD_TYPE_STR) + 1];

    ptr[strlen(ptr) - 1] = '\0';
    if ((ptr[strlen(ptr) - 1] == 10) || (ptr[strlen(ptr) - 1] == 13)) {
        ptr[strlen(ptr) - 1] = '\0';
        idx_info->idx_llen++;   // make the expected index length longer to account for different cr/nl/etc.
    }

    /* Verify the header value in the index */
    if (strcmp(ptr, TSK_HDB_DBTYPE_NSRL_STR) == 0) {
        if ((hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) &&
            (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "binsrch_open: DB detected as %s, index type has NSRL",
                     ptr);
            return 1;
        }
    }
    else if (strcmp(ptr, TSK_HDB_DBTYPE_MD5SUM_STR) == 0) {
        if ((hdb_info->db_type != TSK_HDB_DBTYPE_MD5SUM_ID) &&
            (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "binsrch_open: DB detected as %s, index type has MD5SUM",
                     ptr);
            return 1;
        }
    }
    else if (strcmp(ptr, TSK_HDB_DBTYPE_HK_STR) == 0) {
        if ((hdb_info->db_type != TSK_HDB_DBTYPE_HK_ID) &&
            (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "binsrch_open: DB detected as %s, index type has hashkeeper",
                     ptr);
            return 1;
        }
    }
    else if (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
        tsk_error_set_errstr(
                 "binsrch_open: Unknown Database Type in index header: %s",
                 ptr);
        return 1;
    }

    /* Do some sanity checking */
    if (((idx_info->idx_size - idx_info->idx_off) % idx_info->idx_llen) !=
        0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "binsrch_open: Error, size of index file is not a multiple of row size");
        return 1;
    }

    /* allocate a buffer for a row */
    if ((idx_info->idx_lbuf = tsk_malloc(idx_info->idx_llen + 1)) == NULL) {
        return 1;
    }

    return 0;
}



/**
 * \ingroup hashdblib
 * Search the index for a text/ASCII hash value
 *
 * @param hdb_info Open hash database (with index)
 * @param hash Hash value to search for (NULL terminated string)
 * @param flags Flags to use in lookup
 * @param action Callback function to call for each hash db entry 
 * (not called if QUICK flag is given)
 * @param ptr Pointer to data to pass to each callback
 *
 * @return -1 on error, 0 if hash value not found, and 1 if value was found.
 */
int8_t
binsrch_lookup_str(TSK_HDB_INFO * hdb_info, const char *hash,
                   TSK_HDB_FLAG_ENUM flags, TSK_HDB_LOOKUP_FN action,
                   void *ptr)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx;
    TSK_OFF_T poffset;
    TSK_OFF_T up;               // Offset of the first byte past the upper limit that we are looking in
    TSK_OFF_T low;              // offset of the first byte of the lower limit that we are looking in
    int cmp;
    uint8_t wasFound = 0;
    size_t i;
    uint8_t htype;


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
                 "hdb_lookup: Invalid hash length: %s", hash);
        return -1;
    }

    for (i = 0; i < strlen(hash); i++) {
        if (isxdigit((int) hash[i]) == 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_ARG);
            tsk_error_set_errstr(
                     "hdb_lookup: Invalid hash value (hex only): %s",
                     hash);
            return -1;
        }
    }

    /* Sanity check */
    if (hdb_info->hash_len != strlen(hash)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                 "hdb_lookup: Hash passed is different size than expected (%d vs %Zd)",
                 hdb_info->hash_len, strlen(hash));
        return -1;
    }


    low = idx_info->idx_off;
    up = idx_info->idx_size;

    poffset = 0;

    // We have to lock access to idx_info->idx_lbuf, but since we're in a loop,
    // I'm assuming one lock up front is better than many inside.
    tsk_take_lock(&hdb_info->lock);

    while (1) {
        TSK_OFF_T offset;

        /* If top and bottom are the same, it's not there */
        if (up == low) {
            tsk_release_lock(&hdb_info->lock);
            return 0;
        }

        /* Get the middle of the windows that we are looking at */
        offset = rounddown(((up - low) / 2), idx_info->idx_llen);

        /* Sanity Check */
        if ((offset % idx_info->idx_llen) != 0) {
            tsk_release_lock(&hdb_info->lock);
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
            tsk_release_lock(&hdb_info->lock);
            return 0;
        }

        /* Seek to the offset and read it */
        if (0 != fseeko(idx_info->hIdx, offset, SEEK_SET)) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
            tsk_error_set_errstr(
                     "hdb_lookup: Error seeking in search: %" PRIuOFF,
                     offset);
            return -1;
        }

        if (NULL ==
            fgets(idx_info->idx_lbuf, (int) idx_info->idx_llen + 1,
                  idx_info->hIdx)) {
            if (feof(idx_info->hIdx)) {
                tsk_release_lock(&hdb_info->lock);
                return 0;
            }
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
            tsk_error_set_errstr(
                     "Error reading index file: %lu",
                     (unsigned long) offset);
            return -1;
        }

        /* Sanity Check */
        if ((strlen(idx_info->idx_lbuf) < idx_info->idx_llen) ||
            (idx_info->idx_lbuf[hdb_info->hash_len] != '|')) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "Invalid line in index file: %lu (%s)",
                     (unsigned long) (offset / idx_info->idx_llen),
                     idx_info->idx_lbuf);
            return -1;
        }

        /* Set the delimter to NULL so we can treat the hash as a string */
        idx_info->idx_lbuf[hdb_info->hash_len] = '\0';
        cmp = strcasecmp(idx_info->idx_lbuf, hash);

        /* The one we just read is too small, so set the new lower bound
         * at the start of the next row */
        if (cmp < 0) {
            low = offset + idx_info->idx_llen;
        }

        /* The one we just read is too big, so set the upper bound at this
         * entry */
        else if (cmp > 0) {
            up = offset;
        }

        /* We found it */
        else {
            wasFound = 1;

            if ((flags & TSK_HDB_FLAG_QUICK)
                || (hdb_info->db_type == TSK_HDB_DBTYPE_IDXONLY_ID)) {
                tsk_release_lock(&hdb_info->lock);
                return 1;
            }
            else {
                TSK_OFF_T tmpoff, db_off;

#ifdef TSK_WIN32
                db_off =
                    _atoi64(&idx_info->idx_lbuf[hdb_info->hash_len + 1]);
#else
                db_off =
                    strtoull(&idx_info->idx_lbuf[hdb_info->hash_len + 1],
                             NULL, 10);
#endif

                /* Print the one that we found first */
                if (text_hdb_info->
                    getentry(hdb_info, hash, db_off, flags, action, ptr)) {
                    tsk_release_lock(&hdb_info->lock);
                    tsk_error_set_errstr2( "hdb_lookup");
                    return -1;
                }


                /* there could be additional entries both before and after
                 * this entry - but we can restrict ourselves to the up
                 * and low bounds from our previous hunting 
                 */

                tmpoff = offset - idx_info->idx_llen;
                while (tmpoff >= low) {

                    /* Break if we are at the header */
                    if (tmpoff <= 0)
                        break;

                    if (0 != fseeko(idx_info->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "hdb_lookup: Error seeking for prev entries: %"
                                 PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(idx_info->idx_lbuf,
                              (int) idx_info->idx_llen + 1,
                              idx_info->hIdx)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "Error reading index file (prev): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }
                    else if (strlen(idx_info->idx_lbuf) <
                             idx_info->idx_llen) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                        tsk_error_set_errstr(
                                 "Invalid index file line (prev): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }

                    idx_info->idx_lbuf[hdb_info->hash_len] = '\0';
                    if (strcasecmp(idx_info->idx_lbuf, hash) != 0) {
                        break;
                    }

#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&idx_info->idx_lbuf[hdb_info->hash_len + 1]);
#else

                    db_off =
                        strtoull(&idx_info->idx_lbuf[hdb_info->hash_len + 1], NULL,
                                 10);
#endif
                    if (text_hdb_info->
                        getentry(hdb_info, hash, db_off, flags, action,
                                 ptr)) {
                        tsk_release_lock(&hdb_info->lock);
                        return -1;
                    }
                    tmpoff -= idx_info->idx_llen;
                }

                /* next entries */
                tmpoff = offset + idx_info->idx_llen;
                while (tmpoff < up) {

                    if (0 != fseeko(idx_info->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "hdb_lookup: Error seeking for next entries: %"
                                 PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(idx_info->idx_lbuf,
                              (int) idx_info->idx_llen + 1,
                              idx_info->hIdx)) {
                        if (feof(idx_info->hIdx))
                            break;
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "Error reading index file (next): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }
                    else if (strlen(idx_info->idx_lbuf) <
                             idx_info->idx_llen) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                        tsk_error_set_errstr(
                                 "Invalid index file line (next): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }

                    idx_info->idx_lbuf[hdb_info->hash_len] = '\0';
                    if (strcasecmp(idx_info->idx_lbuf, hash) != 0) {
                        break;
                    }
#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&idx_info->idx_lbuf[hdb_info->hash_len + 1]);
#else
                    db_off =
                        strtoull(&idx_info->idx_lbuf[hdb_info->hash_len + 1], NULL,
                                 10);
#endif
                    if (text_hdb_info->
                        getentry(hdb_info, hash, db_off, flags, action,
                                 ptr)) {
                        tsk_release_lock(&hdb_info->lock);
                        return -1;
                    }

                    tmpoff += idx_info->idx_llen;
                }
            }
            break;
        }
        poffset = offset;
    }
    tsk_release_lock(&hdb_info->lock);

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
binsrch_lookup_raw(TSK_HDB_INFO * hdb_info, uint8_t * hash, uint8_t len,
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

void
binsrch_close(TSK_HDB_INFO *hdb_info)
{
    TSK_TEXT_HDB_INFO *text_hdb_info = (TSK_TEXT_HDB_INFO*)hdb_info;
    TSK_HDB_BINSRCH_IDX_INFO *idx_info = (TSK_HDB_BINSRCH_IDX_INFO*)text_hdb_info->idx;

    if (idx_info->hIdx != NULL) {
        tsk_idx_close_file(idx_info->hIdx);
    }
}
