
/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "tsk_hashdb_i.h"

/**
 * \file binsrch_index.c
 * Contains functions for creating the original binary search / ASCII index
 * and looking up values in it. 
 */

/** Initialize the TSK hash DB index file. This creates the intermediate file,
 * which will have entries added to it.  This file must be sorted before the 
 * process is finished.
 *
 * @param hdb_info Hash database state structure
 * @param htype String of index type to create
 *
 * @return 1 on error and 0 on success
 *
 */
    uint8_t
binsrch_initialize(TSK_HDB_INFO * hdb_info, TSK_TCHAR * htype)
{
    // Creating plain text indices is unsupported
    return 1;
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
    // Creating plain text indices is unsupported
    return 1;
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
    // Creating plain text indices is unsupported
    // @@@ ERROR NEEDED HERE
    return 1;
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
    // Creating plain text indices is unsupported
    // @@@ ERROR NEEDED HERE
    return 1;
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
binsrch_open(TSK_HDB_INFO * hdb_info, TSK_IDX_INFO * idx_info, uint8_t htype)
{
    char head[TSK_HDB_MAXLEN];
    char head2[TSK_HDB_MAXLEN];
    char *ptr;


    if ((idx_info->idx_struct.idx_binsrch =
                (TSK_IDX_BINSRCH *) tsk_malloc
                (sizeof(TSK_IDX_BINSRCH))) == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "binsrch_open: Malloc error");
        return 1;
    }

    if ((htype != TSK_HDB_HTYPE_MD5_ID)
            && (htype != TSK_HDB_HTYPE_SHA1_ID)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_ARG);
        tsk_error_set_errstr(
                "hdb_setupindex: Invalid hash type : %d", htype);
        return 1;
    }

    idx_info->idx_struct.idx_binsrch->idx_llen = TSK_HDB_IDX_LEN(htype);

    /* Verify the index exists, get its size, and open it */
#ifdef TSK_WIN32
    {
        HANDLE hWin;
        DWORD szLow, szHi;

        if (-1 == GetFileAttributes(idx_info->idx_fname)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error finding index file: %"PRIttocTSK,
                    idx_info->idx_fname);
            return 1;
        }

        if ((hWin = CreateFile(idx_info->idx_fname, GENERIC_READ,
                        FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) ==
                INVALID_HANDLE_VALUE) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error opening index file: %"PRIttocTSK,
                    idx_info->idx_fname);
            return 1;
        }
        idx_info->idx_struct.idx_binsrch->hIdx =
            _fdopen(_open_osfhandle((intptr_t) hWin, _O_RDONLY), "r");
        if (idx_info->idx_struct.idx_binsrch->hIdx == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error converting Windows handle to C handle");
            return 1;
        }

        szLow = GetFileSize(hWin, &szHi);
        if (szLow == 0xffffffff) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error getting size of index file: %"PRIttocTSK" - %d",
                    idx_info->idx_fname, (int)GetLastError());
            return 1;
        }
        idx_info->idx_struct.idx_binsrch->idx_size = szLow | ((uint64_t) szHi << 32);
    }

#else
    {
        struct stat sb;
        if (stat(idx_info->idx_fname, &sb) < 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_MISSING);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error finding index file: %s",
                    idx_info->idx_fname);
            return 1;
        }
        idx_info->idx_struct.idx_binsrch->idx_size = sb.st_size;

        if (NULL == (idx_info->idx_struct.idx_binsrch->hIdx = fopen(idx_info->idx_fname, "r"))) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_OPEN);
            tsk_error_set_errstr(
                    "hdb_setupindex: Error opening index file: %s",
                    idx_info->idx_fname);
            return 1;
        }
    }
#endif


    /* Do some testing on the first line */
    if (NULL == fgets(head, TSK_HDB_MAXLEN, idx_info->idx_struct.idx_binsrch->hIdx)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
                 "hdb_setupindex: Header line of index file");
        return 1;
    }

    if (strncmp(head, TSK_HDB_IDX_HEAD_TYPE_STR, strlen(TSK_HDB_IDX_HEAD_TYPE_STR))
        != 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
        tsk_error_set_errstr(
                 "hdb_setupindex: Invalid index file: Missing header line");
        return 1;
    }

    /* Do some testing on the second line */
    if (NULL == fgets(head2, TSK_HDB_MAXLEN, idx_info->idx_struct.idx_binsrch->hIdx)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
        tsk_error_set_errstr(
                 "hdb_setupindex: Error reading line 2 of index file");
        return 1;
    }

    /* Set the offset to the start of the index entries */
    if (strncmp(head2, TSK_HDB_IDX_HEAD_NAME_STR, strlen(TSK_HDB_IDX_HEAD_NAME_STR))
        != 0) {
        idx_info->idx_struct.idx_binsrch->idx_off = (uint16_t) (strlen(head));
    } else {
        idx_info->idx_struct.idx_binsrch->idx_off = (uint16_t) (strlen(head) + strlen(head2));
    }


    /* Skip the space */
    ptr = &head[strlen(TSK_HDB_IDX_HEAD_TYPE_STR) + 1];

    ptr[strlen(ptr) - 1] = '\0';
    if ((ptr[strlen(ptr) - 1] == 10) || (ptr[strlen(ptr) - 1] == 13)) {
        ptr[strlen(ptr) - 1] = '\0';
        idx_info->idx_struct.idx_binsrch->idx_llen++;   // make the expected index length longer to account for different cr/nl/etc.
    }

    /* Verify the header value in the index */
    if (strcmp(ptr, TSK_HDB_DBTYPE_NSRL_STR) == 0) {
        if ((hdb_info->db_type != TSK_HDB_DBTYPE_NSRL_ID) &&
            (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
            tsk_error_set_errstr(
                     "hdb_indexsetup: DB detected as %s, index type has NSRL",
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
                     "hdb_indexsetup: DB detected as %s, index type has MD5SUM",
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
                     "hdb_indexsetup: DB detected as %s, index type has hashkeeper",
                     ptr);
            return 1;
        }
    }
    else if (hdb_info->db_type != TSK_HDB_DBTYPE_IDXONLY_ID) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_UNKTYPE);
        tsk_error_set_errstr(
                 "hdb_setupindex: Unknown Database Type in index header: %s",
                 ptr);
        return 1;
    }

    /* Do some sanity checking */
    if (((idx_info->idx_struct.idx_binsrch->idx_size - idx_info->idx_struct.idx_binsrch->idx_off) % idx_info->idx_struct.idx_binsrch->idx_llen) !=
        0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
        tsk_error_set_errstr(
                 "hdb_setupindex: Error, size of index file is not a multiple of row size");
        return 1;
    }

    /* allocate a buffer for a row */
    if ((idx_info->idx_struct.idx_binsrch->idx_lbuf = tsk_malloc(idx_info->idx_struct.idx_binsrch->idx_llen + 1)) == NULL) {
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


    low = hdb_info->idx_info->idx_struct.idx_binsrch->idx_off;
    up = hdb_info->idx_info->idx_struct.idx_binsrch->idx_size;

    poffset = 0;

    // We have to lock access to idx_info->idx_struct.idx_binsrch->idx_lbuf, but since we're in a loop,
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
        offset = rounddown(((up - low) / 2), hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen);

        /* Sanity Check */
        if ((offset % hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen) != 0) {
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
        if (0 != fseeko(hdb_info->idx_info->idx_struct.idx_binsrch->hIdx, offset, SEEK_SET)) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_READIDX);
            tsk_error_set_errstr(
                     "hdb_lookup: Error seeking in search: %" PRIuOFF,
                     offset);
            return -1;
        }

        if (NULL ==
            fgets(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf, (int) hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen + 1,
                  hdb_info->idx_info->idx_struct.idx_binsrch->hIdx)) {
            if (feof(hdb_info->idx_info->idx_struct.idx_binsrch->hIdx)) {
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
        if ((strlen(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf) < hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen) ||
            (hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len] != '|')) {
            tsk_release_lock(&hdb_info->lock);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
            tsk_error_set_errstr(
                     "Invalid line in index file: %lu (%s)",
                     (unsigned long) (offset / hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen),
                     hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf);
            return -1;
        }

        /* Set the delimter to NULL so we can treat the hash as a string */
        hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len] = '\0';
        cmp = strcasecmp(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf, hash);

        /* The one we just read is too small, so set the new lower bound
         * at the start of the next row */
        if (cmp < 0) {
            low = offset + hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen;
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
                    _atoi64(&hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1]);
#else
                db_off =
                    strtoull(&hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1],
                             NULL, 10);
#endif

                /* Print the one that we found first */
                if (hdb_info->
                    getentry(hdb_info, hash, db_off, flags, action, ptr)) {
                    tsk_release_lock(&hdb_info->lock);
                    tsk_error_set_errstr2( "hdb_lookup");
                    return -1;
                }


                /* there could be additional entries both before and after
                 * this entry - but we can restrict ourselves to the up
                 * and low bounds from our previous hunting 
                 */

                tmpoff = offset - hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen;
                while (tmpoff >= low) {

                    /* Break if we are at the header */
                    if (tmpoff <= 0)
                        break;

                    if (0 != fseeko(hdb_info->idx_info->idx_struct.idx_binsrch->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "hdb_lookup: Error seeking for prev entries: %"
                                 PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf,
                              (int) hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen + 1,
                              hdb_info->idx_info->idx_struct.idx_binsrch->hIdx)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "Error reading index file (prev): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }
                    else if (strlen(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf) <
                             hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                        tsk_error_set_errstr(
                                 "Invalid index file line (prev): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }

                    hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len] = '\0';
                    if (strcasecmp(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf, hash) != 0) {
                        break;
                    }

#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&hdb_info->
                                idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1]);
#else

                    db_off =
                        strtoull(&hdb_info->
                                 idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1], NULL,
                                 10);
#endif
                    if (hdb_info->
                        getentry(hdb_info, hash, db_off, flags, action,
                                 ptr)) {
                        tsk_release_lock(&hdb_info->lock);
                        return -1;
                    }
                    tmpoff -= hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen;
                }

                /* next entries */
                tmpoff = offset + hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen;
                while (tmpoff < up) {

                    if (0 != fseeko(hdb_info->idx_info->idx_struct.idx_binsrch->hIdx, tmpoff, SEEK_SET)) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "hdb_lookup: Error seeking for next entries: %"
                                 PRIuOFF, tmpoff);
                        return -1;
                    }

                    if (NULL ==
                        fgets(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf,
                              (int) hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen + 1,
                              hdb_info->idx_info->idx_struct.idx_binsrch->hIdx)) {
                        if (feof(hdb_info->idx_info->idx_struct.idx_binsrch->hIdx))
                            break;
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_READIDX);
                        tsk_error_set_errstr(
                                 "Error reading index file (next): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }
                    else if (strlen(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf) <
                             hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen) {
                        tsk_release_lock(&hdb_info->lock);
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_HDB_CORRUPT);
                        tsk_error_set_errstr(
                                 "Invalid index file line (next): %lu",
                                 (unsigned long) tmpoff);
                        return -1;
                    }

                    hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len] = '\0';
                    if (strcasecmp(hdb_info->idx_info->idx_struct.idx_binsrch->idx_lbuf, hash) != 0) {
                        break;
                    }
#ifdef TSK_WIN32
                    db_off =
                        _atoi64(&hdb_info->
                                idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1]);
#else
                    db_off =
                        strtoull(&hdb_info->
                                 idx_info->idx_struct.idx_binsrch->idx_lbuf[hdb_info->hash_len + 1], NULL,
                                 10);
#endif
                    if (hdb_info->
                        getentry(hdb_info, hash, db_off, flags, action,
                                 ptr)) {
                        tsk_release_lock(&hdb_info->lock);
                        return -1;
                    }

                    tmpoff += hdb_info->idx_info->idx_struct.idx_binsrch->idx_llen;
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
binsrch_close(TSK_IDX_INFO * idx_info)
{
    //Nothing to do here...
}
