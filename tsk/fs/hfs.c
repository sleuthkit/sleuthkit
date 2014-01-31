/*
** The Sleuth Kit
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**

** Copyright (c) 2009 Brian Carrier.  All rights reserved.
**
** Judson Powers [jpowers@atc-nycorp.com]
** Matt Stillerman [matt@atc-nycorp.com]
** Rob Joyce [rob@atc-nycorp.com]
** Copyright (c) 2008, 2012 ATC-NY.  All rights reserved.
** This file contains data developed with support from the National
** Institute of Justice, Office of Justice Programs, U.S. Department of Justice.
** 
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier@sleuthkit.org]
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/* TCT
 * LICENSE
 *      This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *      Wietse Venema
 *      IBM T.J. Watson Research
 *      P.O. Box 704
 *      Yorktown Heights, NY 10598, USA
 --*/

/*
** You may distribute the Sleuth Kit, or other software that incorporates
** part of all of the Sleuth Kit, in object code form under a license agreement,
** provided that:
** a) you comply with the terms and conditions of the IBM Public License
**    ver 1.0; and
** b) the license agreement
**     i) effectively disclaims on behalf of all Contributors all warranties
**        and conditions, express and implied, including warranties or
**        conditions of title and non-infringement, and implied warranties
**        or conditions of merchantability and fitness for a particular
**        purpose.
**    ii) effectively excludes on behalf of all Contributors liability for
**        damages, including direct, indirect, special, incidental and
**        consequential damages such as lost profits.
**   iii) states that any provisions which differ from IBM Public License
**        ver. 1.0 are offered by that Contributor alone and not by any
**        other party; and
**    iv) states that the source code for the program is available from you,
**        and informs licensees how to obtain it in a reasonable manner on or
**        through a medium customarily used for software exchange.
**
** When the Sleuth Kit or other software that incorporates part or all of
** the Sleuth Kit is made available in source code form:
**     a) it must be made available under IBM Public License ver. 1.0; and
**     b) a copy of the IBM Public License ver. 1.0 must be included with
**        each copy of the program.
*/

/** \file hfs.c
 * Contains the general internal TSK HFS metadata and data unit code
 */

#include "tsk_fs_i.h"
#include "tsk_hfs.h"

#include <stdarg.h>
#ifdef TSK_WIN32
#include <string.h>
#else
#include <strings.h>
#endif

// Compression Stuff

#ifdef HAVE_LIBZ
#include <zlib.h>
#endif

#define XSWAP(a,b) { a ^= b; b ^= a; a ^= b; }

// Forward declarations:
static uint8_t hfs_load_attrs(TSK_FS_FILE * fs_file);
static uint8_t hfs_load_extended_attrs(TSK_FS_FILE * file,
    unsigned char *isCompressed, unsigned char *compDataInRSRC,
    uint64_t * uncSize);
void error_detected(uint32_t errnum, char *errstr, ...);
void error_returned(char *errstr, ...);




#ifdef HAVE_LIBZ

/***************** ZLIB stuff *******************************/

// Adapted from zpipe.c (part of zlib) at http://zlib.net/zpipe.c
#define CHUNK 16384

/*
 * Invokes the zlib library to inflate (uncompress) data.
 *
 * Returns and error code.  Places the uncompressed data in a buffer supplied by the caller.  Also
 * returns the uncompressed length, and the number of compressed bytes consumed.
 *
 * Will stop short of the end of compressed data, if a natural end of a compression unit is reached.  Using
 * bytesConsumed, the caller can then advance the source pointer, and re-invoke the function.  This will then
 * inflate the next following compression unit in the data stream.
 *
 * @param source - buffer of compressed data
 * @param sourceLen  - length of the compressed data.
 * @param dest  -- buffer to  hold the uncompressed results
 * @param destLen -- length of the dest buffer
 * @param uncompressedLength  -- return of the length of the uncompressed data found.
 * @param bytesConsumed  -- return of the number of input bytes of compressed data used.
 * @return 0 on success, a negative number on error
 */
static int
zlib_inflate(char *source, uint64_t sourceLen, char *dest, uint64_t destLen, uint64_t * uncompressedLength, unsigned long *bytesConsumed)       // this is unsigned long because that's what zlib uses.
{

    int ret;
    unsigned have;
    z_stream strm;
    unsigned char in[CHUNK];
    unsigned char out[CHUNK];

    // Some vars to help with copying bytes into "in"
    char *srcPtr = source;
    char *destPtr = dest;
    uint64_t srcAvail = sourceLen;      //uint64_t
    uint64_t amtToCopy;
    uint64_t copiedSoFar = 0;

    /* allocate inflate state */
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    ret = inflateInit(&strm);
    if (ret != Z_OK) {
        error_detected(TSK_ERR_FS_READ,
            "zlib_inflate: failed to initialize inflation engine (%d)",
            ret);
        return ret;
    }

    /* decompress until deflate stream ends or end of file */
    do {

        // Copy up to CHUNK bytes into "in" from source, advancing the pointer, and
        // setting strm.avail_in equal to the number of bytes copied.
        if (srcAvail >= CHUNK) {
            amtToCopy = CHUNK;
            srcAvail -= CHUNK;
        }
        else {
            amtToCopy = srcAvail;
            srcAvail = 0;
        }
        // wipe out any previous value, copy in the bytes, advance the pointer, record number of bytes.
        memset(in, 0, CHUNK);
        if (amtToCopy > SIZE_MAX || amtToCopy > UINT_MAX) {
            error_detected(TSK_ERR_FS_READ,
                "zlib_inflate: amtToCopy in one chunk is too large");
            return -100;
        }
        memcpy(in, srcPtr, (size_t) amtToCopy); // cast OK because of above test
        srcPtr += amtToCopy;
        strm.avail_in = (uInt) amtToCopy;       // cast OK because of above test

        if (strm.avail_in == 0)
            break;
        strm.next_in = in;

        /* run inflate() on input until output buffer not full */
        do {
            strm.avail_out = CHUNK;
            strm.next_out = out;
            ret = inflate(&strm, Z_NO_FLUSH);
            if (ret == Z_NEED_DICT)
                ret = Z_DATA_ERROR;     // we don't have a custom dict
            if (ret < 0) {
                error_detected(TSK_ERR_FS_READ,
                    " zlib_inflate: zlib returned error %d (%s)", ret,
                    strm.msg);
                (void) inflateEnd(&strm);
                return ret;
            }

            have = CHUNK - strm.avail_out;
            // Is there enough space in dest to copy the current chunk?
            if (copiedSoFar + have > destLen) {
                // There is not enough space, so better return an error
                error_detected(TSK_ERR_FS_READ,
                    " zlib_inflate: not enough space in inflation destination\n");
                (void) inflateEnd(&strm);
                return -200;
            }

            // Copy "have" bytes from out to destPtr, advance destPtr
            memcpy(destPtr, out, have);
            destPtr += have;
            copiedSoFar += have;

        } while ((strm.avail_out == 0) && (ret != Z_STREAM_END));


        /* done when inflate() says it's done */
    } while (ret != Z_STREAM_END);

    if (ret == Z_STREAM_END)
        *uncompressedLength = copiedSoFar;

    *bytesConsumed = strm.total_in;
    /* clean up and return */
    (void) inflateEnd(&strm);
    return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

#endif

/* may set error up to string 1
 * returns 0 on success, 1 on failure */
uint8_t
hfs_checked_read_random(TSK_FS_INFO * fs, char *buf, size_t len,
    TSK_OFF_T offs)
{
    ssize_t r;

    r = tsk_fs_read(fs, offs, buf, len);
    if (r != len) {
        if (r >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        return 1;
    }
    return 0;
}

/**********************************************************************
 *
 *  MISC FUNCS
 *
 **********************************************************************/

/* convert the HFS Time (seconds from 1/1/1904)
 * to UNIX (UTC seconds from 1/1/1970)
 * The number is borrowed from linux HFS driver source
 */
uint32_t
hfs_convert_2_unix_time(uint32_t hfsdate)
{
    if (hfsdate < NSEC_BTWN_1904_1970)
        return 0;
    return (uint32_t) (hfsdate - NSEC_BTWN_1904_1970);
}


/**
 * Convert a cnid (metadata address) to big endian array.
 * This is used to create the key for tree lookups.
 * @param cnid Metadata address to convert
 * @param array [out] Array to write data into.
 */
static void
cnid_to_array(uint32_t cnid, uint8_t array[4])
{
    array[3] = (cnid >> 0) & 0xff;
    array[2] = (cnid >> 8) & 0xff;
    array[1] = (cnid >> 16) & 0xff;
    array[0] = (cnid >> 24) & 0xff;
}

/**********************************************************************
 *
 * Lookup Functions
 *
 **********************************************************************/



/* Compares the given HFS+ Extents B-tree key to key constructed
 * for finding the beginning of the data fork extents for the given
 * CNID. (That is, the search key uses the given CNID and has
 * fork = 0 and start_block = 0.)
 */
static int
hfs_ext_compare_keys(HFS_INFO * hfs, uint32_t cnid,
    const hfs_btree_key_ext * key)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint32_t key_cnid;

    key_cnid = tsk_getu32(fs->endian, key->file_id);
    if (key_cnid < cnid)
        return -1;
    if (key_cnid > cnid)
        return 1;

    /* referring to the same cnids */

    /* we are always looking for the data fork */
    if (key->fork_type != HFS_EXT_KEY_TYPE_DATA)
        return 1;

    /* we are always looking for a start_block of zero
       (interested in the beginning of the extents, regardless
       of what the start_block is); all files except the bad
       blocks file should have a start_block greater than
       zero */
    if (tsk_getu32(fs->endian, key->start_block) == 0)
        return 0;
    return 1;
}


/** \internal
 * Returns the length of an HFS+ B-tree INDEX key based on the tree header
 * structure and the length claimed in the record.  With some trees,
 * the length given in the record is not used. 
 * Note that this neither detects nor correctly handles 8-bit keys
 * (which should not be present in HFS+).
 *
 * This does not give the right answer for the Attributes File B-tree, for some
 * HFS+ file systems produced by the Apple OS, while it works for others.  For
 * the Attributes file, INDEX keys should always be as stated in the record itself,
 * never the "maxKeyLen" of the B-tree header.
 *
 * In this software, this function is only invoked when dealing with the Extents file.  In
 * that usage, it is not sufficiently well tested to know if it always gives the right
 * answer or not.  We can only test that with a highly fragmented disk.
 * @param hfs File System
 * @param keylen Length of key as given in record
 * @param header Tree header
 * @returns Length of key
 */
uint16_t
hfs_get_idxkeylen(HFS_INFO * hfs, uint16_t keylen,
    const hfs_btree_header_record * header)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    // if the flag is set, use the length given in the record
    if (tsk_getu32(fs->endian, header->attr) & HFS_BT_HEAD_ATTR_VARIDXKEYS)
        return keylen;
    else
        return tsk_getu16(fs->endian, header->maxKeyLen);
}


/**
 * Convert the extents runs to TSK_FS_ATTR_RUN runs.
 *
 * @param a_fs File system to analyze
 * @param a_extents Raw extents to process (in an array of 8)
 * @param a_start_off Starting block offset of these runs
 * @returns NULL on error or if no runs are in extents (test tsk_errno)
 */
static TSK_FS_ATTR_RUN *
hfs_extents_to_attr(TSK_FS_INFO * a_fs, const hfs_ext_desc * a_extents,
    TSK_OFF_T a_start_off)
{
    TSK_FS_ATTR_RUN *head_run = NULL;
    TSK_FS_ATTR_RUN *prev_run = NULL;
    int i;
    TSK_OFF_T cur_off = a_start_off;

    // since tsk_errno is checked as a return value, make sure it is clean.
    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_extents_to_attr: Converting extents from offset %" PRIuOFF
            " to runlist\n", a_start_off);

    for (i = 0; i < 8; i++) {
        TSK_FS_ATTR_RUN *cur_run;

        uint32_t addr = tsk_getu32(a_fs->endian, a_extents[i].start_blk);
        uint32_t len = tsk_getu32(a_fs->endian, a_extents[i].blk_cnt);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_extents_to_attr: run %i at addr %" PRIu32
                " with len %" PRIu32 "\n", i, addr, len);

        if ((addr == 0) && (len == 0)) {
            break;
        }

        // make a non-resident run
        if ((cur_run = tsk_fs_attr_run_alloc()) == NULL) {
            error_returned(" - hfs_extents_to_attr");
            return NULL;
        }


        cur_run->addr = addr;
        cur_run->len = len;
        cur_run->offset = cur_off;

        if (head_run == NULL)
            head_run = cur_run;
        if (prev_run != NULL)
            prev_run->next = cur_run;
        cur_off += cur_run->len;
        prev_run = cur_run;
    }

    return head_run;
}


/**
 * Look in the extents catalog for entries for a given file. Add the runs
 * to the passed attribute structure. 
 *
 * @param hfs File system being analyzed
 * @param cnid file id of file to search for
 * @param a_attr Attribute to add extents runs to 
 * @param dataForkQ  if true, then find extents for the data fork.  If false, then find extents for the Resource fork.
 * @returns 1 on error and 0 on success
 */
static uint8_t
hfs_ext_find_extent_record_attr(HFS_INFO * hfs, uint32_t cnid,
    TSK_FS_ATTR * a_attr, unsigned char dataForkQ)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t nodesize;          /* size of nodes (all, regardless of the name) */
    uint32_t cur_node;          /* node id of the current node */
    char *node = NULL;
    uint8_t is_done;
    uint8_t desiredType;

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_ext_find_extent_record_attr: Looking for extents for file %"
            PRIu32 " %s\n", cnid,
            dataForkQ ? "data fork" : "resource fork");

    if (!hfs->has_extents_file) {
        // No extents file (which is optional), and so, no further extents are possible.
        return 0;
    }

    // Are we looking for extents of the data fork or the resource fork?
    desiredType =
        dataForkQ ? HFS_EXT_KEY_TYPE_DATA : HFS_EXT_KEY_TYPE_RSRC;

    // Load the extents attribute, if it has not been done so yet.
    if (hfs->extents_file == NULL) {
        ssize_t cnt;

        if ((hfs->extents_file =
                tsk_fs_file_open_meta(fs, NULL,
                    HFS_EXTENTS_FILE_ID)) == NULL) {
            return 1;
        }

        /* cache the data attribute */
        hfs->extents_attr =
            tsk_fs_attrlist_get(hfs->extents_file->meta->attr,
            TSK_FS_ATTR_TYPE_DEFAULT);
        if (!hfs->extents_attr) {
            tsk_error_errstr2_concat
                (" - Default Attribute not found in Extents File");
            return 1;
        }

        // cache the extents file header
        cnt = tsk_fs_attr_read(hfs->extents_attr, 14,
            (char *) &(hfs->extents_header),
            sizeof(hfs_btree_header_record), 0);
        if (cnt != sizeof(hfs_btree_header_record)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2
                ("hfs_ext_find_extent_record_attr: Error reading header");
            return 1;
        }
    }

    // allocate a node buffer 
    nodesize = tsk_getu16(fs->endian, hfs->extents_header.nodesize);
    if ((node = (char *) tsk_malloc(nodesize)) == NULL) {
        return 1;
    }

    /* start at root node */
    cur_node = tsk_getu32(fs->endian, hfs->extents_header.rootNode);

    /* if the root node is zero, then the extents btree is empty */
    /* if no files have overflow extents, the Extents B-tree still
       exists on disk, but is an empty B-tree containing only
       the header node */
    if (cur_node == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                "empty extents btree\n");
        free(node);
        return 0;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_ext_find_extent_record: starting at "
            "root node %" PRIu32 "; nodesize = %"
            PRIu16 "\n", cur_node, nodesize);

    /* Recurse down to the needed leaf nodes and then go forward */
    is_done = 0;
    while (is_done == 0) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        uint16_t num_rec;       /* number of records in this node */
        ssize_t cnt;
        hfs_btree_node *node_desc;

        // sanity check 
        if (cur_node > tsk_getu32(fs->endian,
                hfs->extents_header.totalNodes)) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr
                ("hfs_ext_find_extent_record_attr: Node %d too large for file",
                cur_node);
            free(node);
            return 1;
        }

        // read the current node
        cur_off = cur_node * nodesize;
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_ext_find_extent_record: reading node %" PRIu32
                " at offset %" PRIuOFF "\n", cur_node, cur_off);

        cnt = tsk_fs_attr_read(hfs->extents_attr, cur_off,
            node, nodesize, 0);
        if (cnt != nodesize) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2
                ("hfs_ext_find_extent_record_attr: Error reading node %d at offset %"
                PRIuOFF, cur_node, cur_off);
            free(node);
            return 1;
        }

        // process the header / descriptor
        node_desc = (hfs_btree_node *) node;
        num_rec = tsk_getu16(fs->endian, node_desc->num_rec);

        if (num_rec == 0) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr
                ("hfs_ext_find_extent_record: zero records in node %"
                PRIu32, cur_node);
            free(node);
            return 1;
        }


        /* With an index node, find the record with the largest key that is smaller
         * to or equal to cnid */
        if (node_desc->type == HFS_BT_NODE_TYPE_IDX) {
            uint32_t next_node = 0;
            int rec;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_ext_find_extent_record: Index node %" PRIu32
                    " @ %" PRIu64 " has %" PRIu16 " records\n", cur_node,
                    cur_off, num_rec);

            for (rec = 0; rec < num_rec; rec++) {
                int cmp;
                size_t rec_off;
                hfs_btree_key_ext *key;

                // get the record offset in the node 
                rec_off =
                    tsk_getu16(fs->endian,
                    &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_ext_find_extent_record_attr: offset of record %d in index node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off,
                        nodesize);
                    free(node);
                    return 1;
                }
                key = (hfs_btree_key_ext *) & node[rec_off];

                cmp = hfs_ext_compare_keys(hfs, cnid, key);

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_ext_find_extent_record: record %" PRIu16
                        " ; keylen %" PRIu16 " (FileId: %" PRIu32
                        ", ForkType: %" PRIu8 ", StartBlk: %" PRIu32
                        "); compare: %d\n", rec, tsk_getu16(fs->endian,
                            key->key_len), tsk_getu32(fs->endian,
                            key->file_id), key->fork_type,
                        tsk_getu32(fs->endian, key->start_block), cmp);

                /* save the info from this record unless it is bigger than cnid */
                if ((cmp <= 0) || (next_node == 0)) {
                    hfs_btree_index_record *idx_rec;
                    int keylen =
                        2 + hfs_get_idxkeylen(hfs, tsk_getu16(fs->endian,
                            key->key_len), &(hfs->extents_header));
                    if (rec_off + keylen > nodesize) {
                        tsk_error_set_errno(TSK_ERR_FS_GENFS);
                        tsk_error_set_errstr
                            ("hfs_ext_find_extent_record_attr: offset and keylenth of record %d in index node %d too large (%d vs %"
                            PRIu16 ")", rec, cur_node,
                            (int) rec_off + keylen, nodesize);
                        free(node);
                        return 1;
                    }
                    idx_rec =
                        (hfs_btree_index_record *) & node[rec_off +
                        keylen];
                    next_node = tsk_getu32(fs->endian, idx_rec->childNode);
                }

                // we are bigger than cnid, so move on to the next node
                if (cmp > 0) {
                    break;
                }
            }

            // check if we found a relevant node, if not stop.
            if (next_node == 0) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_ext_find_extent_record_attr: did not find any keys for %d in index node %d",
                        cnid, cur_node);
                is_done = 1;
                break;
            }
            cur_node = next_node;
        }

        /* with a leaf, we process until we are past cnid.  We move right too if we can */
        else if (node_desc->type == HFS_BT_NODE_TYPE_LEAF) {
            int rec;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_ext_find_extent_record: Leaf node %" PRIu32 " @ %"
                    PRIu64 " has %" PRIu16 " records\n", cur_node, cur_off,
                    num_rec);

            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_btree_key_ext *key;
                uint32_t rec_cnid;
                hfs_extents *extents;
                TSK_OFF_T ext_off = 0;
                int keylen;
                TSK_FS_ATTR_RUN *attr_run;

                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                    &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_ext_find_extent_record_attr: offset of record %d in leaf node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off,
                        nodesize);
                    free(node);
                    return 1;
                }
                key = (hfs_btree_key_ext *) & node[rec_off];

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_ext_find_extent_record: record %" PRIu16
                        "; keylen %" PRIu16 " (%" PRIu32
                        ", %" PRIu8 ", %" PRIu32 ")\n", rec,
                        tsk_getu16(fs->endian, key->key_len),
                        tsk_getu32(fs->endian, key->file_id),
                        key->fork_type, tsk_getu32(fs->endian,
                            key->start_block));

                rec_cnid = tsk_getu32(fs->endian, key->file_id);

                // see if this record is for our file
                // OLD logic, just handles the DATA fork
//                if (rec_cnid < cnid) {
//                    continue;
//                }
//                else if ((rec_cnid > cnid)
//                    || (key->fork_type != HFS_EXT_KEY_TYPE_DATA)) {
//                    is_done = 1;
//                    break;
//                }

                // NEW logic, handles both DATA and RSRC forks.
                if (rec_cnid < cnid) {
                    continue;
                }
                if (rec_cnid > cnid) {
                    is_done = 1;
                    break;
                }


                if (key->fork_type != desiredType) {
                    if (dataForkQ) {
                        is_done = 1;
                        break;
                    }
                    else
                        continue;
                }

                // OK, this is one of the extents records that we are seeking, so save it.
                keylen = 2 + tsk_getu16(fs->endian, key->key_len);
                if (rec_off + keylen > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_ext_find_extent_record_attr: offset and keylenth of record %d in leaf node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off + keylen,
                        nodesize);
                    free(node);
                    return 1;
                }

                // get the starting offset of this extent
                ext_off = tsk_getu32(fs->endian, key->start_block);

                // convert the extents to the TSK format
                extents = (hfs_extents *) & node[rec_off + keylen];

                attr_run =
                    hfs_extents_to_attr(fs, extents->extents, ext_off);
                if ((attr_run == NULL) && (tsk_error_get_errno() != 0)) {
                    tsk_error_errstr2_concat
                        (" - hfs_ext_find_extent_record_attr");
                    free(node);
                    return 1;
                }

                if (tsk_fs_attr_add_run(fs, a_attr, attr_run)) {
                    tsk_error_errstr2_concat
                        (" - hfs_ext_find_extent_record_attr");
                    free(node);
                    return 1;
                }
            }
            cur_node = tsk_getu32(fs->endian, node_desc->flink);
            if (cur_node == 0) {
                is_done = 1;
                break;
            }
        }
        else {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("hfs_ext_find_extent_record: btree node %"
                PRIu32 " (%" PRIuOFF ") is neither index nor leaf (%" PRIu8
                ")", cur_node, cur_off, node_desc->type);
            free(node);
            return 1;
        }
    }
    free(node);
    return 0;
}


/** \internal
 * Compares two Catalog B-tree keys.
 * @param hfs File System being analyzed
 * @param key1 Key 1 to compare
 * @param key2 Key 2 to compare
 * @returns -1 if key1 is smaller, 0 if equal, and 1 if key1 is larger
 */
int
hfs_cat_compare_keys(HFS_INFO * hfs, const hfs_btree_key_cat * key1,
    const hfs_btree_key_cat * key2)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint32_t cnid1, cnid2;

    cnid1 = tsk_getu32(fs->endian, key1->parent_cnid);
    cnid2 = tsk_getu32(fs->endian, key2->parent_cnid);

    if (cnid1 < cnid2)
        return -1;
    if (cnid1 > cnid2)
        return 1;

    return hfs_unicode_compare(hfs, &key1->name, &key2->name);
}


/** \internal
 * @param hfs File system
 * @param targ_data can be null
 * @param a_cb callback 
 * @param ptr Pointer to pass to callback
 * @returns 1 on error
 */
uint8_t
hfs_cat_traverse(HFS_INFO * hfs, const void *targ_data,
    TSK_HFS_BTREE_CB a_cb, void *ptr)
{
    TSK_FS_INFO *fs = &(hfs->fs_info);
    uint32_t cur_node;          /* node id of the current node */
    char *node;

    uint16_t nodesize;
    uint8_t is_done = 0;

    tsk_error_reset();

    nodesize = tsk_getu16(fs->endian, hfs->catalog_header.nodesize);
    if ((node = (char *) tsk_malloc(nodesize)) == NULL)
        return 1;

    /* start at root node */
    cur_node = tsk_getu32(fs->endian, hfs->catalog_header.rootNode);

    /* if the root node is zero, then the extents btree is empty */
    /* if no files have overflow extents, the Extents B-tree still
       exists on disk, but is an empty B-tree containing only
       the header node */
    if (cur_node == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_cat_traverse: "
                "empty extents btree\n");
        free(node);
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_cat_traverse: starting at "
            "root node %" PRIu32 "; nodesize = %"
            PRIu16 "\n", cur_node, nodesize);

    /* Recurse down to the needed leaf nodes and then go forward */
    is_done = 0;
    while (is_done == 0) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        uint16_t num_rec;       /* number of records in this node */
        ssize_t cnt;
        hfs_btree_node *node_desc;

        // sanity check 
        if (cur_node > tsk_getu32(fs->endian,
                hfs->catalog_header.totalNodes)) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr
                ("hfs_cat_traverse: Node %d too large for file", cur_node);
            free(node);
            return 1;
        }

        // read the current node
        cur_off = cur_node * nodesize;
        cnt = tsk_fs_attr_read(hfs->catalog_attr, cur_off,
            node, nodesize, 0);
        if (cnt != nodesize) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2
                ("hfs_cat_traverse: Error reading node %d at offset %"
                PRIuOFF, cur_node, cur_off);
            free(node);
            return 1;
        }

        // process the header / descriptor
        node_desc = (hfs_btree_node *) node;
        num_rec = tsk_getu16(fs->endian, node_desc->num_rec);

        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_cat_traverse: node %" PRIu32
                " @ %" PRIu64 " has %" PRIu16 " records\n",
                cur_node, cur_off, num_rec);

        if (num_rec == 0) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("hfs_cat_traverse: zero records in node %"
                PRIu32, cur_node);
            free(node);
            return 1;
        }

        /* With an index node, find the record with the largest key that is smaller
         * to or equal to cnid */
        if (node_desc->type == HFS_BT_NODE_TYPE_IDX) {
            uint32_t next_node = 0;
            int rec;

            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_btree_key_cat *key;
                uint8_t retval;

                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                    &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_cat_traverse: offset of record %d in index node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off,
                        nodesize);
                    free(node);
                    return 1;
                }
                key = (hfs_btree_key_cat *) & node[rec_off];

                /*
                   if (tsk_verbose)
                   tsk_fprintf(stderr,
                   "hfs_cat_traverse: record %" PRIu16
                   " ; keylen %" PRIu16 " (%" PRIu32 ")\n", rec,
                   tsk_getu16(fs->endian, key->key_len),
                   tsk_getu32(fs->endian, key->parent_cnid));
                 */

                /* save the info from this record unless it is too big */
                retval =
                    a_cb(hfs, HFS_BT_NODE_TYPE_IDX, targ_data, key,
                    cur_off + rec_off, ptr);
                if (retval == HFS_BTREE_CB_ERR) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr2
                        ("hfs_cat_traverse: Callback returned error");
                    free(node);
                    return 1;
                }
                // record the closest entry
                else if ((retval == HFS_BTREE_CB_IDX_LT)
                    || (next_node == 0)) {
                    hfs_btree_index_record *idx_rec;
                    int keylen =
                        2 + hfs_get_idxkeylen(hfs, tsk_getu16(fs->endian,
                            key->key_len), &(hfs->catalog_header));
                    if (rec_off + keylen > nodesize) {
                        tsk_error_set_errno(TSK_ERR_FS_GENFS);
                        tsk_error_set_errstr
                            ("hfs_cat_traverse: offset of record and keylength %d in index node %d too large (%d vs %"
                            PRIu16 ")", rec, cur_node,
                            (int) rec_off + keylen, nodesize);
                        free(node);
                        return 1;
                    }
                    idx_rec =
                        (hfs_btree_index_record *) & node[rec_off +
                        keylen];
                    next_node = tsk_getu32(fs->endian, idx_rec->childNode);
                }
                if (retval == HFS_BTREE_CB_IDX_EQGT) {
                    // move down to the next node
                    break;
                }
            }
            // check if we found a relevant node
            if (next_node == 0) {
                tsk_error_set_errno(TSK_ERR_FS_GENFS);
                tsk_error_set_errstr
                    ("hfs_cat_traverse: did not find any keys in index node %d",
                    cur_node);
                is_done = 1;
                break;
            }
            cur_node = next_node;
        }

        /* With a leaf, we look for the specific record. */
        else if (node_desc->type == HFS_BT_NODE_TYPE_LEAF) {
            int rec;

            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_btree_key_cat *key;
                uint8_t retval;

                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                    &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_cat_traverse: offset of record %d in leaf node %d too large (%d vs %"
                        PRIu16 ")", rec, cur_node, (int) rec_off,
                        nodesize);
                    free(node);
                    return 1;
                }
                key = (hfs_btree_key_cat *) & node[rec_off];

                /*
                   if (tsk_verbose)
                   tsk_fprintf(stderr,
                   "hfs_cat_traverse: record %" PRIu16
                   "; keylen %" PRIu16 " (%" PRIu32 ")\n", rec,
                   tsk_getu16(fs->endian, key->key_len),
                   tsk_getu32(fs->endian, key->parent_cnid));
                 */
                //                rec_cnid = tsk_getu32(fs->endian, key->file_id);

                retval =
                    a_cb(hfs, HFS_BT_NODE_TYPE_LEAF, targ_data, key,
                    cur_off + rec_off, ptr);
                if (retval == HFS_BTREE_CB_LEAF_STOP) {
                    is_done = 1;
                    break;
                }
                else if (retval == HFS_BTREE_CB_ERR) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr2
                        ("hfs_cat_traverse: Callback returned error");
                    free(node);
                    return 1;
                }
            }

            // move right to the next node if we got this far
            if (is_done == 0) {
                cur_node = tsk_getu32(fs->endian, node_desc->flink);
                if (cur_node == 0) {
                    is_done = 1;
                }
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_cat_traverse: moving forward to next leaf");
            }
        }
        else {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("hfs_cat_traverse: btree node %" PRIu32
                " (%" PRIu64 ") is neither index nor leaf (%" PRIu8 ")",
                cur_node, cur_off, node_desc->type);
            free(node);
            return 1;
        }
    }
    free(node);
    return 0;
}


static uint8_t
hfs_cat_get_record_offset_cb(HFS_INFO * hfs, int8_t level_type,
    const void *targ_data, const hfs_btree_key_cat * cur_key,
    TSK_OFF_T key_off, void *ptr)
{
    const hfs_btree_key_cat *targ_key = (hfs_btree_key_cat *) targ_data;
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_cat_get_record_offset_cb: %s node want: %" PRIu32
            " vs have: %" PRIu32 "\n",
            (level_type == HFS_BT_NODE_TYPE_IDX) ? "Index" : "Leaf",
            tsk_getu32(hfs->fs_info.endian, targ_key->parent_cnid),
            tsk_getu32(hfs->fs_info.endian, cur_key->parent_cnid));

    if (level_type == HFS_BT_NODE_TYPE_IDX) {
        int diff = hfs_cat_compare_keys(hfs, cur_key, targ_key);
        if (diff < 0)
            return HFS_BTREE_CB_IDX_LT;
        else
            return HFS_BTREE_CB_IDX_EQGT;
    }
    else {
        int diff = hfs_cat_compare_keys(hfs, cur_key, targ_key);

        // see if this record is for our file or if we passed the interesting entries
        if (diff < 0) {
            return HFS_BTREE_CB_LEAF_GO;
        }
        else if (diff == 0) {
            TSK_OFF_T *off = (TSK_OFF_T *) ptr;
            *off =
                key_off + 2 + tsk_getu16(hfs->fs_info.endian,
                cur_key->key_len);
        }
        return HFS_BTREE_CB_LEAF_STOP;
    }
}


/** \internal
 * Find the byte offset (from the start of the catalog file) to a record
 * in the catalog file.  
 * @param hfs File System being analyzed
 * @param needle Key to search for
 * @returns Byte offset or 0 on error. 0 is also returned if catalog
 * record was not found. Check tsk_errno to determine if error occured.
 */
static TSK_OFF_T
hfs_cat_get_record_offset(HFS_INFO * hfs, const hfs_btree_key_cat * needle)
{
    TSK_OFF_T off = 0;
    if (hfs_cat_traverse(hfs, needle, hfs_cat_get_record_offset_cb, &off)) {
        return 0;
    }
    return off;
}



/** \internal
 * Given a byte offset to a leaf record in teh catalog file, read the data as
 * a thread record. This will zero the buffer and read in the size of the thread
 * data. 
 * @param hfs File System
 * @param off Byte offset of record in catalog file (not including key)
 * @param thread [out] Buffer to write thread data into.
 * @returns 0 on success, 1 on failure; sets up to error string 1 */
uint8_t
hfs_cat_read_thread_record(HFS_INFO * hfs, TSK_OFF_T off,
    hfs_thread * thread)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t uni_len;
    size_t cnt;

    memset(thread, 0, sizeof(hfs_thread));
    cnt = tsk_fs_attr_read(hfs->catalog_attr, off, (char *) thread, 10, 0);
    if (cnt != 10) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2
            ("hfs_cat_read_thread_record: Error reading catalog offset %"
            PRIuOFF " (header)", off);
        return 1;
    }

    if ((tsk_getu16(fs->endian, thread->rec_type) != HFS_FOLDER_THREAD)
        && (tsk_getu16(fs->endian, thread->rec_type) != HFS_FILE_THREAD)) {
        tsk_error_set_errno(TSK_ERR_FS_GENFS);
        tsk_error_set_errstr
            ("hfs_cat_read_thread_record: unexpected record type %" PRIu16,
            tsk_getu16(fs->endian, thread->rec_type));
        return 1;
    }

    uni_len = tsk_getu16(fs->endian, thread->name.length);

    if (uni_len > 255) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
        tsk_error_set_errstr
            ("hfs_cat_read_thread_record: invalid string length (%" PRIu16
            ")", uni_len);
        return 1;
    }

    cnt =
        tsk_fs_attr_read(hfs->catalog_attr, off + 10,
        (char *) thread->name.unicode, uni_len * 2, 0);
    if (cnt != uni_len * 2) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2
            ("hfs_cat_read_thread_record: Error reading catalog offset %"
            PRIuOFF " (name)", off + 10);
        return 1;
    }

    return 0;
}

/** \internal
 * Read a catalog record into a local data structure.  This reads the
 * correct amount, depending on if it is a file or folder. 
 * @param hfs File system being analyzed
 * @param off Byte offset (in catalog file) of record (not including key)
 * @param record [out] Structure to read data into
 * @returns 1 on error
 */
uint8_t
hfs_cat_read_file_folder_record(HFS_INFO * hfs, TSK_OFF_T off,
    hfs_file_folder * record)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    size_t cnt;
    char rec_type[2];

    memset(record, 0, sizeof(hfs_file_folder));

    cnt = tsk_fs_attr_read(hfs->catalog_attr, off, rec_type, 2, 0);
    if (cnt != 2) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2
            ("hfs_cat_read_file_folder_record: Error reading record type from catalog offset %"
            PRIuOFF " (header)", off);
        return 1;
    }

    if (tsk_getu16(fs->endian, rec_type) == HFS_FOLDER_RECORD) {
        cnt =
            tsk_fs_attr_read(hfs->catalog_attr, off, (char *) record,
            sizeof(hfs_folder), 0);
        if (cnt != sizeof(hfs_folder)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2
                ("hfs_cat_read_file_folder_record: Error reading catalog offset %"
                PRIuOFF " (folder)", off);
            return 1;
        }
    }
    else if (tsk_getu16(fs->endian, rec_type) == HFS_FILE_RECORD) {
        cnt =
            tsk_fs_attr_read(hfs->catalog_attr, off, (char *) record,
            sizeof(hfs_file), 0);
        if (cnt != sizeof(hfs_file)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2
                ("hfs_cat_read_file_folder_record: Error reading catalog offset %"
                PRIuOFF " (file)", off);
            return 1;
        }
    }
    else {
        tsk_error_set_errno(TSK_ERR_FS_GENFS);
        tsk_error_set_errstr
            ("hfs_cat_read_file_folder_record: unexpected record type %"
            PRIu16, tsk_getu16(fs->endian, rec_type));
        return 1;
    }

    return 0;
}


static TSK_INUM_T
hfs_lookup_hard_link(HFS_INFO * hfs, TSK_INUM_T linknum,
    unsigned char is_directory)
{
    char fBuff[30];
    TSK_FS_DIR *mdir;
    size_t indx;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;

    memset(fBuff, 0, 30);

    if (is_directory) {

        tsk_take_lock(&(hfs->metadata_dir_cache_lock));
        if (hfs->dir_meta_dir == NULL) {
            hfs->dir_meta_dir =
                tsk_fs_dir_open_meta(fs, hfs->meta_dir_inum);
        }
        tsk_release_lock(&(hfs->metadata_dir_cache_lock));

        if (hfs->dir_meta_dir == NULL) {
            error_returned
                ("hfs_lookup_hard_link: could not open the dir metadata directory");
            return 0;
        }
        else {
            mdir = hfs->dir_meta_dir;
        }
        snprintf(fBuff, 30, "dir_%" PRIuINUM, linknum);

    }
    else {

        tsk_take_lock(&(hfs->metadata_dir_cache_lock));
        if (hfs->meta_dir == NULL) {
            hfs->meta_dir = tsk_fs_dir_open_meta(fs, hfs->meta_inum);
        }
        tsk_release_lock(&(hfs->metadata_dir_cache_lock));

        if (hfs->meta_dir == NULL) {
            error_returned
                ("hfs_lookup_hard_link: could not open file metadata directory");
            return 0;
        }
        else {
            mdir = hfs->meta_dir;
        }
        snprintf(fBuff, 30, "iNode%" PRIuINUM, linknum);
    }

    for (indx = 0; indx < tsk_fs_dir_getsize(mdir); indx++) {

        if ((mdir->names != NULL) && mdir->names[indx].name &&
            (fs->name_cmp(fs, mdir->names[indx].name, fBuff) == 0)) {
            // OK this is the one
            return mdir->names[indx].meta_addr;
        }
    }

    // OK, we did not find that linknum
    return 0;
}

/*
 * Given a catalog entry, will test that entry to see if it is a hard link.
 * If it is a hard link, the function returns the inum (or cnid) of the target file.
 * If it is NOT a hard link, then then function returns the inum of the given entry.
 * In both cases, the parameter is_error is set to zero.
 *
 * If an ERROR occurs, if it is a mild error, then is_error is set to 1, and the
 * inum of the given entry is returned.  This signals that hard link detection cannot
 * be carried out.
 *
 * If the error is serious, then is_error is set to 2 or 3, depending on the kind of error, and
 * the TSK error code is set, and the function returns zero.  is_error==2 means that an error
 * occured in looking up the target file in the Catalog.  is_error==3 means that the given
 * entry appears to be a hard link, but the target file does not exist in the Catalog.
 *
 * @param hfs The file system
 * @param entry The catalog entry to check
 * @param is_error A Boolean that is returned indicating an error, or no error.\
 * @return The inum (or cnid) of the hard link target, or of the given catalog entry, or zero.
 */
TSK_INUM_T
hfs_follow_hard_link(HFS_INFO * hfs, hfs_file * cat,
    unsigned char *is_error)
{

    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_INUM_T cnid;
    time_t crtime;
    uint32_t file_type;
    uint32_t file_creator;

    *is_error = 0;              // default, not an error

    if (cat == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_follow_hard_link: Pointer to Catalog entry (2nd arg) is null");
        return 0;
    }

    cnid = tsk_getu32(fs->endian, cat->std.cnid);

    if (cnid < HFS_FIRST_USER_CNID) {
        // Can't be a hard link.  And, cannot look up in Catalog file either!
        return cnid;
    }

    crtime =
        (time_t) hfs_convert_2_unix_time(tsk_getu32(fs->endian,
            cat->std.crtime));


    file_type = tsk_getu32(fs->endian, cat->std.u_info.file_type);
    file_creator = tsk_getu32(fs->endian, cat->std.u_info.file_cr);

    // Only proceed with the rest of this if the flags etc are right
    if (file_type == HFS_HARDLINK_FILE_TYPE
        && file_creator == HFS_HARDLINK_FILE_CREATOR) {

        // see if we have the HFS+ Private Data dir for file links;
        // if not, it can't be a hard link.  (We could warn the user, but
        // we also rely on this when finding the HFS+ Private Data dir in
        // the first place and we don't want a warning on every hfs_open.)
        if (hfs->meta_inum == 0)
            return cnid;

        // For this to work, we need the FS creation times.  Is at least one of these set?
        if ((!hfs->has_root_crtime) && (!hfs->has_meta_dir_crtime)
            && (!hfs->has_meta_crtime)) {
            uint32_t linkNum =
                tsk_getu32(fs->endian, cat->std.perm.special.inum);
            *is_error = 1;
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "WARNING: hfs_follow_hard_link: File system creation times are not set. "
                    "Cannot test inode for hard link. File type and creator indicate that this"
                    " is a hard link (file), with LINK ID = %" PRIu32 "\n",
                    linkNum);
            return cnid;
        }

        if ((!hfs->has_root_crtime) || (!hfs->has_meta_crtime)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "WARNING: hfs_follow_hard_link: Either the root folder or the"
                    " file metadata folder is not accessible.  Testing this potential hard link"
                    " may be impaired.\n");
        }

        // Now we need to check the creation time against the three FS creation times
        if ((hfs->has_meta_crtime && (crtime == hfs->meta_crtime)) ||
            (hfs->has_meta_dir_crtime && (crtime == hfs->metadir_crtime))
            || (hfs->has_root_crtime && (crtime == hfs->root_crtime))) {
            // OK, this is a hard link to a file.
            uint32_t linkNum =
                tsk_getu32(fs->endian, cat->std.perm.special.inum);

            TSK_INUM_T target_cnid;     //  This is the real CNID of the file.

            target_cnid = hfs_lookup_hard_link(hfs, linkNum, FALSE);

            if (target_cnid != 0) {
                // Succeeded in finding that target_cnid in the Catalog file
                return target_cnid;
            }
            else {
                // This should be a hard link, BUT...
                // Did not find the target_cnid in the Catalog file.
                error_returned
                    ("hfs_follow_hard_link: got an error looking up the target of a file link");
                *is_error = 2;
                return 0;
            }
        }

    }
    else if (file_type == HFS_LINKDIR_FILE_TYPE
        && file_creator == HFS_LINKDIR_FILE_CREATOR) {

        // see if we have the HFS+ Private Directory Data dir for links;
        // if not, it can't be a hard link.  (We could warn the user, but
        // we also rely on this when finding the HFS+ Private Directory Data dir in
        // the first place and we don't want a warning on every hfs_open.)
        if (hfs->meta_dir_inum == 0)
            return cnid;

        // For this to work, we need the FS creation times.  Is at least one of these set?
        if ((!hfs->has_root_crtime) && (!hfs->has_meta_dir_crtime)
            && (!hfs->has_meta_crtime)) {
            uint32_t linkNum =
                tsk_getu32(fs->endian, cat->std.perm.special.inum);
            *is_error = 1;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "WARNING: hfs_follow_hard_link: File system creation times are not set. "
                    "Cannot test inode for hard link. File type and creator indicate that this"
                    " is a hard link (directory), with LINK ID = %" PRIu32
                    "\n", linkNum);
            return cnid;
        }

        if ((!hfs->has_root_crtime) || (!hfs->has_meta_crtime)
            || (!hfs->has_meta_dir_crtime)) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "WARNING: hfs_follow_hard_link: Either the root folder or the"
                    " file metadata folder or the directory metatdata folder is"
                    " not accessible.  Testing this potential hard linked folder "
                    "may be impaired.\n");
        }

        // Now we need to check the creation time against the three FS creation times
        if ((hfs->has_meta_crtime && (crtime == hfs->meta_crtime)) ||
            (hfs->has_meta_dir_crtime && (crtime == hfs->metadir_crtime))
            || (hfs->has_root_crtime && (crtime == hfs->root_crtime))) {
            // OK, this is a hard link to a directory.
            uint32_t linkNum =
                tsk_getu32(fs->endian, cat->std.perm.special.inum);

            TSK_INUM_T target_cnid;     //  This is the real CNID of the file.

            target_cnid = hfs_lookup_hard_link(hfs, linkNum, TRUE);

            if (target_cnid != 0) {
                // Succeeded in finding that target_cnid in the Catalog file
                return target_cnid;
            }
            else {
                // This should be a hard link, BUT...
                // Did not find the target_cnid in the Catalog file.
                error_returned
                    ("hfs_follow_hard_link: got an error looking up the target of a dir link");
                *is_error = 2;
                return 0;
            }
        }
    }

    // It cannot be a hard link (file or directory)
    return cnid;
}


/** \internal
 * Lookup an entry in the catalog file and save it into the entry.  Do not
 * call this for the special files that do not have an entry in the catalog. 
 * data structure.
 * @param hfs File system being analyzed
 * @param inum Address (cnid) of file to open
 * @param entry [out] Structure to read data into
 * @returns 1 on error or not found, 0 on success. Check tsk_errno
 * to differentiate between error and not found.  If it is not found, then the
 * errno will be TSK_ERR_FS_INODE_NUM.  Else, it will be some other value.
 */
uint8_t
hfs_cat_file_lookup(HFS_INFO * hfs, TSK_INUM_T inum, HFS_ENTRY * entry,
    unsigned char follow_hard_link)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    hfs_btree_key_cat key;      /* current catalog key */
    hfs_thread thread;          /* thread record */
    hfs_file_folder record;     /* file/folder record */
    TSK_OFF_T off;

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_cat_file_lookup: called for inum %" PRIuINUM "\n", inum);

    // Test if this is a special file that is not located in the catalog
    if ((inum == HFS_EXTENTS_FILE_ID) ||
        (inum == HFS_CATALOG_FILE_ID) ||
        (inum == HFS_ALLOCATION_FILE_ID) ||
        (inum == HFS_STARTUP_FILE_ID) ||
        (inum == HFS_ATTRIBUTES_FILE_ID)) {
        tsk_error_set_errno(TSK_ERR_FS_GENFS);
        tsk_error_set_errstr
            ("hfs_cat_file_lookup: Called on special file: %" PRIuINUM,
            inum);
        return 1;
    }


    /* first look up the thread record for the item we're searching for */

    /* set up the thread record key */
    memset((char *) &key, 0, sizeof(hfs_btree_key_cat));
    cnid_to_array((uint32_t) inum, key.parent_cnid);

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_cat_file_lookup: Looking up thread record (%" PRIuINUM
            ")\n", inum);

    /* look up the thread record */
    off = hfs_cat_get_record_offset(hfs, &key);
    if (off == 0) {
        // no parsing error, just not found
        if (tsk_error_get_errno() == 0) {
            tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
            tsk_error_set_errstr
                ("hfs_cat_file_lookup: Error finding thread node for file (%"
                PRIuINUM ")", inum);
        }
        else {
            tsk_error_set_errstr2
                (" hfs_cat_file_lookup: thread for file (%" PRIuINUM ")",
                inum);
        }
        return 1;
    }

    /* read the thread record */
    if (hfs_cat_read_thread_record(hfs, off, &thread)) {
        tsk_error_set_errstr2(" hfs_cat_file_lookup: file (%" PRIuINUM ")",
            inum);
        return 1;
    }

    /* now look up the actual file/folder record */

    /* build key */
    memset((char *) &key, 0, sizeof(hfs_btree_key_cat));
    memcpy((char *) key.parent_cnid, (char *) thread.parent_cnid,
        sizeof(key.parent_cnid));
    memcpy((char *) &key.name, (char *) &thread.name, sizeof(key.name));

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_cat_file_lookup: Looking up file record (parent: %"
            PRIuINUM ")\n", (uint64_t) tsk_getu32(fs->endian,
                key.parent_cnid));

    /* look up the record */
    off = hfs_cat_get_record_offset(hfs, &key);
    if (off == 0) {
        // no parsing error, just not found
        if (tsk_error_get_errno() == 0) {
            tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
            tsk_error_set_errstr
                ("hfs_cat_file_lookup: Error finding record node %"
                PRIuINUM, inum);
        }
        else {
            tsk_error_set_errstr2(" hfs_cat_file_lookup: file (%" PRIuINUM
                ")", inum);
        }
        return 1;
    }

    /* read the record */
    if (hfs_cat_read_file_folder_record(hfs, off, &record)) {
        tsk_error_set_errstr2(" hfs_cat_file_lookup: file (%" PRIuINUM ")",
            inum);
        return 1;
    }

    /* these memcpy can be gotten rid of, really */
    if (tsk_getu16(fs->endian,
            record.file.std.rec_type) == HFS_FOLDER_RECORD) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_cat_file_lookup: found folder record valence %" PRIu32
                ", cnid %" PRIu32 "\n", tsk_getu32(fs->endian,
                    record.folder.std.valence), tsk_getu32(fs->endian,
                    record.folder.std.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_folder));
    }
    else if (tsk_getu16(fs->endian,
            record.file.std.rec_type) == HFS_FILE_RECORD) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_cat_file_lookup: found file record cnid %" PRIu32
                "\n", tsk_getu32(fs->endian, record.file.std.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_file));
    }
    /* other cases already caught by hfs_cat_read_file_folder_record */

    memcpy((char *) &entry->thread, (char *) &thread, sizeof(hfs_thread));

    entry->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;
    entry->inum = inum;

    if (follow_hard_link) {
        // TEST to see if this is a hard link
        unsigned char is_err;
        TSK_INUM_T target_cnid =
            hfs_follow_hard_link(hfs, &(entry->cat), &is_err);
        if (is_err > 1) {
            error_returned
                ("hfs_cat_file_lookup: error occurred while following a possible hard link for "
                "inum (cnid) =  %" PRIuINUM, inum);
            return 1;
        }
        if (target_cnid != inum) {
            // This is a hard link, and we have got the cnid of the target file, so look it up.
            uint8_t res =
                hfs_cat_file_lookup(hfs, target_cnid, entry, FALSE);
            if (res != 0) {
                error_returned
                    ("hfs_cat_file_lookup: error occurred while looking up the Catalog entry for "
                    "the target of inum (cnid) = %" PRIuINUM " target",
                    inum);
            }
            return 1;
        }

        // Target is NOT a hard link, so fall through to the non-hard link exit.
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_cat_file_lookup exiting\n");
    return 0;
}


/** \internal
* Returns the largest inode number in file system
* @param hfs File system being analyzed
* @returns largest metadata address
*/
static TSK_INUM_T
hfs_find_highest_inum(HFS_INFO * hfs)
{
    // @@@ get actual number from Catalog file (go to far right) (we can't always trust the vol header)
    /* I haven't gotten looking at the end of the Catalog B-Tree to work
       properly. A fast method: if HFS_VH_ATTR_CNIDS_REUSED is set, then
       the maximum CNID is 2^32-1; if it's not set, then nextCatalogId is
       supposed to be larger than all CNIDs on disk.
     */

    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    if (tsk_getu32(fs->endian, hfs->fs->attr) & HFS_VH_ATTR_CNIDS_REUSED)
        return (TSK_INUM_T) 0xffffffff;
    else
        return (TSK_INUM_T) tsk_getu32(fs->endian,
            hfs->fs->next_cat_id) - 1;
}


static TSK_FS_META_MODE_ENUM
hfs_mode_to_tsk_mode(uint16_t a_mode)
{
    TSK_FS_META_MODE_ENUM mode = 0;

    if (a_mode & HFS_IN_ISUID)
        mode |= TSK_FS_META_MODE_ISUID;
    if (a_mode & HFS_IN_ISGID)
        mode |= TSK_FS_META_MODE_ISGID;
    if (a_mode & HFS_IN_ISVTX)
        mode |= TSK_FS_META_MODE_ISVTX;

    if (a_mode & HFS_IN_IRUSR)
        mode |= TSK_FS_META_MODE_IRUSR;
    if (a_mode & HFS_IN_IWUSR)
        mode |= TSK_FS_META_MODE_IWUSR;
    if (a_mode & HFS_IN_IXUSR)
        mode |= TSK_FS_META_MODE_IXUSR;

    if (a_mode & HFS_IN_IRGRP)
        mode |= TSK_FS_META_MODE_IRGRP;
    if (a_mode & HFS_IN_IWGRP)
        mode |= TSK_FS_META_MODE_IWGRP;
    if (a_mode & HFS_IN_IXGRP)
        mode |= TSK_FS_META_MODE_IXGRP;

    if (a_mode & HFS_IN_IROTH)
        mode |= TSK_FS_META_MODE_IROTH;
    if (a_mode & HFS_IN_IWOTH)
        mode |= TSK_FS_META_MODE_IWOTH;
    if (a_mode & HFS_IN_IXOTH)
        mode |= TSK_FS_META_MODE_IXOTH;

    return mode;
}

static TSK_FS_META_TYPE_ENUM
hfs_mode_to_tsk_meta_type(uint16_t a_mode)
{
    switch (a_mode & HFS_IN_IFMT) {
    case HFS_IN_IFIFO:
        return TSK_FS_META_TYPE_FIFO;
    case HFS_IN_IFCHR:
        return TSK_FS_META_TYPE_CHR;
    case HFS_IN_IFDIR:
        return TSK_FS_META_TYPE_DIR;
    case HFS_IN_IFBLK:
        return TSK_FS_META_TYPE_BLK;
    case HFS_IN_IFREG:
        return TSK_FS_META_TYPE_REG;
    case HFS_IN_IFLNK:
        return TSK_FS_META_TYPE_LNK;
    case HFS_IN_IFSOCK:
        return TSK_FS_META_TYPE_SOCK;
    case HFS_IFWHT:
        return TSK_FS_META_TYPE_WHT;
    case HFS_IFXATTR:
        return TSK_FS_META_TYPE_UNDEF;
    default:
        /* error */
        return TSK_FS_META_TYPE_UNDEF;
    }
}


static uint8_t
hfs_make_specialbase(TSK_FS_FILE * fs_file)
{
    fs_file->meta->type = TSK_FS_META_TYPE_REG;
    fs_file->meta->mode = 0;
    fs_file->meta->nlink = 1;
    fs_file->meta->flags =
        (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_file->meta->uid = fs_file->meta->gid = 0;
    fs_file->meta->mtime = fs_file->meta->atime = fs_file->meta->ctime =
        fs_file->meta->crtime = 0;
    fs_file->meta->mtime_nano = fs_file->meta->atime_nano =
        fs_file->meta->ctime_nano = fs_file->meta->crtime_nano = 0;

    if (fs_file->meta->name2 == NULL) {
        if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL) {
            error_returned
                (" - hfs_make_specialbase, couldn't malloc space for a name list");
            return 1;
        }
        fs_file->meta->name2->next = NULL;
    }

    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }
    return 0;
}

/**
 * \internal
 * Create an FS_INODE structure for the catalog file. 
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_catalog(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;
    unsigned char dummy1, dummy2;
    uint64_t dummy3;
    uint8_t result;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_catalog: Making virtual catalog file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_catalog");
        return 1;
    }

    fs_file->meta->addr = HFS_CATALOG_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_CATALOGNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz);


    // convert the  runs in the volume header to attribute runs 
    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->cat_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        error_returned(" - hfs_make_catalog");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_catalog");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz), 0, 0)) {
        error_returned(" - hfs_make_catalog");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_CATALOG_FILE_ID, fs_attr,
            TRUE)) {
        error_returned(" - hfs_make_catalog");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    result = hfs_load_extended_attrs(fs_file, &dummy1, &dummy2, &dummy3);
    if (result != 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "WARNING: Extended attributes failed to load for the Catalog file.\n");
        tsk_error_reset();
    }

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

/**
* \internal
 * Create an FS_FILE for the extents file
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_extents(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_extents: Making virtual extents file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_extents");
        return 1;
    }

    fs_file->meta->addr = HFS_EXTENTS_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_EXTENTSNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz);


    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->ext_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        error_returned(" - hfs_make_extents");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_extents");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz), 0, 0)) {
        error_returned(" - hfs_make_extents");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    //hfs_load_extended_attrs(fs_file);

    // Extents doesn't have an entry in itself

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}


/**
 * \internal
 * Create an FS_INODE structure for the blockmap / allocation file. 
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_blockmap(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;
    unsigned char dummy1, dummy2;
    uint64_t dummy3;
    uint8_t result;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_blockmap: Making virtual blockmap file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_blockmap");
        return 1;
    }

    fs_file->meta->addr = HFS_ALLOCATION_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_ALLOCATIONNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->alloc_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        error_returned(" - hfs_make_blockmap");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_blockmap");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz), 0, 0)) {
        error_returned(" - hfs_make_blockmap");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_ALLOCATION_FILE_ID,
            fs_attr, TRUE)) {
        error_returned(" - hfs_make_blockmap");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }


    result = hfs_load_extended_attrs(fs_file, &dummy1, &dummy2, &dummy3);
    if (result != 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "WARNING: Extended attributes failed to load for the Allocation file.\n");
        tsk_error_reset();
    }

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

/**
* \internal
 * Create an FS_INODE structure for the startup / boot file. 
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_startfile(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;
    unsigned char dummy1, dummy2;
    uint64_t dummy3;
    uint8_t result;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_startfile: Making virtual startup file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_startfile");
        return 1;
    }

    fs_file->meta->addr = HFS_STARTUP_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_STARTUPNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->start_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        error_returned(" - hfs_make_startfile");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_startfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz), 0, 0)) {
        error_returned(" - hfs_make_startfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_STARTUP_FILE_ID, fs_attr,
            TRUE)) {
        error_returned(" - hfs_make_startfile");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    result = hfs_load_extended_attrs(fs_file, &dummy1, &dummy2, &dummy3);
    if (result != 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "WARNING: Extended attributes failed to load for the Start file.\n");
        tsk_error_reset();
    }

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}


/**
 * \internal
 * Create an FS_INODE structure for the attributes file. 
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_attrfile(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_attrfile: Making virtual attributes file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_attrfile");
        return 1;
    }

    fs_file->meta->addr = HFS_ATTRIBUTES_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_ATTRIBUTESNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->attr_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        error_returned(" - hfs_make_attrfile");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_attrfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz), 0, 0)) {
        error_returned(" - hfs_make_attrfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_ATTRIBUTES_FILE_ID,
            fs_attr, TRUE)) {
        error_returned(" - hfs_make_attrfile");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    //hfs_load_extended_attrs(fs_file);

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}



/**
 * \internal
 * Create an FS_FILE structure for the BadBlocks file. 
 *
 * @param hfs File system to analyze
 * @param fs_file Structure to copy file information into.
 * @return 1 on error and 0 on success
 */
static uint8_t
hfs_make_badblockfile(HFS_INFO * hfs, TSK_FS_FILE * fs_file)
{
    TSK_FS_ATTR *fs_attr;
    unsigned char dummy1, dummy2;
    uint64_t dummy3;
    uint8_t result;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_badblockfile: Making virtual badblock file\n");

    if (hfs_make_specialbase(fs_file)) {
        error_returned(" - hfs_make_badblockfile");
        return 1;
    }

    fs_file->meta->addr = HFS_BAD_BLOCK_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_BAD_BLOCK_FILE_NAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size = 0;

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        error_returned(" - hfs_make_badblockfile");
        return 1;
    }

    // add the run to the file.
    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, HFS_FS_ATTR_ID_DATA,
            fs_file->meta->size, fs_file->meta->size, fs_file->meta->size,
            0, 0)) {
        error_returned(" - hfs_make_badblockfile");
        return 1;
    }

    // see if file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_BAD_BLOCK_FILE_ID,
            fs_attr, TRUE)) {
        error_returned(" - hfs_make_badblockfile");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    /* @@@ We have a chicken and egg problem here...  The current design of 
     * fs_attr_set() requires the size to be set, but we dont' know the size
     * until we look into the extents file (which adds to an attribute...).
     * This does not seem to be the best design...  neeed a way to test this. */
    fs_file->meta->size = fs_attr->nrd.initsize;
    fs_attr->size = fs_file->meta->size;
    fs_attr->nrd.allocsize = fs_file->meta->size;

    result = hfs_load_extended_attrs(fs_file, &dummy1, &dummy2, &dummy3);
    if (result != 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "WARNING: Extended attributes failed to load for the BadBlocks file.\n");
        tsk_error_reset();
    }

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}


/** \internal
 * Copy the catalog file or folder record entry into a TSK data structure. 
 * @param a_hfs File system being analyzed
 * @param a_hfs_entry Catalog record entry (HFS_ENTRY *)
 * @param a_fs_file Structure to copy data into (TSK_FS_FILE *)
 * Returns 1 on error.
 */
static uint8_t
hfs_dinode_copy(HFS_INFO * a_hfs, const HFS_ENTRY * a_hfs_entry,
    TSK_FS_FILE * a_fs_file)
{

    // Note, a_hfs_entry->cat is really of type hfs_file.  But, hfs_file_folder is a union
    // of that type with hfs_folder.  Both of hfs_file and hfs_folder have the same first member.
    // So, this cast is appropriate.
    const hfs_file_folder *a_entry =
        (hfs_file_folder *) & (a_hfs_entry->cat);
    const hfs_file_fold_std *std;
    TSK_FS_META *a_fs_meta = a_fs_file->meta;
    TSK_FS_INFO *fs;
    uint16_t hfsmode;
    TSK_INUM_T iStd;            // the inum (or CNID) that occurs in the standard file metadata

    if (a_entry == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_dinode_copy: a_entry = a_hfs_entry->cat is NULL");
        return 1;
    }

    fs = (TSK_FS_INFO *) & a_hfs->fs_info;


    // Just a sanity check.  The inum (or cnid) occurs in two places in the
    // entry data structure.
    iStd = tsk_getu32(fs->endian, a_entry->file.std.cnid);
    if (iStd != a_hfs_entry->inum) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "WARNING: hfs_dinode_copy:  HFS_ENTRY with conflicting values for inum (or cnid).\n");
    }

    if (a_fs_meta == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_dinode_copy: a_fs_meta is NULL");
        return 1;
    }

    // both files and folders start off the same
    std = &(a_entry->file.std);

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_dinode_copy: called for file/folder %" PRIu32 "\n",
            tsk_getu32(fs->endian, std->cnid));

    if (a_fs_meta->content_len < HFS_FILE_CONTENT_LEN) {
        if ((a_fs_meta =
                tsk_fs_meta_realloc(a_fs_meta,
                    HFS_FILE_CONTENT_LEN)) == NULL) {
            return 1;
        }
    }
    a_fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (a_fs_meta->attr) {
        tsk_fs_attrlist_markunused(a_fs_meta->attr);
    }


    /* 
     * Copy the file type specific stuff first 
     */
    hfsmode = tsk_getu16(fs->endian, std->perm.mode);

    if (tsk_getu16(fs->endian, std->rec_type) == HFS_FOLDER_RECORD) {
        // set the type of mode is not set
        if ((hfsmode & HFS_IN_IFMT) == 0)
            a_fs_meta->type = TSK_FS_META_TYPE_DIR;
        a_fs_meta->size = 0;
        memset(a_fs_meta->content_ptr, 0, HFS_FILE_CONTENT_LEN);
    }
    else if (tsk_getu16(fs->endian, std->rec_type) == HFS_FILE_RECORD) {
        hfs_fork *fork;
        // set the type of mode is not set
        if ((hfsmode & HFS_IN_IFMT) == 0)
            a_fs_meta->type = TSK_FS_META_TYPE_REG;
        a_fs_meta->size =
            tsk_getu64(fs->endian, a_entry->file.data.logic_sz);

        // copy the data and resource forks
        fork = (hfs_fork *) a_fs_meta->content_ptr;
        memcpy(fork, &(a_entry->file.data), sizeof(hfs_fork));
        memcpy(&fork[1], &(a_entry->file.resource), sizeof(hfs_fork));
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_dinode_copy error: catalog entry is neither file nor folder\n");
        return 1;
    }

    /*
     * Copy the standard stuff.  
     * Use default values (as defined in spec) if mode is not defined.
     */
    if ((hfsmode & HFS_IN_IFMT) == 0) {
        a_fs_meta->mode = 0;
        a_fs_meta->uid = 99;
        a_fs_meta->gid = 99;
    }
    else {
        a_fs_meta->mode = hfs_mode_to_tsk_mode(hfsmode);
        a_fs_meta->type = hfs_mode_to_tsk_meta_type(hfsmode);
        a_fs_meta->uid = tsk_getu32(fs->endian, std->perm.owner);
        a_fs_meta->gid = tsk_getu32(fs->endian, std->perm.group);
    }

    // this field is set only for "indirect" entries
    if (tsk_getu32(fs->endian, std->perm.special.nlink))
        a_fs_meta->nlink = tsk_getu32(fs->endian, std->perm.special.nlink);
    else
        a_fs_meta->nlink = 1;

    a_fs_meta->mtime =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, std->cmtime));
    a_fs_meta->atime =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, std->atime));
    a_fs_meta->crtime =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, std->crtime));
    a_fs_meta->ctime =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, std->amtime));
    a_fs_meta->time2.hfs.bkup_time =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, std->bkup_date));
    a_fs_meta->mtime_nano = a_fs_meta->atime_nano = a_fs_meta->ctime_nano =
        a_fs_meta->crtime_nano = 0;
    a_fs_meta->time2.hfs.bkup_time_nano = 0;


    a_fs_meta->addr = tsk_getu32(fs->endian, std->cnid);

    // All entries here are used.  
    a_fs_meta->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;

    if (std->perm.o_flags & HFS_PERM_OFLAG_COMPRESSED)
        a_fs_meta->flags |= TSK_FS_META_FLAG_COMP;

    // We copy this inum (or cnid) here, because this file *might* have been a hard link.  In
    // that case, we want to make sure that a_fs_file points consistently to the target of the
    // link.

    if (a_fs_file->name != NULL) {
        a_fs_file->name->meta_addr = a_fs_meta->addr;
    }

    /* TODO @@@ could fill in name2 with this entry's name and parent inode
       from Catalog entry */

    /* set the link string (if the file is a link)
     * The size check is a sanity check so that we don't try to allocate
     * a huge amount of memory for a bad inode value
     */
    if ((a_fs_meta->type == TSK_FS_META_TYPE_LNK) &&
        (a_fs_meta->size >= 0) && (a_fs_meta->size < HFS_MAXPATHLEN)) {

        ssize_t bytes_read;

        a_fs_meta->link = tsk_malloc((size_t) a_fs_meta->size + 1);
        if (a_fs_meta->link == NULL)
            return 1;

        bytes_read = tsk_fs_file_read(a_fs_file, (TSK_OFF_T) 0,
            a_fs_meta->link, (size_t) a_fs_meta->size,
            TSK_FS_FILE_READ_FLAG_NONE);
        a_fs_meta->link[a_fs_meta->size] = '\0';

        if (bytes_read != a_fs_meta->size) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_dinode_copy: failed to read contents of symbolic link; "
                    "expected %u bytes but tsk_fs_file_read() returned %u\n",
                    a_fs_meta->size, bytes_read);
            free(a_fs_meta->link);
            a_fs_meta->link = NULL;
            return 1;
        }
    }

    return 0;
}


/** \internal
 * Load a catalog file entry and save it in the TSK_FS_FILE structure. 
 * 
 * @param fs File system to read from.
 * @param a_fs_file Structure to read into. 
 * @param inum File address to load
 * @returns 1 on error 
 */
static uint8_t
hfs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    HFS_ENTRY entry;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_inode_lookup: fs_file is NULL");
        return 1;
    }

    if (a_fs_file->meta == NULL) {
        a_fs_file->meta = tsk_fs_meta_alloc(HFS_FILE_CONTENT_LEN);
    }
    if (a_fs_file->meta == NULL) {
        return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_inode_lookup: looking up %" PRIuINUM "\n",
            inum);

    // @@@ Will need to add orphan stuff here too

    /* First see if this is a special entry
     * the special ones have their metadata stored in the volume header */
    if (inum == HFS_EXTENTS_FILE_ID) {
        if (!hfs->has_extents_file) {
            error_detected(TSK_ERR_FS_INODE_NUM,
                "Extents File not present");
            return 1;
        }
        if (hfs_make_extents(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else if (inum == HFS_CATALOG_FILE_ID) {
        if (hfs_make_catalog(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else if (inum == HFS_BAD_BLOCK_FILE_ID) {
        // Note: the Extents file and the BadBlocks file are really the same.
        if (!hfs->has_extents_file) {
            error_detected(TSK_ERR_FS_INODE_NUM,
                "BadBlocks File not present");
            return 1;
        }
        if (hfs_make_badblockfile(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else if (inum == HFS_ALLOCATION_FILE_ID) {
        if (hfs_make_blockmap(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else if (inum == HFS_STARTUP_FILE_ID) {
        if (!hfs->has_startup_file) {
            error_detected(TSK_ERR_FS_INODE_NUM,
                "Startup File not present");
            return 1;
        }
        if (hfs_make_startfile(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }
    else if (inum == HFS_ATTRIBUTES_FILE_ID) {
        if (!hfs->has_attributes_file) {
            error_detected(TSK_ERR_FS_INODE_NUM,
                "Attributes File not present");
            return 1;
        }
        if (hfs_make_attrfile(hfs, a_fs_file)) {
            return 1;
        }
        else {
            return 0;
        }
    }

    /* Lookup inode and store it in the HFS structure */
    if (hfs_cat_file_lookup(hfs, inum, &entry, TRUE)) {
        return 1;
    }

    /* Copy the structure in hfs to generic fs_inode */
    if (hfs_dinode_copy(hfs, &entry, a_fs_file)) {
        return 1;
    }

    /* If this is potentially a compressed file, its
     * actual size is unknown until we examine the
     * extended attributes */
    if ((a_fs_file->meta->size == 0) &&
        (a_fs_file->meta->type == TSK_FS_META_TYPE_REG) &&
        (a_fs_file->meta->attr_state != TSK_FS_META_ATTR_ERROR) &&
        ((a_fs_file->meta->attr_state != TSK_FS_META_ATTR_STUDIED) ||
            (a_fs_file->meta->attr == NULL))) {
        hfs_load_attrs(a_fs_file);
    }

    return 0;
}

#ifdef HAVE_LIBZ

typedef struct {
    uint32_t offset;
    uint32_t length;
} CMP_OFFSET_ENTRY;


uint8_t
hfs_attr_walk_special(const TSK_FS_ATTR * fs_attr,
    int flags, TSK_FS_FILE_WALK_CB a_action, void *ptr)
{
    TSK_FS_INFO *fs;
    TSK_ENDIAN_ENUM endian;
    TSK_FS_FILE *fs_file;
    const TSK_FS_ATTR *rAttr;   // resource fork attribute
    char *rawBuf;               // compressed data
    char *uncBuf;               // uncompressed data
    hfs_resource_fork_header rfHeader;
    int attrReadResult;
    uint32_t offsetTableOffset;
    char fourBytes[4];          // Will hold the number of table entries, little endian
    uint32_t tableSize;         // The number of table entries
    hfs_resource_fork_header *resHead;
    uint32_t dataOffset;
    char *offsetTableData;
    CMP_OFFSET_ENTRY *offsetTable;
    size_t indx;                // index for looping over the offset table
    TSK_OFF_T off = 0;          // the offset in the uncompressed data stream consumed thus far

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_attr_walk_special:  Entered, because this is a compressed file with compressed data in the resource fork\n");

    // clean up any error messages that are lying around
    tsk_error_reset();
    if ((fs_attr == NULL) || (fs_attr->fs_file == NULL)
        || (fs_attr->fs_file->meta == NULL)
        || (fs_attr->fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ntfs_attr_walk_special: Null arguments given\n");
        return 1;
    }

    // Check that the ATTR being read is the main DATA resource, 128-0, because this is the
    // only one that can be compressed in HFS+
    if ((fs_attr->id != HFS_FS_ATTR_ID_DATA) ||
        (fs_attr->type != TSK_FS_ATTR_TYPE_HFS_DATA)) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_attr_walk_special: arg specified an attribute %u-%u that is not the data fork, "
            "Only the data fork can be compressed.", fs_attr->type,
            fs_attr->id);
        return 1;
    }

    fs = fs_attr->fs_file->fs_info;
    //hfs = (HFS_INFO *) fs;
    endian = fs->endian;

    /* This MUST be a compressed attribute     */
    if (!(fs_attr->flags & TSK_FS_ATTR_COMP)) {
        error_detected(TSK_ERR_FS_FWALK,
            "hfs_attr_walk_special: called with non-special attribute: %x",
            fs_attr->flags);
        return 1;
    }

    /********  Open the Resource Fork ***********/
    // The file
    fs_file = fs_attr->fs_file;

    // find the attribute for the resource fork
    rAttr =
        tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_HFS_RSRC,
        HFS_FS_ATTR_ID_RSRC, TRUE);
    if (rAttr == NULL) {
        error_returned
            (" hfs_attr_walk_special: could not get the attribute for the resource fork of the file");
        return 1;
    }

    // Allocate two buffers of the compression unit size.
    rawBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    uncBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    if (rawBuf == NULL || uncBuf == NULL) {
        error_returned
            (" hfs_attr_walk_special: buffers for reading and uncompressing");
        return 1;
    }

    // Read the resource fork header
    attrReadResult = tsk_fs_attr_read(rAttr, 0, (char *) &rfHeader,
        sizeof(hfs_resource_fork_header), TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != sizeof(hfs_resource_fork_header)) {
        error_returned
            (" hfs_attr_walk_special: trying to read the resource fork header");
        free(rawBuf);
        free(uncBuf);
        return 1;
    }

    // Begin to parse the resource fork.  For now, we just need the data offset.  But
    // eventually we'll want the other quantities as well.
    // We are assuming that there is exactly one resource, and that this contains the compressed
    // data.  This assumption is true in all examples we have seen.  More general code would
    // parse the Resource Fork map, and find the appropriate entry, then jump to THAT data offset.
    resHead = &rfHeader;
    dataOffset = tsk_getu32(endian, resHead->dataOffset);
    //uint32_t mapOffset = tsk_getu32(endian, resHead->mapOffset);
    //uint32_t dataLength = tsk_getu32(endian, resHead->dataLength);
    //uint32_t mapLength = tsk_getu32(endian, resHead->mapLength);

    // The resource's data begins with an offset table, which defines blocks
    // of (optionally) zlib-compressed data (so that the OS can do file seeks
    // efficiently; each uncompressed block is 64KB).
    offsetTableOffset = dataOffset + 4;

    // read 4 bytes, the number of table entries, little endian
    attrReadResult =
        tsk_fs_attr_read(rAttr, offsetTableOffset, fourBytes, 4,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != 4) {
        error_returned
            (" hfs_attr_walk_special: trying to read the offset table size, "
            "return value of %u should have been 4", attrReadResult);
        free(rawBuf);
        free(uncBuf);
        return 1;
    }
    tableSize = tsk_getu32(TSK_LIT_ENDIAN, fourBytes);

    // Each table entry is 8 bytes long
    offsetTableData = (char *) tsk_malloc(tableSize * 8);
    if (offsetTableData == NULL) {
        error_returned
            (" hfs_attr_walk_special: space for the offset table raw data");
        free(rawBuf);
        free(uncBuf);
        return 1;
    }
    offsetTable =
        (CMP_OFFSET_ENTRY *) tsk_malloc(tableSize *
        sizeof(CMP_OFFSET_ENTRY));
    if (offsetTable == NULL) {
        error_returned
            (" hfs_attr_walk_special: space for the offset table");
        free(offsetTableData);
        free(rawBuf);
        free(uncBuf);
        return 1;
    }

    attrReadResult = tsk_fs_attr_read(rAttr, offsetTableOffset + 4,
        offsetTableData, tableSize * 8, TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != tableSize * 8) {
        error_returned
            (" hfs_attr_walk_special: reading in the compression offset table, "
            "return value %u should have been %u", attrReadResult,
            tableSize * 8);
        free(offsetTableData);
        free(offsetTable);
        free(rawBuf);
        free(uncBuf);
        return 1;
    }

    for (indx = 0; indx < tableSize; indx++) {
        offsetTable[indx].offset =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8);
        offsetTable[indx].length =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8 + 4);
    }

    // FOR entry in the table DO
    for (indx = 0; indx < tableSize; indx++) {
        uint32_t offset = offsetTableOffset + offsetTable[indx].offset;
        uint32_t len = offsetTable[indx].length;
        uint64_t uncLen;        // uncompressed length
        unsigned int blockSize;
        uint64_t lumpSize;
        uint64_t remaining;
        char *lumpStart;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_attr_walk_special: reading one compression unit, number %d, length %d\n",
                indx, len);

        // Read in the chunk of (potentially) compressed data
        attrReadResult = tsk_fs_attr_read(rAttr, offset,
            rawBuf, len, TSK_FS_FILE_READ_FLAG_NONE);
        if (attrReadResult != len) {
            if (attrReadResult < 0)
                error_returned
                    (" hfs_attr_walk_special: reading in the compression offset table, "
                    "return value %u should have been %u", attrReadResult,
                    len);
            else
                error_detected(TSK_ERR_FS_READ,
                    "hfs_attr_walk_special: reading in the compression offset table, "
                    "return value %u should have been %u", attrReadResult,
                    len);
            free(offsetTableData);
            free(offsetTable);
            free(rawBuf);
            free(uncBuf);
            return 1;
        }

        // see if this block is compressed
        if ((len > 0) && ((rawBuf[0] & 0x0F) != 0x0F)) {

            unsigned long bytesConsumed;
            int infResult;

            // Uncompress the chunk of data
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_attr_walk_special: Inflating the compression unit\n");

            infResult = zlib_inflate(rawBuf, (uint64_t) len,
                uncBuf, (uint64_t) COMPRESSION_UNIT_SIZE,
                &uncLen, &bytesConsumed);
            if (infResult != 0) {
                error_returned
                    (" hfs_attr_walk_special: zlib inflation (uncompression) failed",
                    infResult);
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return 1;
            }

        }
        else {

            // actually an uncompressed block of data; just copy
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_attr_walk_special: Copying an uncompressed compression unit\n");

            if ((len - 1) > COMPRESSION_UNIT_SIZE) {
                error_detected(TSK_ERR_FS_READ,
                    "hfs_attr_walk_special: uncompressed block length %u is longer "
                    "than compression unit size %u", len - 1,
                    COMPRESSION_UNIT_SIZE);
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return 1;
            }
            memcpy(uncBuf, rawBuf + 1, len - 1);
            uncLen = len - 1;
        }

        // Call the a_action callback with "Lumps" that are at most the block size.
        blockSize = fs->block_size;
        remaining = uncLen;
        lumpStart = uncBuf;

        while (remaining > 0) {
            int retval;         // action return value
            if (remaining <= blockSize)
                lumpSize = remaining;
            else
                lumpSize = blockSize;

            // Apply the callback function
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_attr_walk_special: Calling action on lump of size %"
                    PRIu64 " offset %" PRIu64 " in the compression unit\n",
                    lumpSize, uncLen - remaining);
            if (lumpSize > SIZE_MAX) {
                error_detected(TSK_ERR_FS_FWALK,
                    " hfs_attr_walk_special: lumpSize is too large for the action");
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return 1;
            }
            retval = a_action(fs_attr->fs_file, off, 0, lumpStart, (size_t) lumpSize,   // cast OK because of above test
                TSK_FS_BLOCK_FLAG_COMP, ptr);

            if (retval == TSK_WALK_ERROR) {
                error_detected(TSK_ERR_FS | 201,
                    "hfs_attr_walk_special: callback returned an error");
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return 1;
            }
            if (retval == TSK_WALK_STOP)
                break;

            // Find the next lump
            off += lumpSize;
            remaining -= lumpSize;
            lumpStart += lumpSize;
        }
    }

    // Done, so free up the allocated resources.
    free(offsetTableData);
    free(offsetTable);
    free(rawBuf);
    free(uncBuf);
    return 0;
}


/** \internal
 *
 * @returns number of bytes read or -1 on error (incl if offset is past EOF)
 */
ssize_t
hfs_file_read_special(const TSK_FS_ATTR * a_fs_attr,
    TSK_OFF_T a_offset, char *a_buf, size_t a_len)
{
    TSK_FS_INFO *fs = NULL;
    TSK_ENDIAN_ENUM endian;
    TSK_FS_FILE *fs_file;
    const TSK_FS_ATTR *rAttr;
    char *rawBuf;
    char *uncBuf;
    hfs_resource_fork_header rfHeader;
    int attrReadResult;
    hfs_resource_fork_header *resHead;
    uint32_t dataOffset;
    uint32_t offsetTableOffset;
    char fourBytes[4];          // Size of the offset table, little endian
    uint32_t tableSize;         // Size of the offset table
    char *offsetTableData;
    CMP_OFFSET_ENTRY *offsetTable;
    size_t indx;                // index for looping over the offset table
    uint64_t sizeUpperBound;
    uint64_t cummulativeSize = 0;
    uint32_t startUnit = 0;
    uint32_t startUnitOffset = 0;
    uint32_t endUnit = 0;
    uint64_t bytesCopied;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_file_read_special: called because this file is compressed, with data in the resource fork\n");

    // Reading zero bytes?  OK at any offset, I say!
    if (a_len == 0)
        return 0;

    if (a_offset < 0 || a_len < 0) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: reading from file at a negative offset, or negative length");
        return -1;
    }

    if (a_len > SIZE_MAX / 2) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: trying to read more than SIZE_MAX/2 is not supported.");
        return -1;
    }

    if ((a_fs_attr == NULL) || (a_fs_attr->fs_file == NULL)
        || (a_fs_attr->fs_file->meta == NULL)
        || (a_fs_attr->fs_file->fs_info == NULL)) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: NULL parameters passed");
        return -1;
    }

    fs = a_fs_attr->fs_file->fs_info;
    //hfs = (HFS_INFO *) fs;
    endian = fs->endian;

    // This should be a compressed file.  If not, that's an error!
    if (!(a_fs_attr->flags & TSK_FS_ATTR_COMP)) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: called with non-special attribute: %x",
            a_fs_attr->flags);
        return -1;
    }

    // Check that the ATTR being read is the main DATA resource, 4352-0, because this is the
    // only one that can be compressed in HFS+
    if ((a_fs_attr->id != HFS_FS_ATTR_ID_DATA) ||
        (a_fs_attr->type != TSK_FS_ATTR_TYPE_HFS_DATA)) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: arg specified an attribute %u-%u that is not the data fork, "
            "Only the data fork can be compressed.", a_fs_attr->type,
            a_fs_attr->id);
        return -1;
    }

    /********  Open the Resource Fork ***********/
    // The file
    fs_file = a_fs_attr->fs_file;

    // find the attribute for the resource fork
    rAttr =
        tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_HFS_RSRC,
        HFS_FS_ATTR_ID_RSRC, TRUE);
    if (rAttr == NULL) {
        error_returned
            (" hfs_file_read_special: could not get the attribute for the resource fork of the file");
        return -1;
    }

    // Allocate two buffers of the compression unit size.
    rawBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    if (rawBuf == NULL) {
        error_returned
            (" hfs_file_read_special: buffers for reading and uncompressing");
        return -1;
    }
    uncBuf = (char *) tsk_malloc(COMPRESSION_UNIT_SIZE);
    if (uncBuf == NULL) {
        error_returned
            (" hfs_file_read_special: buffers for reading and uncompressing");
        free(rawBuf);
        return -1;
    }

    // Read the resource fork header
    attrReadResult = tsk_fs_attr_read(rAttr, 0, (char *) &rfHeader,
        sizeof(hfs_resource_fork_header), TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != sizeof(hfs_resource_fork_header)) {
        error_returned
            (" hfs_file_read_special: trying to read the resource fork header");
        free(rawBuf);
        free(uncBuf);
        return -1;
    }

    // Begin to parse the resource fork.  For now, we just need the data offset.  But
    // eventually we'll want the other quantities as well.
    resHead = &rfHeader;
    dataOffset = tsk_getu32(endian, resHead->dataOffset);
    //uint32_t mapOffset = tsk_getu32(endian, resHead->mapOffset);
    //uint32_t dataLength = tsk_getu32(endian, resHead->dataLength);
    //uint32_t mapLength = tsk_getu32(endian, resHead->mapLength);

    // The resource's data begins with an offset table, which defines blocks
    // of (optionally) zlib-compressed data (so that the OS can do file seeks
    // efficiently; each uncompressed block is 64KB).
    offsetTableOffset = dataOffset + 4;

    // read 4 bytes, the number of table entries, little endian
    attrReadResult =
        tsk_fs_attr_read(rAttr, offsetTableOffset, fourBytes, 4,
        TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != 4) {
        error_returned
            (" hfs_file_read_special: trying to read the offset table size, "
            "return value of %u should have been 4", attrReadResult);
        free(rawBuf);
        free(uncBuf);
        return -1;
    }
    tableSize = tsk_getu32(TSK_LIT_ENDIAN, fourBytes);

    // Each table entry is 8 bytes long
    offsetTableData = tsk_malloc(tableSize * 8);
    if (offsetTableData == NULL) {
        error_returned
            (" hfs_file_read_special: space for the offset table raw data");
        free(rawBuf);
        free(uncBuf);
        return -1;
    }
    offsetTable =
        (CMP_OFFSET_ENTRY *) tsk_malloc(tableSize *
        sizeof(CMP_OFFSET_ENTRY));
    if (offsetTable == NULL) {
        error_returned
            (" hfs_file_read_special: space for the offset table");
        free(offsetTableData);
        free(rawBuf);
        free(uncBuf);
        return -1;
    }

    attrReadResult = tsk_fs_attr_read(rAttr, offsetTableOffset + 4,
        offsetTableData, tableSize * 8, TSK_FS_FILE_READ_FLAG_NONE);
    if (attrReadResult != tableSize * 8) {
        error_returned
            (" hfs_file_read_special: reading in the compression offset table, "
            "return value %u should have been %u", attrReadResult,
            tableSize * 8);
        free(offsetTableData);
        free(offsetTable);
        free(rawBuf);
        free(uncBuf);
        return -1;
    }

    for (indx = 0; indx < tableSize; indx++) {
        offsetTable[indx].offset =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8);
        offsetTable[indx].length =
            tsk_getu32(TSK_LIT_ENDIAN, offsetTableData + indx * 8 + 4);
    }

    sizeUpperBound = tableSize * COMPRESSION_UNIT_SIZE;

    // cast is OK because both a_offset and a_len are >= 0
    if ((uint64_t) (a_offset + a_len) > sizeUpperBound) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_file_read_special: range of bytes requested %lld - %lld falls outside of the length upper bound of the uncompressed stream %llu\n",
            a_offset, a_offset + a_len, sizeUpperBound);
        free(offsetTableData);
        free(offsetTable);
        free(rawBuf);
        free(uncBuf);
        return -1;
    }

    // Compute the range of compression units needed for the request
    for (indx = 0; indx < tableSize; indx++) {
        if (cummulativeSize <= (uint64_t) a_offset &&   // casts OK because a_offset >= 0
            (cummulativeSize + COMPRESSION_UNIT_SIZE >
                (uint64_t) a_offset)) {
            startUnit = indx;
            startUnitOffset = (uint32_t) (a_offset - cummulativeSize);  // This cast is OK, result can't be too large,
            // due to enclosing test.
        }

        if ((cummulativeSize < (uint64_t) (a_offset + a_len)) &&        // casts OK because a_offset and a_len > 0
            (cummulativeSize + COMPRESSION_UNIT_SIZE >=
                (uint64_t) (a_offset + a_len))) {
            endUnit = indx;
        }
        cummulativeSize += COMPRESSION_UNIT_SIZE;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_file_read_special: reading compression units: %" PRIu32
            " to %" PRIu32 "\n", startUnit, endUnit);
    bytesCopied = 0;

    // Read from the indicated comp units
    for (indx = startUnit; indx <= endUnit; indx++) {
        uint32_t offset = offsetTableOffset + offsetTable[indx].offset;
        uint32_t len = offsetTable[indx].length;
        uint64_t uncLen;
        char *uncBufPtr = uncBuf;
        size_t bytesToCopy;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_file_read_special: Reading compression unit %" PRIu32
                "\n", indx);

        // Read in the chunk of compressed data
        attrReadResult = tsk_fs_attr_read(rAttr, offset,
            rawBuf, len, TSK_FS_FILE_READ_FLAG_NONE);
        if (attrReadResult != len) {
            if (attrReadResult < 0)
                error_returned
                    (" hfs_file_read_special: reading in the compression offset table, "
                    "return value %u should have been %u", attrReadResult,
                    len);
            else
                error_detected(TSK_ERR_FS_READ,
                    "hfs_file_read_special: reading in the compression offset table, "
                    "return value %u should have been %u", attrReadResult,
                    len);
            free(offsetTableData);
            free(offsetTable);
            free(rawBuf);
            free(uncBuf);
            return -1;
        }

        // see if this block is compressed
        if ((len > 0) && ((rawBuf[0] & 0x0F) != 0x0F)) {

            unsigned long bytesConsumed;
            int infResult;

            // Uncompress the chunk of data
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_attr_read_special: Inflating the compression unit\n");

            infResult = zlib_inflate(rawBuf, (uint64_t) len,
                uncBuf, (uint64_t) COMPRESSION_UNIT_SIZE,
                &uncLen, &bytesConsumed);
            if (infResult != 0) {
                error_returned
                    (" hfs_attr_walk_special: zlib inflation (uncompression) failed",
                    infResult);
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return -1;
            }

        }
        else {

            // actually an uncompressed block of data; just copy
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_attr_read_special: Copying an uncompressed compression unit\n");

            if ((len - 1) > COMPRESSION_UNIT_SIZE) {
                error_detected(TSK_ERR_FS_READ,
                    "hfs_attr_read_special: uncompressed block length %u is longer "
                    "than compression unit size %u", len - 1,
                    COMPRESSION_UNIT_SIZE);
                free(offsetTableData);
                free(offsetTable);
                free(rawBuf);
                free(uncBuf);
                return -1;
            }
            memcpy(uncBuf, rawBuf + 1, len - 1);
            uncLen = len - 1;
        }

        // There are now uncLen bytes of uncompressed data available from this comp unit.

        // If this is the first comp unit, then we must skip over the startUnitOffset bytes.
        if (indx == startUnit) {
            uncLen -= startUnitOffset;
            uncBufPtr += startUnitOffset;
        }

        // How many bytes to copy from this compression unit?

        if (bytesCopied + uncLen < (uint64_t) a_len)    // cast OK because a_len > 0
            bytesToCopy = (size_t) uncLen;      // uncLen <= size of compression unit, which is small, so cast is OK
        else
            bytesToCopy = (size_t) (((uint64_t) a_len) - bytesCopied);  // diff <= compression unit size, so cast is OK

        // Copy into the output buffer, and update bookkeeping.
        memcpy(a_buf + bytesCopied, uncBufPtr, bytesToCopy);
        bytesCopied += bytesToCopy;
    }

    // Well, we don't know (without a lot of work) what the
    // true uncompressed size of the stream is.  All we know is the "upper bound" which
    // assumes that all of the compression units expand to their full size.  If we did
    // know the true size, then we could reject requests that go beyond the end of the
    // stream.  Instead, we treat the stream as if it is padded out to the full size of
    // the last compression unit with zeros.

    // Have we read and copied all of the bytes requested?
    if (bytesCopied < a_len) {
        // set the remaining bytes to zero
        memset(a_buf + bytesCopied, 0, a_len - (size_t) bytesCopied);   // cast OK because diff must be < compression unit size
    }

    free(offsetTableData);
    free(offsetTable);
    free(rawBuf);
    free(uncBuf);

    return (ssize_t) bytesCopied;       // cast OK, cannot be greater than a_len which cannot be
    // greater than SIZE_MAX/2 (rounded down).
}

#endif


typedef struct {
    TSK_FS_INFO *fs;            // the HFS file system
    TSK_FS_FILE *file;          // the Attributes file, if open
    hfs_btree_header_record *header;    // the Attributes btree header record.
    // For Convenience, unpacked values.
    TSK_ENDIAN_ENUM endian;
    uint32_t rootNode;
    uint16_t nodeSize;
    uint16_t maxKeyLen;
} ATTR_FILE_T;


/** \internal
 * Open the Attributes file, and read the btree header record. Fill in the fields of the ATTR_FILE_T struct.
 *
 * @param fs -- the HFS file system
 * @param header -- the header record struct
 *
 * @return 1 on error, 0 on success
 */
static uint8_t
open_attr_file(TSK_FS_INFO * fs, ATTR_FILE_T * attr_file)
{

    int cnt;                    // will hold bytes read

    hfs_btree_header_record *hrec;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (fs == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("open_attr_file: fs is NULL");
        return 1;
    }

    if (attr_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("open_attr_file: attr_file is NULL");
        return 1;
    }

    // Open the Attributes File
    attr_file->file =
        tsk_fs_file_open_meta(fs, NULL, HFS_ATTRIBUTES_FILE_ID);

    if (attr_file->file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr
            ("open_attr_file: could not open the Attributes file");
        return 1;
    }

    // Allocate some space for the Attributes btree header record (which
    //       is passed back to the caller)
    hrec = (hfs_btree_header_record *)
        malloc(sizeof(hfs_btree_header_record));

    if (hrec == NULL) {
        tsk_error_set_errno(TSK_ERR_FS);
        tsk_error_set_errstr
            ("open_attr_file: could not malloc space for Attributes header record");
        return 1;
    }

    // Read the btree header record
    cnt = tsk_fs_file_read(attr_file->file,
        14,
        (char *) hrec,
        sizeof(hfs_btree_header_record), (TSK_FS_FILE_READ_FLAG_ENUM) 0);
    if (cnt != sizeof(hfs_btree_header_record)) {
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr
            ("open_attr_file: could not open the Attributes file");
        tsk_fs_file_close(attr_file->file);
        free(hrec);
        return 1;
    }

    // Fill in the fields of the attr_file struct (which was passed in by the caller)
    attr_file->fs = fs;
    attr_file->header = hrec;
    attr_file->endian = fs->endian;
    attr_file->nodeSize = tsk_getu16(attr_file->endian, hrec->nodesize);
    attr_file->rootNode = tsk_getu32(attr_file->endian, hrec->rootNode);
    attr_file->maxKeyLen = tsk_getu16(attr_file->endian, hrec->maxKeyLen);

    return 0;
}


/** \internal
 * Closes and frees the data structures associated with ATTR_FILE_T
 */
static uint8_t
close_attr_file(ATTR_FILE_T * attr_file)
{
    if (attr_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("close_attr_file: NULL attr_file arg");
        return 1;
    }

    if (attr_file->file != NULL) {
        tsk_fs_file_close(attr_file->file);
        attr_file->file = NULL;
    }
    if (attr_file->header != NULL) {
        free(attr_file->header);
        attr_file->header = NULL;
    }
    attr_file->rootNode = 0;
    attr_file->nodeSize = 0;
    // Note that we leave the fs component alone.
    return 0;
}


static const char *
hfs_attrTypeName(uint32_t typeNum)
{
    switch (typeNum) {
    case TSK_FS_ATTR_TYPE_HFS_DEFAULT:
        return "DFLT";
    case TSK_FS_ATTR_TYPE_HFS_DATA:
        return "DATA";
    case TSK_FS_ATTR_TYPE_HFS_EXT_ATTR:
        return "ExATTR";
    case TSK_FS_ATTR_TYPE_HFS_COMP_REC:
        return "CMPF";
    case TSK_FS_ATTR_TYPE_HFS_RSRC:
        return "RSRC";
    default:
        return "UNKN";
    }
}


static uint8_t
hfs_load_extended_attrs(TSK_FS_FILE * fs_file,
    unsigned char *isCompressed, unsigned char *compDataInRSRC,
    uint64_t * uncompressedSize)
{
    TSK_FS_INFO *fs = fs_file->fs_info;
    uint64_t fileID;
    ATTR_FILE_T attrFile;
    int cnt;                    // count of chars read from file.
    uint8_t *nodeData;
    TSK_ENDIAN_ENUM endian;
    hfs_btree_node *nodeDescriptor;     // The node descriptor
    uint32_t nodeID;            // The number or ID of the Attributes file node to read.
    hfs_btree_key_attr *keyB;   // ptr to the key of the Attr file record.
    unsigned char done;         // Flag to indicate that we are done looping over leaf nodes
    uint16_t attribute_counter = 2;     // The ID of the next attribute to be loaded.
    HFS_INFO *hfs;


    tsk_error_reset();

    // The CNID (or inode number) of the file
    //  Note that in TSK such numbers are 64 bits, but in HFS+ they are only 32 bits.
    fileID = fs_file->meta->addr;

    if (fs == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_load_extended_attrs: NULL fs arg");
        return 1;
    }

    hfs = (HFS_INFO *) fs;

    if (!hfs->has_attributes_file) {
        // No attributes file, and so, no extended attributes
        return 0;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_load_extended_attrs:  Processing file %" PRIuINUM "\n",
            fileID);


    // Open the Attributes File
    if (open_attr_file(fs, &attrFile)) {
        error_returned
            ("hfs_load_extended_attrs: could not open Attributes file");
        return 1;
    }

    // Is the Attributes file empty?
    if (attrFile.rootNode == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_extended_attrs: Attributes file is empty\n");
        close_attr_file(&attrFile);
        *isCompressed = FALSE;
        *compDataInRSRC = FALSE;
        return 0;
    }

    // A place to hold one node worth of data
    nodeData = (uint8_t *) malloc(attrFile.nodeSize);
    if (nodeData == NULL) {
        error_detected(TSK_ERR_AUX_MALLOC,
            "hfs_load_extended_attrs: Could not malloc space for an Attributes file node");
        close_attr_file(&attrFile);
        return 1;
    }

    // Initialize these
    *isCompressed = FALSE;
    *compDataInRSRC = FALSE;

    endian = attrFile.fs->endian;




    // Start with the root node
    nodeID = attrFile.rootNode;

    // While loop, over nodes in path from root node to the correct LEAF node.
    while (1) {
        uint16_t numRec;        // Number of records in the node
        int recIndx;            // index for looping over records

        if (tsk_verbose) {
            tsk_fprintf(stderr,
                "hfs_load_extended_attrs: Reading Attributes File n ode with ID %"
                PRIu32 "\n", nodeID);
        }

        cnt = tsk_fs_file_read(attrFile.file,
            nodeID * attrFile.nodeSize,
            (char *) nodeData,
            attrFile.nodeSize, (TSK_FS_FILE_READ_FLAG_ENUM) 0);
        if (cnt != attrFile.nodeSize) {
            free(nodeData);
            error_returned
                ("hfs_load_extended_attrs: Could not read in a node from the Attributes File");
            close_attr_file(&attrFile);
            return 1;
        }

        // Parse the Node header
        nodeDescriptor = (hfs_btree_node *) nodeData;

        // If we are at a leaf node, then we have found the right node
        if (nodeDescriptor->type == HFS_ATTR_NODE_LEAF) {
            break;
        }

        // This had better be an INDEX node, if not its an error
        if (nodeDescriptor->type != HFS_ATTR_NODE_INDEX) {
            error_detected(TSK_ERR_FS_READ,
                "hfs_load_extended_attrs: Reached a non-INDEX and non-LEAF node in searching the Attributes File");
            free(nodeData);
            close_attr_file(&attrFile);
            return 1;
        }

        // OK, we are in an INDEX node.  loop over the records to find the last one whose key is
        // smaller than or equal to the desired key

        numRec = tsk_getu16(endian, nodeDescriptor->num_rec);

        if (numRec == 0) {
            // This is wrong, there must always be at least 1 record in an INDEX node.
            free(nodeData);
            error_detected(TSK_ERR_FS_READ,
                "hfs_load_extended_attrs:Attributes File index node %"
                PRIu32 " has zero records", nodeID);
            close_attr_file(&attrFile);
            return 1;
        }

        for (recIndx = 0; recIndx < numRec; recIndx++) {
            uint16_t keyLength;
            int comp;           // comparison result
            char *compStr;      // comparison result, as a string
            uint8_t *recData;   // pointer to the data part of the record
            uint32_t keyFileID;
            int diff;           // difference in bytes between the record start and the record data

            // Offset of the record
            uint8_t *recOffsetData = &nodeData[attrFile.nodeSize - 2 * (recIndx + 1)];  // data describing where this record is
            uint16_t recOffset = tsk_getu16(endian, recOffsetData);
            //uint8_t * nextRecOffsetData = &nodeData[attrFile.nodeSize - 2* (recIndx+2)];

            // Pointer to first byte of record
            uint8_t *record = &nodeData[recOffset];


            // Cast that to the Attributes file key (n.b., the key is the first thing in the record)
            keyB = (hfs_btree_key_attr *) record;
            keyLength = tsk_getu16(endian, keyB->key_len);

            // Is this key less than what we are seeking?
            //int comp = comp_attr_key(endian, keyB, fileID, attrName, startBlock);

            keyFileID = tsk_getu32(endian, keyB->file_id);
            if (keyFileID < fileID) {
                comp = -1;
                compStr = "less than";
            }
            else if (keyFileID > fileID) {
                comp = 1;
                compStr = "greater than";
            }
            else {
                comp = 0;
                compStr = "equal to";
            }
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_extended_attrs: INDEX record %d, fileID %"
                    PRIu32 " is %s the file ID we are seeking, %" PRIu32
                    ".\n", recIndx, keyFileID, compStr, fileID);
            if (comp > 0) {
                // The key of this record is greater than what we are seeking
                if (recIndx == 0) {
                    // This is the first record, so no records are appropriate
                    // Nothing in this btree will match.  We can stop right here.
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 0;
                }

                // This is not the first record, so, the previous record's child is the one we want.
                break;
            }

            // CASE:  key in this record matches the key we are seeking.  The previous record's child
            // is the one we want.  However, if this is the first record, then we want THIS record's child.
            if (comp == 0 && recIndx != 0) {
                break;
            }


            // Extract the child node ID from the data of the record
            recData = &record[keyLength + 2];   // This is +2 because key_len does not include the
            // length of the key_len field itself.

            // Data must start on an even offset from the beginning of the record.
            // So, correct this if needed.
            diff = recData - record;
            if (2 * (diff / 2) != diff) {
                recData += 1;
            }

            // The next four bytes should be the Node ID of the child of this node.
            nodeID = tsk_getu32(endian, recData);

            // At this point, either comp<0 or comp=0 && recIndx=0.  In the latter case we want to
            // descend to the child of this node, so we break.
            if (recIndx == 0 && comp == 0) {
                break;
            }

            // CASE: key in this record is less than key we seek.  comp < 0
            // So, continue looping over records in this node.

        }                       // END loop over records

    }                           // END while loop over Nodes in path from root to LEAF node

    // At this point nodeData holds the contents of a LEAF node with the right range of keys
    // and nodeDescriptor points to the descriptor of that node.

    // Loop over successive LEAF nodes, starting with this one
    done = FALSE;
    while (!done) {
        uint16_t numRec;        // number of records
        int recIndx;            // index for looping over records

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_extended_attrs: Attributes File LEAF Node %"
                PRIu32 ".\n", nodeID);
        numRec = tsk_getu16(endian, nodeDescriptor->num_rec);
        // Note, leaf node could have one (or maybe zero) records

        // Loop over the records in this node
        for (recIndx = 0; recIndx < numRec; recIndx++) {
            // Offset of the record
            uint8_t *recOffsetData = &nodeData[attrFile.nodeSize - 2 * (recIndx + 1)];  // data describing where this record is
            uint16_t recOffset = tsk_getu16(endian, recOffsetData);
            uint16_t keyLength;
            int comp;           // comparison result
            char *compStr;      // comparison result as a string
            uint32_t keyFileID;

            // Pointer to first byte of record
            uint8_t *record = &nodeData[recOffset];

            // Cast that to the Attributes file key
            keyB = (hfs_btree_key_attr *) record;
            keyLength = tsk_getu16(endian, keyB->key_len);

            // Compare record key to the key that we are seeking
            keyFileID = tsk_getu32(endian, keyB->file_id);

            //fprintf(stdout, " Key file ID = %lu\n", keyFileID);
            if (keyFileID < fileID) {
                comp = -1;
                compStr = "less than";
            }
            else if (keyFileID > fileID) {
                comp = 1;
                compStr = "greater than";
            }
            else {
                comp = 0;
                compStr = "equal to";
            }

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_extended_attrs: LEAF Record key file ID %"
                    PRIu32 " is %s the desired file ID %" PRIu32 "\n",
                    keyFileID, compStr, fileID);
            // Are they the same?
            if (comp == 0) {
                // Yes, so load this attribute

                uint8_t *recData;       // pointer to the data part of the record
                hfs_attr_data *attrData;
                uint32_t attributeLength;
                int diff;       // Difference in bytes between the start of the record and the start of data.
                char *buffer;   // buffer to hold the attribute

                int conversionResult;
                char nameBuff[MAX_ATTR_NAME_LENGTH];

                TSK_FS_ATTR_TYPE_ENUM attrType;

                TSK_FS_ATTR *fs_attr;   // Points to the attribute to be loaded.

                recData = &record[keyLength + 2];

                // Data must start on an even offset from the beginning of the record.
                // So, correct this if needed.
                diff = recData - record;
                if (2 * (diff / 2) != diff) {
                    recData += 1;
                }

                // Now this should be a "inline data" kind of record.  The other two kinds are not
                // used for anything, and are not handled in this code.
                attrData = (hfs_attr_data *) recData;
                if (tsk_getu32(endian,
                        attrData->record_type) !=
                    HFS_ATTR_RECORD_INLINE_DATA) {
                    error_detected(TSK_ERR_FS_UNSUPFUNC,
                        "hfs_load_extended_attrs: The Attributes File record found was not of type INLINE_DATA");
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 1;
                }

                // This is the length of the useful data, not including the record header
                attributeLength = tsk_getu32(endian, attrData->attr_size);

                buffer = malloc(attributeLength);
                if (buffer == NULL) {
                    error_detected(TSK_ERR_AUX_MALLOC,
                        "hfs_load_extended_attrs: Could not malloc space for the attribute.");
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 1;
                }

                memcpy(buffer, attrData->attr_data, attributeLength);

                // Use the "attr_name" part of the key as the attribute name
                // but must convert to UTF8.  Unfortunately, there does not seem to
                // be any easy way to determine how long the converted string will
                // be because UTF8 is a variable length encoding. However, the longest
                // it will be is 3 * the max number of UTF16 code units.  Add one for null
                // termination.   (thanks Judson!)

                conversionResult = hfs_UTF16toUTF8(fs, keyB->attr_name,
                    tsk_getu16(endian, keyB->attr_name_len),
                    nameBuff, MAX_ATTR_NAME_LENGTH, 0);
                if (conversionResult != 0) {
                    error_returned
                        ("-- hfs_load_extended_attrs could not convert the attr_name in the btree key into a UTF8 attribute name");
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 1;
                }


                // What is the type of this attribute?  If it is a compression record, then
                // use TSK_FS_ATTR_TYPE_HFS_COMP_REC.  Else, use TSK_FS_ATTR_TYPE_HFS_EXT_ATTR
                if (strcmp(nameBuff, "com.apple.decmpfs") == 0) {
                    // Now, look at the compression record
                    DECMPFS_DISK_HEADER *cmph =
                        (DECMPFS_DISK_HEADER *) buffer;
                    uint32_t cmpType =
                        tsk_getu32(TSK_LIT_ENDIAN, cmph->compression_type);
                    uint64_t uncSize = tsk_getu64(TSK_LIT_ENDIAN,
                        cmph->uncompressed_size);

                    if (tsk_verbose)
                        tsk_fprintf(stderr,
                            "hfs_load_extended_attrs: This attribute is a compression record.\n");

                    attrType = TSK_FS_ATTR_TYPE_HFS_COMP_REC;
                    *isCompressed = TRUE;       // The data is governed by a compression record (but might not be compressed)
                    *uncompressedSize = uncSize;

                    if (cmpType == 3) {
                        // Data is inline.  We will load the uncompressed data as a resident attribute.

                        TSK_FS_ATTR *fs_attr_unc;

                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                "hfs_load_extended_attrs: Compressed data is inline in the attribute, will load this as the default DATA attribute.\n");

                        if (attributeLength <= 16) {
                            if (tsk_verbose)
                                tsk_fprintf(stderr,
                                    "hfs_load_extended_attrs: WARNING, Compression Record of type 3 is not followed by"
                                    " compressed data. No data will be loaded into the DATA attribute.\n");
                        }
                        else {
                            // There is data following the compression record, as there should be.
                            if ((fs_attr_unc =
                                    tsk_fs_attrlist_getnew(fs_file->meta->
                                        attr, TSK_FS_ATTR_RES)) == NULL) {
                                error_returned
                                    (" - hfs_load_extended_attrs, FS_ATTR for uncompressed data");
                                free(nodeData);
                                close_attr_file(&attrFile);
                                return 1;
                            }

                            if ((cmph->attr_bytes[0] & 0x0F) == 0x0F) {
                                if (tsk_verbose)
                                    tsk_fprintf(stderr,
                                        "hfs_load_extended_attrs: Leading byte, 0x0F, indicates that the data is not really compressed.\n"
                                        "hfs_load_extended_attrs:  Loading the default DATA attribute.");
                                //cmpSize = attributeLength - 17; // subtr. size of header + 1 indicator byte

                                // Load the remainder of the attribute as 128-0
                                // set the details in the fs_attr structure.  Note, we are loading this
                                // as a RESIDENT attribute.
                                if (tsk_fs_attr_set_str(fs_file,
                                        fs_attr_unc, "DATA",
                                        TSK_FS_ATTR_TYPE_HFS_DATA,
                                        HFS_FS_ATTR_ID_DATA,
                                        (void *) (buffer + 17),
                                        (size_t) uncSize)) {
                                    error_returned
                                        (" - hfs_load_extended_attrs");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }

                            }
                            else {      // Leading byte is not 0x0F

#ifdef HAVE_LIBZ
                                char *uncBuf;
                                uint64_t uLen;
                                unsigned long bytesConsumed;
                                int infResult;

                                if (tsk_verbose)
                                    tsk_fprintf(stderr,
                                        "hfs_load_extended_attrs: Uncompressing (inflating) data.");
                                // Uncompress the remainder of the attribute, and load as 128-0
                                // Note: cast is OK because uncSize will be quite modest, less than 4000.
                                uncBuf = (char *) tsk_malloc((size_t) uncSize + 100);   // add some extra space
                                if (uncBuf == NULL) {
                                    error_returned
                                        (" - hfs_load_extended_attrs, space for the uncompressed attr");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }

                                infResult = zlib_inflate(buffer + 16, (uint64_t) (attributeLength - 16),        // source, srcLen
                                    uncBuf, (uint64_t) (uncSize + 100), // dest, destLen
                                    &uLen, &bytesConsumed);     // returned by the function
                                if (infResult != 0) {
                                    error_returned
                                        (" hfs_load_extended_attrs, zlib could not uncompress attr");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }
                                if (bytesConsumed != attributeLength - 16) {
                                    error_detected(TSK_ERR_FS_READ,
                                        " hfs_load_extended_attrs, zlib did not consumed the whole compressed data");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }
                                if (uLen != uncSize) {
                                    error_detected(TSK_ERR_FS_READ,
                                        " hfs_load_extended_attrs, actual uncompressed size not equal to the size in the compression record");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }
                                if (tsk_verbose)
                                    tsk_fprintf(stderr,
                                        "hfs_load_extended_attrs: Loading inflated data as default DATA attribute.");
                                // set the details in the fs_attr structure.  Note, we are loading this
                                // as a RESIDENT attribute.
                                if (tsk_fs_attr_set_str(fs_file,
                                        fs_attr_unc, "DATA",
                                        TSK_FS_ATTR_TYPE_HFS_DATA,
                                        HFS_FS_ATTR_ID_DATA, uncBuf,
                                        (size_t) uncSize)) {
                                    error_returned
                                        (" - hfs_load_extended_attrs");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }
#else
                                // ZLIB compression library is not available, so we will load a zero-length
                                // default DATA attribute.  Without this, icat may misbehave.

                                // This is one byte long, so the ptr is not null, but only loading zero bytes.
                                uint8_t uncBuf[1];

                                if (tsk_verbose)
                                    tsk_fprintf(stderr,
                                        "hfs_load_extended_attrs: ZLIB not available, so loading an empty default DATA attribute.\n");

                                if (tsk_fs_attr_set_str(fs_file,
                                        fs_attr_unc, "DATA",
                                        TSK_FS_ATTR_TYPE_HFS_DATA,
                                        HFS_FS_ATTR_ID_DATA, uncBuf,
                                        (size_t) 0)) {
                                    error_returned
                                        (" - hfs_load_extended_attrs");
                                    free(nodeData);
                                    close_attr_file(&attrFile);
                                    return 1;
                                }

#endif

                            }   // END if leading byte is 0x0F  ELSE clause
                        }       // END if attributeLength <= 16  ELSE clause
                    }
                    else if (cmpType == 4) {
                        // Data is compressed in the resource fork
                        *compDataInRSRC = TRUE; // The compressed data is in the RSRC fork
                        if (tsk_verbose)
                            tsk_fprintf(stderr,
                                "hfs_load_extended_attrs: Compressed data is in the file Resource Fork.\n");
                    }
                }
                else {          // Attrbute name is NOT com.apple.decmpfs
                    attrType = TSK_FS_ATTR_TYPE_HFS_EXT_ATTR;
                }               // END if attribute name is com.apple.decmpfs  ELSE clause

                if ((fs_attr =
                        tsk_fs_attrlist_getnew(fs_file->meta->attr,
                            TSK_FS_ATTR_RES)) == NULL) {
                    error_returned(" - hfs_load_extended_attrs");
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 1;
                }

                if (tsk_verbose) {
                    tsk_fprintf(stderr,
                        "hfs_load_extended_attrs: loading attribute %s, type %u (%s)\n",
                        nameBuff, (uint32_t) attrType,
                        hfs_attrTypeName((uint32_t) attrType));
                }

                // set the details in the fs_attr structure
                if (tsk_fs_attr_set_str(fs_file, fs_attr, nameBuff,
                        attrType, attribute_counter, (void *) buffer,
                        attributeLength)) {
                    error_returned(" - hfs_load_extended_attrs");
                    free(nodeData);
                    close_attr_file(&attrFile);
                    return 1;
                }
                attribute_counter++;

            }                   // END if comp == 0
            if (comp == 1) {
                // since this record key is greater than our search key, all
                // subsequent records will also be greater.
                done = TRUE;
                break;
            }
        }                       // END loop over records in one LEAF node

        /*
         * We get to this point if either:
         *
         * 1. We finish the loop over records and we are still loading attributes
         *    for the given file.  In this case we are NOT done, and must read in
         *    the next leaf node, and process its records.  The following code
         *    loads the next leaf node before we return to the top of the loop.
         *
         * 2. We "broke" out of the loop over records because we found a key that
         *    whose file ID is greater than the one we are working on.  In that case
         *    we are done.  The following code does not run, and we exit the
         *    while loop over successive leaf nodes.
         */

        if (!done) {
            // We did not finish loading the attributes when we got to the end of that node,
            // so we must get the next node, and continue.

            // First determine the nodeID of the next LEAF node
            uint32_t newNodeID = tsk_getu32(endian, nodeDescriptor->flink);

            //fprintf(stdout, "Next Node ID = %u\n",  newNodeID);
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_extended_attrs: Processed last record of THIS node, still gathering attributes.\n");

            // If we are at the very last leaf node in the btree, then
            // this "flink" will be zero.  We break out of this loop over LEAF nodes.
            if (newNodeID == 0) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_load_extended_attrs: But, there are no more leaf nodes, so we are done.\n");
                break;
            }

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_extended_attrs: Reading the next LEAF node %"
                    PRIu32 ".\n", nodeID);

            nodeID = newNodeID;

            cnt = tsk_fs_file_read(attrFile.file,
                nodeID * attrFile.nodeSize,
                (char *) nodeData,
                attrFile.nodeSize, (TSK_FS_FILE_READ_FLAG_ENUM) 0);
            if (cnt != attrFile.nodeSize) {
                error_returned
                    ("hfs_load_extended_attrs: Could not read in the next LEAF node from the Attributes File btree");
                free(nodeData);
                close_attr_file(&attrFile);
                return 1;
            }

            // Parse the Node header
            nodeDescriptor = (hfs_btree_node *) nodeData;

            // If we are NOT leaf node, then this is an error
            if (nodeDescriptor->type != HFS_ATTR_NODE_LEAF) {
                error_detected(TSK_ERR_FS_CORRUPT,
                    "hfs_load_extended_attrs: found a non-LEAF node as a successor to a LEAF node");
                close_attr_file(&attrFile);
                free(nodeData);
                return 1;
            }
        }                       // END if(! done)



    }                           // END while(! done)  loop over successive LEAF nodes

    free(nodeData);
    close_attr_file(&attrFile);
    return 0;
}

typedef struct RES_DESCRIPTOR {
    char type[5];               // type is really 4 chars, but we will null-terminate
    uint16_t id;
    uint32_t offset;
    uint32_t length;
    char *name;                 // NULL if a name is not defined for this resource
    struct RES_DESCRIPTOR *next;
} RES_DESCRIPTOR;

void
free_res_descriptor(RES_DESCRIPTOR * rd)
{
    RES_DESCRIPTOR *nxt;

    if (rd == NULL)
        return;
    nxt = rd->next;
    if (rd->name != NULL)
        free(rd->name);
    free(rd);
    free_res_descriptor(nxt);   // tail recursive
}

/**
 * The purpose of this function is to parse the resource fork of a file, and to return
 * a data structure that is, in effect, a table of contents for the resource fork.  The
 * data structure is a null-terminated linked list of entries.  Each one describes one
 * resource.  If the resource fork is empty, or if there is not a resource fork at all,
 * or an error occurs, this function returns NULL.
 *
 * A non-NULL answer should be freed by the caller, using free_res_descriptor.
 *
 */

static RES_DESCRIPTOR *
hfs_parse_resource_fork(TSK_FS_FILE * fs_file)
{

    RES_DESCRIPTOR *result = NULL;
    RES_DESCRIPTOR *last = NULL;
    TSK_FS_INFO *fs_info;
    hfs_fork *fork_info;
    hfs_fork *resForkInfo;
    uint64_t resSize;
    const TSK_FS_ATTR *rAttr;
    hfs_resource_fork_header rfHeader;
    hfs_resource_fork_header *resHead;
    uint32_t dataOffset;
    uint32_t mapOffset;
    uint32_t mapLength;
    char *map;
    int attrReadResult;
    int attrReadResult1;
    int attrReadResult2;
    hfs_resource_fork_map_header *mapHdr;
    uint16_t typeListOffset;
    uint16_t nameListOffset;
    unsigned char hasNameList;
    char *nameListBegin = NULL;
    hfs_resource_type_list *typeList;
    uint16_t numTypes;
    hfs_resource_type_list_item *tlItem;
    int mindx;                  // index for looping over resource types

    if (fs_file == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_parse_resource_fork: null fs_file");
        return NULL;
    }


    if (fs_file->meta == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_parse_resource_fork: fs_file has null metadata");
        return NULL;
    }

    if (fs_file->meta->content_ptr == NULL) {
        if (tsk_verbose)
            fprintf(stderr,
                "hfs_parse_resource_fork: fs_file has null fork data structures, so no resources.\n");
        return NULL;
    }

    // Extract the fs
    fs_info = fs_file->fs_info;
    if (fs_info == NULL) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_parse_resource_fork: null fs within fs_info");
        return NULL;
    }



    // Try to look at the Resource Fork for an HFS+ file
    // Should be able to cast this to hfs_fork *
    fork_info = (hfs_fork *) fs_file->meta->content_ptr;        // The data fork
    // The resource fork is the second one.
    resForkInfo = &fork_info[1];
    resSize = tsk_getu64(fs_info->endian, resForkInfo->logic_sz);
    //uint32_t numBlocks = tsk_getu32(fs_info->endian, resForkInfo->total_blk);
    //uint32_t clmpSize = tsk_getu32(fs_info->endian, resForkInfo->clmp_sz);

    // Hmm, certainly no resources here!
    if (resSize == 0) {
        return NULL;
    }

    // OK, resource size must be > 0

    // find the attribute for the resource fork
    rAttr =
        tsk_fs_file_attr_get_type(fs_file, TSK_FS_ATTR_TYPE_HFS_RSRC,
        HFS_FS_ATTR_ID_RSRC, TRUE);


    if (rAttr == NULL) {
        error_returned
            ("hfs_parse_resource_fork: could not get the resource fork attribute");
        return NULL;
    }

    // JUST read the resource fork header


    attrReadResult1 =
        tsk_fs_attr_read(rAttr, 0, (char *) &rfHeader,
        sizeof(hfs_resource_fork_header), TSK_FS_FILE_READ_FLAG_NONE);

    if (attrReadResult1 < 0
        || attrReadResult1 != sizeof(hfs_resource_fork_header)) {
        error_returned
            (" hfs_parse_resource_fork: trying to read the resource fork header");
        return NULL;
    }

    // Begin to parse the resource fork
    resHead = &rfHeader;
    dataOffset = tsk_getu32(fs_info->endian, resHead->dataOffset);
    mapOffset = tsk_getu32(fs_info->endian, resHead->mapOffset);
    //uint32_t dataLength = tsk_getu32(fs_info->endian, resHead->dataLength);
    mapLength = tsk_getu32(fs_info->endian, resHead->mapLength);

    // Read in the WHOLE map
    map = (char *) tsk_malloc(mapLength);
    if (map == NULL) {
        error_returned
            ("- hfs_parse_resource_fork: could not allocate space for the resource fork map");
        return NULL;
    }

    attrReadResult =
        tsk_fs_attr_read(rAttr, (uint64_t) mapOffset, map,
        (size_t) mapLength, TSK_FS_FILE_READ_FLAG_NONE);

    if (attrReadResult < 0 || attrReadResult != mapLength) {
        error_returned
            ("- hfs_parse_resource_fork: could not read the map");
        free(map);
        return NULL;
    }

    mapHdr = (hfs_resource_fork_map_header *) map;

    typeListOffset = tsk_getu16(fs_info->endian, mapHdr->typeListOffset);

    nameListOffset = tsk_getu16(fs_info->endian, mapHdr->nameListOffset);

    if (nameListOffset >= mapLength || nameListOffset == 0) {
        hasNameList = FALSE;
    }
    else {
        hasNameList = TRUE;
        nameListBegin = map + nameListOffset;
    }

    typeList = (hfs_resource_type_list *) (map + typeListOffset);
    numTypes = tsk_getu16(fs_info->endian, typeList->typeCount) + 1;

    for (mindx = 0; mindx < numTypes; mindx++) {
        uint16_t numRes;
        uint16_t refOff;
        int pindx;              // index for looping over resources
        uint16_t rID;
        uint32_t rOffset;

        tlItem = &(typeList->type[mindx]);
        numRes = tsk_getu16(fs_info->endian, tlItem->count) + 1;
        refOff = tsk_getu16(fs_info->endian, tlItem->offset);


        for (pindx = 0; pindx < numRes; pindx++) {
            int16_t nameOffset;
            char *nameBuffer;
            RES_DESCRIPTOR *rsrc;
            char lenBuff[4];    // first 4 bytes of a resource encodes its length
            uint32_t rLen;      // Resource length

            hfs_resource_refListItem *item =
                ((hfs_resource_refListItem *) (((uint8_t *) typeList) +
                    refOff)) + pindx;
            nameOffset = tsk_gets16(fs_info->endian, item->resNameOffset);
            nameBuffer = NULL;

            if (hasNameList && nameOffset != -1) {
                char *name = nameListBegin + nameOffset;
                uint8_t nameLen = (uint8_t) name[0];
                nameBuffer = tsk_malloc(nameLen + 1);
                if (nameBuffer == NULL) {
                    error_returned
                        ("hfs_parse_resource_fork: allocating space for the name of a resource");
                    free_res_descriptor(result);
                    return NULL;
                }
                memcpy(nameBuffer, name + 1, nameLen);
                nameBuffer[nameLen] = (char) 0;
            }
            else {
                nameBuffer = tsk_malloc(7);
                if (nameBuffer == NULL) {
                    error_returned
                        ("hfs_parse_resource_fork: allocating space for the (null) name of a resource");
                    free_res_descriptor(result);
                    return NULL;
                }
                memcpy(nameBuffer, "<none>", 6);
                nameBuffer[6] = (char) 0;
            }

            rsrc = (RES_DESCRIPTOR *) tsk_malloc(sizeof(RES_DESCRIPTOR));
            if (rsrc == NULL) {
                error_returned
                    ("hfs_parse_resource_fork: space for a resource descriptor");
                free_res_descriptor(result);
                return NULL;
            }

            // Build the linked list
            if (result == NULL)
                result = rsrc;
            if (last != NULL)
                last->next = rsrc;
            last = rsrc;
            rsrc->next = NULL;

            rID = tsk_getu16(fs_info->endian, item->resID);
            rOffset =
                tsk_getu24(fs_info->endian,
                item->resDataOffset) + dataOffset;

            // Just read the first four bytes of the resource to get its length.  It MUST
            // be at least 4 bytes long
            attrReadResult2 = tsk_fs_attr_read(rAttr, (uint64_t) rOffset,
                lenBuff, (size_t) 4, TSK_FS_FILE_READ_FLAG_NONE);

            if (attrReadResult2 != 4) {
                error_returned
                    ("- hfs_parse_resource_fork: could not read the 4-byte length at beginning of resource");
                free_res_descriptor(result);
                return NULL;
            }
            rLen = tsk_getu32(TSK_BIG_ENDIAN, lenBuff); //TODO

            rsrc->id = rID;
            rsrc->offset = rOffset + 4;
            memcpy(rsrc->type, tlItem->type, 4);
            rsrc->type[4] = (char) 0;
            rsrc->length = rLen;
            rsrc->name = nameBuffer;

        }                       // END loop over resources of one type

    }                           // END loop over resource types

    return result;
}


static uint8_t
hfs_load_attrs(TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs;
    HFS_INFO *hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;
    hfs_fork *forkx;
    unsigned char resource_fork_has_contents = FALSE;
    unsigned char compression_flag = FALSE;
    unsigned char isCompressed = FALSE;
    unsigned char compDataInRSRCFork = FALSE;
    uint64_t uncompressedSize;
    uint64_t logicalSize;       // of a fork

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file == NULL) || (fs_file->meta == NULL)
        || (fs_file->fs_info == NULL)) {
        error_detected(TSK_ERR_FS_ARG,
            "hfs_load_attrs: fs_file or meta is NULL");
        return 1;
    }


    fs = (TSK_FS_INFO *) fs_file->fs_info;
    hfs = (HFS_INFO *) fs;


    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_load_attrs: Processing file %" PRIuINUM "\n",
            fs_file->meta->addr);


    // see if we have already loaded the runs
    if (fs_file->meta->attr_state == TSK_FS_META_ATTR_STUDIED) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_attrs: Attributes already loaded\n");
        return 0;
    }
    else if (fs_file->meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_attrs: Previous attempt to load attributes resulted in error\n");
        return 1;
    }

    // Now (re)-initialize the attrlist that will hold the list of attributes
    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else if (fs_file->meta->attr == NULL) {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }

    /****************** EXTENDED ATTRIBUTES *******************************/
    // We do these first, so that we can detect the mode of compression, if
    // any.  We need to know that mode in order to handle the forks.

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_load_attrs: loading the HFS+ extended attributes\n");

    if (hfs_load_extended_attrs(fs_file, &isCompressed,
            &compDataInRSRCFork, &uncompressedSize)) {
        error_returned(" - hfs_load_attrs A");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    if (isCompressed) {
        fs_file->meta->size = uncompressedSize;
    }

    // This is the flag indicating compression, from the Catalog File record.
    compression_flag = (fs_file->meta->flags & TSK_FS_META_FLAG_COMP) != 0;

    if (compression_flag && !isCompressed) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_attrs: WARNING, HFS marks this as a"
                " compressed file, but no compression record was found.\n");
    }
    if (isCompressed && !compression_flag) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_attrs: WARNING, this file has a compression"
                " record, but the HFS compression flag is not set.\n");
    }

    /************* FORKS (both) ************************************/

    // Process the data and resource forks.  We only do this if the
    // fork data structures are non-null, so test that:
    if (fs_file->meta->content_ptr != NULL) {

        /**************  DATA FORK STUFF ***************************/

        // Get the data fork data-structure
        forkx = (hfs_fork *) fs_file->meta->content_ptr;

        // If this is a compressed file, then either this attribute is already loaded
        // because the data was in the compression record, OR
        // the compressed data is in the resource fork.  We will load those runs when
        // we handle the resource fork.
        if (!isCompressed) {
            // We only load this attribute if this fork has non-zero length
            // or if this is a REG or LNK file.  Otherwise, we skip


            logicalSize = tsk_getu64(fs->endian, forkx->logic_sz);

            if (logicalSize > 0 ||
                fs_file->meta->type == TSK_FS_META_TYPE_REG ||
                fs_file->meta->type == TSK_FS_META_TYPE_LNK) {


                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_load_attrs: loading the data fork attribute\n");

                // get an attribute structure to store the data in
                if ((fs_attr = tsk_fs_attrlist_getnew(fs_file->meta->attr,
                            TSK_FS_ATTR_NONRES)) == NULL) {
                    error_returned(" - hfs_load_attrs");
                    return 1;
                }
                /* NOTE that fs_attr is now tied to fs_file->meta->attr.
                 * that means that we do not need to free it if we abort in the
                 * following code (and doing so will cause double free errors). */

                if (logicalSize > 0) {

                    // Convert runs of blocks to the TSK internal form
                    if (((attr_run =
                                hfs_extents_to_attr(fs, forkx->extents,
                                    0)) == NULL)
                        && (tsk_error_get_errno() != 0)) {
                        error_returned(" - hfs_load_attrs");
                        return 1;
                    }



                    // add the runs to the attribute and the attribute to the file.
                    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run,
                            "DATA", TSK_FS_ATTR_TYPE_HFS_DATA,
                            HFS_FS_ATTR_ID_DATA, logicalSize, logicalSize,
                            (TSK_OFF_T) tsk_getu32(fs->endian,
                                forkx->total_blk) * fs->block_size, 0,
                            0)) {
                        error_returned(" - hfs_load_attrs (DATA)");
                        tsk_fs_attr_run_free(attr_run);
                        return 1;
                    }

                    // see if extents file has additional runs
                    if (hfs_ext_find_extent_record_attr(hfs,
                            (uint32_t) fs_file->meta->addr, fs_attr,
                            TRUE)) {
                        error_returned(" - hfs_load_attrs B");
                        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
                        return 1;
                    }

                }
                else {
                    // logicalSize == 0, but this is either a REG or LNK file
                    // so, it should have a DATA fork attribute of zero length.
                    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, "DATA",
                            TSK_FS_ATTR_TYPE_HFS_DATA, HFS_FS_ATTR_ID_DATA,
                            0, 0, 0, 0, 0)) {
                        error_returned(" - hfs_load_attrs (non-file)");
                        return 1;
                    }
                }

            }                   // END  logicalSize>0 or REG or LNK file type
        }                       // END if not Compressed



        /**************  RESOURCE FORK STUFF ************************************/

        // Get the resource fork.
        //Note that content_ptr points to an array of two
        // hfs_fork data structures, the second of which
        // describes the blocks of the resource fork.

        forkx = &((hfs_fork *) fs_file->meta->content_ptr)[1];

        logicalSize = tsk_getu64(fs->endian, forkx->logic_sz);

        // Skip if the length of the resource fork is zero
        if (logicalSize > 0) {

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_load_attrs: loading the resource fork\n");

            resource_fork_has_contents = TRUE;

            // get an attribute structure to store the resource fork data in.  We will
            // reuse the fs_attr variable, since we are done with the data fork.
            if ((fs_attr =
                    tsk_fs_attrlist_getnew(fs_file->meta->attr,
                        TSK_FS_ATTR_NONRES)) == NULL) {
                error_returned(" - hfs_load_attrs (RSRC)");
                return 1;
            }
            /* NOTE that fs_attr is now tied to fs_file->meta->attr.
             * that means that we do not need to free it if we abort in the
             * following code (and doing so will cause double free errors). */


            // convert the resource fork to the TSK format
            if (((attr_run =
                        hfs_extents_to_attr(fs, forkx->extents,
                            0)) == NULL)
                && (tsk_error_get_errno() != 0)) {
                error_returned(" - hfs_load_attrs");
                return 1;
            }

            // add the runs to the attribute and the attribute to the file.
            if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, "RSRC",
                    TSK_FS_ATTR_TYPE_HFS_RSRC, HFS_FS_ATTR_ID_RSRC,
                    tsk_getu64(fs->endian, forkx->logic_sz),
                    tsk_getu64(fs->endian, forkx->logic_sz),
                    (TSK_OFF_T) tsk_getu32(fs->endian,
                        forkx->total_blk) * fs->block_size, 0, 0)) {
                error_returned(" - hfs_load_attrs (RSRC)");
                tsk_fs_attr_run_free(attr_run);
                return 1;
            }

            // see if extents file has additional runs for the resource fork.
            if (hfs_ext_find_extent_record_attr(hfs,
                    (uint32_t) fs_file->meta->addr, fs_attr, FALSE)) {
                error_returned(" - hfs_load_attrs C");
                fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
                return 1;
            }


            if (isCompressed && compDataInRSRCFork) {

                // OK, we are going to load those same resource fork blocks as the "DATA"
                // attribute, but will mark it as compressed.
                // get an attribute structure to store the resource fork data in.  We will
                // reuse the fs_attr variable, since we are done with the data fork.
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "File is compressed with data in the resource fork. "
                        "Loading the default DATA attribute.\n");
                if ((fs_attr =
                        tsk_fs_attrlist_getnew(fs_file->meta->attr,
                            TSK_FS_ATTR_NONRES)) == NULL) {
                    error_returned
                        (" - hfs_load_attrs (RSRC loading as DATA)");
                    return 1;
                }
                /* NOTE that fs_attr is now tied to fs_file->meta->attr.
                 * that means that we do not need to free it if we abort in the
                 * following code (and doing so will cause double free errors). */

#ifdef HAVE_LIBZ

                // convert the resource fork to the TSK format
                if (((attr_run =
                            hfs_extents_to_attr(fs, forkx->extents,
                                0)) == NULL)
                    && (tsk_error_get_errno() != 0)) {
                    error_returned
                        (" - hfs_load_attrs, RSRC fork as DATA fork");
                    return 1;
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_load_attrs:  Loading RSRC fork block runs as the default DATA attribute.\n");

                // add the runs to the attribute and the attribute to the file.
                if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, "DATA",
                        TSK_FS_ATTR_TYPE_HFS_DATA, HFS_FS_ATTR_ID_DATA,
                        logicalSize,
                        logicalSize,
                        (TSK_OFF_T) tsk_getu32(fs->endian,
                            forkx->total_blk) * fs->block_size,
                        TSK_FS_ATTR_COMP | TSK_FS_ATTR_NONRES, 0)) {
                    error_returned
                        (" - hfs_load_attrs (RSRC loading as DATA)");
                    tsk_fs_attr_run_free(attr_run);
                    return 1;
                }

                // see if extents file has additional runs for the resource fork.
                if (hfs_ext_find_extent_record_attr(hfs,
                        (uint32_t) fs_file->meta->addr, fs_attr, FALSE)) {
                    error_returned
                        (" - hfs_load_attrs (RSRC loading as DATA");
                    fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
                    return 1;
                }

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_load_attrs: setting the \"special\" function pointers to inflate compressed data.\n");

                fs_attr->w = hfs_attr_walk_special;
                fs_attr->r = hfs_file_read_special;

#else
                // We don't have zlib, so the uncompressed data is not available to us,
                // however, we must have a default DATA attribute, or icat will misbehave.
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_load_attrs: No zlib compression library, so setting a zero-length default DATA attribute.\n");

                if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, "DATA",
                        TSK_FS_ATTR_TYPE_HFS_DATA, HFS_FS_ATTR_ID_DATA, 0,
                        0, 0, 0, 0)) {
                    error_returned(" - hfs_load_attrs (non-file)");
                    return 1;
                }

#endif
            }

        }                       // END resource fork size > 0

    }                           // END the fork data structures are non-NULL

    if (isCompressed && compDataInRSRCFork && !resource_fork_has_contents) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_load_attrs: WARNING, compression record claims that compressed data"
                " is in the Resource Fork, but that fork is empty or non-existent.\n");
    }

    // Finish up.
    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    return 0;
}






/** \internal
* Get allocation status of file system block.
* adapted from IsAllocationBlockUsed from:
* http://developer.apple.com/technotes/tn/tn1150.html
*
* @param hfs File system being analyzed
* @param b Block address 
* @returns 1 if allocated, 0 if not, -1 on error
*/
static int8_t
hfs_block_is_alloc(HFS_INFO * hfs, TSK_DADDR_T a_addr)
{
    TSK_FS_INFO *fs = &(hfs->fs_info);
    TSK_OFF_T b;
    size_t b2;

    // lazy loading
    if (hfs->blockmap_file == NULL) {
        if ((hfs->blockmap_file =
                tsk_fs_file_open_meta(fs, NULL,
                    HFS_ALLOCATION_FILE_ID)) == NULL) {
            tsk_error_errstr2_concat(" - Loading blockmap file");
            return -1;
        }

        /* cache the data attribute */
        hfs->blockmap_attr =
            tsk_fs_attrlist_get(hfs->blockmap_file->meta->attr,
            TSK_FS_ATTR_TYPE_DEFAULT);
        if (!hfs->blockmap_attr) {
            tsk_error_errstr2_concat
                (" - Data Attribute not found in Blockmap File");
            return -1;
        }
        hfs->blockmap_cache_start = -1;
        hfs->blockmap_cache_len = 0;
    }

    // get the byte offset
    b = (TSK_OFF_T) a_addr / 8;
    if (b > hfs->blockmap_file->meta->size) {
        tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
        tsk_error_set_errstr("hfs_block_is_alloc: block %" PRIuDADDR
            " is too large for bitmap (%" PRIuOFF ")", a_addr,
            hfs->blockmap_file->meta->size);
        return -1;
    }

    // see if it is in the cache
    if ((hfs->blockmap_cache_start == -1)
        || (hfs->blockmap_cache_start > b)
        || (hfs->blockmap_cache_start + hfs->blockmap_cache_len <= b)) {
        size_t cnt = tsk_fs_attr_read(hfs->blockmap_attr, b,
            hfs->blockmap_cache,
            sizeof(hfs->blockmap_cache), 0);
        if (cnt < 1) {
            tsk_error_set_errstr2
                ("hfs_block_is_alloc: Error reading block bitmap at offset %"
                PRIuOFF, b);
            return -1;
        }
        hfs->blockmap_cache_start = b;
        hfs->blockmap_cache_len = cnt;
    }
    b2 = (size_t) (b - hfs->blockmap_cache_start);
    return (hfs->blockmap_cache[b2] & (1 << (7 - (a_addr % 8)))) != 0;
}


TSK_FS_BLOCK_FLAG_ENUM
hfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    return (hfs_block_is_alloc((HFS_INFO *) a_fs, a_addr) == 1) ?
        TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;
}


static uint8_t
hfs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T start_blk,
    TSK_DADDR_T end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM flags,
    TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "hfs_block_walk";
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "%s: start_blk: %" PRIuDADDR " end_blk: %"
            PRIuDADDR " flags: %" PRIu32 "\n", myname, start_blk, end_blk,
            flags);

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_blk < fs->first_block || start_blk > fs->last_block) {
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: invalid start block number: %" PRIuDADDR
            "", myname, start_blk);
        return 1;
    }
    if (end_blk < fs->first_block || end_blk > fs->last_block) {
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: invalid last block number: %" PRIuDADDR
            "", myname, end_blk);
        return 1;
    }

    if (start_blk > end_blk)
        XSWAP(start_blk, end_blk);

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }

    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    /*
     * Iterate
     */
    for (addr = start_blk; addr <= end_blk; addr++) {
        int retval;
        int myflags;

        /* identify if the block is allocated or not */
        myflags = hfs_block_is_alloc(hfs, addr) ?
            TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;

        if (flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        if (tsk_fs_block_get_flag(fs, fs_block, addr,
                (TSK_FS_BLOCK_FLAG_ENUM) myflags) == NULL) {
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = action(fs_block, ptr);
        if (TSK_WALK_STOP == retval) {
            break;
        }
        else if (TSK_WALK_ERROR == retval) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    tsk_fs_block_free(fs_block);
    return 0;
}


uint8_t
hfs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM flags,
    TSK_FS_META_WALK_CB action, void *ptr)
{
    TSK_INUM_T inum;
    TSK_FS_FILE *fs_file;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_inode_walk: start_inum: %" PRIuINUM " end_inum: %"
            PRIuINUM " flags: %" PRIu32 "\n", start_inum, end_inum, flags);

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("inode_walk: Start inode: %" PRIuINUM "",
            start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("inode_walk: End inode: %" PRIuINUM "",
            end_inum);
        return 1;
    }

    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (flags & TSK_FS_META_FLAG_ORPHAN) {
        flags |= TSK_FS_META_FLAG_UNALLOC;
        flags &= ~TSK_FS_META_FLAG_ALLOC;
        flags |= TSK_FS_META_FLAG_USED;
        flags &= ~TSK_FS_META_FLAG_UNUSED;
    }

    else {
        if (((flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }

        /* If neither of the USED or UNUSED flags are set, then set them
         * both
         */
        if (((flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
        }
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta = tsk_fs_meta_alloc(HFS_FILE_CONTENT_LEN)) == NULL)
        return 1;

    if (start_inum > end_inum)
        XSWAP(start_inum, end_inum);

    for (inum = start_inum; inum <= end_inum; inum++) {
        int retval;

        if (hfs_inode_lookup(fs, fs_file, inum)) {
            // deleted files may not exist in the catalog
            if (tsk_error_get_errno() == TSK_ERR_FS_INODE_NUM) {
                tsk_error_reset();
                continue;
            }
            else {
                return 1;
            }
        }

        if ((fs_file->meta->flags & flags) != fs_file->meta->flags)
            continue;

        /* call action */
        retval = action(fs_file, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            return 1;
        }
    }

    tsk_fs_file_close(fs_file);
    return 0;
}

/* return the name of a file at a given inode
 * in a newly-allocated string, or NULL on error
 */
char *
hfs_get_inode_name(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    HFS_ENTRY entry;
    char *fn = NULL;

    if (hfs_cat_file_lookup(hfs, inum, &entry, FALSE))
        return NULL;

    fn = malloc(HFS_MAXNAMLEN + 1);
    if (fn == NULL)
        return NULL;

    if (hfs_UTF16toUTF8(fs, entry.thread.name.unicode,
            tsk_getu16(fs->endian, entry.thread.name.length), fn,
            HFS_MAXNAMLEN + 1, HFS_U16U8_FLAG_REPLACE_SLASH)) {
        free(fn);
        return NULL;
    }

    return fn;
}

/* print the name of a file at a given inode
 * returns 0 on success, 1 on error */
static uint8_t
print_inode_name(FILE * hFile, TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    char fn[HFS_MAXNAMLEN + 1];
    HFS_ENTRY entry;

    if (hfs_cat_file_lookup(hfs, inum, &entry, FALSE))
        return 1;

    if (hfs_UTF16toUTF8(fs, entry.thread.name.unicode,
            tsk_getu16(fs->endian, entry.thread.name.length), fn,
            HFS_MAXNAMLEN + 1, HFS_U16U8_FLAG_REPLACE_SLASH))
        return 1;

    tsk_fprintf(hFile, "%s", fn);

    return 0;
}

/* tail recursive function to print a path... prints the parent path, then
 * appends / and the name of the given inode. prints nothing for root
 * returns 0 on success, 1 on failure
 */
static uint8_t
print_parent_path(FILE * hFile, TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    char fn[HFS_MAXNAMLEN + 1];
    HFS_ENTRY entry;

    if (inum == HFS_ROOT_INUM)
        return 0;

    if (inum <= HFS_ROOT_INUM) {
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("print_parent_path: out-of-range inode %"
            PRIuINUM, inum);
        return 1;
    }

    if (hfs_cat_file_lookup(hfs, inum, &entry, FALSE))
        return 1;

    if (hfs_UTF16toUTF8(fs, entry.thread.name.unicode,
            tsk_getu16(fs->endian, entry.thread.name.length), fn,
            HFS_MAXNAMLEN + 1,
            HFS_U16U8_FLAG_REPLACE_SLASH | HFS_U16U8_FLAG_REPLACE_CONTROL))
        return 1;

    if (print_parent_path(hFile, fs, (TSK_INUM_T) tsk_getu32(fs->endian,
                entry.thread.parent_cnid)))
        return 1;

    tsk_fprintf(hFile, "/%s", fn);
    return 0;
}

/* print the file name corresponding to an inode, in brackets after a space.
 * uses Unix path conventions, and does not include the volume name.
 * returns 0 on success, 1 on failure
 */
static uint8_t
print_inode_file(FILE * hFile, TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_fprintf(hFile, " [");
    if (inum == HFS_ROOT_INUM)
        tsk_fprintf(hFile, "/");
    else {
        if (print_parent_path(hFile, fs, inum)) {
            tsk_fprintf(hFile, "unknown]");
            return 1;
        }
    }
    tsk_fprintf(hFile, "]");
    return 0;
}

static uint8_t
hfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for HFS yet");
    return 1;
}


static uint8_t
hfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    // char *myname = "hfs_fsstat";
    HFS_INFO *hfs = (HFS_INFO *) fs;
    hfs_plus_vh *sb = hfs->fs;
    time_t mac_time;
    TSK_INUM_T inode;
    char timeBuf[128];

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_fstat: called\n");

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: ");
    if (tsk_getu16(fs->endian, hfs->fs->signature) == HFS_VH_SIG_HFSPLUS)
        tsk_fprintf(hFile, "HFS+\n");
    else if (tsk_getu16(fs->endian, hfs->fs->signature) == HFS_VH_SIG_HFSX)
        tsk_fprintf(hFile, "HFSX\n");
    else
        tsk_fprintf(hFile, "Unknown\n");

    // print name and number of version
    tsk_fprintf(hFile, "File System Version: ");
    switch (tsk_getu16(fs->endian, hfs->fs->version)) {
    case 4:
        tsk_fprintf(hFile, "HFS+\n");
        break;
    case 5:
        tsk_fprintf(hFile, "HFSX\n");
        break;
    default:
        tsk_fprintf(hFile, "Unknown (%" PRIu16 ")\n",
            tsk_getu16(fs->endian, hfs->fs->version));
        break;
    }

    if (tsk_getu16(fs->endian, hfs->fs->signature) == HFS_VH_SIG_HFSX) {
        tsk_fprintf(hFile, "Case Sensitive: %s\n",
            hfs->is_case_sensitive ? "yes" : "no");
    }

    if (hfs->hfs_wrapper_offset > 0) {
        tsk_fprintf(hFile,
            "File system is embedded in an HFS wrapper at offset %" PRIuOFF
            "\n", hfs->hfs_wrapper_offset);
    }

    tsk_fprintf(hFile, "\nVolume Name: ");
    if (print_inode_name(hFile, fs, HFS_ROOT_INUM))
        return 1;
    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Volume Identifier: %08" PRIx32 "%08" PRIx32 "\n",
        tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_ID1]),
        tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_ID2]));


    // print last mounted info
    tsk_fprintf(hFile, "\nLast Mounted By: ");
    if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFS_VH_MVER_HFSPLUS)
        tsk_fprintf(hFile, "Mac OS X\n");
    else if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFS_VH_MVER_HFSJ)
        tsk_fprintf(hFile, "Mac OS X, Journaled\n");
    else if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFS_VH_MVER_FSK)
        tsk_fprintf(hFile, "failed journal replay\n");
    else if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFS_VH_MVER_FSCK)
        tsk_fprintf(hFile, "fsck_hfs\n");
    else if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFS_VH_MVER_OS89)
        tsk_fprintf(hFile, "Mac OS 8.1 - 9.2.2\n");
    else
        tsk_fprintf(hFile, "Unknown (%" PRIx32 "\n",
            tsk_getu32(fs->endian, sb->last_mnt_ver));

    /* State of the file system */
    if ((tsk_getu32(fs->endian, hfs->fs->attr) & HFS_VH_ATTR_UNMOUNTED)
        && (!(tsk_getu32(fs->endian,
                    hfs->fs->attr) & HFS_VH_ATTR_INCONSISTENT)))
        tsk_fprintf(hFile, "Volume Unmounted Properly\n");
    else
        tsk_fprintf(hFile, "Volume Unmounted Improperly\n");

    tsk_fprintf(hFile, "Mount Count: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->write_cnt));


    // Dates
    // (creation date is in local time zone, not UTC, according to TN 1150)
    mac_time =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, hfs->fs->cr_date));
    tsk_fprintf(hFile, "\nCreation Date: \t%s\n",
        tsk_fs_time_to_str(mktime(gmtime(&mac_time)), timeBuf));

    mac_time =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, hfs->fs->m_date));
    tsk_fprintf(hFile, "Last Written Date: \t%s\n",
        tsk_fs_time_to_str(mac_time, timeBuf));

    mac_time =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian,
            hfs->fs->bkup_date));
    tsk_fprintf(hFile, "Last Backup Date: \t%s\n",
        tsk_fs_time_to_str(mac_time, timeBuf));

    mac_time =
        hfs_convert_2_unix_time(tsk_getu32(fs->endian, hfs->fs->chk_date));
    tsk_fprintf(hFile, "Last Checked Date: \t%s\n",
        tsk_fs_time_to_str(mac_time, timeBuf));


    if (tsk_getu32(fs->endian, hfs->fs->attr) & HFS_VH_ATTR_SOFTWARE_LOCK)
        tsk_fprintf(hFile, "Software write protect enabled\n");

    /* Print journal information */
    if (tsk_getu32(fs->endian, sb->attr) & HFS_VH_ATTR_JOURNALED) {
        tsk_fprintf(hFile, "\nJournal Info Block: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb->jinfo_blk));
    }

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);

    inode = tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_BOOT]);
    tsk_fprintf(hFile, "Bootable Folder ID: %" PRIuINUM, inode);
    if (inode > 0)
        print_inode_file(hFile, fs, inode);
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_START]);
    tsk_fprintf(hFile, "Startup App ID: %" PRIuINUM, inode);
    if (inode > 0)
        print_inode_file(hFile, fs, inode);
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_OPEN]);
    tsk_fprintf(hFile, "Startup Open Folder ID: %" PRIuINUM, inode);
    if (inode > 0)
        print_inode_file(hFile, fs, inode);
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_BOOT9]);
    tsk_fprintf(hFile, "Mac OS 8/9 Blessed System Folder ID: %" PRIuINUM,
        inode);
    if (inode > 0)
        print_inode_file(hFile, fs, inode);
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, sb->finder_info[HFS_VH_FI_BOOTX]);
    tsk_fprintf(hFile, "Mac OS X Blessed System Folder ID: %" PRIuINUM,
        inode);
    if (inode > 0)
        print_inode_file(hFile, fs, inode);
    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Number of files: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->file_cnt));
    tsk_fprintf(hFile, "Number of folders: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->fldr_cnt));


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "Allocation Block Size: %u\n", fs->block_size);

    tsk_fprintf(hFile, "Number of Free Blocks: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->free_blks));

    if (tsk_getu32(fs->endian, hfs->fs->attr) & HFS_VH_ATTR_BADBLOCKS)
        tsk_fprintf(hFile, "Volume has bad blocks\n");

    return 0;
}


/************************* istat *******************************/


/**
 * Text encoding names defined in TN1150, Table 2.
 */
static char *
text_encoding_name(uint32_t enc)
{
    switch (enc) {
    case 0:
        return "MacRoman";
    case 1:
        return "MacJapanese";
    case 2:
        return "MacChineseTrad";
    case 4:
        return "MacKorean";
    case 5:
        return "MacArabic";
    case 6:
        return "MacHebrew";
    case 7:
        return "MacGreek";
    case 8:
        return "MacCyrillic";
    case 9:
        return "MacDevanagari";
    case 10:
        return "MacGurmukhi";
    case 11:
        return "MacGujarati";
    case 12:
        return "MacOriya";
    case 13:
        return "MacBengali";
    case 14:
        return "MacTamil";
    case 15:
        return "Telugu";
    case 16:
        return "MacKannada";
    case 17:
        return "MacMalayalam";
    case 18:
        return "MacSinhalese";
    case 19:
        return "MacBurmese";
    case 20:
        return "MacKhmer";
    case 21:
        return "MacThai";
    case 22:
        return "MacLaotian";
    case 23:
        return "MacGeorgian";
    case 24:
        return "MacArmenian";
    case 25:
        return "MacChineseSimp";
    case 26:
        return "MacTibetan";
    case 27:
        return "MacMongolian";
    case 28:
        return "MacEthiopic";
    case 29:
        return "MacCentralEurRoman";
    case 30:
        return "MacVietnamese";
    case 31:
        return "MacExtArabic";
    case 33:
        return "MacSymbol";
    case 34:
        return "MacDingbats";
    case 35:
        return "MacTurkish";
    case 36:
        return "MacCroatian";
    case 37:
        return "MacIcelandic";
    case 38:
        return "MacRomanian";
    case 49:
    case 140:
        return "MacFarsi";
    case 48:
    case 152:
        return "MacUkrainian";
    default:
        return "Unknown encoding";
    }
}

#define HFS_PRINT_WIDTH 8
typedef struct {
    FILE *hFile;
    int idx;
    TSK_DADDR_T startBlock;
    uint32_t blockCount;
    unsigned char accumulating;
} HFS_PRINT_ADDR;

static void
output_print_addr(HFS_PRINT_ADDR * print)
{
    if (!print->accumulating)
        return;
    if (print->blockCount == 1) {
        tsk_fprintf(print->hFile, "%" PRIuDADDR "  ", print->startBlock);
        print->idx += 1;
    }
    else if (print->blockCount > 1) {
        tsk_fprintf(print->hFile, "%" PRIuDADDR "-%" PRIuDADDR "  ",
            print->startBlock, print->startBlock + print->blockCount - 1);
        print->idx += 2;
    }
    if (print->idx >= HFS_PRINT_WIDTH) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
    }
}

static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    HFS_PRINT_ADDR *print = (HFS_PRINT_ADDR *) ptr;

    if (print->accumulating) {
        if (addr == print->startBlock + print->blockCount) {
            print->blockCount++;
        }
        else {
            output_print_addr(print);

            print->startBlock = addr;
            print->blockCount = 1;
        }
    }
    else {
        print->startBlock = addr;
        print->blockCount = 1;
        print->accumulating = TRUE;
    }

    return TSK_WALK_CONT;
}

/**
 * Print details on a specific file to a file handle. 
 *
 * @param fs File system file is located in
 * @param hFile File name to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 * 
 * @returns 1 on error and 0 on success
 */
static uint8_t
hfs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_FS_FILE *fs_file;
    char hfs_mode[12];
    HFS_PRINT_ADDR print;
    HFS_ENTRY entry;
    char timeBuf[128];
    // Compression ATTR, if there is one:
    const TSK_FS_ATTR *compressionAttr = NULL;
    RES_DESCRIPTOR *rd;         // descriptor of a resource

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_istat: inum: %" PRIuINUM " numblock: %" PRIu32 "\n",
            inum, numblock);

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        error_returned("hfs_istat: getting metadata for the file");
        return 1;
    }

    if (inum >= HFS_FIRST_USER_CNID) {
        int rslt;
        tsk_fprintf(hFile, "File Path: ");
        rslt = print_parent_path(hFile, fs, inum);
        if (rslt != 0)
            tsk_fprintf(hFile, " Error in printing path\n");
        else
            tsk_fprintf(hFile, "\n");
    }
    else {
        // All of the files in this inum range have names without nulls,
        // slashes or control characters.  So, it is OK to print this UTF8
        // string this way.
        if (fs_file->meta->name2 != NULL)
            tsk_fprintf(hFile, "File Name: %s\n",
                fs_file->meta->name2->name);
    }

    tsk_fprintf(hFile, "Catalog Record: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_file->meta->flags & TSK_FS_META_FLAG_UNALLOC) ? "Not " : "");

    tsk_fprintf(hFile, "Type:\t");
    if (fs_file->meta->type == TSK_FS_META_TYPE_REG)
        tsk_fprintf(hFile, "File\n");
    else if (fs_file->meta->type == TSK_FS_META_TYPE_DIR)
        tsk_fprintf(hFile, "Folder\n");
    else
        tsk_fprintf(hFile, "\n");

    tsk_fs_meta_make_ls(fs_file->meta, hfs_mode, sizeof(hfs_mode));
    tsk_fprintf(hFile, "Mode:\t%s\n", hfs_mode);
    tsk_fprintf(hFile, "Size:\t%" PRIuOFF "\n", fs_file->meta->size);

    if (fs_file->meta->link)
        tsk_fprintf(hFile, "Symbolic link to:\t%s\n", fs_file->meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_file->meta->uid, fs_file->meta->gid);

    tsk_fprintf(hFile, "Link count:\t%d\n", fs_file->meta->nlink);

    if (hfs_cat_file_lookup(hfs, inum, &entry, TRUE) == 0) {
        hfs_uni_str *nm = &entry.thread.name;
        char name_buf[HFS_MAXNAMLEN + 1];
        TSK_INUM_T par_cnid;    // parent CNID

        tsk_fprintf(hFile, "\n");
        hfs_UTF16toUTF8(fs, nm->unicode, (int) tsk_getu16(fs->endian,
                nm->length), &name_buf[0], HFS_MAXNAMLEN + 1,
            HFS_U16U8_FLAG_REPLACE_SLASH | HFS_U16U8_FLAG_REPLACE_CONTROL);
        tsk_fprintf(hFile, "File Name: %s\n", name_buf);

        // Test here to see if this is a hard link.
        par_cnid = tsk_getu32(fs->endian, &(entry.thread.parent_cnid));
        if ((hfs->has_meta_dir_crtime && par_cnid == hfs->meta_dir_inum) ||
            (hfs->has_meta_crtime && par_cnid == hfs->meta_inum)) {
            int instr = strncmp(name_buf, "iNode", 5);
            int drstr = strncmp(name_buf, "dir_", 4);

            if (instr == 0 &&
                hfs->has_meta_crtime && par_cnid == hfs->meta_inum) {
                tsk_fprintf(hFile, "This is a hard link to a file\n");
            }
            else if (drstr == 0 &&
                hfs->has_meta_dir_crtime &&
                par_cnid == hfs->meta_dir_inum) {
                tsk_fprintf(hFile, "This is a hard link to a folder.\n");
            }
        }

        /* The cat.perm union contains file-type specific values.
         * Print them if they are relevant. */
        if ((fs_file->meta->type == TSK_FS_META_TYPE_CHR) ||
            (fs_file->meta->type == TSK_FS_META_TYPE_BLK)) {
            tsk_fprintf(hFile, "Device ID:\t%" PRIu32 "\n",
                tsk_getu32(fs->endian, entry.cat.std.perm.special.raw));
        }
        else if ((tsk_getu32(fs->endian,
                    entry.cat.std.u_info.file_type) ==
                HFS_HARDLINK_FILE_TYPE)
            && (tsk_getu32(fs->endian,
                    entry.cat.std.u_info.file_cr) ==
                HFS_HARDLINK_FILE_CREATOR)) {
            // technically, the creation date of this item should be the same as either the
            // creation date of the "HFS+ Private Data" folder or the creation date of the root folder
            tsk_fprintf(hFile, "Hard link inode number\t %" PRIu32 "\n",
                tsk_getu32(fs->endian, entry.cat.std.perm.special.inum));
        }

        tsk_fprintf(hFile, "Admin flags: %" PRIu8,
            entry.cat.std.perm.a_flags);
        if (entry.cat.std.perm.a_flags != 0) {
            tsk_fprintf(hFile, " - ");
            if (entry.cat.std.perm.a_flags & HFS_PERM_AFLAG_ARCHIVED)
                tsk_fprintf(hFile, "archived ");
            if (entry.cat.std.perm.a_flags & HFS_PERM_AFLAG_IMMUTABLE)
                tsk_fprintf(hFile, "immutable ");
            if (entry.cat.std.perm.a_flags & HFS_PERM_AFLAG_APPEND)
                tsk_fprintf(hFile, "append-only ");
        }
        tsk_fprintf(hFile, "\n");

        tsk_fprintf(hFile, "Owner flags: %" PRIu8,
            entry.cat.std.perm.o_flags);
        if (entry.cat.std.perm.o_flags != 0) {
            tsk_fprintf(hFile, " - ");
            if (entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_NODUMP)
                tsk_fprintf(hFile, "no-dump ");
            if (entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_IMMUTABLE)
                tsk_fprintf(hFile, "immutable ");
            if (entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_APPEND)
                tsk_fprintf(hFile, "append-only ");
            if (entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_OPAQUE)
                tsk_fprintf(hFile, "opaque ");
            if (entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_COMPRESSED)
                tsk_fprintf(hFile, "compressed ");
        }
        tsk_fprintf(hFile, "\n");

        if (tsk_getu16(fs->endian,
                entry.cat.std.flags) & HFS_FILE_FLAG_LOCKED)
            tsk_fprintf(hFile, "Locked\n");
        if (tsk_getu16(fs->endian,
                entry.cat.std.flags) & HFS_FILE_FLAG_ATTR)
            tsk_fprintf(hFile, "Has extended attributes\n");
        if (tsk_getu16(fs->endian,
                entry.cat.std.flags) & HFS_FILE_FLAG_ACL)
            tsk_fprintf(hFile, "Has security data (ACLs)\n");

        // File_type and file_cr are not relevant for Folders
        if (fs_file->meta->type != TSK_FS_META_TYPE_DIR) {
            int windx;          // loop index
            tsk_fprintf(hFile,
                "File type:\t%04" PRIx32 "  ",
                tsk_getu32(fs->endian, entry.cat.std.u_info.file_type));

            for (windx = 0; windx < 4; windx++) {
                uint8_t cu = entry.cat.std.u_info.file_type[windx];
                if (cu >= 32 && cu <= 126)
                    tsk_fprintf(hFile, "%c", (char) cu);
                else
                    tsk_fprintf(hFile, " ");
            }
            tsk_fprintf(hFile, "\n");
            tsk_fprintf(hFile,
                "File creator:\t%04" PRIx32 "  ",
                tsk_getu32(fs->endian, entry.cat.std.u_info.file_cr));
            for (windx = 0; windx < 4; windx++) {
                uint8_t cu = entry.cat.std.u_info.file_cr[windx];
                if (cu >= 32 && cu <= 126)
                    tsk_fprintf(hFile, "%c", (char) cu);
                else
                    tsk_fprintf(hFile, " ");
            }
            tsk_fprintf(hFile, "\n");
        }                       // END if(not folder)

        if (tsk_getu16(fs->endian,
                entry.cat.std.u_info.flags) & HFS_FINDER_FLAG_NAME_LOCKED)
            tsk_fprintf(hFile, "Name locked\n");
        if (tsk_getu16(fs->endian,
                entry.cat.std.u_info.flags) & HFS_FINDER_FLAG_HAS_BUNDLE)
            tsk_fprintf(hFile, "Has bundle\n");
        if (tsk_getu16(fs->endian,
                entry.cat.std.u_info.flags) & HFS_FINDER_FLAG_IS_INVISIBLE)
            tsk_fprintf(hFile, "Is invisible\n");
        if (tsk_getu16(fs->endian,
                entry.cat.std.u_info.flags) & HFS_FINDER_FLAG_IS_ALIAS)
            tsk_fprintf(hFile, "Is alias\n");

        tsk_fprintf(hFile, "Text encoding:\t%" PRIx32 " = %s\n",
            tsk_getu32(fs->endian, entry.cat.std.text_enc),
            text_encoding_name(tsk_getu32(fs->endian,
                    entry.cat.std.text_enc)));

        if (tsk_getu16(fs->endian,
                entry.cat.std.rec_type) == HFS_FILE_RECORD) {
            tsk_fprintf(hFile, "Resource fork size:\t%" PRIu64 "\n",
                tsk_getu64(fs->endian, entry.cat.resource.logic_sz));
        }
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted times:\n");
        if (fs_file->meta->mtime)
            fs_file->meta->mtime -= sec_skew;
        if (fs_file->meta->atime)
            fs_file->meta->atime -= sec_skew;
        if (fs_file->meta->ctime)
            fs_file->meta->ctime -= sec_skew;
        if (fs_file->meta->crtime)
            fs_file->meta->crtime -= sec_skew;
        if (fs_file->meta->time2.hfs.bkup_time)
            fs_file->meta->time2.hfs.bkup_time -= sec_skew;

        tsk_fprintf(hFile, "Created:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->crtime, timeBuf));
        tsk_fprintf(hFile, "Content Modified:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Attributes Modified:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->ctime, timeBuf));
        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->atime, timeBuf));
        tsk_fprintf(hFile, "Backed Up:\t%s\n",
            tsk_fs_time_to_str(fs_file->meta->time2.hfs.bkup_time,
                timeBuf));

        if (fs_file->meta->mtime == 0)
            fs_file->meta->mtime += sec_skew;
        if (fs_file->meta->atime == 0)
            fs_file->meta->atime += sec_skew;
        if (fs_file->meta->ctime == 0)
            fs_file->meta->ctime += sec_skew;
        if (fs_file->meta->crtime == 0)
            fs_file->meta->crtime += sec_skew;
        if (fs_file->meta->time2.hfs.bkup_time == 0)
            fs_file->meta->time2.hfs.bkup_time += sec_skew;

        tsk_fprintf(hFile, "\nOriginal times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nTimes:\n");
    }

    tsk_fprintf(hFile, "Created:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->crtime, timeBuf));
    tsk_fprintf(hFile, "Content Modified:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->mtime, timeBuf));
    tsk_fprintf(hFile, "Attributes Modified:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->ctime, timeBuf));
    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->atime, timeBuf));
    tsk_fprintf(hFile, "Backed Up:\t%s\n",
        tsk_fs_time_to_str(fs_file->meta->time2.hfs.bkup_time, timeBuf));

    // IF this is a regular file, then print out the blocks of the DATA and RSRC forks.
    if (tsk_getu16(fs->endian, entry.cat.std.rec_type) == HFS_FILE_RECORD) {
        // Only print DATA fork blocks if this file is NOT compressed
        // N.B., a compressed file has no data fork, and tsk_fs_file_walk() will
        //   do the wrong thing!
        if (!(entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_COMPRESSED)) {
            tsk_fprintf(hFile, "\nData Fork Blocks:\n");
            print.idx = 0;
            print.hFile = hFile;
            print.accumulating = FALSE;
            print.startBlock = 0;
            print.blockCount = 0;

            if (tsk_fs_file_walk_type(fs_file,
                    TSK_FS_ATTR_TYPE_HFS_DATA, HFS_FS_ATTR_ID_DATA,
                    (TSK_FS_FILE_WALK_FLAG_AONLY |
                        TSK_FS_FILE_WALK_FLAG_SLACK), print_addr_act,
                    (void *) &print)) {
                tsk_fprintf(hFile, "\nError reading file data fork\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
            else {
                output_print_addr(&print);
                if (print.idx != 0)
                    tsk_fprintf(hFile, "\n");
            }
        }

        // Only print out the blocks of the Resource fork if it has nonzero size
        if (tsk_getu64(fs->endian, entry.cat.resource.logic_sz) > 0) {
            tsk_fprintf(hFile, "\nResource Fork Blocks:\n");

            print.idx = 0;
            print.hFile = hFile;
            print.accumulating = FALSE;
            print.startBlock = 0;
            print.blockCount = 0;

            if (tsk_fs_file_walk_type(fs_file,
                    TSK_FS_ATTR_TYPE_HFS_RSRC, HFS_FS_ATTR_ID_RSRC,
                    (TSK_FS_FILE_WALK_FLAG_AONLY |
                        TSK_FS_FILE_WALK_FLAG_SLACK), print_addr_act,
                    (void *) &print)) {
                tsk_fprintf(hFile, "\nError reading file resource fork\n");
                tsk_error_print(hFile);
                tsk_error_reset();
            }
            else {
                output_print_addr(&print);
                if (print.idx != 0)
                    tsk_fprintf(hFile, "\n");
            }
        }

    }

    // Force the loading of all attributes.
    (void) tsk_fs_file_attr_get(fs_file);

    /* Print all of the attributes */
    tsk_fprintf(hFile, "\nAttributes: \n");
    if (fs_file->meta->attr) {
        int cnt, i;

        // cycle through the attributes
        cnt = tsk_fs_file_attr_getsize(fs_file);
        for (i = 0; i < cnt; i++) {
            const char *type;   // type of the attribute as a string
            const TSK_FS_ATTR *fs_attr =
                tsk_fs_file_attr_get_idx(fs_file, i);
            if (!fs_attr)
                continue;

            type = hfs_attrTypeName((uint32_t) fs_attr->type);


            // We will need to do something better than this, in the end.
            //type = "Data";

            /* print the layout if it is non-resident and not "special" */
            if (fs_attr->flags & TSK_FS_ATTR_NONRES) {
                //NTFS_PRINT_ADDR print_addr;

                tsk_fprintf(hFile,
                    "Type: %s (%" PRIu32 "-%" PRIu16
                    ")   Name: %s   Non-Resident%s%s%s   size: %"
                    PRIuOFF "  init_size: %" PRIuOFF "\n", type,
                    fs_attr->type, fs_attr->id,
                    (fs_attr->name) ? fs_attr->name : "N/A",
                    (fs_attr->flags & TSK_FS_ATTR_ENC) ? ", Encrypted" :
                    "",
                    (fs_attr->flags & TSK_FS_ATTR_COMP) ? ", Compressed" :
                    "",
                    (fs_attr->flags & TSK_FS_ATTR_SPARSE) ? ", Sparse" :
                    "", fs_attr->size, fs_attr->nrd.initsize);
            }                   // END:  non-resident attribute case
            else {
                tsk_fprintf(hFile,
                    "Type: %s (%" PRIu32 "-%" PRIu16
                    ")   Name: %s   Resident%s%s%s   size: %"
                    PRIuOFF "\n",
                    type,
                    fs_attr->type,
                    fs_attr->id,
                    (fs_attr->name) ? fs_attr->name : "N/A",
                    (fs_attr->flags & TSK_FS_ATTR_ENC) ? ", Encrypted" :
                    "",
                    (fs_attr->flags & TSK_FS_ATTR_COMP) ? ", Compressed" :
                    "",
                    (fs_attr->flags & TSK_FS_ATTR_SPARSE) ? ", Sparse" :
                    "", fs_attr->size);
                if (fs_attr->type == TSK_FS_ATTR_TYPE_HFS_COMP_REC) {
                    if (compressionAttr == NULL) {
                        compressionAttr = fs_attr;
                    }
                    else {
                        // Problem:  there is more than one compression attribute
                        error_detected(TSK_ERR_FS_CORRUPT,
                            "hfs_istat: more than one compression attribute");
                        return 1;
                    }
                }
            }                   // END: else (RESIDENT attribute case)
        }                       // END:  for(;;)  loop over attributes
    }                           // END:  if(fs_file->meta->attr is non-NULL)

    if ((entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_COMPRESSED)
        && (compressionAttr == NULL))
        tsk_fprintf(hFile,
            "WARNING: Compression Flag is set, but there"
            " is no compression record for this file.\n");
    if (((entry.cat.std.perm.o_flags & HFS_PERM_OFLAG_COMPRESSED) == 0)
        && (compressionAttr != NULL))
        tsk_fprintf(hFile,
            "WARNING: Compression Flag is NOT set, but there"
            " is a compression record for this file.\n");

    // IF this is a compressed file
    if (compressionAttr != NULL) {
        const TSK_FS_ATTR *fs_attr = compressionAttr;
        int attrReadResult;
        DECMPFS_DISK_HEADER *cmph;
        uint32_t cmpType;
        uint64_t uncSize;
        unsigned char reallyCompressed = FALSE;
        uint64_t cmpSize = 0;

        // Read the attribute.  It cannot be too large because it is stored in
        // a btree node
        char *aBuf = (char *) tsk_malloc((size_t) fs_attr->size);
        if (aBuf == NULL) {
            error_returned("hfs_istat: space for a compression attribute");
            return 1;
        }
        attrReadResult = tsk_fs_attr_read(fs_attr, (TSK_OFF_T) 0,
            aBuf, (size_t) fs_attr->size,
            (TSK_FS_FILE_READ_FLAG_ENUM) 0x00);
        if (attrReadResult == -1) {
            error_returned("hfs_istat: reading the compression attribute");
            free(aBuf);
            return 1;
        }
        else if (attrReadResult < fs_attr->size) {
            error_detected(TSK_ERR_FS_READ,
                "hfs_istat: could not read the whole compression attribute");
            free(aBuf);
            return 1;
        }
        // Now, cast the attr into a compression header
        cmph = (DECMPFS_DISK_HEADER *) aBuf;
        cmpType = tsk_getu32(TSK_LIT_ENDIAN, cmph->compression_type);
        uncSize = tsk_getu64(TSK_LIT_ENDIAN, cmph->uncompressed_size);

        if (cmpType == 3) {
            // Data is inline
            if ((cmph->attr_bytes[0] & 0x0F) == 0x0F) {
                reallyCompressed = FALSE;
                cmpSize = fs_attr->size - 17;   // subtr. size of header + 1 indicator byte
            }
            else {
                reallyCompressed = TRUE;
                cmpSize = fs_attr->size - 16;   // subt size of header
            }
        }
        else if (cmpType == 4) {
            // Data is compressed in the resource fork
            reallyCompressed = TRUE;
        }
        tsk_fprintf(hFile, "\nCompressed File:\n");
        tsk_fprintf(hFile, "    Uncompressed size: %llu\n", uncSize);
        if (cmpType == 4) {
            tsk_fprintf(hFile,
                "    Data is zlib compressed in the resource fork\n");
        }
        else if (cmpType == 3) {
            tsk_fprintf(hFile,
                "    Data follows compression record in the CMPF attribute\n");
            tsk_fprintf(hFile, "    %" PRIu64 " bytes of data at offset ",
                cmpSize);
            if (reallyCompressed)
                tsk_fprintf(hFile, "16, zlib compressed\n");
            else
                tsk_fprintf(hFile, "17, not compressed\n");
        }
        else {
            tsk_fprintf(hFile, "    Compression type is UNKNOWN\n");
        }
        free(aBuf);
        if (cmpType == 4
            && (tsk_getu64(fs->endian, entry.cat.resource.logic_sz) == 0))
            tsk_fprintf(hFile,
                "WARNING: Compression record indicates compressed data"
                " in the RSRC Fork, but that fork is empty.\n");
    }

    // This will return NULL if there is an error, or if there are no resources
    rd = hfs_parse_resource_fork(fs_file);
    // TODO: Should check the errnum here to see if there was an error

    if (rd != NULL) {
        tsk_fprintf(hFile, "\nResources:\n");
        while (rd) {
            tsk_fprintf(hFile,
                "  Type: %s \tID: %-5u \tOffset: %-5u \tSize: %-5u \tName: %s\n",
                rd->type, rd->id, rd->offset, rd->length, rd->name);
            rd = rd->next;
        }
    }
    // This is OK to call with NULL
    free_res_descriptor(rd);

    tsk_fs_file_close(fs_file);
    return 0;
}



static TSK_FS_ATTR_TYPE_ENUM
hfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    // The HFS+ special files have a default attr type of "Default"
    TSK_INUM_T inum = a_file->meta->addr;
    if (inum == 3 ||            // Extents File
        inum == 4 ||            // Catalog File
        inum == 5 ||            // Bad Blocks File
        inum == 6 ||            // Block Map (Allocation File)
        inum == 7 ||            // Startup File
        inum == 8 ||            // Attributes File
        inum == 14 ||           // Not sure if these two will actually work.  I don't see
        inum == 15)             // any code to load the attrs of these files, if they exist.
        return TSK_FS_ATTR_TYPE_DEFAULT;
    // The "regular" files and symbolic links have a DATA fork with type "DATA"
    if (a_file->meta->type == TSK_FS_META_TYPE_REG ||
        a_file->meta->type == TSK_FS_META_TYPE_LNK)
        // This should be an HFS-specific type.
        return TSK_FS_ATTR_TYPE_HFS_DATA;

    // We've got to return *something* for every file, so we return this.
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

static void
hfs_close(TSK_FS_INFO * fs)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    // We'll grab this lock a bit early.
    tsk_take_lock(&(hfs->metadata_dir_cache_lock));
    fs->tag = 0;

    free(hfs->fs);
    tsk_fs_file_close(hfs->catalog_file);
    hfs->catalog_attr = NULL;

    if (hfs->blockmap_file) {
        tsk_fs_file_close(hfs->blockmap_file);
        hfs->blockmap_attr = NULL;
    }

    if (hfs->meta_dir) {
        tsk_fs_dir_close(hfs->meta_dir);
        hfs->meta_dir = NULL;
    }

    if (hfs->dir_meta_dir) {
        tsk_fs_dir_close(hfs->dir_meta_dir);
        hfs->dir_meta_dir = NULL;
    }

    if (hfs->extents_file) {
        tsk_fs_file_close(hfs->extents_file);
        hfs->extents_file = NULL;
    }

    tsk_release_lock(&(hfs->metadata_dir_cache_lock));
    tsk_deinit_lock(&(hfs->metadata_dir_cache_lock));

    tsk_fs_free((TSK_FS_INFO *)hfs);
}

/* hfs_open - open an hfs file system
 *
 * Return NULL on error (or not an HFS or HFS+ file system)
 * */

TSK_FS_INFO *
hfs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset,
    TSK_FS_TYPE_ENUM ftype, uint8_t test)
{
    HFS_INFO *hfs;
    unsigned int len;
    TSK_FS_INFO *fs;
    ssize_t cnt;
    TSK_FS_FILE *file;          // The root directory, or the metadata directories
    TSK_INUM_T inum;            // The inum (or CNID) of the metadata directories
    int8_t result;              // of tsk_fs_path2inum()

    tsk_error_reset();

    if (TSK_FS_TYPE_ISHFS(ftype) == 0) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in hfs_open");
        return NULL;
    }

    if ((hfs = (HFS_INFO *) tsk_fs_malloc(sizeof(HFS_INFO))) == NULL)
        return NULL;

    fs = &(hfs->fs_info);

    fs->ftype = TSK_FS_TYPE_HFS;
    fs->duname = "Allocation Block";
    fs->tag = TSK_FS_INFO_TAG;
    fs->flags = 0;

    fs->img_info = img_info;
    fs->offset = offset;

    /*
     * Read the superblock.
     */
    len = sizeof(hfs_plus_vh);
    if ((hfs->fs = (hfs_plus_vh *) tsk_malloc(len)) == NULL) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)hfs);
        return NULL;
    }

    if (hfs_checked_read_random(fs, (char *) hfs->fs, len,
            (TSK_OFF_T) HFS_VH_OFF)) {
        tsk_error_set_errstr2("hfs_open: superblock");
        fs->tag = 0;
        free(hfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hfs);
        return NULL;
    }

    /*
     * Verify we are looking at an HFS+ image
     */
    if (tsk_fs_guessu16(fs, hfs->fs->signature, HFS_VH_SIG_HFSPLUS) &&
        tsk_fs_guessu16(fs, hfs->fs->signature, HFS_VH_SIG_HFSX) &&
        tsk_fs_guessu16(fs, hfs->fs->signature, HFS_VH_SIG_HFS)) {

        fs->tag = 0;
        free(hfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hfs);
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an HFS+ file system (magic)");
        return NULL;
    }

    /*
     * Handle an HFS-wrapped HFS+ image, which is a HFS volume that contains
     * the HFS+ volume inside of it. 
     */
    if (tsk_getu16(fs->endian, hfs->fs->signature) == HFS_VH_SIG_HFS) {

        hfs_mdb *wrapper_sb = (hfs_mdb *) hfs->fs;

        // Verify that we are setting a wrapper and not a normal HFS volume
        if ((tsk_getu16(fs->endian,
                    wrapper_sb->drEmbedSigWord) == HFS_VH_SIG_HFSPLUS)
            || (tsk_getu16(fs->endian,
                    wrapper_sb->drEmbedSigWord) == HFS_VH_SIG_HFSX)) {

            TSK_FS_INFO *fs_info2;
            // offset in sectors to start of first HFS block
            uint16_t drAlBlSt =
                tsk_getu16(fs->endian, wrapper_sb->drAlBlSt);

            // size of each HFS block
            uint32_t drAlBlkSiz =
                tsk_getu32(fs->endian, wrapper_sb->drAlBlkSiz);

            // start of embedded FS 
            uint16_t startBlock = tsk_getu16(fs->endian,
                wrapper_sb->drEmbedExtent_startBlock);

            // calculate the offset; 512 here is intentional.
            // TN1150 says "The drAlBlSt field contains the offset, in
            // 512-byte blocks, of the wrapper's allocation block 0 relative
            // to the start of the volume"
            TSK_OFF_T hfsplus_offset =
                (drAlBlSt * (TSK_OFF_T) 512) +
                (drAlBlkSiz * (TSK_OFF_T) startBlock);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_open: HFS+/HFSX within HFS wrapper at byte offset %"
                    PRIuOFF "\n", hfsplus_offset);

            fs->tag = 0;
            free(hfs->fs);
            tsk_fs_free((TSK_FS_INFO *)hfs);

            /* just re-open with the new offset, then record the offset */
            fs_info2 =
                hfs_open(img_info, offset + hfsplus_offset, ftype, test);

            if (fs_info2)
                ((HFS_INFO *) fs_info2)->hfs_wrapper_offset =
                    hfsplus_offset;

            return fs_info2;
        }
        else {
            fs->tag = 0;
            free(hfs->fs);
            tsk_fs_free((TSK_FS_INFO *)hfs);
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("HFS file systems (other than wrappers HFS+/HFSX file systems) are not supported");
            return NULL;
        }
    }

    fs->block_count = tsk_getu32(fs->endian, hfs->fs->blk_cnt);
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;

    /* this isn't really accurate; fs->block_size reports only the size
       of the allocation block; the size of the device block has to be
       found from the device (allocation block size should always be
       larger than device block size and an even multiple of the device
       block size) */
    fs->dev_bsize = fs->block_size =
        tsk_getu32(fs->endian, hfs->fs->blk_sz);

    // determine the last block we have in this image
    if ((TSK_DADDR_T) ((img_info->size - offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    // Initialize the lock
    tsk_init_lock(&(hfs->metadata_dir_cache_lock));

    /*
     * Set function pointers
     */
    fs->inode_walk = hfs_inode_walk;
    fs->block_walk = hfs_block_walk;
    fs->block_getflags = hfs_block_getflags;
    fs->load_attrs = hfs_load_attrs;
    fs->get_default_attr_type = hfs_get_default_attr_type;

    fs->file_add_meta = hfs_inode_lookup;
    fs->dir_open_meta = hfs_dir_open_meta;
    fs->fsstat = hfs_fsstat;
    fs->fscheck = hfs_fscheck;
    fs->istat = hfs_istat;
    fs->close = hfs_close;

    // lazy loading of block map
    hfs->blockmap_file = NULL;
    hfs->blockmap_attr = NULL;
    hfs->blockmap_cache_start = -1;
    hfs->blockmap_cache_len = 0;

    fs->first_inum = HFS_ROOT_INUM;
    fs->root_inum = HFS_ROOT_INUM;
    fs->last_inum = HFS_FIRST_USER_CNID - 1;    // we will later increase this
    fs->inum_count = fs->last_inum - fs->first_inum + 1;

    /* We will load the extents file data when we need it */
    hfs->extents_file = NULL;
    hfs->extents_attr = NULL;

    /* Load the catalog file though */
    if ((hfs->catalog_file =
            tsk_fs_file_open_meta(fs, NULL,
                HFS_CATALOG_FILE_ID)) == NULL) {
        fs->tag = 0;
        free(hfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hfs);
        return NULL;
    }

    /* cache the data attribute */
    hfs->catalog_attr =
        tsk_fs_attrlist_get(hfs->catalog_file->meta->attr,
        TSK_FS_ATTR_TYPE_DEFAULT);
    if (!hfs->catalog_attr) {
        fs->tag = 0;
        tsk_fs_file_close(hfs->catalog_file);
        free(hfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hfs);
        tsk_error_errstr2_concat
            (" - Data Attribute not found in Catalog File");
        return NULL;
    }

    // cache the catalog file header
    cnt = tsk_fs_attr_read(hfs->catalog_attr, 14,
        (char *) &(hfs->catalog_header),
        sizeof(hfs_btree_header_record), 0);
    if (cnt != sizeof(hfs_btree_header_record)) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("hfs_open: Error reading catalog header");
        fs->tag = 0;
        free(hfs->fs);
        tsk_fs_free((TSK_FS_INFO *)hfs);
        return NULL;
    }

    if (tsk_getu16(fs->endian, hfs->fs->version) == HFS_VH_VER_HFSPLUS)
        hfs->is_case_sensitive = 0;
    else if (tsk_getu16(fs->endian, hfs->fs->version) == HFS_VH_VER_HFSX) {
        if (hfs->catalog_header.compType == HFS_BT_HEAD_COMP_SENS)
            hfs->is_case_sensitive = 1;
        else if (hfs->catalog_header.compType == HFS_BT_HEAD_COMP_INSENS)
            hfs->is_case_sensitive = 0;
        else {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_open: invalid value (0x%02" PRIx8
                    ") for key compare type; using case-insensitive\n",
                    hfs->catalog_header.compType);
            hfs->is_case_sensitive = 0;
        }
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: unknown HFS+/HFSX version (%" PRIu16 "\n",
                tsk_getu16(fs->endian, hfs->fs->version));
        hfs->is_case_sensitive = 0;
    }

    // update the numbers.
    fs->last_inum = hfs_find_highest_inum(hfs);
    fs->inum_count = fs->last_inum + 1;

    snprintf((char *) fs->fs_id, 17, "%08" PRIx32 "%08" PRIx32,
        tsk_getu32(fs->endian, hfs->fs->finder_info[HFS_VH_FI_ID1]),
        tsk_getu32(fs->endian, hfs->fs->finder_info[HFS_VH_FI_ID2]));
    fs->fs_id_used = 16;

    /* journal */
    fs->jblk_walk = hfs_jblk_walk;
    fs->jentry_walk = hfs_jentry_walk;
    fs->jopen = hfs_jopen;
    fs->name_cmp = hfs_name_cmp;
    fs->journ_inum = 0;

    /* Creation Times */

    // First, the root
    file = tsk_fs_file_open_meta(fs, NULL, 2);
    if (file != NULL) {
        hfs->root_crtime = file->meta->crtime;
        hfs->has_root_crtime = TRUE;
        tsk_fs_file_close(file);
    }
    else {
        hfs->has_root_crtime = FALSE;
    }
    file = NULL;

    // disable hard link traversal while finding the hard
    // link directories themselves (to prevent problems if
    // there are hard links in the root directory)
    hfs->meta_inum = 0;
    hfs->meta_dir_inum = 0;

    // Now the (file) metadata directory

    // The metadata directory is a sub-directory of the root.  Its name begins with four nulls, followed
    // by "HFS+ Private Data".  The file system parsing code replaces nulls in filenames with UTF8_NULL_REPLACE.
    // In the released version of TSK, this replacement is the character '^'.
    // NOTE: There is a standard Unicode replacement which is 0xfffd in UTF16 and 0xEF 0xBF 0xBD in UTF8.
    // Systems that require the standard definition can redefine UTF8_NULL_REPLACE and UTF16_NULL_REPLACE
    // in tsk_hfs.h
    hfs->has_meta_crtime = FALSE;
    result =
        tsk_fs_path2inum(fs,
        "/" UTF8_NULL_REPLACE UTF8_NULL_REPLACE UTF8_NULL_REPLACE
        UTF8_NULL_REPLACE "HFS+ Private Data", &inum, NULL);
    if (result == 0) {
        TSK_FS_FILE *file_tmp = tsk_fs_file_open_meta(fs, NULL, inum);
        if (file_tmp != NULL) {
            hfs->meta_crtime = file_tmp->meta->crtime;
            hfs->has_meta_crtime = TRUE;
            hfs->meta_inum = inum;
            tsk_fs_file_close(file_tmp);
        }
    }

    // Now, the directory metadata directory

    // The "directory" metadata directory, where hardlinked directories actually live, is a subdirectory
    // of the root.  The beginning of the name of this directory is ".HFS+ Private Directory Data" which
    // is followed by a carriage return (ASCII 13).
    hfs->has_meta_dir_crtime = FALSE;
    result =
        tsk_fs_path2inum(fs, "/.HFS+ Private Directory Data\r", &inum,
        NULL);
    if (result == 0) {
        TSK_FS_FILE *file_tmp = tsk_fs_file_open_meta(fs, NULL, inum);
        if (file_tmp != NULL) {
            hfs->metadir_crtime = file_tmp->meta->crtime;
            hfs->has_meta_dir_crtime = TRUE;
            hfs->meta_dir_inum = inum;
            tsk_fs_file_close(file_tmp);
        }
    }

    if (hfs->has_root_crtime && hfs->has_meta_crtime
        && hfs->has_meta_dir_crtime) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Creation times for key folders have been read and cached.\n");
    }
    if (!hfs->has_root_crtime) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Warning: Could not open the root directory.  "
                "Hard link detection and some other functions will be impaired\n");
    }
    else if (tsk_verbose) {
        tsk_fprintf(stderr,
            "hfs_open: The root directory is accessible.\n");
    }

    if (tsk_verbose) {
        if (hfs->has_meta_crtime)
            tsk_fprintf(stderr,
                "hfs_open: \"/^^^^HFS+ Private Data\" metadata folder is accessible.\n");
        else
            tsk_fprintf(stderr,
                "hfs_open: Optional \"^^^^HFS+ Private Data\" metadata folder is not accessible, or does not exist.\n");
        if (hfs->has_meta_dir_crtime)
            tsk_fprintf(stderr,
                "hfs_open: \"/HFS+ Private Directory Data^\" metadata folder is accessible.\n");
        else
            tsk_fprintf(stderr,
                "hfs_open: Optional \"/HFS+ Private Directory Data^\" metadata folder is not accessible, or does not exist.\n");
    }

    // These caches will be set, if they are needed.
    hfs->meta_dir = NULL;
    hfs->dir_meta_dir = NULL;

    if (tsk_getu32(fs->endian,
            hfs->fs->start_file.extents[0].blk_cnt) == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Optional Startup File is not present.\n");
        hfs->has_startup_file = FALSE;
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_open: Startup File is present.\n");
        hfs->has_startup_file = TRUE;
    }

    if (tsk_getu32(fs->endian, hfs->fs->ext_file.extents[0].blk_cnt) == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Optional Extents File (and Badblocks File) is not present.\n");
        hfs->has_extents_file = FALSE;
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Extents File (and BadBlocks File) is present.\n");
        hfs->has_extents_file = TRUE;
    }

    if (tsk_getu32(fs->endian, hfs->fs->attr_file.extents[0].blk_cnt) == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_open: Optional Attributes File is not present.\n");
        hfs->has_attributes_file = FALSE;
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_open: Attributes File is present.\n");
        hfs->has_attributes_file = TRUE;
    }

    return fs;
}


/*
 * Error Handling
 */

/**
 * Call this when an error is first detected.  It sets the error code and it also
 * sets the primary error string, describing the lowest level of error.  (Actually,
 * it appends to the error string.)
 *
 * If the error code is already set, then this appends to the primary error
 * string an hex representation of the new error code, plus the new error message.
 *
 * @param errnum  The desired error code
 * @param errstr  The format string for the error message
 */
void
error_detected(uint32_t errnum, char *errstr, ...)
{
    va_list args;

    va_start(args, errstr);

    {
        TSK_ERROR_INFO *errInfo = tsk_error_get_info();
        char *loc_errstr = errInfo->errstr;

        if (errInfo->t_errno == 0)
            errInfo->t_errno = errnum;
        else {
            //This should not happen!  We don't want to wipe out the existing error
            //code, so we write the new code into the error string, in hex.
            int sl = strlen(errstr);
            snprintf(loc_errstr + sl, TSK_ERROR_STRING_MAX_LENGTH - sl,
                " Next errnum: 0x%x ", errnum);
        }
        if (errstr != NULL) {
            int sl = strlen(loc_errstr);
            vsnprintf(loc_errstr + sl, TSK_ERROR_STRING_MAX_LENGTH - sl,
                errstr, args);
        }
    }

    va_end(args);

}

/**
 * Call this when a called TSK function returns an error.  Presumably, that
 * function will have set the error code and the primary error string.  This
 * *appends* to the secondary error string.  It should be called to describe
 * the context of the call.  If no error code has been set, then this sets a
 * default code so that it is not zero.
 *
 * @param errstr  The format string for the error message
 */
void
error_returned(char *errstr, ...)
{
    va_list args;
    va_start(args, errstr);

    {
        TSK_ERROR_INFO *errInfo = tsk_error_get_info();
        char *loc_errstr2 = errInfo->errstr2;

        if (errInfo->t_errno == 0)
            errInfo->t_errno = TSK_ERR_AUX_GENERIC;
        if (errstr != NULL) {
            int sl = strlen(loc_errstr2);
            vsnprintf(loc_errstr2 + sl, TSK_ERROR_STRING_MAX_LENGTH - sl,
                errstr, args);
        }
    }
    va_end(args);
}
