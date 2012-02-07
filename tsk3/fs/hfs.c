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
** Copyright (c) 2009-2011 Brian Carrier.  All rights reserved.
**
** Judson Powers [jpowers@atc-nycorp.com]
** Copyright (c) 2008 ATC-NY.  All rights reserved.
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
 * Contains the general internal TSK HFS metadata and data unit code -- Not included in code by default.
 */

#include "tsk_fs_i.h"
#include "tsk_hfs.h"

#define XSWAP(a,b) { a ^= b; b ^= a; a ^= b; }

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
hfs2unixtime(uint32_t hfsdate)
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

        if ((addr == 0) && (len == 0))
            break;

        // make a non-resident run
        if ((cur_run = tsk_fs_attr_run_alloc()) == NULL)
            return NULL;

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
 * @returns 1 on error and 0 on success
 */
static uint8_t
hfs_ext_find_extent_record_attr(HFS_INFO * hfs, uint32_t cnid,
    TSK_FS_ATTR * a_attr)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t nodesize;          /* size of nodes (all, regardless of the name) */
    uint32_t cur_node;          /* node id of the current node */
    char *node = NULL;
    uint8_t is_done;

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_ext_find_extent_record_attr: Looking for extents for file %"
            PRIu32 "\n", cnid);

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
                ("- Default Attribute not found in Extents File");
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
                        ("hfs_ext_find_extent_record_attr: offset of record %d in index node %d too large (%zu vs %"
                        PRIu16 ")", rec, cur_node, rec_off, nodesize);
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
                            ("hfs_ext_find_extent_record_attr: offset and keylenth of record %d in index node %d too large (%zu vs %"
                            PRIu16 ")", rec, cur_node, rec_off + keylen,
                            nodesize);
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
                    fprintf(stderr,
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
                        ("hfs_ext_find_extent_record_attr: offset of record %d in leaf node %d too large (%zu vs %"
                        PRIu16 ")", rec, cur_node, rec_off, nodesize);
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
                if (rec_cnid < cnid) {
                    continue;
                }
                else if ((rec_cnid > cnid)
                    || (key->fork_type != HFS_EXT_KEY_TYPE_DATA)) {
                    is_done = 1;
                    break;
                }

                keylen = 2 + tsk_getu16(fs->endian, key->key_len);
                if (rec_off + keylen > nodesize) {
                    tsk_error_set_errno(TSK_ERR_FS_GENFS);
                    tsk_error_set_errstr
                        ("hfs_ext_find_extent_record_attr: offset and keylenth of record %d in leaf node %d too large (%zu vs %"
                        PRIu16 ")", rec, cur_node, rec_off + keylen,
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
                        ("- hfs_ext_find_extent_record_attr");
                    free(node);
                    return 1;
                }

                if (tsk_fs_attr_add_run(fs, a_attr, attr_run)) {
                    tsk_error_errstr2_concat
                        ("- hfs_ext_find_extent_record_attr");
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
                        ("hfs_cat_traverse: offset of record %d in index node %d too large (%zu vs %"
                        PRIu16 ")", rec, cur_node, rec_off, nodesize);
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
                            ("hfs_cat_traverse: offset of record and keylength %d in index node %d too large (%zu vs %"
                            PRIu16 ")", rec, cur_node, rec_off + keylen,
                            nodesize);
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
                        ("hfs_cat_traverse: offset of record %d in leaf node %d too large (%zu vs %"
                        PRIu16 ")", rec, cur_node, rec_off, nodesize);
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
                    fprintf(stderr,
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
        fprintf(stderr,
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


/** \internal
 * Lookup an entry in the catalog file and save it into the entry.  Do not
 * call this for the special files that do not have an entry in the catalog.
 * data structure.
 * @param hfs File system being analyzed
 * @param inum Address (cnid) of file to open
 * @param entry [out] Structure to read data into
 * @returns 1 on error or not found, 0 on success. Check tsk_errno
 * to differentiate between error and not found.
 */
uint8_t
hfs_cat_file_lookup(HFS_INFO * hfs, TSK_INUM_T inum, HFS_ENTRY * entry)
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
            PRIuINUM ")\n", tsk_getu32(fs->endian, key.parent_cnid));

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
            fprintf(stderr,
                "hfs_cat_file_lookup: found folder record valence %" PRIu32
                ", cnid %" PRIu32 "\n", tsk_getu32(fs->endian,
                    record.folder.std.valence), tsk_getu32(fs->endian,
                    record.folder.std.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_folder));
    }
    else if (tsk_getu16(fs->endian,
            record.file.std.rec_type) == HFS_FILE_RECORD) {
        if (tsk_verbose)
            fprintf(stderr,
                "hfs_cat_file_lookup: found file record cnid %" PRIu32
                "\n", tsk_getu32(fs->endian, record.file.std.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_file));
    }
    /* other cases already caught by hfs_cat_read_file_folder_record */

    memcpy((char *) &entry->thread, (char *) &thread, sizeof(hfs_thread));

    entry->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;
    entry->inum = inum;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_cat_file_lookup exited\n");
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
hfsmode2tskmode(uint16_t a_mode)
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
hfsmode2tskmetatype(uint16_t a_mode)
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
                tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
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

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_catalog: Making virtual catalog file\n");

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_CATALOG_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_CATALOGNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz);


    // convert the  runs in the volume header to attribute runs
    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->cat_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat("- hfs_make_catalog");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat("- hfs_make_catalog");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz), 0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_catalog");
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_CATALOG_FILE_ID, fs_attr)) {
        tsk_error_errstr2_concat("- hfs_make_catalog");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
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

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_EXTENTS_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_EXTENTSNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz);


    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->ext_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat("- hfs_make_extents");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat("- hfs_make_extents");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz), 0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_extents");
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

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

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_blockmap: Making virtual blockmap file\n");

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_ALLOCATION_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_ALLOCATIONNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->alloc_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat("- hfs_make_blockmap");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat("- hfs_make_blockmap");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->alloc_file.logic_sz), 0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_blockmap");
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_ALLOCATION_FILE_ID,
            fs_attr)) {
        tsk_error_errstr2_concat("- hfs_make_blockmap");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
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

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_startfile: Making virtual startup file\n");

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_STARTUP_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_STARTUPNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->start_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat(" - hfs_make_startfile");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat("- hfs_make_startfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->start_file.logic_sz), 0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_startfile");
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_STARTUP_FILE_ID, fs_attr)) {
        tsk_error_errstr2_concat("- hfs_make_startfile");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
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

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_ATTRIBUTES_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_ATTRIBUTESNAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size =
        tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz);

    if (((attr_run =
                hfs_extents_to_attr(fs, hfs->fs->attr_file.extents,
                    0)) == NULL) && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
        return 1;
    }

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat(" - hfs_make_attrfile");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz),
            tsk_getu64(fs->endian, hfs->fs->attr_file.logic_sz), 0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_ATTRIBUTES_FILE_ID,
            fs_attr)) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

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

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_badblockfile: Making virtual badblock file\n");

    if (hfs_make_specialbase(fs_file))
        return 1;

    fs_file->meta->addr = HFS_BAD_BLOCK_FILE_ID;
    strncpy(fs_file->meta->name2->name, HFS_BAD_BLOCK_FILE_NAME,
        TSK_FS_META_NAME_LIST_NSIZE);

    fs_file->meta->size = 0;

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
        return 1;
    }

    // Add the run to the file.
    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            fs_file->meta->size, fs_file->meta->size, fs_file->meta->size,
            0, 0)) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
        tsk_fs_attr_free(fs_attr);
        return 1;
    }

    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_BAD_BLOCK_FILE_ID,
            fs_attr)) {
        tsk_error_errstr2_concat("- hfs_make_attrfile");
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

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}


/** \internal
 * Copy the catalog file or folder record entry into a TSK data structure.
 * @param a_hfs File system being analyzed
 * @param a_entry Catalog record entry
 * @param a_fs_meta Structure to copy data into
 * Returns 1 on error.
 */
static uint8_t
hfs_dinode_copy(HFS_INFO * a_hfs, const hfs_file_folder * a_entry,
    TSK_FS_META * a_fs_meta)
{
    const hfs_file_fold_std *std;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & a_hfs->fs_info;
    uint16_t hfsmode;

    if (a_fs_meta == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_dinode_copy: a_fs_meta is NULL");
        return 1;
    }

    // both files and folders start of the same
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
        a_fs_meta->mode = hfsmode2tskmode(hfsmode);
        a_fs_meta->type = hfsmode2tskmetatype(hfsmode);
        a_fs_meta->uid = tsk_getu32(fs->endian, std->perm.owner);
        a_fs_meta->gid = tsk_getu32(fs->endian, std->perm.group);
    }

    // this field is set only for "indirect" entries
    if (tsk_getu32(fs->endian, std->perm.special.nlink))
        a_fs_meta->nlink = tsk_getu32(fs->endian, std->perm.special.nlink);
    else
        a_fs_meta->nlink = 1;

    a_fs_meta->mtime = hfs2unixtime(tsk_getu32(fs->endian, std->cmtime));
    a_fs_meta->atime = hfs2unixtime(tsk_getu32(fs->endian, std->atime));
    a_fs_meta->crtime = hfs2unixtime(tsk_getu32(fs->endian, std->crtime));
    a_fs_meta->ctime = hfs2unixtime(tsk_getu32(fs->endian, std->amtime));
    a_fs_meta->time2.hfs.bkup_time =
        hfs2unixtime(tsk_getu32(fs->endian, std->bkup_date));
    a_fs_meta->mtime_nano = a_fs_meta->atime_nano = a_fs_meta->ctime_nano =
        a_fs_meta->crtime_nano = 0;
    a_fs_meta->time2.hfs.bkup_time_nano = 0;


    a_fs_meta->addr = tsk_getu32(fs->endian, std->cnid);

    // All entries here are used.
    a_fs_meta->flags = TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_USED;

    /* TODO @@@ could fill in name2 with this entry's name and parent inode
       from Catalog entry */

    /* If a sym link, copy the destination to a_fs_meta->link */
    /*
       if (fs_file->meta->type == TSK_FS_META_TYPE_LNK) {
       @@@ Need to do this.  We need to read the file content,
       but we don't really have enough context (i.e. FS_FILE)
       to simply use the existing load and read functions.
       Probably need to make a dummy TSK_FS_FILE.
       }
     */

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
        if (a_fs_file->meta == NULL)
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
        if (hfs_make_extents(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }
    else if (inum == HFS_CATALOG_FILE_ID) {
        if (hfs_make_catalog(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }
    else if (inum == HFS_BAD_BLOCK_FILE_ID) {
        if (hfs_make_badblockfile(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }
    else if (inum == HFS_ALLOCATION_FILE_ID) {
        if (hfs_make_blockmap(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }
    else if (inum == HFS_STARTUP_FILE_ID) {
        if (hfs_make_startfile(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }
    else if (inum == HFS_ATTRIBUTES_FILE_ID) {
        if (hfs_make_attrfile(hfs, a_fs_file))
            return 1;
        else
            return 0;
    }

    /* Lookup inode and store it in the HFS structure */
    if (hfs_cat_file_lookup(hfs, inum, &entry))
        return 1;

    /* Copy the structure in hfs to generic fs_inode */
    if (hfs_dinode_copy(hfs, (const hfs_file_folder *) &entry.cat,
            a_fs_file->meta)) {
        return 1;
    }

    return 0;
}

/** \internal
 * Populate the attributes in fs_file using the internal fork data.  This uses
 * the data cached in the content_ptr structure.
 * @param fs_file File to load attributes for
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
hfs_load_attrs(TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs;
    HFS_INFO *hfs;
    TSK_FS_ATTR *fs_attr;
    TSK_FS_ATTR_RUN *attr_run;
    hfs_fork *fork;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file == NULL) || (fs_file->meta == NULL)
        || (fs_file->fs_info == NULL)) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_load_attrs: fs_file or meta is NULL");
        return 1;
    }
    if (fs_file->meta->content_ptr == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("hfs_load_attrs: content_ptr is NULL");
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
        return 0;
    }
    else if (fs_file->meta->attr_state == TSK_FS_META_ATTR_ERROR) {
        return 1;
    }
    // not sure why this would ever happen, but...
    else if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else if (fs_file->meta->attr == NULL) {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }

    // get an attribute structure to store the data in
    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        tsk_error_errstr2_concat(" - hfs_load_attrs");
        return 1;
    }
    /* NOTE that fs_attr is now tied to fs_file->meta->attr.
     * that means that we do not need to free it if we abort in the
     * following code (and doing so will cause double free errors). */

    // if not a file or symbolic link, then make an empty entry
    if ((fs_file->meta->type != TSK_FS_META_TYPE_REG)
        && (fs_file->meta->type != TSK_FS_META_TYPE_LNK)) {
        if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL,
                TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT, 0, 0, 0,
                0, 0)) {
            tsk_error_errstr2_concat("- hfs_load_attrs (non-file)");
            return 1;
        }
        fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
        return 0;
    }

    /*
       @@@ We need to detect hard links and load up the indirect node info
       instead of the current node info.

       //Detect Hard links
       else if ((tsk_getu32(fs->endian,
       entry.cat.std.u_info.file_type) == HFS_HARDLINK_FILE_TYPE)
       && (tsk_getu32(fs->endian,
       entry.cat.std.u_info.file_cr) ==
       HFS_HARDLINK_FILE_CREATOR)) {

       //  Get the indirect node value
       tsk_getu32(fs->endian, entry.cat.std.perm.special.inum)

       // Find the indirect node
       "/____HFS+ Private Data/iNodeXXXX"
       // Load its runs and look in extents for others (based on its CNID)
     */


    // Get the data fork and convert it to the TSK format
    fork = (hfs_fork *) fs_file->meta->content_ptr;
    if (((attr_run = hfs_extents_to_attr(fs, fork->extents, 0)) == NULL)
        && (tsk_error_get_errno() != 0)) {
        tsk_error_errstr2_concat("- hfs_load_attrs");
        return 1;
    }

    // add the runs to the attribute and the attribute to the file.
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
            tsk_getu64(fs->endian, fork->logic_sz),
            tsk_getu64(fs->endian, fork->logic_sz),
            (TSK_OFF_T) tsk_getu32(fs->endian,
                fork->total_blk) * fs->block_size, 0, 0)) {
        tsk_error_errstr2_concat("- hfs_load_attrs");
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }

    // see if extents file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs,
            (uint32_t) fs_file->meta->addr, fs_attr)) {
        tsk_error_errstr2_concat("- hfs_load_attrs");
        fs_file->meta->attr_state = TSK_FS_META_ATTR_ERROR;
        return 1;
    }

    // @@@ Load resource fork too

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
    int8_t ret;

    tsk_take_lock(&hfs->lock);

    // lazy loading
    if (hfs->blockmap_file == NULL) {
        if ((hfs->blockmap_file =
                tsk_fs_file_open_meta(fs, NULL,
                    HFS_ALLOCATION_FILE_ID)) == NULL) {
            tsk_release_lock(&hfs->lock);
            tsk_error_errstr2_concat("- Loading blockmap file");
            return -1;
        }

        /* cache the data attribute */
        hfs->blockmap_attr =
            tsk_fs_attrlist_get(hfs->blockmap_file->meta->attr,
            TSK_FS_ATTR_TYPE_DEFAULT);
        if (!hfs->blockmap_attr) {
            tsk_release_lock(&hfs->lock);
            tsk_error_errstr2_concat
                ("- Data Attribute not found in blockmap File");
            return -1;
        }
        hfs->blockmap_cache_start = -1;
        hfs->blockmap_cache_len = 0;
    }

    // get the byte offset
    b = (TSK_OFF_T) a_addr / 8;
    if (b > hfs->blockmap_file->meta->size) {
        tsk_release_lock(&hfs->lock);
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
            tsk_release_lock(&hfs->lock);
            tsk_error_set_errstr2
                ("hfs_block_is_alloc: Error reading block bitmap at offset %"
                PRIuOFF, b);
            return -1;
        }
        hfs->blockmap_cache_start = b;
        hfs->blockmap_cache_len = cnt;
    }
    b2 = (size_t) (b - hfs->blockmap_cache_start);

    ret = (hfs->blockmap_cache[b2] & (1 << (7 - (a_addr % 8)))) != 0;
    tsk_release_lock(&hfs->lock);
    return ret;
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


        if (tsk_fs_block_get(fs, fs_block, addr) == NULL) {
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
    if (start_inum < fs->first_inum) {
        tsk_fprintf(stderr,
            "Starting inode number is too small (%" PRIuINUM ")",
            start_inum);
        return 1;
    }
    if (start_inum > fs->last_inum) {
        tsk_fprintf(stderr,
            "Starting inode number is too large (%" PRIuINUM ")",
            start_inum);
        return 1;
    }

    if (end_inum < fs->first_inum) {
        tsk_fprintf(stderr,
            "Ending inode number is too small (%" PRIuINUM ")", end_inum);
        return 1;
    }

    if (end_inum > fs->last_inum) {
        tsk_fprintf(stderr,
            "Ending inode number is too large (%" PRIuINUM ")", end_inum);
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
char *hfs_get_inode_name(TSK_FS_INFO * fs, TSK_INUM_T inum) {
    HFS_INFO *hfs = (HFS_INFO *) fs;
    HFS_ENTRY entry;
	
    if (hfs_cat_file_lookup(hfs, inum, &entry))
        return NULL;

	char *fn = malloc( HFS_MAXNAMLEN + 1 );
	if ( fn == NULL )
		return NULL;
	
    if (hfs_uni2ascii(fs, entry.thread.name.unicode,
					  tsk_getu16(fs->endian, entry.thread.name.length), fn,
					  HFS_MAXNAMLEN + 1)) {
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

    if (hfs_cat_file_lookup(hfs, inum, &entry))
        return 1;

    if (hfs_uni2ascii(fs, entry.thread.name.unicode,
            tsk_getu16(fs->endian, entry.thread.name.length), fn,
            HFS_MAXNAMLEN + 1))
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

    if (hfs_cat_file_lookup(hfs, inum, &entry))
        return 1;

    if (hfs_uni2ascii(fs, entry.thread.name.unicode,
            tsk_getu16(fs->endian, entry.thread.name.length), fn,
            HFS_MAXNAMLEN + 1))
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
    char timeBuf[32];

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
    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->cr_date));
    tsk_fprintf(hFile, "\nCreation Date: \t%s\n",
        tsk_fs_time_to_str(mktime(gmtime(&mac_time)), timeBuf));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->m_date));
    tsk_fprintf(hFile, "Last Written Date: \t%s\n",
        tsk_fs_time_to_str(mac_time, timeBuf));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->bkup_date));
    tsk_fprintf(hFile, "Last Backup Date: \t%s\n",
        tsk_fs_time_to_str(mac_time, timeBuf));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->chk_date));
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

#define HFS_PRINT_WIDTH 8
typedef struct {
    FILE *hFile;
    int idx;
} HFS_PRINT_ADDR;

static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM flags, void *ptr)
{
    HFS_PRINT_ADDR *print = (HFS_PRINT_ADDR *) ptr;
    tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr);

    if (++(print->idx) == HFS_PRINT_WIDTH) {
        tsk_fprintf(print->hFile, "\n");
        print->idx = 0;
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
    char timeBuf[32];

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_istat: inum: %" PRIuINUM " numblock: %" PRIu32 "\n",
            inum, numblock);

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        tsk_error_errstr2_concat("- istat");
        return 1;
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

    tsk_fprintf(hFile, "Path:\t");
    if ( inum == HFS_ROOT_INUM )
        tsk_fprintf(hFile, "/");
    else
        print_parent_path(hFile, fs, inum);
    tsk_fprintf(hFile, "\n");

    tsk_fs_meta_make_ls(fs_file->meta, hfs_mode, sizeof(hfs_mode));
    tsk_fprintf(hFile, "Mode:\t%s\n", hfs_mode);
    tsk_fprintf(hFile, "Size:\t%" PRIuOFF "\n", fs_file->meta->size);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_file->meta->uid, fs_file->meta->gid);

    tsk_fprintf(hFile, "Link count:\t%d\n", fs_file->meta->nlink);

    if (hfs_cat_file_lookup(hfs, inum, &entry) == 0) {
        tsk_fprintf(hFile, "\n");

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

        tsk_fprintf(hFile,
            "File type:\t%04" PRIx32 "\nFile creator:\t%04" PRIx32 "\n",
            tsk_getu32(fs->endian, entry.cat.std.u_info.file_type),
            tsk_getu32(fs->endian, entry.cat.std.u_info.file_type));

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

        // @@@ The tech note has a table that converts nums to encoding names.
        tsk_fprintf(hFile, "Text encoding:\t%" PRIx32 "\n",
            tsk_getu32(fs->endian, entry.cat.std.text_enc));

        if (tsk_getu16(fs->endian,
                entry.cat.std.rec_type) == HFS_FILE_RECORD) {
            tsk_fprintf(hFile, "Resource fork size:\t%" PRIu64 "\n",
                tsk_getu64(fs->endian, entry.cat.resource.logic_sz));
        }
    }

    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted times:\n");
        fs_file->meta->mtime -= sec_skew;
        fs_file->meta->atime -= sec_skew;
        fs_file->meta->ctime -= sec_skew;
        fs_file->meta->crtime -= sec_skew;
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

        fs_file->meta->mtime += sec_skew;
        fs_file->meta->atime += sec_skew;
        fs_file->meta->ctime += sec_skew;
        fs_file->meta->crtime += sec_skew;
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


    // @@@ Will need to add resource fork to here when support is added.
    tsk_fprintf(hFile, "\nData Fork Blocks:\n");
    print.idx = 0;
    print.hFile = hFile;

    if (tsk_fs_file_walk(fs_file,
            (TSK_FS_FILE_WALK_FLAG_AONLY | TSK_FS_FILE_WALK_FLAG_SLACK),
            print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading file\n");
        tsk_error_print(hFile);
        tsk_error_reset();
    }
    else if (print.idx != 0) {
        tsk_fprintf(hFile, "\n");
    }

    tsk_fs_file_close(fs_file);
    return 0;
}

static TSK_FS_ATTR_TYPE_ENUM
hfs_get_default_attr_type(const TSK_FS_FILE * a_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}

static void
hfs_close(TSK_FS_INFO * fs)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    fs->tag = 0;

    free(hfs->fs);
    tsk_fs_file_close(hfs->catalog_file);
    hfs->catalog_attr = NULL;

    if (hfs->blockmap_file) {
        tsk_fs_file_close(hfs->blockmap_file);
        hfs->blockmap_attr = NULL;
    }

    tsk_deinit_lock(&hfs->lock);

    tsk_fs_free(fs);
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
        free(hfs);
        return NULL;
    }

    if (hfs_checked_read_random(fs, (char *) hfs->fs, len,
            (TSK_OFF_T) HFS_VH_OFF)) {
        tsk_error_set_errstr2("hfs_open: superblock");
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
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
        free(hfs);
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("not an HFS+ file system (magic)");
        if (tsk_verbose)
            fprintf(stderr, "hfs_open: Invalid magic value\n");
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

            // @@@ VERIFY THE USE OF 512 here instead of something else....
            TSK_OFF_T hfsplus_offset =
                (drAlBlSt * (TSK_OFF_T) 512) +
                (drAlBlkSiz * (TSK_OFF_T) startBlock);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_open: HFS+/HFSX within HFS wrapper at byte offset %"
                    PRIuOFF "\n", hfsplus_offset);

            fs->tag = 0;
            free(hfs->fs);
            free(hfs);

            /* just re-open with the new offset, then record the offset */
            fs_info2 =
                hfs_open(img_info, offset + hfsplus_offset, ftype, test);

            if (fs_info2)
                ((HFS_INFO *) fs_info2)->hfs_wrapper_offset =
                    hfsplus_offset;

            tsk_init_lock(&hfs->lock);

            return fs_info2;
        }
        else {
            fs->tag = 0;
            free(hfs->fs);
            free(hfs);
            tsk_error_set_errno(TSK_ERR_FS_MAGIC);
            tsk_error_set_errstr
                ("HFS file systems (other than wrappers HFS+/HFSX file systems) are not supported");
            if (tsk_verbose)
                fprintf(stderr,
                    "hfs_open: Wrappers other than HFS+/HFSX are not supported (%d)\n",
                    tsk_getu16(fs->endian, hfs->fs->signature));
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

    // init lock
    tsk_init_lock(&hfs->lock);

    /* Load the catalog file though */
    if ((hfs->catalog_file =
            tsk_fs_file_open_meta(fs, NULL,
                HFS_CATALOG_FILE_ID)) == NULL) {
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        if (tsk_verbose)
            fprintf(stderr, "hfs_open: Error opening catalog file\n");
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
        free(hfs);
        tsk_error_errstr2_concat
            ("- Data Attribute not found in Catalog File");
        if (tsk_verbose)
            fprintf(stderr,
                "hfs_open: Error finding data attribute in catalog file\n");
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
        free(hfs);
        if (tsk_verbose)
            fprintf(stderr, "hfs_open: Error reading catalog header\n");
        return NULL;
    }

    // figure out case sensitivity
    if (tsk_getu16(fs->endian, hfs->fs->version) == HFS_VH_VER_HFSPLUS) {
        hfs->is_case_sensitive = 0;
    }
    else if (tsk_getu16(fs->endian, hfs->fs->version) == HFS_VH_VER_HFSX) {
        if (hfs->catalog_header.compType == HFS_BT_HEAD_COMP_SENS) {
            hfs->is_case_sensitive = 1;
        }
        else if (hfs->catalog_header.compType == HFS_BT_HEAD_COMP_INSENS) {
            hfs->is_case_sensitive = 0;
        }
        else {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_open: invalid value (0x%02" PRIx8
                    ") for key compare type\n",
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

    return fs;
}
