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
            tsk_errno = TSK_ERR_FS_READ;
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
    return (uint32_t) (hfsdate - NSEC_BTWN_1904_1970);
}


/**********************************************************************
 *
 * Lookup Functions
 *
 **********************************************************************/

static int hfs_load_blockmap(HFS_INFO *);

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
hfs_is_block_alloc(HFS_INFO * hfs, TSK_DADDR_T b)
{
    TSK_DADDR_T a;
    uint8_t this_byte;

    // lazy loading of block map
    if (hfs->block_map == NULL) {
        if (hfs_load_blockmap(hfs)) {
            // @@@ FIX error
            tsk_fprintf(stderr,
                "ERROR hfs_is_block_alloc: failed to load block map\n");
            return -1;
        }
    }

    a = b / 8;
    if (a > hfs->block_map_size) {
        // @@@ FIX error
        tsk_fprintf(stderr,
            "WARNING hfs_is_block_alloc: block %" PRIuDADDR
            " is past the end of the allocation file\n", b);
        return -1;
    }

    this_byte = hfs->block_map[a];
    return (this_byte & (1 << (7 - (b % 8)))) != 0;
}

/* Compares the given HFS+ Extents B-tree key to key constructed
 * for finding the beginning of the data fork extents for the given
 * CNID. (That is, the search key uses the given CNID and has
 * fork = 0 and start_block = 0.)
 */
static int
hfs_compare_extent_keys(HFS_INFO * hfs, uint32_t cnid, hfs_ext_key * key)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint32_t key_cnid;

    key_cnid = tsk_getu32(fs->endian, key->file_id);
    if (key_cnid < cnid)
        return -1;
    if (key_cnid > cnid)
        return 1;

    /* referring to the same cnids */

    /* we are always looking for the data fork (0);
       a nonzero fork (e.g., the resource fork 0xff) is higher */
    if (key->fork_type[0] != 0)
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
 * Returns the length of an HFS+ B-tree key based on the tree header
 * structure and the length claimed in the record.  With some trees,
 * the length given in the record is not used. 
 * Note that this neither detects nor correctly handles 8-bit keys
 * (which should not be present in HFS+).
 * @param hfs File System
 * @param keylen Length of key as given in record
 * @param header Tree header
 * @returns Length of key
 */
static uint16_t
hfs_get_keylen(HFS_INFO * hfs, uint16_t keylen,
    hfs_btree_header_record * header)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    // if the flag is set, use the length given in the record
    if (tsk_getu32(fs->endian, header->attr) & HFS_BT_VARKEYS)
        return keylen;
    else
        return tsk_getu16(fs->endian, header->max_len);
}

/** \internal
 * Returns the byte offset on disk of the given node (nodenum) in the Extents B-tree.
 * Unlike the other files on disk, the Extents B-tree never occupies more than 8
 * extents, so we can simply use the in-volume-header extents to get its layout.
 * @param hfs File system
 * @param hdr Header record (to get node size)
 * @param nodenum Node number in B-Tree to find
 * @returns byte offset or 0 on failure. 
 */
static TSK_OFF_T
hfs_ext_find_node_offset(HFS_INFO * hfs, hfs_btree_header_record * hdr,
    uint32_t nodenum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t nodesize;          /* size of each node */
    int i;
    uint64_t bytes;             /* bytes left this extent */
    TSK_OFF_T r_offs;           /* offset we are reading from */
    TSK_OFF_T f_offs;           /* offset into the extents file */
    TSK_OFF_T n_offs;           /* offset of the node we are looking for */
    hfs_sb *sb = hfs->fs;

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_ext_find_node_offset: finding offset of "
            "btree node: %" PRIu32 "\n", nodenum);

    /* find first extent with data in it */
    /* included from previous code -- are there cases where
       the initial extents will appear empty? */
    i = 0;
    while ((i < 8)
        && !(tsk_getu32(fs->endian, sb->ext_file.extents[i].blk_cnt)))
        i++;

    if (i > 7) {
        tsk_errno = TSK_ERR_FS_GENFS;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_ext_find_node_offset: no data found in extents file extents");
        return 0;
    }

    bytes =
        tsk_getu32(fs->endian,
        sb->ext_file.extents[i].blk_cnt) * (TSK_OFF_T) fs->block_size;
    r_offs =
        tsk_getu32(fs->endian,
        sb->ext_file.extents[i].start_blk) * (TSK_OFF_T) fs->block_size;
    f_offs = 0;

    nodesize = tsk_getu16(fs->endian, hfs->catalog_header.nodesize);

    /* calculate where we will find the 'nodenum' node */
    n_offs = nodesize * nodenum;

    while (f_offs < n_offs) {

        if (n_offs <= (f_offs + (TSK_OFF_T)bytes)) {

            r_offs += n_offs - f_offs;
            f_offs = n_offs;

        }
        else {

            i++;

            if (i > 7) {
                tsk_errno = TSK_ERR_FS_GENFS;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "hfs_ext_find_node_offset: file seek error while searching for node %"
                    PRIu32 "\n", nodenum);
                return 0;
            }

            r_offs =
                tsk_getu32(fs->endian,
                sb->ext_file.extents[i].start_blk) *
                (TSK_OFF_T) fs->block_size;
            f_offs += bytes;
            bytes =
                tsk_getu32(fs->endian,
                sb->ext_file.extents[i].blk_cnt) *
                (TSK_OFF_T) fs->block_size;

        }
    }

    return r_offs;

}

/** \internal
 * Process a B-Tree node record and return the record contents and the 
 * offset of the data content in the record. 
 * Note that this neither detects nor correctly handles odd-length keys
 * or 8-bit keys (neither should be present in HFS+).
 * @param hfs File system being analyzed
 * @param header Header of B-Tree record is in.  If NULL, then 
 * only the keylength in the record is used (i.e. flag settings ignored).
 * @param rec_off Byte offset in disk where record starts
 * @param [out] a_buf Pointer to buffer to store record in (or NULL).  
 * Must be at least 2 bytes long if it is not NULL.
 * @param a_buf_len Length of buf (amount of record to read)
 * @param clear If 1,  clear the key value before reading into it. 
 * @returns Offset of data content in record or 0 on error
 */
TSK_OFF_T
hfs_read_key(HFS_INFO * hfs, hfs_btree_header_record * header,
    TSK_OFF_T rec_off, char *a_buf, int a_buf_len, uint8_t clear)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    char buf[2];
    char *dest = a_buf ? a_buf : buf;
    uint16_t keylen;

    tsk_error_reset();

    if (a_buf && clear)         /* zero a_buf */
        memset(a_buf + 2, 0, a_buf_len - 2);

    // get the key length as reported in the record
    if (hfs_checked_read_random(fs, dest, 2, rec_off))  /* read size */
        return 0;

    keylen = tsk_getu16(fs->endian, dest);
    // use the header to figure out if we should be ignoring this length or not
    if (header)
        keylen = hfs_get_keylen(hfs, keylen, header);

    if ((header && (keylen > tsk_getu16(fs->endian, header->max_len)))
        || (!header && (keylen > 516))) {       /* sanity check key length */
        tsk_errno = TSK_ERR_FS_GENFS;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_read_key: key length out of range (%" PRIu16 ")", keylen);
        return 0;
    }

    // read the key and other data into the buffer if they asked for it
    if (a_buf) {                /* read key */
        if (hfs_checked_read_random(fs, a_buf + 2,
                (keylen + 2 <= a_buf_len) ?
                keylen : a_buf_len - 2, rec_off + 2))
            return 0;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_read_key: read key of length %" PRIu16 "\n", keylen);

    return rec_off + 2 + keylen;        /* return record data address */
}

/** \internal
 * Return the disk byte offset of a record in a btree node.
 * Note that this points to start of the record (hfs_read_key
 * can be used to determine the content offset).
 *
 * @param hfs File system node is in
 * @param node_off Byte offset in disk of start of node. 
 * @param nodesize Size, in bytes, of each node
 * @param rec Record number to return offset of
 * @returns 0 on error or offset. 
 */
TSK_OFF_T
hfs_get_bt_rec_off(HFS_INFO * hfs, TSK_OFF_T node_off,
    uint16_t nodesize, uint16_t rec)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    TSK_OFF_T off;
    char buf[2];

    tsk_error_reset();

    off = node_off + nodesize - 2 * (rec + 1);  /* location of record offset */
    if (hfs_checked_read_random(fs, buf, 2, off))       /* read record offset */
        return 0;
    off = node_off + tsk_getu16(fs->endian, buf);       /* go to record */

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_get_bt_rec_off: record %" PRIu16 " @ %" PRIu64
            " (node @ %" PRIu64 ")\n", rec, off, node_off);

    return off;
}

/* Advances to the next record in the Extents B-tree, given information about
 * where you currently are in the B-tree.
 * Assumes that you are actually keeping track of these many fields. They
 * must correctly contain the current values. If the current node is changed,
 * they will be changed to their new values.
 * Returns cur_node. If you have reached the end of the node chain (no more
 * records), cur_node will be set to zero and returned.
 */
/** \internal
 * Takes current state variables as input and advances to next record.  If
 * the next record is in a different node, then it advances the node.  If a
 * new node needs to be loaded, the values passed as arguments are updated. 
 *
 * @param hfs [in] File system being analyzed
 * @param rec [in,out] Record number of the current record in the current node
 * @param num_rec [in,out] Number of records in current node
 * @param node [in,out] Node structure for current node
 * @param cur_node [in,out] Address of current node
 * @param cur_node_off [in,out] XXXX
 * @param header [in] Header of tree
 * @returns 0 on error */
static uint32_t
hfs_ext_next_record(HFS_INFO * hfs, uint16_t * rec, uint16_t * num_rec,
    hfs_btree_node * node, uint32_t * cur_node, TSK_OFF_T * cur_node_off,
    hfs_btree_header_record * header)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    tsk_error_reset();

    /* passing invalid pointers (or null) to this function is unchecked */

    (*rec)++;

    if (*rec >= *num_rec) {     /* ran out of records in this node */
        *cur_node = tsk_getu32(fs->endian, node->flink);
        if (*cur_node == 0)
            return *cur_node;
        *cur_node_off = hfs_ext_find_node_offset(hfs, header, *cur_node);
        if (*cur_node_off == 0) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_ext_next_record: find next node offset (%" PRIu32 ")",
                *cur_node);
            return 0;
        }
        if (hfs_checked_read_random(fs, (char *) node,
                sizeof(hfs_btree_node), *cur_node_off)) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_ext_next_record: read btree node %" PRIu32 " at %"
                PRIuDADDR, *cur_node, *cur_node_off);
            return 0;
        }
        *num_rec = tsk_getu16(fs->endian, node->num_rec);
        *rec = 0;
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_ext_next_record: advanced to next node %" PRIu32
                "(@ %" PRIu64 ", has %" PRIu16 "records \n", *cur_node,
                *cur_node_off, *num_rec);
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_ext_next_record: advanced to record %" PRIu16 "\n",
                *rec);
    }

    return *cur_node;
}


// @@@ This could probably return TSK_FS_ATTR
/**  \internal
 * Returns the extents (data runs) for the data fork of a given file.  The
 * caller must free the returned array. 
 * 
 * @param hfs File system being analyzed
 * @param cnid CNID of the file to get data on
 * @param first_ext Pointer to 8 extents of file that have already been found 
 * (or NULL).  Note if it is not NULL, it must have 8 elements in the array. It
 * will be copied to start of returned array. 
 * @returns Array of extents (not guaranteed to be a multple of 8).  The final
 * entry will have 0,0 entries.  NULL on error.  
 * Note that if first_ext is NULL and no extents are
 * found, this function will also return NULL.
 * May set up to error string 2.  
 */
static hfs_ext_desc *
hfs_ext_find_extent_record(HFS_INFO * hfs, uint32_t cnid,
    hfs_ext_desc * first_ext)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    hfs_btree_header_record header;     /* header for the Extents btree */
    uint16_t leafsize;          /* size of nodes (all, regardless of the name) */

    uint32_t cur_node;          /* node id of the current node */

    hfs_ext_desc *out_ext;
    int num_out_ext;

    TSK_OFF_T off;

    char buf[4];
    int i;

    tsk_error_reset();

    /* initialize the output extents */
    if (first_ext == NULL) {
        num_out_ext = 0;
        out_ext = NULL;
    }
    else {
        num_out_ext = 8;
        out_ext = (hfs_ext_desc *)
            tsk_malloc(9 * sizeof(hfs_ext_desc));
        if (out_ext == NULL)
            return NULL;
        memcpy(out_ext, first_ext, 8 * sizeof(hfs_ext_desc));
        memset(out_ext + 8, 0, sizeof(hfs_ext_desc));
        /* we make 9 output extents so that if these are all the extents,
           there's a guaranteed terminating (0,0); we only set num_out_ext
           to 8 so that we overwrite our 9th extent if we don't need it */
    }

    /* Get the starting address of the extents file to read header record */
    // @@@@ ERROR: header is 0 here, which doesn't help to find the node size, which is why it is passe to find_....
    off = hfs_ext_find_node_offset(hfs, &header, 0);
    if (off == 0) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "hfs_ext_find_extent_record: finding extents header node");
        if (out_ext != NULL)
            free(out_ext);
        return NULL;
    }
    off += 14;                  // sizeof(hfs_btree_node) 
    if (hfs_checked_read_random(fs, (char *) &header, sizeof(header), off)) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "hfs_ext_find_extent_record: reading extents header node at %"
            PRIuDADDR, off);
        if (out_ext != NULL)
            free(out_ext);
        return NULL;
    }
    leafsize = tsk_getu16(fs->endian, header.nodesize);

    /* start at root node */
    cur_node = tsk_getu32(fs->endian, header.root);

    /* if the root node is zero, then the extents btree is empty */
    /* if no files have overflow extents, the Extents B-tree still
       exists on disk, but is an empty B-tree containing only
       the header node */
    if (cur_node == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                "empty extents btree\n");
        return out_ext;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_ext_find_extent_record: starting at "
            "root node %" PRIu32 "; header @ %" PRIuOFF "; leafsize = %"
            PRIu16 "\n", cur_node, off, leafsize);

    while (1) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        hfs_btree_node node;    /* data of the current node */
        uint16_t num_rec;       /* number of records in this node */
        hfs_ext_key key;        /* current key */
        TSK_DADDR_T addr, recaddr;
        uint16_t rec, recno;

        /* load node header */
        cur_off = hfs_ext_find_node_offset(hfs, &header, cur_node);
        if (cur_off == 0) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: finding extents node (%"
                PRIu32 ")", cur_node);
            if (out_ext != NULL)
                free(out_ext);
            return NULL;
        }

        // @@@ We could probably make this faster by reading the entire node

        if (hfs_checked_read_random(fs, (char *) &node, sizeof(node),
                cur_off)) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: reading extents node (%"
                PRIu32 " at %" PRIuDADDR ")", cur_node, cur_off);
            if (out_ext != NULL)
                free(out_ext);
            return NULL;
        }

        num_rec = tsk_getu16(fs->endian, node.num_rec);

        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_ext_find_extent_record: node %" PRIu32
                " @ %" PRIu64 " has %" PRIu16 " records\n",
                cur_node, cur_off, num_rec);

        if (num_rec == 0) {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: zero records in node %"
                PRIu32, cur_node);
            if (out_ext != NULL)
                free(out_ext);
            return NULL;
        }

        /* find largest key smaller than or equal to cnid */
        recno = 0;
        recaddr = 0;
        for (rec = 0; rec < num_rec; rec++) {
            int cmp;

            // get the record offset
            addr = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
            if (addr == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_ext_find_extent_record: finding record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                if (out_ext != NULL)
                    free(out_ext);
                return NULL;
            }

            // get the content offet and read the key
            addr =
                hfs_read_key(hfs, &header, addr, (char *) &key,
                sizeof(hfs_ext_key), 1);
            if (addr == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_ext_find_extent_record: reading key for record %"
                    PRIu16 " in node %" PRIu32, rec, cur_node);
                if (out_ext != NULL)
                    free(out_ext);
                return NULL;
            }
            cmp = hfs_compare_extent_keys(hfs, cnid, &key);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_ext_find_extent_record: record %" PRIu16 " @ %"
                    PRIu64 "; keylen %" PRIu16 " (%" PRIu32 ", %" PRIu8
                    ", %" PRIu32 "); compare: %d\n", rec, addr,
                    tsk_getu16(fs->endian, key.key_len),
                    tsk_getu32(fs->endian, key.file_id), key.fork_type[0],
                    tsk_getu32(fs->endian, key.start_block), cmp);

            /* find the largest key less than or equal to our key */
            /* if all keys are larger than our key, select the leftmost key */
            if ((cmp <= 0) || (recaddr == 0)) {
                recaddr = addr;
                recno = rec;
            }
            if (cmp >= 0)
                break;
        }

        if (node.kind == HFS_BTREE_INDEX_NODE) {
            /* replace cur node number with the node number referenced
             * by the found key, continue until we hit a leaf. */
            if (hfs_checked_read_random(fs, buf, 4, recaddr)) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_ext_find_extent_record: reading pointer in record %"
                    PRIu16 " in node %" PRIu32, rec, cur_node);
                if (out_ext != NULL)
                    free(out_ext);
                return NULL;
            }
            cur_node = tsk_getu32(fs->endian, buf);
        }
        else if (node.kind == HFS_BTREE_LEAF_NODE) {
            rec = recno;        /* using rec as our counting variable again, for kicks */

            /* reget key */
            addr = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
            if (addr == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_ext_find_extent_record: finding record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                if (out_ext != NULL)
                    free(out_ext);
                return NULL;
            }
            addr =
                hfs_read_key(hfs, &header, addr, (char *) &key,
                sizeof(hfs_ext_key), 1);
            if (addr == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_ext_find_extent_record: reading key for record %"
                    PRIu16 " in node %" PRIu32, rec, cur_node);
                if (out_ext != NULL)
                    free(out_ext);
                return NULL;
            }

            /* we've been searching for a start block of zero, and we're
             * essentially guaranteed it won't have a start block of zero;
             * as a result, we may very well be one left of our target --
             * but since we alternately take the leftmost record, we might *not*
             * be one left of our target */

            /* we don't check for it, but note that the current record would have
             * to be less than the record we're looking for -- if it's greater,
             * there's no record in the btree for us */

            /* correct this, first */

            /* if associated with the wrong file */
            if (tsk_getu32(fs->endian, key.file_id) != cnid) {

                /* go to the next record */
                if ((hfs_ext_next_record(hfs, &rec, &num_rec, &node,
                            &cur_node, &cur_off, &header)) == 0) {
                    if (cur_node != 0) {
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "hfs_ext_find_extent_record: advancing to next record (record %"
                            PRIu16 " node %" PRIu32 ")", rec, cur_node);
                        if (out_ext != NULL)
                            free(out_ext);
                        return NULL;
                    }

                    /* here, means that our file is not in the overflow extents tree */
                    if (tsk_verbose)
                        tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                            "end of extents btree before finding any extents\n");
                    return out_ext;
                }

                /* load new key data, since I'm about to use it */
                addr = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
                if (addr == 0) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "hfs_ext_find_extent_record: finding record %"
                        PRIu16 " in node %" PRIu32, rec, cur_node);
                    if (out_ext != NULL)
                        free(out_ext);
                    return NULL;
                }
                addr =
                    hfs_read_key(hfs, &header, addr, (char *) &key,
                    sizeof(hfs_ext_key), 1);
                if (addr == 0) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "hfs_ext_find_extent_record: reading key for record %"
                        PRIu16 " in node %" PRIu32, rec, cur_node);
                    if (out_ext != NULL)
                        free(out_ext);
                    return NULL;
                }
            }

            /* iterate as long as this is associated with our file */
            while (1) {
                /* expand output extents record */
                num_out_ext += 8;
                if (out_ext) {  /* already allocated */
                    out_ext = (hfs_ext_desc *)
                        tsk_realloc((char *) out_ext,
                        num_out_ext * sizeof(hfs_ext_desc));
                }
                else {          /* not already allocated */
                    out_ext = (hfs_ext_desc *)
                        tsk_malloc(num_out_ext * sizeof(hfs_ext_desc));
                }
                if (out_ext == NULL)
                    return NULL;

                /* if we've moved on to a different file (or fork), stop */
                if ((tsk_getu32(fs->endian, key.file_id) != cnid) ||
                    (key.fork_type[0] != 0)) {
                    memset(((char *) out_ext) + (num_out_ext * 8 - 64), 0, 64);
                    return out_ext;
                }

                /* read extents data */
                if (hfs_checked_read_random(fs,
                        ((char *) out_ext) + (num_out_ext * 8 - 64), 64,
                        addr)) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "hfs_ext_find_extent_record: reading extents data (record %"
                        PRIu16 " node %" PRIu32 ")", rec, cur_node);
                    free(out_ext);
                    return NULL;
                }

                if (tsk_verbose) {
                    for (i = num_out_ext - 8; i < num_out_ext; i++) {
                        tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                            "overflow extent start: %" PRIu32 ", length: %"
                            PRIu32 "\n", tsk_getu32(fs->endian,
                                out_ext[i].start_blk),
                            tsk_getu32(fs->endian, out_ext[i].blk_cnt));
                    }
                }

                /* according to Apple, if any start_blk and blk_cnt both == 0,
                   we can stop, but we'll continue until we run out of
                   extents for this file and fork regardless of their content */

                /* go to the next record */
                if ((hfs_ext_next_record(hfs, &rec, &num_rec, &node,
                            &cur_node, &cur_off, &header)) == 0) {
                    if (cur_node != 0) {
                        snprintf(tsk_errstr2, TSK_ERRSTR_L,
                            "hfs_ext_find_extent_record: advancing to next record (record %"
                            PRIu16 " node %" PRIu32 ")", rec, cur_node);
                        free(out_ext);
                        return NULL;
                    }

                    /* ran out of records (file was at the end of the tree) */
                    if (tsk_verbose)
                        tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                            "end of extents btree reached while finding extents\n");
                    return out_ext;
                }

                /* load new key data */
                addr = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
                if (addr == 0) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "hfs_ext_find_extent_record: finding record %"
                        PRIu16 " in node %" PRIu32, rec, cur_node);
                    free(out_ext);
                    return NULL;
                }
                addr =
                    hfs_read_key(hfs, &header, addr, (char *) &key,
                    sizeof(hfs_ext_key), 1);
                if (addr == 0) {
                    snprintf(tsk_errstr2, TSK_ERRSTR_L,
                        "hfs_ext_find_extent_record: reading key for record %"
                        PRIu16 " in node %" PRIu32, rec, cur_node);
                    free(out_ext);
                    return NULL;
                }

            }

        }
        else {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: btree node %" PRIu32
                " (%" PRIu64 ") is neither index nor leaf (%" PRIu8 ")",
                cur_node, cur_off, node.kind);
            if (out_ext != NULL)
                free(out_ext);
            return NULL;
        }
    }

}


/**
 * Convert the extents runs to TSK_FS_ATTR_RUN runs.
 *
 * @param a_fs File system to analyze
 * @param a_extents Raw extents to process (in an array of 8)
 * @param a_start_off Starting byte offset of these runs
 * @returns NULL on error
 */
static TSK_FS_ATTR_RUN *
hfs_extents_to_attr(TSK_FS_INFO * a_fs, const hfs_ext_desc * a_extents, TSK_OFF_T a_start_off)
{
    TSK_FS_ATTR_RUN *head_run = NULL;
    TSK_FS_ATTR_RUN *prev_run = NULL;
    int i;
    TSK_OFF_T cur_off = a_start_off;

    for (i = 0; i < 8; i++) {
        TSK_FS_ATTR_RUN *cur_run;
        
        uint32_t addr =
            tsk_getu32(a_fs->endian, a_extents[i].start_blk);
        uint32_t len =
            tsk_getu32(a_fs->endian, a_extents[i].blk_cnt);

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
        cur_off += (cur_run->len * a_fs->block_size);
        prev_run = cur_run;
    }
    
    return head_run;
}


/**
 * Look in the extents catalog for entries for a given file.
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

    tsk_error_reset();
    
    // Load the extents attribute, if it has not been done so yet.
    if (hfs->extents_file == NULL) {
        ssize_t cnt;
        
        if ((hfs->extents_file =
             tsk_fs_file_open_meta(fs, NULL, HFS_EXTENTS_FILE_ID)) == NULL) {
            return 0;
        }
        
        /* cache the data attribute */
        hfs->extents_attr =
            tsk_fs_attrlist_get(hfs->extents_file->meta->attr, TSK_FS_ATTR_TYPE_DEFAULT);
        if (!hfs->catalog_attr) {
            strncat(tsk_errstr2, " - Default Attribute not found in Extents File",
                    TSK_ERRSTR_L - strlen(tsk_errstr2));
            return 0;
        }
        
        // cache the extents file header
        cnt = tsk_fs_attr_read(hfs->extents_attr, 14,
                               (char *) &(hfs->extents_header),
                               sizeof(hfs_btree_header_record), 0);
        if (cnt != sizeof(hfs_btree_header_record)) {
            return 0;        
        }
    }

    nodesize = tsk_getu16(fs->endian, hfs->extents_header.nodesize);
    if ((node = (char *) tsk_malloc(nodesize)) == NULL)
        return 1;
    // @@@ ADD FREE CODE

    /* start at root node */
    cur_node = tsk_getu32(fs->endian, hfs->extents_header.root);

    /* if the root node is zero, then the extents btree is empty */
    /* if no files have overflow extents, the Extents B-tree still
       exists on disk, but is an empty B-tree containing only
       the header node */
    if (cur_node == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_ext_find_extent_record: "
                "empty extents btree\n");
        return 0;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_ext_find_extent_record: starting at "
            "root node %" PRIu32 "; nodesize = %"
            PRIu16 "\n", cur_node, nodesize);

    while (1) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        uint16_t num_rec;       /* number of records in this node */
        ssize_t cnt;
        hfs_btree_node *node_desc;

        cur_off = cur_node * nodesize;

        cnt = tsk_fs_attr_read(hfs->extents_attr, cur_off,
            node, nodesize, 0);
        if (cnt != nodesize) {
            // @@@
            return 1;
        }

        node_desc = (hfs_btree_node *) node;

        num_rec = tsk_getu16(fs->endian, node_desc->num_rec);

        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_ext_find_extent_record: node %" PRIu32
                " @ %" PRIu64 " has %" PRIu16 " records\n",
                cur_node, cur_off, num_rec);

        if (num_rec == 0) {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: zero records in node %"
                PRIu32, cur_node);
            return 1;
        }


        if (node_desc->kind == HFS_BTREE_INDEX_NODE) {
            uint32_t next_node = 0;
            int rec;

            /* find largest key smaller than or equal to cnid */
            for (rec = 0; rec < num_rec; rec++) {
                int cmp;
                size_t rec_off;
                hfs_ext_key *key;

                // get the record offset in the node
                rec_off =
                    tsk_getu32(fs->endian,
                    &node[nodesize - (rec + 1) * 4]);
                if (rec_off > nodesize) {
                    // @@@ ERROR
                }
                key = (hfs_ext_key *) & node[rec_off];
                cmp = hfs_compare_extent_keys(hfs, cnid, key);

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_ext_find_extent_record: record %" PRIu16
                        " ; keylen %" PRIu16 " (%" PRIu32
                        ", %" PRIu8 ", %" PRIu32 "); compare: %d\n", rec,
                         tsk_getu16(fs->endian, key->key_len),
                        tsk_getu32(fs->endian, key->file_id),
                        key->fork_type[0], tsk_getu32(fs->endian,
                            key->start_block), cmp);

                /* find the largest key less than or equal to our key */
                /* if all keys are larger than our key, select the leftmost key */
                if ((cmp <= 0) || (next_node == 0)) {
                    int keylen = tsk_getu16(fs->endian, key->key_len);
                    // @@@ SANITY CHECK ON NODELEN AND rec_addr+keylen
                    next_node =
                        tsk_getu32(fs->endian, &node[rec_off + keylen]);
                }
                else {
                    break;
                }
            }
            if (next_node == 0) {
                // @@@@
            }
            cur_node = next_node;
        }

        else if (node_desc->kind == HFS_BTREE_LEAF_NODE) {
            int rec;
            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_ext_key *key;
                uint32_t rec_cnid;
                hfs_extents *extents;
                TSK_OFF_T ext_off = 0;
				int keylen;
                TSK_FS_ATTR_RUN *attr_run;

                // get the record offset in the node
                rec_off =
                    tsk_getu32(fs->endian,
                    &node[nodesize - (rec + 1) * 4]);
                if (rec_off > nodesize) {
                    // @@@ ERROR
                }
                key = (hfs_ext_key *) & node[rec_off];

                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "hfs_ext_find_extent_record: record %" PRIu16
                        "; keylen %" PRIu16 " (%" PRIu32
                        ", %" PRIu8 ", %" PRIu32 ")\n", rec,
                         tsk_getu16(fs->endian, key->key_len),
                        tsk_getu32(fs->endian, key->file_id),
                        key->fork_type[0], tsk_getu32(fs->endian,
                            key->start_block));

                rec_cnid = tsk_getu32(fs->endian, key->file_id);

                // see if this record is for our file
                if (rec_cnid < cnid)
                    continue;
                else if ((rec_cnid > cnid) || (key->fork_type[0] != 0))
                    break;

                // get the starting offset of this extent
                ext_off = tsk_getu32(fs->endian, key->start_block);

                keylen = tsk_getu16(fs->endian, key->key_len);
                // @@@ SANITY CHECK ON NODELEN AND rec_addr+2+keylen

                extents = (hfs_extents *) & node[rec_off + keylen];
                        
                attr_run = 
                    hfs_extents_to_attr(fs, extents->extents, ext_off);
                if (attr_run == NULL) {
                        /// @@@
                }

                if (tsk_fs_attr_add_run(fs, a_attr, attr_run)) {
                        // @@@
                }
            }
        }
        else {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_ext_find_extent_record: btree node %" PRIu32
                " (%" PRIu64 ") is neither index nor leaf (%" PRIu8 ")",
                cur_node, cur_off, node_desc->kind);
            return 1;
        }
    }
}


/* return the offset into the image that catalog btree node 'node' is at */
/* returns 0 on failure; may set up to error string 1 */
TSK_OFF_T
hfs_cat_find_node_offset(HFS_INFO * hfs, uint32_t nodenum)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t nodesize;          /* size of each node */
    int i;
    uint64_t bytes;             /* bytes left this extent */
    TSK_OFF_T r_offs;           /* offset we are reading from */
    TSK_OFF_T f_offs;           /* offset into the catalog file */
    TSK_OFF_T n_offs;           /* offset of the node we are looking for */
    hfs_ext_desc *extents;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_cat_find_node_offset: finding offset of "
            "btree node: %" PRIu32 "\n", nodenum);

    extents = hfs->cat_extents;

    /* find first extent with data in it */
    /* as above, holdover from previous code */
    i = 0;
    while (!(tsk_getu32(fs->endian, extents[i].blk_cnt)))
        i++;

    if (i > 7) {
        tsk_errno = TSK_ERR_FS_GENFS;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_cat_find_node_offset: no data found in catalog file extents");
        return 0;
    }

    bytes =
        tsk_getu32(fs->endian,
        extents[i].blk_cnt) * (TSK_OFF_T) fs->block_size;
    r_offs =
        tsk_getu32(fs->endian,
        extents[i].start_blk) * (TSK_OFF_T) fs->block_size;
    f_offs = 0;

    nodesize = tsk_getu16(fs->endian, hfs->catalog_header.nodesize);

    /* calculate where we will find the 'nodenum' node */
    n_offs = nodesize * nodenum;

    while (f_offs < n_offs) {

        if (n_offs <= (f_offs + (TSK_OFF_T)bytes)) {

            r_offs += n_offs - f_offs;
            f_offs = n_offs;

        }
        else {

            i++;

            if (i > 7) {
                tsk_errno = TSK_ERR_FS_GENFS;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                    "hfs_cat_find_node_offset: file seek error while searching for node %"
                    PRIu32 "\n", nodenum);
                return 0;
            }

            r_offs =
                tsk_getu32(fs->endian,
                extents[i].start_blk) * (TSK_OFF_T) fs->block_size;
            f_offs += bytes;
            bytes =
                tsk_getu32(fs->endian,
                extents[i].blk_cnt) * (TSK_OFF_T) fs->block_size;

        }
    }

    return r_offs;
}

/* Advances to the next record in the Catalog B-tree, given information about
 * where you currently are in the B-tree.
 * Assumes that you are actually keeping track of these many fields. They
 * must correctly contain the current values. If the current node is changed,
 * they will be changed to their new values.
 * Returns cur_node. If you have reached the end of the node chain (no more
 * records), cur_node will be set to zero and returned.
 * May set up to error string 2. Returns 0 on error. */
uint32_t
hfs_cat_next_record(HFS_INFO * hfs, uint16_t * rec, uint16_t * num_rec,
    hfs_btree_node * node, uint32_t * cur_node, TSK_OFF_T * cur_off,
    hfs_btree_header_record * header)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    tsk_error_reset();

    (*rec)++;

    if (*rec >= *num_rec) {     /* ran out of records in this node */
        *cur_node = tsk_getu32(fs->endian, node->flink);
        if (*cur_node == 0)
            return *cur_node;
        *cur_off = hfs_cat_find_node_offset(hfs, *cur_node);
        if (*cur_off == 0) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_cat_next_record: find next node offset (%" PRIu32 ")",
                *cur_node);
            return 0;
        }
        if (hfs_checked_read_random(fs, (char *) node,
                sizeof(hfs_btree_node), *cur_off)) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_cat_next_record: read btree node %" PRIu32 " at %"
                PRIuDADDR, *cur_node, *cur_off);
            return 0;
        }
        *num_rec = tsk_getu16(fs->endian, node->num_rec);
        *rec = 0;
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_cat_next_record: advanced to next node %" PRIu32
                "(@ %" PRIu64 ", has %" PRIu16 "records \n", *cur_node,
                *cur_off, *num_rec);
    }
    else {
        if (tsk_verbose)
            tsk_fprintf(stderr,
                "hfs_cat_next_record: advanced to record %" PRIu16 "\n",
                *rec);
    }

    return *cur_node;
}

/** \internal
 * Returns the largest inode number in file system
 * @param hfs File system being analyzed
 * @returns largest metadata address
 */
static TSK_INUM_T
hfs_find_highest_inum(HFS_INFO * hfs)
{
    // @@@ get actual number from Catalog file
    /* I haven't gotten looking at the end of the Catalog B-Tree to work
       properly. A fast method: if HFS_BIT_VOLUME_CNIDS_REUSED is set, then
       the maximum CNID is 2^32-1; if it's not set, then nextCatalogId is
       supposed to be larger than all CNIDs on disk.
     */

    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    if (tsk_getu32(fs->endian,
            hfs->fs->attr) & HFS_BIT_VOLUME_CNIDS_REUSED)
        return (TSK_INUM_T) 0xffffffff;
    else
        return (TSK_INUM_T) tsk_getu32(fs->endian,
            hfs->fs->next_cat_id) - 1;
}


// @@@ We should have a version of this that allows one key to have cnid already in local order...

/** \internal
 * Compares two Catalog B-tree keys.
 * @param hfs File System being analyzed
 * @param key1 Key 1 to compare
 * @param key2 Key 2 to compare
 * @returns -1 if key1 is smaller, 0 if equal, and 1 if key1 is larger
 */
int
hfs_compare_catalog_keys(HFS_INFO * hfs, hfs_cat_key * key1,
    hfs_cat_key * key2)
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
 * Find the byte offset (from the start of the disk) to a record
 * in the catalog file.
 * @param hfs File System being analyzed
 * @param needle Key to search for
 * @returns Byte offset or 0 on error. 0 is also returned if catalog
 * record was not found. Check tsk_errno to determine if error occured.
 */
static TSK_OFF_T
hfs_catalog_get_record_offset(HFS_INFO * hfs, hfs_cat_key * needle)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    hfs_btree_header_record header;     /* header for the Catalog btree */
    uint16_t leafsize;          /* size of nodes (all, regardless of the name) */
    uint32_t cur_node;          /* node id of the current node */
    TSK_OFF_T off;

    tsk_error_reset();

    /* read catalog header record */
    off = hfs_cat_find_node_offset(hfs, 0);
    if (off == 0) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "hfs_catalog_get_record_offset: find catalog header node");
        return 0;
    }
    off += 14;                  // sizeof header
    if (hfs_checked_read_random(fs, (char *) &header, sizeof(header), off)) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L,
            "hfs_catalog_get_record_offset: read catalog header node");
        return 0;
    }
    leafsize = tsk_getu16(fs->endian, header.nodesize); // @@@ This should be hard coded

    /* start at root node */
    cur_node = tsk_getu32(fs->endian, header.root);

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_catalog_get_record_offset: starting at "
            "root node %" PRIu32 "; header @ %" PRIu64 "; leafsize = %"
            PRIu16 "\n", cur_node, off, leafsize);

    while (1) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        hfs_cat_key key;        /* current key */
        uint16_t num_rec;       /* number of records in this node */
        TSK_DADDR_T recaddr;
        uint16_t rec, recno;
        char buf[4];
        int cmp;
        hfs_btree_node node;    /* data of the current node */

        /* load node header */
        cur_off = hfs_cat_find_node_offset(hfs, cur_node);
        if (cur_off == 0) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_catalog_get_record_offset: find catalog node %" PRIu32,
                cur_node);
            return 0;
        }
        if (hfs_checked_read_random(fs, (char *) &node, sizeof(node),
                cur_off)) {
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                "hfs_catalog_get_record_offset: read catalog node %" PRIu32
                " at %" PRIuDADDR, cur_node, cur_off);
            return 0;
        }
        num_rec = tsk_getu16(fs->endian, node.num_rec);

        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_catalog_get_record_offset: node %" PRIu32
                " @ %" PRIu64 " has %" PRIu16 " records\n",
                cur_node, cur_off, num_rec);

        if (num_rec == 0) {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_catalog_get_record_offset: zero records in node %" PRIu32,
                cur_node);
            return 0;
        }

        /* find largest key smaller than or equal to our key */
        recno = 0;
        recaddr = 0;
        for (rec = 0; rec < num_rec; rec++) {

            off = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
            if (off == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_catalog_get_record_offset: finding record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                return 0;
            }
            off =
                hfs_read_key(hfs, &header, off, (char *) &key,
                sizeof(hfs_cat_key), 1);
            if (off == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_catalog_get_record_offset: reading record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                return 0;
            }
            cmp = hfs_compare_catalog_keys(hfs, &key, needle);

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "hfs_catalog_get_record_offset: record %" PRIu16 " @ %"
                    PRIu64 "; keylen %" PRIu16 " (%" PRIu32 ", %" PRIu16
                    "); compare: %d\n", rec, off, tsk_getu16(fs->endian,
                        key.key_len), tsk_getu32(fs->endian,
                        key.parent_cnid), tsk_getu16(fs->endian,
                        key.name.length), cmp);

            /* find the largest key less than or equal to our key */
            /* if all keys are larger than our key, select the leftmost key */
            if ((cmp <= 0) || (recaddr == 0)) {
                recaddr = off;
                recno = rec;
            }
            if (cmp >= 0)
                break;
        }

        if (node.kind == HFS_BTREE_INDEX_NODE) {
            /* replace cur node number with the node number referenced
             * by the found key, continue */
            if (hfs_checked_read_random(fs, buf, 4, recaddr)) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_catalog_get_record_offset: reading pointer in record %"
                    PRIu16 " in node %" PRIu32, rec, cur_node);
                return 0;
            }
            cur_node = tsk_getu32(fs->endian, buf);
        }
        else if (node.kind == HFS_BTREE_LEAF_NODE) {
            rec = recno;

            /* reget key */
            off = hfs_get_bt_rec_off(hfs, cur_off, leafsize, rec);
            if (off == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_catalog_get_record_offset: finding record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                return 0;
            }
            off =
                hfs_read_key(hfs, &header, off, (char *) &key,
                sizeof(hfs_ext_key), 1);
            if (off == 0) {
                snprintf(tsk_errstr2, TSK_ERRSTR_L,
                    "hfs_catalog_get_record_offset: reading record %" PRIu16
                    " in node %" PRIu32, rec, cur_node);
                return 0;
            }

            if (hfs_compare_catalog_keys(hfs, &key, needle) == 0)
                return off;
            return 0;           /* this key not found */

        }
        else {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "hfs_catalog_get_record_offset: btree node %" PRIu32
                " (%" PRIu64 ") is neither index nor leaf (%" PRIu8 ")",
                cur_node, cur_off, node.kind);
            return 0;
        }
    }
}

/* Thread records are variable-length. This function reads in from disk only that
 * data actually contained within the thread record into a fixed-size (maximum-size)
 * hfs_thread structure, zeroing the remainder of the structure
 * Returns 0 on success, 1 on failure; sets up to error string 1 */
uint8_t
hfs_read_thread_record(HFS_INFO * hfs, TSK_DADDR_T addr,
    hfs_thread * thread)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    uint16_t uni_len;

    memset(thread, 0, sizeof(hfs_thread));
    if (hfs_checked_read_random(fs, (char *) thread, 10, addr))
        return 1;

    if ((tsk_getu16(fs->endian, thread->record_type) != HFS_FOLDER_THREAD)
        && (tsk_getu16(fs->endian,
                thread->record_type) != HFS_FILE_THREAD)) {
        tsk_errno = TSK_ERR_FS_GENFS;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_read_thread_record: unexpected record type %" PRIu16,
            tsk_getu16(fs->endian, thread->record_type));
        return 1;
    }

    uni_len = tsk_getu16(fs->endian, thread->name.length);

    if (uni_len > 255) {
        tsk_errno = TSK_ERR_FS_INODE_COR;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_read_thread_record: invalid string length (%" PRIu16 ")",
            uni_len);
        return 1;
    }

    if (hfs_checked_read_random(fs, (char *) thread->name.unicode,
            uni_len * 2, addr + 10))
        return 1;

    return 0;
}

/** \internal
 * Read a catalog record into a local data structure.  This reads the
 * correct amount, depending on if it is a file or folder. 
 * @param hfs File system being analyzed
 * @param off Byte offset (in disk) of record 
 * @param record [out] Structure to read data into
 * @returns 1 on error
 */
uint8_t
hfs_read_file_folder_record(HFS_INFO * hfs, TSK_OFF_T off,
    hfs_file_folder * record)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);

    memset(record, 0, sizeof(hfs_file_folder));
    if (hfs_checked_read_random(fs, (char *) record, 2, off))
        return 1;

    if (tsk_getu16(fs->endian, record->file.rec_type) == HFS_FOLDER_RECORD) {
        if (hfs_checked_read_random(fs, ((char *) record) + 2,
                sizeof(hfs_folder) - 2, off + 2))
            return 1;
    }
    else if (tsk_getu16(fs->endian,
            record->file.rec_type) == HFS_FILE_RECORD) {
        if (hfs_checked_read_random(fs, ((char *) record) + 2,
                sizeof(hfs_file) - 2, off + 2))
            return 1;
    }
    else {
        tsk_errno = TSK_ERR_FS_GENFS;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_read_file_folder_record: unexpected record type %" PRIu16,
            tsk_getu16(fs->endian, record->file.rec_type));
        return 1;
    }

    return 0;
}

/** \internal
 * Lookup an entry in the catalog file and save it into the entry
 * data structure.
 * @param hfs File system being analyzed
 * @param inum Address (cnid) of file to open
 * @param entry [out] Structure to read data into
 * @returns 1 on error or not found, 0 on success. Check tsk_errno
 * to differentiate between error and not found.
 */
static uint8_t
hfs_catalog_lookup(HFS_INFO * hfs, TSK_INUM_T inum, HFS_ENTRY * entry)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    hfs_cat_key key;            /* current catalog key */
    uint32_t cnid;              /* catalog node ID of the entry (= inum) */
    hfs_thread thread;          /* thread record */
    hfs_file_folder record;     /* file/folder record */
    TSK_OFF_T off;

    char fname[HFS_MAXNAMLEN + 1];
	uint32_t *temp_32ptr;

    tsk_error_reset();

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_catalog_lookup: called for inum %" PRIuINUM "\n", inum);
    
    // Test if this is a special file that is not located in the catalog
    if ((inum == HFS_EXTENTS_FILE_ID) ||
       (inum == HFS_CATALOG_FILE_ID) || 
       (inum == HFS_ALLOCATION_FILE_ID) ||
       (inum == HFS_STARTUP_FILE_ID) ||
       (inum == HFS_ATTRIBUTES_FILE_ID)) {
        // @@@ Add error message
        return 1;
    }
    
    
    /* first look up the thread record for the item we're searching for */

    /* set up the thread record key */
    cnid = (uint32_t) inum;
    memset((char *) &key, 0, sizeof(hfs_cat_key));

    
    temp_32ptr = (uint32_t *) (key.parent_cnid);
    // @@@ Why is this needed, cnid is inum, which is local ordering...
    // I think the goal is to put it back into BE ordering, but that seems to not work..
    *temp_32ptr = tsk_getu32(fs->endian, (char *) &cnid);

    /* look up the thread record */
    off = hfs_catalog_get_record_offset(hfs, &key);

    if (off == 0)
        return 1;

    /* read the thread record */
    if (hfs_read_thread_record(hfs, off, &thread))
        return 1;

    if (hfs_uni2ascii(fs, thread.name.unicode,
            tsk_getu16(fs->endian, thread.name.length),
            fname, HFS_MAXNAMLEN + 1))
        return 1;

    if (tsk_verbose)
        fprintf(stderr,
            "hfs_catalog_lookup: parent cnid %" PRIu32 " node name (%"
            PRIu16 ") %s\n", tsk_getu32(fs->endian, thread.parent_cnid),
            tsk_getu16(fs->endian, thread.name.length), fname);

    /* now look up the actual file/folder record */

    /* build key */
    memset((char *) &key, 0, sizeof(hfs_cat_key));
    memcpy(((char *) &key) + 2, ((char *) &thread) + 4,
        sizeof(hfs_cat_key) - 2);

    /* look up the record */
    off = hfs_catalog_get_record_offset(hfs, &key);
    if (off == 0)
        return 1;

    /* read the record */
    if (hfs_read_file_folder_record(hfs, off, &record))
        return 1;

    /* these memcpy can be gotten rid of, really */
    if (tsk_getu16(fs->endian, record.file.rec_type) == HFS_FOLDER_RECORD) {
        if (tsk_verbose)
            fprintf(stderr,
                "hfs_catalog_lookup: found folder record valence %" PRIu32
                ", cnid %" PRIu32 "\n", tsk_getu32(fs->endian,
                    record.folder.valence), tsk_getu32(fs->endian,
                    record.folder.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_folder));
    }
    else if (tsk_getu16(fs->endian,
            record.file.rec_type) == HFS_FILE_RECORD) {
        if (tsk_verbose)
            fprintf(stderr,
                "hfs_catalog_lookup: found file record cnid %" PRIu32 "\n",
                tsk_getu32(fs->endian, record.file.cnid));
        memcpy((char *) &entry->cat, (char *) &record, sizeof(hfs_file));
    }
    /* other cases already caught by hfs_read_file_folder_record */

    memcpy((char *) &entry->thread, (char *) &thread, sizeof(hfs_thread));

    entry->flags |= TSK_FS_META_FLAG_ALLOC;     /// @@@ What about USED, etc.?
    entry->inum = inum;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_catalog_lookup exited\n");
    return 0;
}


/* hfs_load_blockmap - This function will allocate a bitmap of blocks which
 * are allocated.
 */
static int
hfs_load_blockmap(HFS_INFO * hfs)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & (hfs->fs_info);
    hfs_ext_desc *extents;
    int i;
    uint8_t *ptr;
    uint32_t bytes_remaining;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_load_blockmap: called\n");

    /* Note: the allocation file can be larger than the number of bytes
       computed below. According to TN1150, all extra bits must be set to 0.
       We avoid storing those empty bits; a consistency checker may want to
       actually load the whole allocation file and check that these bits
       are in fact empty. */

    hfs->block_map_size =
        (uint32_t) roundup(fs->block_count / 8, fs->block_size);
    if ((hfs->block_map =
            (uint8_t *) tsk_malloc(hfs->block_map_size)) == NULL)
        return 1;

    memset(hfs->block_map, 0, hfs->block_map_size);

    extents =
        hfs_ext_find_extent_record(hfs, HFS_ALLOCATION_FILE_ID,
        hfs->fs->alloc_file.extents);
    if (extents == NULL) {
        tsk_fprintf(stderr,
            "hfs_load_blockmap: failed to find extents for allocation file\n");
        return 1;
    }

    i = 0;
    ptr = hfs->block_map;
    bytes_remaining = hfs->block_map_size;
    while (bytes_remaining > 0) {
        uint32_t blocks;
        uint32_t bytes;
        TSK_OFF_T offset;

        blocks = tsk_getu32(fs->endian, extents[i].blk_cnt);
        if (blocks == 0) {
            tsk_fprintf(stderr,
                "hfs_load_blockmap: ran out of data for allocation file\n");
            free(extents);
            return 1;
        }

		bytes = (bytes_remaining < blocks * fs->block_size) ? bytes_remaining : blocks * fs->block_size;
        offset =
            (TSK_OFF_T) tsk_getu32(fs->endian,
            extents[i].start_blk) * fs->block_size;
        if (hfs_checked_read_random(fs, (char *) ptr, bytes, offset)) {
            free(extents);
            return 1;
        }
        bytes_remaining -= bytes;
        ptr += bytes;
    }

    free(extents);
    return 0;
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
    
    fs_file->meta->type = TSK_FS_META_TYPE_VIRT;
    fs_file->meta->mode = 0;
    fs_file->meta->nlink = 1;
    fs_file->meta->addr = HFS_CATALOG_FILE_ID;
    fs_file->meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_file->meta->uid = fs_file->meta->gid = 0;
    fs_file->meta->mtime = fs_file->meta->atime = fs_file->meta->ctime = fs_file->meta->crtime = 0;
    
    if (fs_file->meta->name2 == NULL) {
        if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
             tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_file->meta->name2->next = NULL;
    }
    strncpy(fs_file->meta->name2->name, HFS_CATALOGNAME,
            TSK_FS_META_NAME_LIST_NSIZE);
    
    fs_file->meta->size = tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz); 
    
    
    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else  {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }
    
    if ((attr_run = hfs_extents_to_attr(fs, hfs->fs->cat_file.extents, 0)) == NULL) {
        strncat(tsk_errstr2, " - hfs_make_catalog",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }
    
    if ((fs_attr = tsk_fs_attrlist_getnew(fs_file->meta->attr, TSK_FS_ATTR_NONRES)) == NULL) {
        strncat(tsk_errstr2, " - hfs_make_catalog",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }
    
    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
                            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz), 
                            tsk_getu64(fs->endian, hfs->fs->cat_file.logic_sz), 0, 0)) {
        strncat(tsk_errstr2, " - hfs_make_catalog",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }
    
    // see if catalog file has additional runs
    if (hfs_ext_find_extent_record_attr(hfs, HFS_CATALOG_FILE_ID,
                                        fs_attr)) {
        strncat(tsk_errstr2, " - hfs_make_catalog",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
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
    
    fs_file->meta->type = TSK_FS_META_TYPE_VIRT;
    fs_file->meta->mode = 0;
    fs_file->meta->nlink = 1;
    fs_file->meta->addr = HFS_EXTENTS_FILE_ID;
    fs_file->meta->flags = (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_ALLOC);
    fs_file->meta->uid = fs_file->meta->gid = 0;
    fs_file->meta->mtime = fs_file->meta->atime = fs_file->meta->ctime = fs_file->meta->crtime = 0;
    
    if (fs_file->meta->name2 == NULL) {
        if ((fs_file->meta->name2 = (TSK_FS_META_NAME_LIST *)
             tsk_malloc(sizeof(TSK_FS_META_NAME_LIST))) == NULL)
            return 1;
        fs_file->meta->name2->next = NULL;
    }
    strncpy(fs_file->meta->name2->name, HFS_EXTENTSNAME,
            TSK_FS_META_NAME_LIST_NSIZE);
    
    fs_file->meta->size = tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz); 
    
    
    if (fs_file->meta->attr != NULL) {
        tsk_fs_attrlist_markunused(fs_file->meta->attr);
    }
    else  {
        fs_file->meta->attr = tsk_fs_attrlist_alloc();
    }
    
    if ((attr_run = hfs_extents_to_attr(fs, hfs->fs->ext_file.extents, 0)) == NULL) {
        strncat(tsk_errstr2, " - hfs_make_extents",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        return 1;
    }
    
    if ((fs_attr = tsk_fs_attrlist_getnew(fs_file->meta->attr, TSK_FS_ATTR_NONRES)) == NULL) {
        strncat(tsk_errstr2, " - hfs_make_extents",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }
    
    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, attr_run, NULL,
                            TSK_FS_ATTR_TYPE_DEFAULT, TSK_FS_ATTR_ID_DEFAULT,
                            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz), 
                            tsk_getu64(fs->endian, hfs->fs->ext_file.logic_sz), 0, 0)) {
        strncat(tsk_errstr2, " - hfs_make_extents",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        tsk_fs_attr_free(fs_attr);
        tsk_fs_attr_run_free(attr_run);
        return 1;
    }
    
    // Extents doesn't have an entry in itself
    
    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;
    return 0;
}

/*
 * Copy the inode into the generic structure
 * Returns 1 on error.
 */
static uint8_t
hfs_dinode_copy(HFS_INFO * hfs, hfs_file *entry, TSK_FS_META * fs_meta)
{
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & hfs->fs_info;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_dinode_copy: called\n");

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->mode =
        hfsmode2tskmode(tsk_getu32(fs->endian, entry->perm.mode));

    if (tsk_getu16(fs->endian, entry->rec_type) == HFS_FOLDER_RECORD) {
        fs_meta->size = 0;
        fs_meta->type =
            hfsmode2tskmetatype(tsk_getu16(fs->endian,
                entry->perm.mode));
        if (fs_meta->type != TSK_FS_META_TYPE_DIR) {
            tsk_fprintf(stderr,
                "hfs_dinode_copy error: folder has non-directory type %"
                PRIu16 "\n", fs_meta->type);
            return 1;
        }
    }
    else if (tsk_getu16(fs->endian,
            entry->rec_type) == HFS_FILE_RECORD) {
        fs_meta->size = tsk_getu64(fs->endian, entry->data.logic_sz);
        fs_meta->type =
            hfsmode2tskmetatype(tsk_getu16(fs->endian,
                entry->perm.mode));
        if (fs_meta->type == TSK_FS_META_TYPE_DIR) {
            tsk_fprintf(stderr,
                "hfs_dinode_copy error: file has directory type\n");
            return 1;
        }
    }
    else {
        tsk_fprintf(stderr,
            "hfs_dinode_copy error: catalog entry is neither file nor folder\n");
        return 1;
    }

    fs_meta->uid = tsk_getu32(fs->endian, entry->perm.owner);
    fs_meta->gid = tsk_getu32(fs->endian, entry->perm.group);
    fs_meta->mtime =
        hfs2unixtime(tsk_getu32(fs->endian, entry->cmtime));
    fs_meta->atime =
        hfs2unixtime(tsk_getu32(fs->endian, entry->atime));
    fs_meta->crtime =
        hfs2unixtime(tsk_getu32(fs->endian, entry->ctime));
    fs_meta->ctime =
        hfs2unixtime(tsk_getu32(fs->endian, entry->attr_mtime));
    fs_meta->time2.hfs.bkup_time =
        hfs2unixtime(tsk_getu32(fs->endian, entry->bkup_date));
    fs_meta->addr = 0; // @@@@ entry->inum;

    fs_meta->flags = 0; // @@@ entry->flags;

    /* TODO could fill in name2 with this entry's name and parent inode
       from Catalog entry */

    // @@@ Shouldn't there be basic filling in of record locations etc?

    return 0;
}


/** \internal
 * Read a catalog file entry and save it in the generic TSK_FS_META format.
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
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_inode_lookup: fs_file is NULL");
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
    else if (inum == HFS_ALLOCATION_FILE_ID) {
        // @@@
    }
    else if (inum == HFS_STARTUP_FILE_ID) {
        // @@@
    }
    else if (inum == HFS_ATTRIBUTES_FILE_ID) {
        // @@@
    }
    
    /* Lookup inode and store it in the HFS structure */
    if (hfs_catalog_lookup(hfs, inum, &entry))
        return 1;

    /* Copy the structure in hfs to generic fs_inode */
    if (hfs_dinode_copy(hfs, &entry.cat, a_fs_file->meta)) {
        return 1;
    }

    return 0;
}

/** \internal
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
hfs_make_data_run(TSK_FS_FILE * fs_file)
{
    TSK_FS_INFO *fs;
    HFS_INFO *hfs;
    int i;
    TSK_FS_ATTR *fs_attr;
    HFS_ENTRY entry;
    hfs_ext_desc *extents;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file == NULL) || (fs_file->meta == NULL)
        || (fs_file->fs_info == NULL)) {
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_make_data_run: fs_file or meta is NULL");
        return 1;
    }
    fs = (TSK_FS_INFO *) fs_file->fs_info;
    hfs = (HFS_INFO *) fs;


    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_make_data_run: Processing file %" PRIuINUM "\n",
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


    // look up the catalog entries for this file
    // (they have already been looked up once before, but that information
    // isn't propagated to here, so we look it up again)
    if (hfs_catalog_lookup(hfs, fs_file->meta->addr, &entry))
        return 1;

    // if the catalog entry is not a file entry (presumably it would have
    // to be a folder entry), then it has no data
    if (tsk_getu16(fs->endian, entry.cat.rec_type) != HFS_FILE_RECORD)
        return 0;

    if ((fs_attr =
            tsk_fs_attrlist_getnew(fs_file->meta->attr,
                TSK_FS_ATTR_NONRES)) == NULL) {
        return 1;
    }
    // initialize the data run
    if (tsk_fs_attr_set_run(fs_file, fs_attr, NULL, NULL, 0, 0,
            fs_file->meta->size, roundup(fs_file->meta->size,
                fs->block_size), 0, 0)) {
        return 1;
    }

    extents =
        hfs_ext_find_extent_record(hfs, (uint32_t)entry.inum,
        entry.cat.data.extents);

    if (extents == NULL)
        return 1;

    for (i = 0; (tsk_getu32(fs->endian, extents[i].start_blk) != 0) ||
        (tsk_getu32(fs->endian, extents[i].blk_cnt) != 0); i++) {
        TSK_FS_ATTR_RUN *data_run;

        data_run = tsk_fs_attr_run_alloc();
        if (data_run == NULL) {
            free(extents);
            return -1;
        }

        data_run->addr = (TSK_DADDR_T) tsk_getu32(fs->endian,
            extents[i].start_blk);
        data_run->len = (TSK_DADDR_T) tsk_getu32(fs->endian,
            extents[i].blk_cnt);

        // save the run
        tsk_fs_attr_append_run(fs, fs_attr, data_run);
    }

    // note that the old code used to check if the total number of blocks in the
    // extents was too large or small for the size of the file (fork)
    // this is no longer done (at least within this function)

    fs_file->meta->attr_state = TSK_FS_META_ATTR_STUDIED;

    free(extents);
    return 0;
}


TSK_FS_BLOCK_FLAG_ENUM
hfs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    return hfs_is_block_alloc((HFS_INFO *) a_fs, a_addr) ?
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
        tsk_fprintf(stderr,
            "%s: invalid start block number: %" PRIuDADDR "", myname,
            start_blk);
        return 1;
    }
    if (end_blk < fs->first_block || end_blk > fs->last_block) {
        tsk_fprintf(stderr,
            "%s: invalid last block number: %" PRIuDADDR "", myname,
            end_blk);
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
        myflags = hfs_is_block_alloc(hfs, addr) ?
            TSK_FS_BLOCK_FLAG_ALLOC : TSK_FS_BLOCK_FLAG_UNALLOC;

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;


        if (tsk_fs_block_get(fs, fs_block, addr) == NULL) {
            tsk_fprintf(stderr,
                "hfs_block_walk: Error reading block %" PRIuDADDR
                ": %m", addr);
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
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_INUM_T inum;
    TSK_FS_FILE *fs_file;
    HFS_ENTRY entry;

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

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta = tsk_fs_meta_alloc(HFS_FILE_CONTENT_LEN)) == NULL)
        return 1;

    if (start_inum > end_inum)
        XSWAP(start_inum, end_inum);

    for (inum = start_inum; inum <= end_inum; inum++) {
        int retval;

        /* this section is logically the same as just calling hfs_inode_lookup,
         * but reuses a single malloc'ed fs_inode
         */

        if (hfs_catalog_lookup(hfs, inum, &entry)) {
            if (tsk_errno == 0)
                continue;
            else
                return 1;
        }

        /* Copy the structure in hfs to generic fs_inode */
        if (hfs_dinode_copy(hfs, &entry.cat, fs_file->meta))
            return 1;

        // @@@ We should be looking at some flags here...

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

    /*
     * Cleamup.
     */
    tsk_fs_file_close(fs_file);
    return 0;
}

/* print the name of a file at a given inode
 * returns 0 on success, 1 on error */
static uint8_t
print_inode_name(FILE * hFile, TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    char fn[HFS_MAXNAMLEN + 1];
    HFS_ENTRY entry;

    if (hfs_catalog_lookup(hfs, inum, &entry))
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
        tsk_errno = TSK_ERR_FS_INODE_NUM;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "print_parent_path: out-of-range inode %" PRIuINUM, inum);
        return 1;
    }

    if (hfs_catalog_lookup(hfs, inum, &entry))
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
        if (print_parent_path(hFile, fs, inum))
            return 1;
    }
    tsk_fprintf(hFile, "]");
    return 0;
}

static uint8_t
hfs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_fprintf(stderr, "fscheck not implemented for HFS yet");
    return 0;
}


static uint8_t
hfs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    // char *myname = "hfs_fsstat";
    HFS_INFO *hfs = (HFS_INFO *) fs;
    hfs_sb *sb = hfs->fs;
    time_t mac_time;
    TSK_INUM_T inode;

    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_fstat: called\n");

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "File System Type: ");

    if (tsk_getu16(fs->endian, hfs->fs->signature) == HFSPLUS_MAGIC)
        tsk_fprintf(hFile, "HFS+\n");
    else if (tsk_getu16(fs->endian, hfs->fs->signature) == HFSX_MAGIC)
        tsk_fprintf(hFile, "HFSX\n");
    else
        tsk_fprintf(hFile, "Unknown\n");

    tsk_fprintf(hFile, "File System Version: %" PRIu16,
        tsk_getu16(fs->endian, hfs->fs->version));

    switch (tsk_getu16(fs->endian, hfs->fs->version)) {
    case 4:
        tsk_fprintf(hFile, " (HFS+)\n");
        break;
    case 5:
        tsk_fprintf(hFile, " (HFSX)\n");
        break;
    default:
        tsk_fprintf(hFile, " (unknown)\n");
        break;
    }

    tsk_fprintf(hFile, "Last mounted version: %" PRIx32,
        tsk_getu32(fs->endian, sb->last_mnt_ver));

    if (tsk_getu32(fs->endian, sb->last_mnt_ver) == HFSPLUS_MOUNT_VERSION)
        tsk_fprintf(hFile, " (Mac OS X)\n");
    else if (tsk_getu32(fs->endian,
            sb->last_mnt_ver) == HFSJ_MOUNT_VERSION)
        tsk_fprintf(hFile, " (Mac OS X, Journaled)\n");
    else if (tsk_getu32(fs->endian, sb->last_mnt_ver) == FSK_MOUNT_VERSION)
        tsk_fprintf(hFile, " (failed journal replay)\n");
    else
        tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Volume Name: ");
    if (print_inode_name(hFile, fs, HFS_ROOT_INUM))
        return 1;
    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Number of files: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->file_cnt));

    tsk_fprintf(hFile, "Number of folders: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->fldr_cnt));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->c_date));
    tsk_fprintf(hFile, "Created: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->m_date));
    tsk_fprintf(hFile, "Last Written at: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->bkup_date));
    tsk_fprintf(hFile, "Last Backed Up at: %s", ctime(&mac_time));

    mac_time = hfs2unixtime(tsk_getu32(fs->endian, hfs->fs->chk_date));
    tsk_fprintf(hFile, "Last Checked at: %s", ctime(&mac_time));

    /* State of the file system */
    if ((tsk_getu32(fs->endian, hfs->fs->attr) & HFS_BIT_VOLUME_UNMOUNTED)
        || ((tsk_getu32(fs->endian,
                    hfs->fs->attr) & HFS_BIT_VOLUME_INCONSISTENT) == 0))
        tsk_fprintf(hFile, "Volume Unmounted Properly\n");
    else
        tsk_fprintf(hFile, "Volume Unmounted Improperly\n");

    if (tsk_getu32(fs->endian, hfs->fs->attr) & HFS_BIT_VOLUME_BADBLOCKS)
        tsk_fprintf(hFile, "Volume has bad blocks\n");

    tsk_fprintf(hFile, "Write count: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->write_cnt));

    /* Print journal information */
    if (tsk_getu32(fs->endian, sb->attr) & HFS_BIT_VOLUME_JOURNALED) {
        tsk_fprintf(hFile, "\nJournal Info Block: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb->jinfo_blk));
    }

    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "First Block of Catalog File: %" PRIu32 "\n",
        tsk_getu32(fs->endian, hfs->fs->cat_file.extents[0].start_blk));

    tsk_fprintf(hFile, "Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);

    inode = tsk_getu32(fs->endian, &(sb->finder_info[0]));
    tsk_fprintf(hFile, "Bootable Folder ID: %" PRIuINUM, inode);
    if (inode > HFS_ROOT_INUM)
        if (print_inode_file(hFile, fs, inode))
            return 1;
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, &(sb->finder_info[4]));
    tsk_fprintf(hFile, "Startup App ID: %" PRIuINUM, inode);
    if (inode > HFS_ROOT_INUM)
        if (print_inode_file(hFile, fs, inode))
            return 1;
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, &(sb->finder_info[8]));
    tsk_fprintf(hFile, "Startup Open Folder ID: %" PRIuINUM, inode);
    if (inode > HFS_ROOT_INUM)
        if (print_inode_file(hFile, fs, inode))
            return 1;
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, &(sb->finder_info[12]));
    tsk_fprintf(hFile, "Mac OS 8/9 Blessed System Folder ID: %" PRIuINUM,
        inode);
    if (inode > HFS_ROOT_INUM)
        if (print_inode_file(hFile, fs, inode))
            return 1;
    tsk_fprintf(hFile, "\n");

    inode = tsk_getu32(fs->endian, &(sb->finder_info[20]));
    tsk_fprintf(hFile, "Mac OS X Blessed System Folder ID: %" PRIuINUM,
        inode);
    if (inode > HFS_ROOT_INUM)
        if (print_inode_file(hFile, fs, inode))
            return 1;
    tsk_fprintf(hFile, "\n");

    tsk_fprintf(hFile, "Volume Identifier: %08" PRIx32 "%08" PRIx32 "\n",
        tsk_getu32(fs->endian, &(sb->finder_info[24])),
        tsk_getu32(fs->endian, &(sb->finder_info[28])));

    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Block Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "Allocation Block Size: %u\n", fs->block_size);

    tsk_fprintf(hFile, "Free Blocks: %" PRIu32 "\n",
        tsk_getu32(fs->endian, sb->free_blks));

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

uint8_t
hfs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    TSK_FS_FILE *fs_file;
    char hfs_mode[11];
    HFS_PRINT_ADDR print;
    HFS_ENTRY entry;

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_istat: inum: %" PRIuINUM " numblock: %" PRIu32 "\n",
            inum, numblock);




    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL)
        return 1;

    tsk_fprintf(hFile, "\nINODE INFORMATION\n");
    tsk_fprintf(hFile, "Entry:\t%" PRIuINUM "\n", inum);

    tsk_fprintf(hFile, "Type:\t");

    
    if (fs_file->meta->type == TSK_FS_META_TYPE_REG)
        tsk_fprintf(hFile, "File\n");
    else if (fs_file->meta->type == TSK_FS_META_TYPE_DIR)
        tsk_fprintf(hFile, "Folder\n");

    tsk_fs_make_ls(fs_file->meta, hfs_mode);
    tsk_fprintf(hFile, "Mode:\t%s\n", hfs_mode);
    
    tsk_fprintf(hFile, "Created:\t%s", ctime(&fs_file->meta->crtime));
    tsk_fprintf(hFile, "Content Modified:\t%s",
                ctime(&fs_file->meta->mtime));
    tsk_fprintf(hFile, "Attributes Modified:\t%s",
                ctime(&fs_file->meta->ctime));
    tsk_fprintf(hFile, "Accessed:\t%s", ctime(&fs_file->meta->atime));
    tsk_fprintf(hFile, "Backed Up:\t%s",
                ctime(&fs_file->meta->time2.hfs.bkup_time));
    
    
    if (hfs_catalog_lookup(hfs, inum, &entry) == 0) {
        tsk_fprintf(hFile, "Owner-ID:\t%" PRIu32 "\n", tsk_getu32(fs->endian,
                entry.cat.perm.owner));
        tsk_fprintf(hFile, "Group-ID:\t%" PRIu32 "\n", tsk_getu32(fs->endian,
                entry.cat.perm.group));
        if (((tsk_getu16(fs->endian,
                         entry.cat.perm.mode) & HFS_IN_IFMT) == HFS_IN_IFCHR)
            || ((tsk_getu16(fs->endian,
                            entry.cat.perm.mode) & HFS_IN_IFMT) == HFS_IN_IFBLK)) {
            tsk_fprintf(hFile, "Device ID:\t%" PRIu32 "\n",
                        tsk_getu32(fs->endian, entry.cat.perm.special.raw));
        }
        else if ((tsk_getu32(fs->endian,
                             entry.cat.u_info.file_type) == HFS_HARDLINK_FILE_TYPE)
                 && (tsk_getu32(fs->endian,
                                entry.cat.u_info.file_cr) == HFS_HARDLINK_FILE_CREATOR)) {
            // technically, the creation date of this item should be the same as either the
            // creation date of the "HFS+ Private Data" folder or the creation date of the root folder
            tsk_fprintf(hFile, "Hard link inode number\t %" PRIu32 "\n",
                        tsk_getu32(fs->endian, entry.cat.perm.special.inum));
        }
        else {
            // only files within the "HFS+ Private Data" folder are actually hard link files
            // (and even then, only the ones labelled "iNode*"
            tsk_fprintf(hFile, "Link count:\t%" PRIu32 "\n",
                        tsk_getu32(fs->endian, entry.cat.perm.special.nlink));
    }
        
        if (tsk_getu16(fs->endian, entry.cat.flags) & HFS_FILE_FLAG_LOCKED)
            tsk_fprintf(hFile, "Locked\n");
        if (tsk_getu16(fs->endian, entry.cat.flags) & HFS_FILE_FLAG_ATTR)
            tsk_fprintf(hFile, "Has extended attributes\n");
        if (tsk_getu16(fs->endian, entry.cat.flags) & HFS_FILE_FLAG_ACL)
            tsk_fprintf(hFile, "Has security data (ACLs)\n");
        
        tsk_fprintf(hFile,
                    "File type:\t%04" PRIx32 "\nFile creator:\t%04" PRIx32 "\n",
                    tsk_getu32(fs->endian, entry.cat.u_info.file_type),
                    tsk_getu32(fs->endian, entry.cat.u_info.file_type));
        
        if (tsk_getu16(fs->endian,
                       entry.cat.u_info.flags) & HFS_FINDER_FLAG_NAME_LOCKED)
            tsk_fprintf(hFile, "Name locked\n");
        if (tsk_getu16(fs->endian,
                       entry.cat.u_info.flags) & HFS_FINDER_FLAG_HAS_BUNDLE)
            tsk_fprintf(hFile, "Has bundle\n");
        if (tsk_getu16(fs->endian,
                       entry.cat.u_info.flags) & HFS_FINDER_FLAG_IS_INVISIBLE)
            tsk_fprintf(hFile, "Is invisible\n");
        if (tsk_getu16(fs->endian,
                       entry.cat.u_info.flags) & HFS_FINDER_FLAG_IS_ALIAS)
            tsk_fprintf(hFile, "Is alias\n");
        
        tsk_fprintf(hFile, "Text encoding:\t%" PRIx32 "\n",
                    tsk_getu32(fs->endian, entry.cat.text_enc));
        
        if (tsk_getu16(fs->endian, entry.cat.rec_type) == HFS_FILE_RECORD) {
            tsk_fprintf(hFile,
                        "Data fork size:\t%" PRIu64 "\nResource fork size:\t%" PRIu64
                        "\n", tsk_getu64(fs->endian, entry.cat.data.logic_sz),
                        tsk_getu64(fs->endian, entry.cat.resource.logic_sz));
        }        
    }

    print.idx = 0;
    print.hFile = hFile;

    tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY,
        print_addr_act, (void *) &print);

    if (print.idx != 0)
        tsk_fprintf(hFile, "\n");

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

    if (hfs->block_map != NULL)
        free(hfs->block_map);
    free(hfs);
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
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L, "Invalid FS Type in hfs_open");
        return NULL;
    }

    if ((hfs = (HFS_INFO *) tsk_malloc(sizeof(HFS_INFO))) == NULL)
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
    len = sizeof(hfs_sb);
    if ((hfs->fs = (hfs_sb *) tsk_malloc(len)) == NULL) {
        fs->tag = 0;
        free(hfs);
        return NULL;
    }

    if (hfs_checked_read_random(fs, (char *) hfs->fs, len,
            (TSK_OFF_T) HFS_SBOFF)) {
        snprintf(tsk_errstr2, TSK_ERRSTR_L, "hfs_open: superblock");
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        return NULL;
    }


    /*
     * Verify we are looking at an HFS+ image
     */
    if (tsk_fs_guessu16(fs, hfs->fs->signature, HFSPLUS_MAGIC) &&
        tsk_fs_guessu16(fs, hfs->fs->signature, HFSX_MAGIC)) {
        if (!tsk_fs_guessu16(fs, hfs->fs->signature, HFS_MAGIC)) {
            tsk_fprintf(stderr, "HFS volumes not supported\n");
        }
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        tsk_errno = TSK_ERR_FS_MAGIC;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "not an HFS+ file system (magic)");
        return NULL;
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
    fs->load_attrs = hfs_make_data_run;
    fs->get_default_attr_type = hfs_get_default_attr_type;

    fs->file_add_meta = hfs_inode_lookup;
    fs->dir_open_meta = hfs_dir_open_meta;
    fs->fsstat = hfs_fsstat;
    fs->fscheck = hfs_fscheck;
    fs->istat = hfs_istat;
    fs->close = hfs_close;

    // lazy loading of block map
    hfs->block_map = NULL;
    hfs->block_map_size = 0;


    fs->first_inum = HFS_ROOT_INUM;
    fs->root_inum = HFS_ROOT_INUM;
    fs->last_inum = HFS_FIRST_USER_CNID - 1;        // we will later increase this
    fs->inum_count = fs->last_inum - fs->first_inum + 1;
    
    /* Load the Catalog file extents (data runs) starting with 
     * the data in the volume header */
    // @@@@ How will this know to load only one entry from the volume header?
    hfs->cat_extents =
        hfs_ext_find_extent_record(hfs, HFS_CATALOG_FILE_ID,
        hfs->fs->cat_file.extents);
    if (hfs->cat_extents == NULL) {
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        return NULL;
    }

    hfs->extents_file = NULL;   // we will load this when needed
    hfs->extents_attr = NULL;   
    
    
    
    if ((hfs->catalog_file =
         tsk_fs_file_open_meta(fs, NULL, HFS_CATALOG_FILE_ID)) == NULL) {
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        return NULL;
    }
    
    /* cache the data attribute */
    hfs->catalog_attr =
        tsk_fs_attrlist_get(hfs->catalog_file->meta->attr, TSK_FS_ATTR_TYPE_DEFAULT);
    if (!hfs->catalog_attr) {
        fs->tag = 0;
        tsk_fs_file_close(hfs->catalog_file);
        free(hfs->fs);
        free(hfs);
        strncat(tsk_errstr2, " - Data Attribute not found in Catalog File",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        return NULL;
    }

    // cache the catalog file header
    cnt = tsk_fs_attr_read(hfs->catalog_attr, 14,
                           (char *) &(hfs->catalog_header),
                           sizeof(hfs_btree_header_record), 0);
    if (cnt != sizeof(hfs_btree_header_record)) {
        // @@@
        fs->tag = 0;
        free(hfs->fs);
        free(hfs);
        return NULL;        
    }
    
    if (tsk_getu16(fs->endian, hfs->fs->version) == 4)
        hfs->is_case_sensitive = 0;
    else if (tsk_getu16(fs->endian, hfs->fs->version) == 5) {
        if (hfs->catalog_header.k_type == 0xcf)
            hfs->is_case_sensitive = 0;
        else if (hfs->catalog_header.k_type == 0xbc)
            hfs->is_case_sensitive = 1;
        else {
            tsk_fprintf(stderr,
                "hfs_open: invalid value (0x%02" PRIx8
                ") for key compare type\n", hfs->catalog_header.k_type);
            hfs->is_case_sensitive = 0;
        }
    }
    else {
        tsk_fprintf(stderr,
            "hfs_open: unknown HFS+/HFSX version (%" PRIu16 "\n",
            tsk_getu16(fs->endian, hfs->fs->version));
        hfs->is_case_sensitive = 0;
    }

    // @@@@ inum_count should be last-first
    // update the numbers.
    fs->last_inum = hfs_find_highest_inum(hfs);
    fs->inum_count = tsk_getu32(fs->endian, hfs->fs->file_cnt) +
        tsk_getu32(fs->endian, hfs->fs->fldr_cnt);

    snprintf((char *) fs->fs_id, 17, "%08" PRIx32 "%08" PRIx32,
        tsk_getu32(fs->endian, &(hfs->fs->finder_info[24])),
        tsk_getu32(fs->endian, &(hfs->fs->finder_info[28])));
    fs->fs_id_used = 16;

    /* journal */
    fs->jblk_walk = hfs_jblk_walk;
    fs->jentry_walk = hfs_jentry_walk;
    fs->jopen = hfs_jopen;
    fs->journ_inum = 0;

    return fs;
}
