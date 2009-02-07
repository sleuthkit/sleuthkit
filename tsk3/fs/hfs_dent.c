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

/** \file hfs_dent.c
 * Contains the file name layer code for HFS+ file systems -- not included in
 * code by default.
 */

#include "tsk_fs_i.h"
#include "tsk_hfs.h"

#define UTF16_NULL 0x0000
#define UTF16_NULL_REPLACE 0x005e
#define UTF16_SLASH 0x002f
#define UTF16_COLON 0x003a

/* convert HFS+'s UTF16 to UTF8
 * replaces null characters with another character (0xfffd)
 * replaces slashes (permitted by HFS+ but causes problems with TSK)
 *   with colons (generally not allowed by Mac OS X)
 * note that at least one directory on HFS+ volumes begins with
 *   four nulls, so we do need to handle nulls; also, Apple chooses
 *   to encode nulls as UTF8 \xC0\x80, which is not a valid UTF8 sequence
 * returns 0 on success, 1 on failure; sets up to error string 1 */
uint8_t
hfs_uni2ascii(TSK_FS_INFO * fs, uint8_t * uni, int ulen, char *asc,
    int alen)
{
    char *aptr;
    uint8_t *uniclean;
    uint8_t *uptr;
    int i;
    TSKConversionResult r;

    // remove nulls from the Unicode string
    // convert / to :
    uniclean = (uint8_t *) tsk_malloc(ulen * 2);
    memcpy(uniclean, uni, ulen * 2);
    for (i = 0; i < ulen; ++i) {
        uint16_t uc = tsk_getu16(fs->endian, uniclean + i * 2);
        int changed = 0;
        if (uc == UTF16_NULL) {
            uc = UTF16_NULL_REPLACE;
            changed = 1;
        }
        else if (uc == UTF16_SLASH) {
            uc = UTF16_COLON;
            changed = 1;
        }
        if (changed)
            *((uint16_t *) (uniclean + i * 2)) =
                tsk_getu16(fs->endian, (uint8_t *) & uc);
    }

    memset(asc, 0, alen);
    aptr = asc;
    uptr = uniclean;
    r = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &uptr,
        (const UTF16 *) (uptr + ulen * 2), (UTF8 **) & aptr,
        (UTF8 *) aptr + alen - 1, TSKstrictConversion);

    if (r != TSKconversionOK) {
        tsk_errno = TSK_ERR_FS_UNICODE;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "hfs_uni2ascii: unicode conversion failed (%" PRIu8 ")", r);
        free(uniclean);
        return 1;
    }

    free(uniclean);
    return 0;
}

static TSK_FS_NAME_TYPE_ENUM
hfsmode2tsknametype(uint16_t a_mode)
{
    switch (a_mode & HFS_IN_IFMT) {
    case HFS_IN_IFIFO:
        return TSK_FS_NAME_TYPE_FIFO;
    case HFS_IN_IFCHR:
        return TSK_FS_NAME_TYPE_CHR;
    case HFS_IN_IFDIR:
        return TSK_FS_NAME_TYPE_DIR;
    case HFS_IN_IFBLK:
        return TSK_FS_NAME_TYPE_BLK;
    case HFS_IN_IFREG:
        return TSK_FS_NAME_TYPE_REG;
    case HFS_IN_IFLNK:
        return TSK_FS_NAME_TYPE_LNK;
    case HFS_IN_IFSOCK:
        return TSK_FS_NAME_TYPE_SOCK;
    case HFS_IFWHT:
        return TSK_FS_NAME_TYPE_WHT;
    case HFS_IFXATTR:
        return TSK_FS_NAME_TYPE_UNDEF;
    default:
        /* error */
        return TSK_FS_NAME_TYPE_UNDEF;
    }
}

/** \internal
 * Process a directory and load up FS_DIR with the entries. If a pointer to
 * an already allocated FS_DIR struture is given, it will be cleared.  If no existing
 * FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return 
 * value is error or corruption, then the FS_DIR structure could  
 * have entries (depending on when the error occured). 
 *
 * @param a_fs File system to analyze
 * @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
 * structure or a new structure. 
 * @param a_addr Address of directory to process.
 * @returns error, corruption, ok etc. 
 */
TSK_RETVAL_ENUM
hfs_dir_open_meta(TSK_FS_INFO * fs, TSK_FS_DIR ** a_fs_dir,
                  TSK_INUM_T a_addr)
{
    HFS_INFO *hfs = (HFS_INFO *) fs;
    uint32_t cnid;              /* catalog node ID of the entry (= inum) */
    uint32_t cur_node;          /* node id of the current node */
    char *node;    
    TSK_FS_DIR *fs_dir;
    TSK_FS_NAME *fs_name;
    uint16_t nodesize;
    uint8_t is_done = 0;
    
    tsk_error_reset();
    
    cnid = (uint32_t) a_addr;
    
    if (tsk_verbose)
        fprintf(stderr,
                "hfs_dir_open_meta: called for directory %" PRIu32 "\n", cnid);
    
    if (a_addr < fs->first_inum || a_addr > fs->last_inum) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_WALK_RNG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
                 "hfs_dir_open_meta: Invalid inode value: %" PRIuINUM, a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_ARG;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
                 "hfs_dir_open_meta: NULL fs_data argument given");
        return TSK_ERR;
    }
    
    if (tsk_verbose)
        tsk_fprintf(stderr,
                    "hfs_dir_open_meta: Processing directory %" PRIuINUM "\n",
                    a_addr);
    
    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
    }
    else {
        if ((*a_fs_dir = fs_dir = tsk_fs_dir_alloc(fs, 128)) == NULL) {
            return TSK_ERR;
        }
    }
    
    if ((fs_name = tsk_fs_name_alloc(HFS_MAXNAMLEN, 0)) == NULL) {
        return TSK_ERR;
    }
    
    if ((fs_dir->fs_file =
         tsk_fs_file_open_meta(fs, NULL, a_addr)) == NULL) {
        strncat(tsk_errstr2, " - hfs_dir_open_meta",
                TSK_ERRSTR_L - strlen(tsk_errstr2));
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }
    
    // if we are listing the root directory, add the Orphan directory and special HFS file entries
    if (a_addr == fs->root_inum) {
        int i;
        for (i = 0; i < 6; i++) {
            switch (i) {
                case 0:
                    strncpy(fs_name->name, HFS_EXTENTS_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_EXTENTS_FILE_ID;
                    break;
                case 1:
                    strncpy(fs_name->name, HFS_CATALOG_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_CATALOG_FILE_ID;
                    break;
                case 2:
                    strncpy(fs_name->name, HFS_BAD_BLOCK_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_BAD_BLOCK_FILE_ID;
                    break;
                case 3:
                    strncpy(fs_name->name, HFS_ALLOCATION_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_ALLOCATION_FILE_ID;
                    break;
                case 4:
                    strncpy(fs_name->name, HFS_STARTUP_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_STARTUP_FILE_ID;
                    break;
                case 5:
                    strncpy(fs_name->name, HFS_ATTRIBUTES_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_ATTRIBUTES_FILE_ID;
                    break;
                    /*
                case 6:
                    strncpy(fs_name->name, HFS_REPAIR_CATALOG_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_REPAIR_CATALOG_FILE_ID;
                    break;
                case 7:
                    strncpy(fs_name->name, HFS_BOGUS_EXTENT_FILE_NAME, fs_name->name_size);
                    fs_name->meta_addr = HFS_BOGUS_EXTENT_FILE_ID;
                    break;                    
                    */
            }
            fs_name->type = TSK_FS_NAME_TYPE_REG;
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            if (tsk_fs_dir_add(fs_dir, fs_name)) {
                tsk_fs_name_free(fs_name);
                return TSK_ERR;
            }
        }
    }
    
    nodesize = tsk_getu16(fs->endian, hfs->catalog_header.nodesize);
    if ((node = (char *) tsk_malloc(nodesize)) == NULL) {
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }
    
    /* start at root node */
    cur_node = tsk_getu32(fs->endian, hfs->catalog_header.root);
    
    /* if the root node is zero, then the extents btree is empty */
    /* if no files have overflow extents, the Extents B-tree still
        exists on disk, but is an empty B-tree containing only
        the header node */
    if (cur_node == 0) {
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_dir_open_meta: "
                        "empty extents btree\n");
        tsk_fs_name_free(fs_name);
        free(node);
        return TSK_OK;
    }
    
    if (tsk_verbose)
        tsk_fprintf(stderr, "hfs_dir_open_meta: starting at "
                    "root node %" PRIu32 "; nodesize = %"
                    PRIu16 "\n", cur_node, nodesize);
    
    /* Recurse down to the needed leaf nodes and then go forward */
    is_done = 0;
    while (is_done == 0) {
        TSK_OFF_T cur_off;      /* start address of cur_node */
        uint16_t num_rec;       /* number of records in this node */
        ssize_t cnt;
        hfs_btree_node *node_desc;
        
        // read the current node
        cur_off = cur_node * nodesize;
        cnt = tsk_fs_attr_read(hfs->catalog_attr, cur_off,
                               node, nodesize, 0);
        if (cnt != nodesize) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_errno = TSK_ERR_FS_READ;
            }
            snprintf(tsk_errstr2, TSK_ERRSTR_L,
                     "hfs_dir_open_meta: Error reading catalog node %d at offset %"PRIuOFF, cur_node, cur_off); 
            tsk_fs_name_free(fs_name);
            free(node);
            return TSK_ERR;
        }
        
        // process the header / descriptor
        node_desc = (hfs_btree_node *) node;
        num_rec = tsk_getu16(fs->endian, node_desc->num_rec);
        
        if (tsk_verbose)
            tsk_fprintf(stderr, "hfs_dir_open_meta: node %" PRIu32
                        " @ %" PRIu64 " has %" PRIu16 " records\n",
                        cur_node, cur_off, num_rec);
        
        if (num_rec == 0) {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                     "hfs_dir_open_meta: zero records in node %"
                     PRIu32, cur_node);
            tsk_fs_name_free(fs_name);
            free(node);
            return TSK_COR;
        }
        
        /* With an index node, find the record with the largest key that is smaller
         * to or equal to cnid */
        if (node_desc->kind == HFS_BTREE_INDEX_NODE) {
            uint32_t next_node = 0;
            int rec;
            
            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_cat_key *key;
                
                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                               &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_errno = TSK_ERR_FS_GENFS;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                             "hfs_dir_open_meta: offset of record %d in index node %d too large (%zu vs %"PRIu16")",
                             rec, cur_node, rec_off, nodesize);
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_COR;
                }
                key = (hfs_cat_key *) & node[rec_off];
                
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "hfs_dir_open_meta: record %" PRIu16
                                " ; keylen %" PRIu16 " (%" PRIu32")\n", rec,
                                tsk_getu16(fs->endian, key->key_len),
                                tsk_getu32(fs->endian, key->parent_cnid));
                
                /* save the info from this record unless it is bigger than cnid */
                if ((tsk_getu32(fs->endian, key->parent_cnid) <= cnid) || (next_node == 0)) {
                    int keylen = tsk_getu16(fs->endian, key->key_len) + 2;
                    if (rec_off + keylen > nodesize) {
                        tsk_errno = TSK_ERR_FS_GENFS;
                        snprintf(tsk_errstr, TSK_ERRSTR_L,
                                 "hfs_dir_open_meta: offset of record + keylen %d in index node %d too large (%zu vs %"PRIu16")",
                                 rec, cur_node, rec_off+keylen, nodesize);
                        tsk_fs_name_free(fs_name);
                        free(node);
                        return TSK_COR;
                    }
                    next_node =
                        tsk_getu32(fs->endian, &node[rec_off + keylen]);
                }
                else {
                    // we are bigger than cnid, so move down to the next node
                    break;
                }
            }
            
            // check if we found a relevant node
            if (next_node == 0) {
                tsk_errno = TSK_ERR_FS_GENFS;
                snprintf(tsk_errstr, TSK_ERRSTR_L,
                         "hfs_dir_open_meta: did not find any keys for %d in index node %d",
                         cnid, cur_node);
                // @@@ is this an error?  It is probably just an empty directory, so the error msg does not ned to be set..
                is_done = 1;
                break;
            }
            cur_node = next_node;
        }
        
        /* with a leaf, we process until we are past cnid.  We move right too if we can */
        else if (node_desc->kind == HFS_BTREE_LEAF_NODE) {
            int rec;
            
            for (rec = 0; rec < num_rec; rec++) {
                size_t rec_off;
                hfs_cat_key *key;
                uint16_t rec_type;
                size_t rec_off2;
                
                // get the record offset in the node
                rec_off =
                    tsk_getu16(fs->endian,
                               &node[nodesize - (rec + 1) * 2]);
                if (rec_off > nodesize) {
                    tsk_errno = TSK_ERR_FS_GENFS;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                             "hfs_dir_open_meta: offset of record %d in leaf node %d too large (%zu vs %"PRIu16")",
                             rec, cur_node, rec_off, nodesize);
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_COR;
                }
                key = (hfs_cat_key *) & node[rec_off];
                
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                                "hfs_dir_open_meta: record %" PRIu16
                                "; keylen %" PRIu16 " (%" PRIu32")\n", rec,
                                tsk_getu16(fs->endian, key->key_len),
                                tsk_getu32(fs->endian, key->parent_cnid));
                
                // see if this record is for our file or if we passed the interesting entries
                if (tsk_getu32(fs->endian, key->parent_cnid) < cnid) {
                    continue;
                }
                else if(tsk_getu32(fs->endian, key->parent_cnid) > cnid) {
                    is_done = 1;
                    break;
                }
               
                rec_off2 = rec_off + 2 + tsk_getu16(fs->endian, key->key_len);
                if (rec_off2 > nodesize) {
                    tsk_errno = TSK_ERR_FS_GENFS;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                             "hfs_dir_open_meta: offset of record+keylen %d in leaf node %d too large (%zu vs %"PRIu16")",
                             rec, cur_node, rec_off2, nodesize);
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_COR;
                }
                rec_type = tsk_getu16(fs->endian, &node[rec_off2]);
                if (rec_type == HFS_FILE_THREAD) {
                    tsk_errno = TSK_ERR_FS_GENFS;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                             "hfs_dir_open_meta: Got File Thread record in record %d in leaf node %d",
                             rec, cur_node);
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_COR;
                }
                
                /* This will link the folder to its parent, which is the ".." entry */
                else if (rec_type == HFS_FOLDER_THREAD) {
                    hfs_thread *thread = (hfs_thread *)&node[rec_off2];
                    
                    strcpy(fs_name->name, "..");
                    fs_name->meta_addr = tsk_getu32(fs->endian, thread->parent_cnid);
                    fs_name->type = TSK_FS_NAME_TYPE_DIR;
                    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;                     
                }

                /* This is a folder in the folder */
                else if (rec_type == HFS_FOLDER_RECORD) {
                    hfs_folder *folder = (hfs_folder *)&node[rec_off2];
                    
                    fs_name->meta_addr = tsk_getu32(fs->endian, folder->cnid);
                    fs_name->type = TSK_FS_NAME_TYPE_DIR;
                    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
                    
                    if (hfs_uni2ascii(fs, key->name.unicode,
                                      tsk_getu16(fs->endian, key->name.length),
                                      fs_name->name, HFS_MAXNAMLEN + 1)) {
                        tsk_fs_name_free(fs_name);
                        free(node);
                        return TSK_ERR;
                    }
                }
                
                /* This is a normal file in the folder */
                else if (rec_type == HFS_FILE_RECORD) {
                    hfs_file *file = (hfs_file *)&node[rec_off2];
                    fs_name->meta_addr = tsk_getu32(fs->endian, file->cnid);
                    fs_name->type = hfsmode2tsknametype (tsk_getu16(fs->endian, file->perm.mode));
                    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;                     
                    if (hfs_uni2ascii(fs, key->name.unicode,
                                      tsk_getu16(fs->endian, key->name.length),
                                      fs_name->name, HFS_MAXNAMLEN + 1)) {
                        tsk_fs_name_free(fs_name);
                        free(node);
                        return TSK_ERR;
                    }
                }
                else {
                    tsk_errno = TSK_ERR_FS_GENFS;
                    snprintf(tsk_errstr, TSK_ERRSTR_L,
                             "hfs_dir_open_meta: Unknown record type %d in leaf node %d",
                             rec_type, cur_node);
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_COR;                    
                }
                
                if (tsk_fs_dir_add(fs_dir, fs_name)) {
                    tsk_fs_name_free(fs_name);
                    free(node);
                    return TSK_ERR;
                }                
            }
            
            // move right to the next node if we got this far
            cur_node = tsk_getu32(fs->endian, node_desc->flink);
            if (cur_node == 0) {
                is_done = 1;
                break;
            }
        }
        else {
            tsk_errno = TSK_ERR_FS_GENFS;
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                     "hfs_dir_open_meta: btree node %" PRIu32
                     " (%" PRIu64 ") is neither index nor leaf (%" PRIu8 ")",
                     cur_node, cur_off, node_desc->kind);
            
            tsk_fs_name_free(fs_name);
            free(node);
            return TSK_COR;
        }
    }
    tsk_fs_name_free(fs_name);
    free(node);
    return TSK_OK;
}

