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
** Matt Stillerman [matt@atc-nycorp.com]
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

/** \file hfs_dent.c
 * Contains the file name layer code for HFS+ file systems -- not included in
 * code by default.
 */

#include "tsk_fs_i.h"
#include "tsk_hfs.h"

/* convert HFS+'s UTF16 to UTF8
 * replaces null characters with another character (0xfffd)
 * replaces slashes (permitted by HFS+ but causes problems with TSK)
 *   with colons (generally not allowed by Mac OS X)
 * note that at least one directory on HFS+ volumes begins with
 *   four nulls, so we do need to handle nulls; also, Apple chooses
 *   to encode nulls as UTF8 \xC0\x80, which is not a valid UTF8 sequence
 *
 *   @param fs  the file system
 *   @param uni  the UTF16 string as a sequence of bytes
 *   @param ulen  then length of the UTF16 string in characters
 *   @param asc   a buffer to hold the UTF8 result
 *   @param alen  the length of that buffer
 *   @param flags  control some aspects of the conversion
 *   @return 0 on success, 1 on failure; sets up to error string 1
 *
 *   HFS_U16U8_FLAG_REPLACE_SLASH  if this flag is set, then slashes will be replaced
 *   by colons.  Otherwise, they will not be replaced.
 *
 *   HFS_U16U8_FLAG_REPLACE_CONTROL if this flag is set, then all control characters
 *   will be replaced by the UTF16_NULL_REPLACE character. N.B., always replaces
 *   null characters regardless of this flag.
 */
uint8_t
hfs_UTF16toUTF8(TSK_FS_INFO * fs, uint8_t * uni, int ulen, char *asc,
    int alen, uint32_t flags)
{
    UTF8 *ptr8;
    uint8_t *uniclean;
    UTF16 *ptr16;
    int i;
    TSKConversionResult r;

    // remove nulls from the Unicode string
    // convert / to :
    uniclean = (uint8_t *) tsk_malloc(ulen * 2);
    if (!uniclean)
        return 1;

    memcpy(uniclean, uni, ulen * 2);

    for (i = 0; i < ulen; ++i) {
        uint16_t uc = tsk_getu16(fs->endian, uniclean + i * 2);


        int changed = 0;
        if (uc == UTF16_NULL) {
            uc = UTF16_NULL_REPLACE;
            changed = 1;
        }
        else if ((flags & HFS_U16U8_FLAG_REPLACE_SLASH)
            && uc == UTF16_SLASH) {
            uc = UTF16_COLON;
            changed = 1;
        }

        else if ((flags & HFS_U16U8_FLAG_REPLACE_CONTROL)
            && uc < UTF16_LEAST_PRINTABLE) {
            uc = (uint16_t) UTF16_NULL_REPLACE;
            changed = 1;
        }

        if (changed)
            *((uint16_t *) (uniclean + i * 2)) =
                tsk_getu16(fs->endian, (uint8_t *) & uc);
    }

    // convert to UTF-8
    memset(asc, 0, alen);

    ptr8 = (UTF8 *) asc;
    ptr16 = (UTF16 *) uniclean;
    r = tsk_UTF16toUTF8(fs->endian, (const UTF16 **) &ptr16,
        (const UTF16 *) (&uniclean[ulen * 2]), &ptr8,
        (UTF8 *) & asc[alen], TSKstrictConversion);

    free(uniclean);
    if (r != TSKconversionOK) {
        tsk_error_set_errno(TSK_ERR_FS_UNICODE);
        tsk_error_set_errstr
            ("hfs_UTF16toUTF8: unicode conversion failed (%d)", (int) r);
        return 1;
    }

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


// used to pass data to the callback
typedef struct {
    TSK_FS_DIR *fs_dir;
    TSK_FS_NAME *fs_name;
} HFS_DIR_OPEN_META_INFO;

static uint8_t
hfs_dir_open_meta_cb(HFS_INFO * hfs, int8_t level_type,
    const void *targ_data, const hfs_btree_key_cat * cur_key,
    TSK_OFF_T key_off, void *ptr)
{
    uint32_t *cnid_p = (uint32_t *) targ_data;
    HFS_DIR_OPEN_META_INFO *info = (HFS_DIR_OPEN_META_INFO *) ptr;
    TSK_FS_INFO *fs = &hfs->fs_info;

    if (tsk_verbose)
        fprintf(stderr,
            "hfs_dir_open_meta_cb: want %" PRIu32 " vs got %" PRIu32
            " (%s node)\n", *cnid_p, tsk_getu32(hfs->fs_info.endian,
                cur_key->parent_cnid),
            (level_type == HFS_BT_NODE_TYPE_IDX) ? "Index" : "Leaf");

    if (level_type == HFS_BT_NODE_TYPE_IDX) {
        if (tsk_getu32(hfs->fs_info.endian,
                cur_key->parent_cnid) < *cnid_p) {
            return HFS_BTREE_CB_IDX_LT;
        }
        else {
            return HFS_BTREE_CB_IDX_EQGT;
        }
    }
    else {
        uint8_t *rec_buf = (uint8_t *) cur_key;
        uint16_t rec_type;
        size_t rec_off2;

        if (tsk_getu32(hfs->fs_info.endian,
                cur_key->parent_cnid) < *cnid_p) {
            return HFS_BTREE_CB_LEAF_GO;
        }
        else if (tsk_getu32(hfs->fs_info.endian,
                cur_key->parent_cnid) > *cnid_p) {
            return HFS_BTREE_CB_LEAF_STOP;
        }
        rec_off2 = 2 + tsk_getu16(hfs->fs_info.endian, cur_key->key_len);
        // @@@ NEED TO REPLACE THIS SOMEHOW, but need to figure out the max length
        /*
           if (rec_off2 > nodesize) {
           tsk_error_set_errno(TSK_ERR_FS_GENFS);
           tsk_error_set_errstr(
           "hfs_dir_open_meta: offset of record+keylen %d in leaf node %d too large (%zu vs %"
           PRIu16 ")", rec, cur_node, rec_off2, nodesize);
           tsk_fs_name_free(fs_name);
           free(node);
           return TSK_COR;
           }
         */
        rec_type = tsk_getu16(hfs->fs_info.endian, &rec_buf[rec_off2]);

        // Catalog entry is for a file
        if (rec_type == HFS_FILE_THREAD) {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            tsk_error_set_errstr("hfs_dir_open_meta: Entry"
                " is a file, not a folder");
            return HFS_BTREE_CB_ERR;
        }

        /* This will link the folder to its parent, which is the ".." entry */
        else if (rec_type == HFS_FOLDER_THREAD) {
            hfs_thread *thread = (hfs_thread *) & rec_buf[rec_off2];
            strcpy(info->fs_name->name, "..");
            info->fs_name->meta_addr =
                tsk_getu32(hfs->fs_info.endian, thread->parent_cnid);
            info->fs_name->type = TSK_FS_NAME_TYPE_DIR;
            info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        }

        /* This is a folder in the folder */
        else if (rec_type == HFS_FOLDER_RECORD) {
            hfs_folder *folder = (hfs_folder *) & rec_buf[rec_off2];

            info->fs_name->meta_addr =
                tsk_getu32(hfs->fs_info.endian, folder->std.cnid);
            info->fs_name->type = TSK_FS_NAME_TYPE_DIR;
            info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;


            if (hfs_UTF16toUTF8(fs, (uint8_t *) cur_key->name.unicode,
                    tsk_getu16(hfs->fs_info.endian, cur_key->name.length),
                    info->fs_name->name, HFS_MAXNAMLEN + 1,
                    HFS_U16U8_FLAG_REPLACE_SLASH)) {
                return HFS_BTREE_CB_ERR;
            }
        }

        /* This is a normal file in the folder */
        else if (rec_type == HFS_FILE_RECORD) {
            hfs_file *file = (hfs_file *) & rec_buf[rec_off2];
            // This could be a hard link.  We need to test this CNID, and follow it if necessary.
            unsigned char is_err;
            TSK_INUM_T file_cnid =
                tsk_getu32(hfs->fs_info.endian, file->std.cnid);
            TSK_INUM_T target_cnid =
                hfs_follow_hard_link(hfs, file, &is_err);
            if (is_err > 1) {
                error_returned
                    ("hfs_dir_open_meta_cb: trying to follow a possible hard link in the directory");
                return HFS_BTREE_CB_ERR;
            }
            if (target_cnid != file_cnid) {
                HFS_ENTRY entry;
                uint8_t lkup;   // lookup result

                // This is a hard link.  We need to fill in the name->type and name->meta_addr from the target
                info->fs_name->meta_addr = target_cnid;
                // get the Catalog entry for the target CNID

                lkup = hfs_cat_file_lookup(hfs, target_cnid, &entry,
                    FALSE);
                if (lkup != 0) {
                    error_returned
                        ("hfs_dir_open_meta_cb: retrieving the catalog entry for the target of a hard link");
                    return HFS_BTREE_CB_ERR;
                }
                info->fs_name->type =
                    hfsmode2tsknametype(tsk_getu16(hfs->fs_info.endian,
                        entry.cat.std.perm.mode));
            }
            else {
                // This is NOT a hard link.
                info->fs_name->meta_addr =
                    tsk_getu32(hfs->fs_info.endian, file->std.cnid);
                info->fs_name->type =
                    hfsmode2tsknametype(tsk_getu16(hfs->fs_info.endian,
                        file->std.perm.mode));
            }
            info->fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
            if (hfs_UTF16toUTF8(fs, (uint8_t *) cur_key->name.unicode,
                    tsk_getu16(hfs->fs_info.endian, cur_key->name.length),
                    info->fs_name->name, HFS_MAXNAMLEN + 1,
                    HFS_U16U8_FLAG_REPLACE_SLASH)) {
                return HFS_BTREE_CB_ERR;
            }
        }
        else {
            tsk_error_set_errno(TSK_ERR_FS_GENFS);
            // @@@ MAY NEED TO IMPROVE BELOW MESSAGE
            tsk_error_set_errstr
                ("hfs_dir_open_meta: Unknown record type %d in leaf node",
                rec_type);
            return HFS_BTREE_CB_ERR;
        }

        if (tsk_fs_dir_add(info->fs_dir, info->fs_name)) {
            return HFS_BTREE_CB_ERR;
        }
        return HFS_BTREE_CB_LEAF_GO;
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
    TSK_FS_DIR *fs_dir;
    TSK_FS_NAME *fs_name;
    HFS_DIR_OPEN_META_INFO info;


    tsk_error_reset();

    cnid = (uint32_t) a_addr;

    if (tsk_verbose)
        fprintf(stderr,
            "hfs_dir_open_meta: called for directory %" PRIu32 "\n", cnid);

    if (a_addr < fs->first_inum || a_addr > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("hfs_dir_open_meta: Invalid inode value: %"
            PRIuINUM, a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("hfs_dir_open_meta: NULL fs_dir argument given");
        return TSK_ERR;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "hfs_dir_open_meta: Processing directory %" PRIuINUM "\n",
            a_addr);

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr;
    }
    else if ((*a_fs_dir = fs_dir =
            tsk_fs_dir_alloc(fs, a_addr, 128)) == NULL) {
        return TSK_ERR;
    }

    if ((fs_name = tsk_fs_name_alloc(HFS_MAXNAMLEN, 0)) == NULL) {
        return TSK_ERR;
    }
    info.fs_dir = fs_dir;
    info.fs_name = fs_name;

    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(fs, NULL, a_addr)) == NULL) {
        tsk_error_errstr2_concat(" - hfs_dir_open_meta");
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    // if we are listing the root directory, add the Orphan directory and special HFS file entries
    if (a_addr == fs->root_inum) {
        int i;
        for (i = 0; i < 6; i++) {
            switch (i) {
            case 0:
                if (!hfs->has_extents_file)
                    continue;
                strncpy(fs_name->name, HFS_EXTENTS_FILE_NAME,
                    fs_name->name_size);
                fs_name->meta_addr = HFS_EXTENTS_FILE_ID;
                break;
            case 1:
                strncpy(fs_name->name, HFS_CATALOG_FILE_NAME,
                    fs_name->name_size);
                fs_name->meta_addr = HFS_CATALOG_FILE_ID;
                break;
            case 2:
                // Note: the Extents file and the BadBlocks file are really the same.
                if (!hfs->has_extents_file)
                    continue;
                strncpy(fs_name->name, HFS_BAD_BLOCK_FILE_NAME,
                    fs_name->name_size);
                fs_name->meta_addr = HFS_BAD_BLOCK_FILE_ID;
                break;
            case 3:
                strncpy(fs_name->name, HFS_ALLOCATION_FILE_NAME,
                    fs_name->name_size);
                fs_name->meta_addr = HFS_ALLOCATION_FILE_ID;
                break;
            case 4:
                if (!hfs->has_startup_file)
                    continue;
                strncpy(fs_name->name, HFS_STARTUP_FILE_NAME,
                    fs_name->name_size);
                fs_name->meta_addr = HFS_STARTUP_FILE_ID;
                break;
            case 5:
                if (!hfs->has_attributes_file)
                    continue;
                strncpy(fs_name->name, HFS_ATTRIBUTES_FILE_NAME,
                    fs_name->name_size);
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

    if (hfs_cat_traverse(hfs, &cnid, hfs_dir_open_meta_cb, &info)) {
        tsk_fs_name_free(fs_name);
        return TSK_ERR;
    }

    tsk_fs_name_free(fs_name);
    return TSK_OK;
}

int
hfs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    HFS_INFO *hfs = (HFS_INFO *) a_fs_info;
    if (hfs->is_case_sensitive)
        return strcmp(s1, s2);
    else
        return strcasecmp(s1, s2);
}
