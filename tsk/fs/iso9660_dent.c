/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c)2007 Brian Carrier.  All righs reserved.
**
**
** This software is subject to the IBM Public License ver. 1.0,
** which was displayed prior to download and is included in the readme.txt
** file accompanying the Sleuth Kit files.  It may also be requested from:
** Crucial Security Inc.
** 14900 Conference Center Drive
** Chantilly, VA 20151
**
** Copyright (c) 2007-2011 Brian Carrier.  All rights reserved
**
** Wyatt Banks [wbanks@crucialsecurity.com]
** Copyright (c) 2005 Crucial Security Inc.  All rights reserved.
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
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

/**
 * \file iso9660_dent.c
 * Contains the internal TSK ISO9660 file system code to handle the parsing of
 * file names and directory structures.
 */

#include "tsk_fs_i.h"
#include "tsk_iso9660.h"



/** \internal
 * process the data from inside of a directory and load the corresponding
 * file data into a TSK_FS_DIR structure.
 *
 * @param a_fs File system
 * @param a_fs_dir Structure to store file names into
 * @param buf Buffer that contains the directory content
 * @param a_length Number of bytes in buffer
 * @param a_addr The metadata address for the directory being processed
 * @param a_dir_addr The block offset where this directory starts
 * @returns TSK_ERR on error and TSK_OK otherwise
 */
static uint8_t
iso9660_proc_dir(TSK_FS_INFO * a_fs, TSK_FS_DIR * a_fs_dir, char *buf,
    size_t a_length, TSK_INUM_T a_addr, TSK_OFF_T a_dir_addr)
{
    ISO_INFO *iso = (ISO_INFO *) a_fs;
    TSK_FS_NAME *fs_name;
    size_t buf_idx;

    iso9660_dentry *dd;         /* directory descriptor */
    iso9660_inode_node *in;
    TSK_OFF_T dir_offs = a_dir_addr * a_fs->block_size;

    // had an issue once where dir was too small
    // many later calculations assume we can fit at least one entry
    if (a_length < sizeof(iso9660_dentry)) {      
        return TSK_OK;
    }

    if ((fs_name = tsk_fs_name_alloc(ISO9660_MAXNAMLEN + 1, 0)) == NULL)
        return TSK_ERR;

    buf_idx = 0;
    dd = (iso9660_dentry *) & buf[buf_idx];

    /* handle "." entry */
    fs_name->meta_addr = a_addr;
    strcpy(fs_name->name, ".");
    fs_name->type = TSK_FS_NAME_TYPE_DIR;
    fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

    tsk_fs_dir_add(a_fs_dir, fs_name);

    buf_idx += dd->entry_len;
    if (buf_idx > a_length - sizeof(iso9660_dentry)) {
        free(buf);
        tsk_fs_name_free(fs_name);
        return TSK_OK;
    }
    dd = (iso9660_dentry *) & buf[buf_idx];

    /* handle ".." entry */
    in = iso->in_list;
    while (in
        && (tsk_getu32(a_fs->endian, in->inode.dr.ext_loc_m) !=
            tsk_getu32(a_fs->endian, dd->ext_loc_m)))
        in = in->next;
    if (in) {
        fs_name->meta_addr = in->inum;
        strcpy(fs_name->name, "..");

        fs_name->type = TSK_FS_NAME_TYPE_DIR;
        fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

        tsk_fs_dir_add(a_fs_dir, fs_name);
    }
    buf_idx += dd->entry_len;

    // process the rest of the entries in the directory
    while (buf_idx < a_length - sizeof(iso9660_dentry)) {
        dd = (iso9660_dentry *) & buf[buf_idx];

        // process the entry (if it has a defined and valid length)
        if ((dd->entry_len) && (buf_idx + dd->entry_len <= a_length)) {

            /* We need to find the data in the pre-processed list because that
             * contains the meta data address that TSK assigned to this file.
             * We find the entry by looking for one that was stored at the same
             * byte offset that we now are.  We used to use the extent location, but
             * we found an image
             * that had a file with 0 bytes with the same starting block as another
             * file. */
            for (in = iso->in_list; in; in = in->next) {
                if (in->dentry_offset == dir_offs + buf_idx)
                    break;
            }

            // we may have not found it because we are reading corrupt data...
            if (!in) {
                buf_idx++;
                continue;
            }

            // copy the data in fs_name for loading
            fs_name->meta_addr = in->inum;
            strncpy(fs_name->name, in->inode.fn, ISO9660_MAXNAMLEN);

            if (dd->flags & ISO9660_FLAG_DIR)
                fs_name->type = TSK_FS_NAME_TYPE_DIR;
            else
                fs_name->type = TSK_FS_NAME_TYPE_REG;
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;

            tsk_fs_dir_add(a_fs_dir, fs_name);

            buf_idx += dd->entry_len;
        }
        /* If the length was not defined, we are probably in a hole in the
         * directory.  The contents are  block aligned. So, we
         * scan ahead until we get either a non-zero entry or the block boundary */
        else {
            buf_idx++;
            for (; buf_idx < a_length - sizeof(iso9660_dentry); buf_idx++) {
                if (buf[buf_idx] != 0) {
                    dd = (iso9660_dentry *) & buf[buf_idx];
                    if ((dd->entry_len)
                        && (buf_idx + dd->entry_len < a_length))
                        break;
                }

                if (buf_idx % a_fs->block_size == 0)
                    break;
            }
        }
    }

    free(buf);
    tsk_fs_name_free(fs_name);

    return TSK_OK;
}



/** \internal
 * Process a directory and load up FS_DIR with the entries. If a pointer to
 * an already allocated FS_DIR structure is given, it will be cleared.  If no existing
 * FS_DIR structure is passed (i.e. NULL), then a new one will be created. If the return
 * value is error or corruption, then the FS_DIR structure could
 * have entries (depending on when the error occurred).
 *
 * @param a_fs File system to analyze
 * @param a_fs_dir Pointer to FS_DIR pointer. Can contain an already allocated
 * structure or a new structure.
 * @param a_addr Address of directory to process.
 * @returns error, corruption, ok etc.
 */
TSK_RETVAL_ENUM
iso9660_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    TSK_RETVAL_ENUM retval;
    TSK_FS_DIR *fs_dir;
    ssize_t cnt;
    char *buf;
    size_t length;

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr
            ("iso9660_dir_open_meta: Invalid inode value: %" PRIuINUM,
            a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("iso9660_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "iso9660_dir_open_meta: Processing directory %" PRIuINUM "\n",
            a_addr);

    fs_dir = *a_fs_dir;
    if (fs_dir) {
        tsk_fs_dir_reset(fs_dir);
        fs_dir->addr = a_addr;
    }
    else {
        if ((*a_fs_dir = fs_dir =
                tsk_fs_dir_alloc(a_fs, a_addr, 128)) == NULL) {
            return TSK_ERR;
        }
    }

    //  handle the orphan directory if its contents were requested
    if (a_addr == TSK_FS_ORPHANDIR_INUM(a_fs)) {
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);
    }

    fs_dir->fs_file = tsk_fs_file_open_meta(a_fs, NULL, a_addr);
    if (fs_dir->fs_file == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("iso9660_dir_open_meta: %" PRIuINUM
            " is not a valid inode", a_addr);
        return TSK_COR;
    }

    /* read directory extent into memory */
    length = (size_t) fs_dir->fs_file->meta->size;
    if ((buf = tsk_malloc(length)) == NULL)
        return TSK_ERR;

    cnt = tsk_fs_file_read(fs_dir->fs_file, 0, buf, length, 0);
    if (cnt != length) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr2("iso9660_dir_open_meta");
        return TSK_ERR;
    }

    // process the contents
    retval = iso9660_proc_dir(a_fs, fs_dir, buf, length, a_addr,
        fs_dir->fs_file->meta->attr->head->nrd.run->addr);

    // if we are listing the root directory, add the Orphan directory entry
    if (a_addr == a_fs->root_inum) {
        TSK_FS_NAME *fs_name = tsk_fs_name_alloc(256, 0);
        if (fs_name == NULL)
            return TSK_ERR;

        if (tsk_fs_dir_make_orphan_dir_name(a_fs, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }
        tsk_fs_name_free(fs_name);
    }

    return retval;
}

int
iso9660_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1, const char *s2)
{
    return strcmp(s1, s2);
}
