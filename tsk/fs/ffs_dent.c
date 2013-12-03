/*
** ffs_dent
** The  Sleuth Kit
**
** File name layer for a FFS/UFS image
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2006 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILs
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ffs_dent.c
 * Contains the internal TSK UFS/FFS file name (directory entry) processing  functions
 */

#include <ctype.h>
#include "tsk_fs_i.h"
#include "tsk_ffs.h"


static uint8_t
ffs_dent_copy(FFS_INFO * ffs, char *ffs_dent, TSK_FS_NAME * fs_name)
{
    TSK_FS_INFO *a_fs = &(ffs->fs_info);

    /* this one has the type field */
    if ((a_fs->ftype == TSK_FS_TYPE_FFS1)
        || (a_fs->ftype == TSK_FS_TYPE_FFS2)) {
        ffs_dentry1 *dir = (ffs_dentry1 *) ffs_dent;

        fs_name->meta_addr = tsk_getu32(a_fs->endian, dir->d_ino);

        if (fs_name->name_size != FFS_MAXNAMLEN) {
            if (tsk_fs_name_realloc(fs_name, FFS_MAXNAMLEN))
                return 1;
        }

        /* ffs null terminates so we can strncpy */
        strncpy(fs_name->name, dir->d_name, fs_name->name_size);

        switch (dir->d_type) {
        case FFS_DT_REG:
            fs_name->type = TSK_FS_NAME_TYPE_REG;
            break;
        case FFS_DT_DIR:
            fs_name->type = TSK_FS_NAME_TYPE_DIR;
            break;
        case FFS_DT_CHR:
            fs_name->type = TSK_FS_NAME_TYPE_CHR;
            break;
        case FFS_DT_BLK:
            fs_name->type = TSK_FS_NAME_TYPE_BLK;
            break;
        case FFS_DT_FIFO:
            fs_name->type = TSK_FS_NAME_TYPE_FIFO;
            break;
        case FFS_DT_SOCK:
            fs_name->type = TSK_FS_NAME_TYPE_SOCK;
            break;
        case FFS_DT_LNK:
            fs_name->type = TSK_FS_NAME_TYPE_LNK;
            break;
        case FFS_DT_WHT:
            fs_name->type = TSK_FS_NAME_TYPE_WHT;
            break;
        case FFS_DT_UNKNOWN:
        default:
            fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
            break;
        }
    }
    else if (a_fs->ftype == TSK_FS_TYPE_FFS1B) {
        ffs_dentry2 *dir = (ffs_dentry2 *) ffs_dent;

        fs_name->meta_addr = tsk_getu32(a_fs->endian, dir->d_ino);

        if (fs_name->name_size != FFS_MAXNAMLEN) {
            if (tsk_fs_name_realloc(fs_name, FFS_MAXNAMLEN))
                return 1;
        }

        /* ffs null terminates so we can strncpy */
        strncpy(fs_name->name, dir->d_name, fs_name->name_size);

        fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ffs_dent_copy: Unknown FS type");
        return 1;
    }

    fs_name->flags = 0;
    return 0;
}


/*
 * @param a_is_del Set to 1 if block is from a deleted directory.
 */
static TSK_RETVAL_ENUM
ffs_dent_parse_block(FFS_INFO * ffs, TSK_FS_DIR * fs_dir, uint8_t a_is_del,
    char *buf, unsigned int len)
{
    unsigned int idx;
    unsigned int inode = 0, dellen = 0, reclen = 0;
    unsigned int minreclen = 4;
    TSK_FS_INFO *fs = &(ffs->fs_info);

    char *dirPtr;
    TSK_FS_NAME *fs_name;

    if ((fs_name = tsk_fs_name_alloc(FFS_MAXNAMLEN + 1, 0)) == NULL)
        return TSK_ERR;

    /* update each time by the actual length instead of the
     ** recorded length so we can view the deleted entries
     */
    for (idx = 0; idx <= len - FFS_DIRSIZ_lcl(1); idx += minreclen) {
        unsigned int namelen = 0;

        dirPtr = (char *) &buf[idx];

        /* copy to local variables */
        if ((fs->ftype == TSK_FS_TYPE_FFS1)
            || (fs->ftype == TSK_FS_TYPE_FFS2)) {
            ffs_dentry1 *dir = (ffs_dentry1 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->d_ino);
            namelen = dir->d_namlen;
            reclen = tsk_getu16(fs->endian, dir->d_reclen);
        }
        /* TSK_FS_TYPE_FFS1B */
        else if (fs->ftype == TSK_FS_TYPE_FFS1B) {
            ffs_dentry2 *dir = (ffs_dentry2 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->d_ino);
            namelen = tsk_getu16(fs->endian, dir->d_namlen);
            reclen = tsk_getu16(fs->endian, dir->d_reclen);
        }

        /* what is the minimum size needed for this entry */
        minreclen = FFS_DIRSIZ_lcl(namelen);

        /* Perform a couple sanity checks
         ** OpenBSD never zeros the inode number, but solaris
         ** does.  These checks will hopefully catch all non
         ** entries
         */
        if ((inode > fs->last_inum) ||  // inode is unsigned
            (namelen > FFS_MAXNAMLEN) ||        // namelen is unsigned
            (namelen == 0) ||
            (reclen < minreclen) || (reclen % 4) || (idx + reclen > len)) {

            /* we don't have a valid entry, so skip ahead 4 */
            minreclen = 4;
            if (dellen > 0)
                dellen -= 4;
            continue;
        }

        /* Before we process an entry in unallocated space, make
         * sure that it also ends in the unalloc space */
        if ((dellen) && (dellen < minreclen)) {
            minreclen = 4;
            dellen -= 4;
            continue;
        }

        /* the entry is valid */
        if (ffs_dent_copy(ffs, dirPtr, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }


        /* Do we have a deleted entry? (are we in a deleted space) */
        if ((dellen > 0) || (inode == 0) || (a_is_del)) {
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            if (dellen)
                dellen -= minreclen;
        }
        else {
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        }
        if (tsk_fs_dir_add(fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* If we have some slack and an entry could exist in it, the set dellen */
        if (dellen <= 0) {
            if (reclen - minreclen >= FFS_DIRSIZ_lcl(1))
                dellen = reclen - minreclen;
            else
                minreclen = reclen;
        }
    }

    tsk_fs_name_free(fs_name);
    return TSK_OK;
}                               /* end ffs_dent_parse_block */

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
ffs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    TSK_OFF_T size;
    FFS_INFO *ffs = (FFS_INFO *) a_fs;
    char *dirbuf;
    int nchnk, cidx;
    TSK_FS_LOAD_FILE load_file;
    TSK_FS_DIR *fs_dir;

    /* If we get corruption in one of the blocks, then continue processing.
     * retval_final will change when corruption is detected.  Errors are
     * returned immediately. */
    TSK_RETVAL_ENUM retval_tmp;
    TSK_RETVAL_ENUM retval_final = TSK_OK;


    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("ffs_dir_open_meta: Invalid inode value: %"
            PRIuINUM, a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ffs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "ffs_dir_open_meta: Processing directory %" PRIuINUM "\n",
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

    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- ffs_dir_open_meta");
        return TSK_COR;
    }

    /* make a copy of the directory contents that we can process */
    /* round up cause we want the slack space too */
    size = roundup(fs_dir->fs_file->meta->size, FFS_DIRBLKSIZ);
    if ((dirbuf = tsk_malloc((size_t) size)) == NULL) {
        return TSK_ERR;
    }

    load_file.total = load_file.left = (size_t) size;
    load_file.base = load_file.cur = dirbuf;

    if (tsk_fs_file_walk(fs_dir->fs_file,
            TSK_FS_FILE_WALK_FLAG_SLACK,
            tsk_fs_load_file_action, (void *) &load_file)) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- ffs_dir_open_meta");
        free(dirbuf);
        return TSK_COR;
    }

    /* Not all of the directory was copied, so we return */
    if (load_file.left > 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_FWALK);
        tsk_error_set_errstr("ffs_dir_open_meta: Error reading directory %"
            PRIuINUM, a_addr);
        free(dirbuf);
        return TSK_COR;
    }

    /* Directory entries are written in chunks of DIRBLKSIZ
     ** determine how many chunks of this size we have to read to
     ** get a full block
     **
     ** Entries do not cross over the DIRBLKSIZ boundary
     */
    nchnk = (int) (size) / (FFS_DIRBLKSIZ) + 1;

    for (cidx = 0; cidx < nchnk && (int64_t) size > 0; cidx++) {
        int len = (FFS_DIRBLKSIZ < size) ? FFS_DIRBLKSIZ : (int) size;

        retval_tmp =
            ffs_dent_parse_block(ffs, fs_dir,
            (fs_dir->fs_file->meta->
                flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0,
            dirbuf + cidx * FFS_DIRBLKSIZ, len);

        if (retval_tmp == TSK_ERR) {
            retval_final = TSK_ERR;
            break;
        }
        else if (retval_tmp == TSK_COR) {
            retval_final = TSK_COR;
        }
        size -= len;
    }
    free(dirbuf);

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

    return retval_final;
}
