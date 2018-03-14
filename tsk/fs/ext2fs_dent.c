/*
** ext2fs_dent
** The Sleuth Kit
**
** File name layer support for an Ext2 / Ext3 FS
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2006 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** TCTUTILS
** Copyright (c) 2001 Brian Carrier.  All rights reserved
**
**
** This software is distributed under the Common Public License 1.0
**
*/

/**
 * \file ext2fs_dent.c
 * Contains the internal TSK file name processing code for Ext2 / ext3
 */

#include <ctype.h>
#include "tsk_fs_i.h"
#include "tsk_ext2fs.h"



static uint8_t
ext2fs_dent_copy(EXT2FS_INFO * ext2fs,
    char *ext2_dent, TSK_FS_NAME * fs_name)
{
    TSK_FS_INFO *fs = &(ext2fs->fs_info);

    if (ext2fs->deentry_type == EXT2_DE_V1) {
        ext2fs_dentry1 *dir = (ext2fs_dentry1 *) ext2_dent;

        fs_name->meta_addr = tsk_getu32(fs->endian, dir->inode);

        /* ext2 does not null terminate */
        if (tsk_getu16(fs->endian, dir->name_len) >= fs_name->name_size) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("ext2fs_dent_copy: Name Space too Small %d %" PRIuSIZE "",
                tsk_getu16(fs->endian, dir->name_len), fs_name->name_size);
            return 1;
        }

        /* Copy and Null Terminate */
        strncpy(fs_name->name, dir->name, tsk_getu16(fs->endian,
                dir->name_len));
        fs_name->name[tsk_getu16(fs->endian, dir->name_len)] = '\0';

        fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
    }
    else {
        ext2fs_dentry2 *dir = (ext2fs_dentry2 *) ext2_dent;

        fs_name->meta_addr = tsk_getu32(fs->endian, dir->inode);

        /* ext2 does not null terminate */
        if (dir->name_len >= fs_name->name_size) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_ARG);
            tsk_error_set_errstr
                ("ext2_dent_copy: Name Space too Small %d %" PRIuSIZE "",
                dir->name_len, fs_name->name_size);
            return 1;
        }

        /* Copy and Null Terminate */
        strncpy(fs_name->name, dir->name, dir->name_len);
        fs_name->name[dir->name_len] = '\0';

        switch (dir->type) {
        case EXT2_DE_REG:
            fs_name->type = TSK_FS_NAME_TYPE_REG;
            break;
        case EXT2_DE_DIR:
            fs_name->type = TSK_FS_NAME_TYPE_DIR;
            break;
        case EXT2_DE_CHR:
            fs_name->type = TSK_FS_NAME_TYPE_CHR;
            break;
        case EXT2_DE_BLK:
            fs_name->type = TSK_FS_NAME_TYPE_BLK;
            break;
        case EXT2_DE_FIFO:
            fs_name->type = TSK_FS_NAME_TYPE_FIFO;
            break;
        case EXT2_DE_SOCK:
            fs_name->type = TSK_FS_NAME_TYPE_SOCK;
            break;
        case EXT2_DE_LNK:
            fs_name->type = TSK_FS_NAME_TYPE_LNK;
            break;
        case EXT2_DE_UNKNOWN:
        default:
            fs_name->type = TSK_FS_NAME_TYPE_UNDEF;
            break;
        }
    }

    fs_name->flags = 0;

    return 0;
}



/*
 * @param a_is_del Set to 1 if block is from a deleted directory.
 */
static TSK_RETVAL_ENUM
ext2fs_dent_parse_block(EXT2FS_INFO * ext2fs, TSK_FS_DIR * a_fs_dir,
    uint8_t a_is_del, TSK_LIST ** list_seen, char *buf, int len)
{
    TSK_FS_INFO *fs = &(ext2fs->fs_info);

    int dellen = 0;
    int idx;
    uint16_t reclen;
    uint32_t inode;
    char *dirPtr;
    TSK_FS_NAME *fs_name;
    int minreclen = 4;

    if ((fs_name = tsk_fs_name_alloc(EXT2FS_MAXNAMLEN + 1, 0)) == NULL)
        return TSK_ERR;

    /* update each time by the actual length instead of the
     ** recorded length so we can view the deleted entries
     */
    for (idx = 0; idx <= len - EXT2FS_DIRSIZ_lcl(1); idx += minreclen) {

        unsigned int namelen;
        dirPtr = &buf[idx];

        if (ext2fs->deentry_type == EXT2_DE_V1) {
            ext2fs_dentry1 *dir = (ext2fs_dentry1 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->inode);
            namelen = tsk_getu16(fs->endian, dir->name_len);
            reclen = tsk_getu16(fs->endian, dir->rec_len);
        }
        else {
            ext2fs_dentry2 *dir = (ext2fs_dentry2 *) dirPtr;
            inode = tsk_getu32(fs->endian, dir->inode);
            namelen = dir->name_len;
            reclen = tsk_getu16(fs->endian, dir->rec_len);
        }

        minreclen = EXT2FS_DIRSIZ_lcl(namelen);

        /*
         ** Check if we may have a valid directory entry.  If we don't,
         ** then increment to the next word and try again.
         */
        if ((inode > fs->last_inum) ||  // inode is unsigned
            (namelen > EXT2FS_MAXNAMLEN) || (namelen == 0) ||   // namelen is unsigned
            (reclen < minreclen) || (reclen % 4) || (idx + reclen > len)) {

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

        if (ext2fs_dent_copy(ext2fs, dirPtr, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* Do we have a deleted entry? */
        if ((dellen > 0) || (inode == 0) || (a_is_del)) {
            fs_name->flags = TSK_FS_NAME_FLAG_UNALLOC;
            if (dellen > 0)
                dellen -= minreclen;
        }
        /* We have a non-deleted entry */
        else {
            fs_name->flags = TSK_FS_NAME_FLAG_ALLOC;
        }
        if (tsk_fs_dir_add(a_fs_dir, fs_name)) {
            tsk_fs_name_free(fs_name);
            return TSK_ERR;
        }

        /* If the actual length is shorter then the
         ** recorded length, then the next entry(ies) have been
         ** deleted.  Set dellen to the length of data that
         ** has been deleted
         **
         ** Because we aren't guaranteed with Ext2FS that the next
         ** entry begins right after this one, we will check to
         ** see if the difference is less than a possible entry
         ** before we waste time searching it
         */
        if (dellen <= 0) {
            if (reclen - minreclen >= EXT2FS_DIRSIZ_lcl(1))
                dellen = reclen - minreclen;
            else
                minreclen = reclen;
        }
    }

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
ext2fs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    EXT2FS_INFO *ext2fs = (EXT2FS_INFO *) a_fs;
    char *dirbuf;
    TSK_OFF_T size;
    TSK_FS_DIR *fs_dir;
    TSK_LIST *list_seen = NULL;

    /* If we get corruption in one of the blocks, then continue processing.
     * retval_final will change when corruption is detected.  Errors are
     * returned immediately. */
    TSK_RETVAL_ENUM retval_tmp;
    TSK_RETVAL_ENUM retval_final = TSK_OK;

    if (a_addr < a_fs->first_inum || a_addr > a_fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("ext2fs_dir_open_meta: inode value: %"
            PRIuINUM "\n", a_addr);
        return TSK_ERR;
    }
    else if (a_fs_dir == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ext2fs_dir_open_meta: NULL fs_attr argument given");
        return TSK_ERR;
    }

    if (tsk_verbose) {
        tsk_fprintf(stderr,
            "ext2fs_dir_open_meta: Processing directory %" PRIuINUM
            "\n", a_addr);
#ifdef Ext4_DBG
        tsk_fprintf(stderr,
            "ext2fs_dir_open_meta: $OrphanFiles Inum %" PRIuINUM
            " == %" PRIuINUM ": %d\n", TSK_FS_ORPHANDIR_INUM(a_fs), a_addr,
            a_addr == TSK_FS_ORPHANDIR_INUM(a_fs));
#endif
    }

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
#ifdef Ext4_DBG
        tsk_fprintf(stderr, "DEBUG: Getting ready to process ORPHANS\n");
#endif
        return tsk_fs_dir_find_orphans(a_fs, fs_dir);
    }
    else {
#ifdef Ext4_DBG
        tsk_fprintf(stderr,
            "DEBUG: not orphan %" PRIuINUM "!=%" PRIuINUM "\n", a_addr,
            TSK_FS_ORPHANDIR_INUM(a_fs));
#endif
    }

    if ((fs_dir->fs_file =
            tsk_fs_file_open_meta(a_fs, NULL, a_addr)) == NULL) {
        tsk_error_reset();
        tsk_error_errstr2_concat("- ext2fs_dir_open_meta");
        return TSK_COR;
    }

    // We only read in and process a single block at a time
    if ((dirbuf = tsk_malloc((size_t)a_fs->block_size)) == NULL) {
        return TSK_ERR;
    }

    size = roundup(fs_dir->fs_file->meta->size, a_fs->block_size);
    TSK_OFF_T offset = 0;

    while ((int64_t) size > 0) {
        int len =
            (a_fs->block_size < size) ? a_fs->block_size : (int) size;

        int cnt = tsk_fs_file_read(fs_dir->fs_file, offset, dirbuf, len, (TSK_FS_FILE_READ_FLAG_ENUM)0);
        if (cnt != len) {
            printf("  Failed - read 0x%x bytes\n", cnt);
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_FWALK);
            tsk_error_set_errstr
            ("ext2fs_dir_open_meta: Error reading directory contents: %"
                PRIuINUM "\n", a_addr);
            free(dirbuf);
            return TSK_COR;
        }

        retval_tmp =
            ext2fs_dent_parse_block(ext2fs, fs_dir,
            (fs_dir->fs_file->meta->
                flags & TSK_FS_META_FLAG_UNALLOC) ? 1 : 0, &list_seen,
            dirbuf, len);

        if (retval_tmp == TSK_ERR) {
            retval_final = TSK_ERR;
            break;
        }
        else if (retval_tmp == TSK_COR) {
            retval_final = TSK_COR;
        }

        size -= len;
        offset += len;
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
