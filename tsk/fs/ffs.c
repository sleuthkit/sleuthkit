/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002-2003 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/* TCT
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

/**
 * \file ffs.c
 * Contains the internal TSK UFS / FFS file system functions
 */

#include "tsk_fs_i.h"
#include "tsk_ffs.h"



/* ffs_group_load - load cylinder group descriptor info into cache
 *
 * Note: This routine assumes &ffs->lock is locked by the caller.
 *
 * return 1 on error and 0 on success
 * */
static uint8_t
ffs_group_load(FFS_INFO * ffs, FFS_GRPNUM_T grp_num)
{
    TSK_DADDR_T addr;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check
     */
    if (grp_num < 0 || grp_num >= ffs->groups_count) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr
            ("ffs_group_load: invalid cylinder group number: %" PRI_FFSGRP
            "", grp_num);
        return 1;
    }

    /*
     * Allocate/read cylinder group info on the fly. Trust that a cylinder
     * group always fits within a logical disk block (as promised in the
     * 4.4BSD <ufs/ffs/fs.h> include file).
     */
    if (ffs->grp_buf == NULL) {
        if ((ffs->grp_buf = tsk_malloc(ffs->ffsbsize_b)) == NULL) {
            return 1;
        }
    }

    addr = cgtod_lcl(fs, ffs->fs.sb1, grp_num);
    if (ffs->grp_addr != addr) {
        ffs_cgd *cg;
        ssize_t cnt;
        cnt = tsk_fs_read_block(fs, addr, ffs->grp_buf, ffs->ffsbsize_b);
        if (cnt != ffs->ffsbsize_b) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("ffs_group_load: Group %" PRI_FFSGRP
                " at %" PRIuDADDR, grp_num, addr);
            return 1;
        }
        ffs->grp_addr = addr;

        /* Perform a sanity check on the data to make sure offsets are in range */
        cg = (ffs_cgd *) ffs->grp_buf;
        if ((tsk_gets32(fs->endian, cg->cg_iusedoff) > ffs->ffsbsize_b)
            || (tsk_gets32(fs->endian, cg->cg_freeoff) > ffs->ffsbsize_b)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_CORRUPT);
            tsk_error_set_errstr2("ffs_group_load: Group %" PRI_FFSGRP
                " descriptor offsets too large at %" PRIuDADDR, grp_num,
                addr);
            return 1;
        }
    }

    ffs->grp_num = grp_num;
    return 0;
}


/*
 * ffs_dinode_load - read disk inode and load the data into ffs_inode structure
 *
 * Return 0 on success and 1 on error
 */
static uint8_t
ffs_dinode_load(FFS_INFO * ffs, TSK_INUM_T inum, ffs_inode * dino_buf)
{
    TSK_DADDR_T addr;
    TSK_OFF_T offs;
    TSK_FS_INFO *fs = (TSK_FS_INFO *) & ffs->fs_info;

    /*
     * Sanity check.
     * Use last_num-1 to account for virtual Orphan directory in last_inum.
     */
    if (inum < fs->first_inum || inum > fs->last_inum - 1) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_INODE_NUM);
        tsk_error_set_errstr("ffs_dinode_load: address: %" PRIuINUM, inum);
        return 1;
    }

    /*
     * Allocate/read the inode table buffer on the fly.
     */

    /* lock access to itbl_buf */
    tsk_take_lock(&ffs->lock);

    if (ffs->itbl_buf == NULL) {
        if ((ffs->itbl_buf = tsk_malloc(ffs->ffsbsize_b)) == NULL) {
            tsk_release_lock(&ffs->lock);
            return 1;
        }
    }


    /* UFS2 is different because it does not initialize all inodes
     * when the file system is created.  Therefore we need to check
     * the group descriptor to find out if this is in the valid
     * range
     */
    if (fs->ftype == TSK_FS_TYPE_FFS2) {
        ffs_cgd2 *cg2;
        FFS_GRPNUM_T grp_num;

        if (dino_buf == NULL) {
            tsk_release_lock(&ffs->lock);
            return 1;
        }

        /* Lookup the cylinder group descriptor if it isn't
         * cached
         */
        grp_num = (FFS_GRPNUM_T) itog_lcl(fs, ffs->fs.sb1, inum);
        if (ffs_group_load(ffs, grp_num)) {
            tsk_release_lock(&ffs->lock);
            return 1;
        }

        cg2 = (ffs_cgd2 *) ffs->grp_buf;

        /* If the inode is not init, then do not worry about it */
        if ((inum - grp_num * tsk_getu32(fs->endian,
                    ffs->fs.sb2->cg_inode_num)) >= tsk_getu32(fs->endian,
                cg2->cg_initediblk)) {
            memset((char *) dino_buf, 0, sizeof(ffs_inode2));
        }

        else {
            ssize_t cnt;
            /* Get the base and offset addr for the inode in the tbl */
            addr = itod_lcl(fs, ffs->fs.sb1, inum);

            if (ffs->itbl_addr != addr) {
                cnt = tsk_fs_read_block
                    (fs, addr, ffs->itbl_buf, ffs->ffsbsize_b);
                if (cnt != ffs->ffsbsize_b) {
                    tsk_release_lock(&ffs->lock);
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("ffs_dinode_load: FFS2 inode table at %"
                        PRIuDADDR, addr);
                    return 1;
                }
                ffs->itbl_addr = addr;
            }

            offs = itoo_lcl(fs, ffs->fs.sb2, inum) * sizeof(ffs_inode2);

            memcpy((char *) dino_buf, ffs->itbl_buf + offs,
                sizeof(ffs_inode2));
        }
    }
    else {
        if (dino_buf == NULL) {
            tsk_release_lock(&ffs->lock);
            return 1;
        }

        addr = itod_lcl(fs, ffs->fs.sb1, inum);
        if (ffs->itbl_addr != addr) {
            ssize_t cnt;
            cnt =
                tsk_fs_read_block(fs, addr, ffs->itbl_buf,
                ffs->ffsbsize_b);
            if (cnt != ffs->ffsbsize_b) {
                tsk_release_lock(&ffs->lock);
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("ffs_dinode_load: FFS1 inode table at %" PRIuDADDR,
                    addr);
                return 1;
            }
            ffs->itbl_addr = addr;
        }

        offs = itoo_lcl(fs, ffs->fs.sb1, inum) * sizeof(ffs_inode1);

        memcpy((char *) dino_buf, ffs->itbl_buf + offs,
            sizeof(ffs_inode1));
    }

    tsk_release_lock(&ffs->lock);

    return 0;
}


static TSK_FS_META_TYPE_ENUM
ffsmode2tsktype(uint16_t a_mode)
{
    switch (a_mode & FFS_IN_FMT) {
    case FFS_IN_REG:
        return TSK_FS_META_TYPE_REG;
    case FFS_IN_DIR:
        return TSK_FS_META_TYPE_DIR;
    case FFS_IN_SOCK:
        return TSK_FS_META_TYPE_SOCK;
    case FFS_IN_LNK:
        return TSK_FS_META_TYPE_LNK;
    case FFS_IN_BLK:
        return TSK_FS_META_TYPE_BLK;
    case FFS_IN_CHR:
        return TSK_FS_META_TYPE_CHR;
    case FFS_IN_FIFO:
        return TSK_FS_META_TYPE_FIFO;
    case FFS_IN_SHAD:
        return TSK_FS_META_TYPE_SHAD;
    case FFS_IN_WHT:
        return TSK_FS_META_TYPE_WHT;
    default:
        return TSK_FS_META_TYPE_UNDEF;
    }
}

static uint16_t
ffsmode2tskmode(uint16_t a_mode)
{
    uint16_t mode = 0;

    if (a_mode & FFS_IN_ISUID)
        mode |= TSK_FS_META_MODE_ISUID;
    if (a_mode & FFS_IN_ISGID)
        mode |= TSK_FS_META_MODE_ISGID;
    if (a_mode & FFS_IN_ISVTX)
        mode |= TSK_FS_META_MODE_ISVTX;

    if (a_mode & FFS_IN_IRUSR)
        mode |= TSK_FS_META_MODE_IRUSR;
    if (a_mode & FFS_IN_IWUSR)
        mode |= TSK_FS_META_MODE_IWUSR;
    if (a_mode & FFS_IN_IXUSR)
        mode |= TSK_FS_META_MODE_IXUSR;

    if (a_mode & FFS_IN_IRGRP)
        mode |= TSK_FS_META_MODE_IRGRP;
    if (a_mode & FFS_IN_IWGRP)
        mode |= TSK_FS_META_MODE_IWGRP;
    if (a_mode & FFS_IN_IXGRP)
        mode |= TSK_FS_META_MODE_IXGRP;

    if (a_mode & FFS_IN_IROTH)
        mode |= TSK_FS_META_MODE_IROTH;
    if (a_mode & FFS_IN_IWOTH)
        mode |= TSK_FS_META_MODE_IWOTH;
    if (a_mode & FFS_IN_IXOTH)
        mode |= TSK_FS_META_MODE_IXOTH;

    return mode;
}

/* ffs_dinode_copy - copy cached disk inode to generic inode
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
ffs_dinode_copy(FFS_INFO * ffs, TSK_FS_META * fs_meta,
    TSK_INUM_T dino_inum, const ffs_inode * dino_buf)
{
    int i, j;
    unsigned int count;
    TSK_FS_INFO *fs = &(ffs->fs_info);
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg;
    unsigned char *inosused = NULL;
    TSK_INUM_T ibase;

    if (dino_buf == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ffs_dinode_copy: dino_buf is NULL");
        return 1;
    }

    fs_meta->attr_state = TSK_FS_META_ATTR_EMPTY;
    if (fs_meta->attr) {
        tsk_fs_attrlist_markunused(fs_meta->attr);
    }

    fs_meta->flags = 0;
    fs_meta->seq = 0;

    /* If the symlink field is set from a previous run, then free it */
    if (fs_meta->link) {
        free(fs_meta->link);
        fs_meta->link = NULL;
    }

    fs_meta->addr = dino_inum;

    /* OpenBSD and FreeBSD style */
    if (fs->ftype == TSK_FS_TYPE_FFS1) {
        ffs_inode1 *in = (ffs_inode1 *) dino_buf;
        TSK_DADDR_T *addr_ptr;

        fs_meta->mode =
            ffsmode2tskmode(tsk_getu16(fs->endian, in->di_mode));
        fs_meta->type =
            ffsmode2tsktype(tsk_getu16(fs->endian, in->di_mode));

        fs_meta->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_meta->size = tsk_getu64(fs->endian, in->di_size);
        fs_meta->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_meta->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_meta->mtime = tsk_gets32(fs->endian, in->di_mtime);
        fs_meta->atime = tsk_gets32(fs->endian, in->di_atime);
        fs_meta->ctime = tsk_gets32(fs->endian, in->di_ctime);
        fs_meta->crtime = 0;
        fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
            fs_meta->crtime_nano = 0;

        if (fs_meta->content_len < FFS_FILE_CONTENT_LEN) {
            if ((fs_meta =
                    tsk_fs_meta_realloc(fs_meta,
                        FFS_FILE_CONTENT_LEN)) == NULL) {
                return 1;
            }
        }
        addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

        for (i = 0; i < FFS_NDADDR; i++)
            addr_ptr[i] = tsk_gets32(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            addr_ptr[FFS_NDADDR + i] =
                tsk_gets32(fs->endian, in->di_ib[i]);


        /* set the link string (if the file is a link)
         * The size check is a sanity check so that we don't try and allocate
         * a huge amount of memory for a bad inode value
         */
        if ((fs_meta->type == TSK_FS_META_TYPE_LNK)
            && (fs_meta->size < FFS_MAXPATHLEN)
            && (fs_meta->size >= 0)) {
            int i;

            fs_meta->link = tsk_malloc((size_t) fs_meta->size + 1);
            if (fs_meta->link == NULL) {
                return 1;
            }

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers   */
            if (fs_meta->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 4 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 4 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                fs_meta->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                memset(fs_meta->content_ptr, 0, fs_meta->content_len);
            }

            /* it is in blocks (the regular way) */
            else {
                char *buf;
                char *ptr = fs_meta->link;

                if ((buf = (char *)
                        tsk_malloc(fs->block_size)) == NULL) {
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ssize_t cnt;
                    TSK_DADDR_T *addr_ptr =
                        (TSK_DADDR_T *) fs_meta->content_ptr;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_meta->size - count <
                        fs->block_size) ? (int) fs_meta->size -
                        count : fs->block_size;

                    cnt =
                        tsk_fs_read_block(fs, addr_ptr[i],
                        buf, fs->block_size);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_FS_READ);
                        }
                        tsk_error_set_errstr2
                            ("ffs_dinode_copy: FFS1A symlink dest at %"
                            PRIuDADDR, addr_ptr[i]);
                        free(buf);
                        return 1;
                    }

                    memcpy(ptr, buf, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }
                /* terminate the string */
                *ptr = '\0';

                /* Clean up name */
                i = 0;
                while (fs_meta->link[i] != '\0') {
                    if (TSK_IS_CNTRL(fs_meta->link[i]))
                        fs_meta->link[i] = '^';
                    i++;
                }

                free(buf);
            }
        }                       /* end of symlink */
    }
    /* TSK_FS_TYPE_FFS1B - Solaris */
    else if (fs->ftype == TSK_FS_TYPE_FFS1B) {
        ffs_inode1b *in = (ffs_inode1b *) dino_buf;
        TSK_DADDR_T *addr_ptr;

        fs_meta->mode =
            ffsmode2tskmode(tsk_getu16(fs->endian, in->di_mode));
        fs_meta->type =
            ffsmode2tsktype(tsk_getu16(fs->endian, in->di_mode));

        fs_meta->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_meta->size = tsk_getu64(fs->endian, in->di_size);
        fs_meta->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_meta->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_meta->mtime = tsk_gets32(fs->endian, in->di_mtime);
        fs_meta->atime = tsk_gets32(fs->endian, in->di_atime);
        fs_meta->ctime = tsk_gets32(fs->endian, in->di_ctime);
        fs_meta->crtime = 0;
        fs_meta->mtime_nano = fs_meta->atime_nano = fs_meta->ctime_nano =
            fs_meta->crtime_nano = 0;

        if (fs_meta->content_len < FFS_FILE_CONTENT_LEN) {
            if ((fs_meta =
                    tsk_fs_meta_realloc(fs_meta,
                        FFS_FILE_CONTENT_LEN)) == NULL) {
                return 1;
            }
        }
        addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

        for (i = 0; i < FFS_NDADDR; i++)
            addr_ptr[i] = tsk_gets32(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            addr_ptr[FFS_NDADDR + i] =
                tsk_gets32(fs->endian, in->di_ib[i]);

        if ((fs_meta->type == TSK_FS_META_TYPE_LNK)
            && (fs_meta->size < FFS_MAXPATHLEN)
            && (fs_meta->size >= 0)) {

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers   */
            if (fs_meta->size < 4 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 4 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 4 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                fs_meta->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                memset(fs_meta->content_ptr, 0, fs_meta->content_len);
            }

            /* it is in blocks (the regular way) */
            else {
                char *buf;
                char *ptr;

                if ((buf = (char *)
                        tsk_malloc(fs->block_size)) == NULL)
                    return 1;

                fs_meta->link = ptr =
                    tsk_malloc((size_t) fs_meta->size + 1);
                if (fs_meta->link == NULL) {
                    free(buf);
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ssize_t cnt;
                    TSK_DADDR_T *addr_ptr =
                        (TSK_DADDR_T *) fs_meta->content_ptr;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_meta->size - count <
                        fs->block_size) ? (int) fs_meta->size -
                        count : fs->block_size;

                    cnt =
                        tsk_fs_read_block(fs, addr_ptr[i],
                        buf, fs->block_size);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_FS_READ);
                        }
                        tsk_error_set_errstr2
                            ("ffs_dinode_copy: FFS1B symlink dest at %"
                            PRIuDADDR, addr_ptr[i]);
                        free(buf);
                        return 1;
                    }

                    memcpy(ptr, buf, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }

                /* terminate the string */
                *ptr = '\0';

                free(buf);
            }
        }
    }
    else if (fs->ftype == TSK_FS_TYPE_FFS2) {
        ffs_inode2 *in = (ffs_inode2 *) dino_buf;
        TSK_DADDR_T *addr_ptr;

        fs_meta->mode =
            ffsmode2tskmode(tsk_getu16(fs->endian, in->di_mode));
        fs_meta->type =
            ffsmode2tsktype(tsk_getu16(fs->endian, in->di_mode));

        fs_meta->nlink = tsk_gets16(fs->endian, in->di_nlink);
        fs_meta->size = tsk_getu64(fs->endian, in->di_size);
        fs_meta->uid = tsk_getu32(fs->endian, in->di_uid);
        fs_meta->gid = tsk_getu32(fs->endian, in->di_gid);

        fs_meta->mtime = (time_t) tsk_gets64(fs->endian, in->di_mtime);
        fs_meta->atime = (time_t) tsk_gets64(fs->endian, in->di_atime);
        fs_meta->ctime = (time_t) tsk_gets64(fs->endian, in->di_ctime);
        fs_meta->crtime = 0;
        fs_meta->mtime_nano = tsk_getu32(fs->endian, in->di_mtimensec);
        fs_meta->atime_nano = tsk_getu32(fs->endian, in->di_atimensec);
        fs_meta->ctime_nano = tsk_getu32(fs->endian, in->di_ctimensec);
        fs_meta->crtime_nano = tsk_getu32(fs->endian, in->di_crtimensec);

        if (fs_meta->content_len < FFS_FILE_CONTENT_LEN) {
            if ((fs_meta =
                    tsk_fs_meta_realloc(fs_meta,
                        FFS_FILE_CONTENT_LEN)) == NULL) {
                return 1;
            }
        }
        addr_ptr = (TSK_DADDR_T *) fs_meta->content_ptr;

        for (i = 0; i < FFS_NDADDR; i++)
            addr_ptr[i] = tsk_gets64(fs->endian, in->di_db[i]);

        for (i = 0; i < FFS_NIADDR; i++)
            addr_ptr[FFS_NDADDR + i] =
                tsk_gets64(fs->endian, in->di_ib[i]);


        /* set the link string (if the file is a link)
         * The size check is a sanity check so that we don't try and allocate
         * a huge amount of memory for a bad inode value
         */
        if ((fs_meta->type == TSK_FS_META_TYPE_LNK)
            && (fs_meta->size < FFS_MAXPATHLEN)
            && (fs_meta->size >= 0)) {

            fs_meta->link = tsk_malloc((size_t) fs_meta->size + 1);
            if (fs_meta->link == NULL) {
                return 1;
            }

            count = 0;          /* index into the link array */

            /* it is located directly in the pointers
             * Only the new style inode has this "fast link"
             */
            if (fs_meta->size < 8 * (FFS_NDADDR + FFS_NIADDR)) {
                char *ptr;

                /* Direct block pointer locations */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_db[i];
                    for (j = 0; j < 8 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                /* indirect block pointers */
                for (i = 0; i < FFS_NIADDR && count < fs_meta->size; i++) {
                    ptr = (char *) &in->di_ib[i];
                    for (j = 0; j < 8 && count < fs_meta->size; j++)
                        fs_meta->link[count++] = ptr[j];
                }

                fs_meta->link[count] = '\0';

                /* clear the values to avoid other code from reading them */
                memset(fs_meta->content_ptr, 0, fs_meta->content_len);
            }

            /* it is in blocks (the regular way) */
            else {
                char *buf;
                char *ptr = fs_meta->link;

                if ((buf = (char *)
                        tsk_malloc(fs->block_size)) == NULL) {
                    return 1;
                }

                /* there is a max link length of 1000, so we should never
                 * need the indirect blocks
                 */
                for (i = 0; i < FFS_NDADDR && count < fs_meta->size; i++) {
                    ssize_t cnt;
                    TSK_DADDR_T *addr_ptr = fs_meta->content_ptr;

                    /* Do we need the entire block, or just part of it? */
                    int read_count =
                        (fs_meta->size - count <
                        fs->block_size) ? (int) fs_meta->size -
                        count : fs->block_size;

                    cnt = tsk_fs_read_block(fs,
                        addr_ptr[i], buf, fs->block_size);
                    if (cnt != fs->block_size) {
                        if (cnt >= 0) {
                            tsk_error_reset();
                            tsk_error_set_errno(TSK_ERR_FS_READ);
                        }
                        tsk_error_set_errstr2
                            ("ffs_dinode_copy: FFS2 symlink dest at %"
                            PRIuDADDR, addr_ptr[i]);
                        free(buf);
                        return 1;
                    }

                    memcpy(ptr, buf, read_count);
                    count += read_count;
                    ptr = (char *) ((uintptr_t) ptr + read_count);
                }
                /* terminate the string */
                *ptr = '\0';

                free(buf);
            }
        }                       /* end of symlink */
    }
    else {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ffs_dinode_copy: Unknown FFS Type");
        return 1;
    }

    /* set the flags */
    grp_num = (FFS_GRPNUM_T) itog_lcl(fs, ffs->fs.sb1, dino_inum);

    tsk_take_lock(&ffs->lock);
    if (ffs_group_load(ffs, grp_num)) {
        tsk_release_lock(&ffs->lock);
        return 1;
    }

    cg = (ffs_cgd *) ffs->grp_buf;

    inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
    ibase = grp_num * tsk_gets32(fs->endian, ffs->fs.sb1->cg_inode_num);

    /* get the alloc flag */
    fs_meta->flags = (isset(inosused, dino_inum - ibase) ?
        TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC);

    tsk_release_lock(&ffs->lock);

    /* used/unused */
    fs_meta->flags |= (fs_meta->ctime ?
        TSK_FS_META_FLAG_USED : TSK_FS_META_FLAG_UNUSED);

    return 0;
}




/* ffs_inode_lookup - lookup inode, external interface
 *
 * Return 1 on error
 *
 * */
static uint8_t
ffs_inode_lookup(TSK_FS_INFO * fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    ffs_inode *dino_buf;
    FFS_INFO *ffs = (FFS_INFO *) fs;

    if (a_fs_file == NULL) {
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("ffs_inode_lookup: fs_file is NULL");
        return 1;
    }

    /* copy it to the TSK_FS_META structure */
    if (a_fs_file->meta == NULL) {
        a_fs_file->meta = tsk_fs_meta_alloc(FFS_FILE_CONTENT_LEN);
        if (a_fs_file->meta == NULL)
            return 1;
    }
    else {
        tsk_fs_meta_reset(a_fs_file->meta);
    }

    // see if they are looking for the special "orphans" directory
    if (inum == TSK_FS_ORPHANDIR_INUM(fs)) {
        if (tsk_fs_dir_make_orphan_dir_meta(fs, a_fs_file->meta))
            return 1;
        else
            return 0;
    }

    /* Lookup the inode and store it in ffs */
    if ((dino_buf = (ffs_inode *) tsk_malloc(sizeof(ffs_inode2))) == NULL)
        return 1;

    if (ffs_dinode_load(ffs, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    if (ffs_dinode_copy(ffs, a_fs_file->meta, inum, dino_buf)) {
        free(dino_buf);
        return 1;
    }

    free(dino_buf);

    return 0;
}



/**************************************************************************
 *
 * INODE WALKING
 *
 **************************************************************************/



/* ffs_inode_walk - inode iterator
 *
 * flags used: TSK_FS_META_FLAG_USED, TSK_FS_META_FLAG_UNUSED,
 *  TSK_FS_META_FLAG_ALLOC, TSK_FS_META_FLAG_UNALLOC, TSK_FS_META_FLAG_ORPHAN
 *
 *  return 1 on error and 0 on success
 */
uint8_t
ffs_inode_walk(TSK_FS_INFO * fs, TSK_INUM_T start_inum,
    TSK_INUM_T end_inum, TSK_FS_META_FLAG_ENUM a_flags,
    TSK_FS_META_WALK_CB action, void *ptr)
{
    char *myname = "ffs_inode_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = NULL;
    TSK_INUM_T inum;
    unsigned char *inosused = NULL;
    TSK_FS_FILE *fs_file;
    int myflags;
    TSK_INUM_T ibase = 0;
    TSK_INUM_T end_inum_tmp;
    ffs_inode *dino_buf;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (start_inum < fs->first_inum || start_inum > fs->last_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start inode: %" PRIuINUM "", myname,
            start_inum);
        return 1;
    }
    else if (end_inum < fs->first_inum || end_inum > fs->last_inum
        || end_inum < start_inum) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End inode: %" PRIuINUM "", myname,
            end_inum);
        return 1;
    }

    /* If ORPHAN is wanted, then make sure that the flags are correct */
    if (a_flags & TSK_FS_META_FLAG_ORPHAN) {
        a_flags |= TSK_FS_META_FLAG_UNALLOC;
        a_flags &= ~TSK_FS_META_FLAG_ALLOC;
        a_flags |= TSK_FS_META_FLAG_USED;
        a_flags &= ~TSK_FS_META_FLAG_UNUSED;
    }
    else {
        if (((a_flags & TSK_FS_META_FLAG_ALLOC) == 0) &&
            ((a_flags & TSK_FS_META_FLAG_UNALLOC) == 0)) {
            a_flags |= (TSK_FS_META_FLAG_ALLOC | TSK_FS_META_FLAG_UNALLOC);
        }

        /* If neither of the USED or UNUSED flags are set, then set them
         * both
         */
        if (((a_flags & TSK_FS_META_FLAG_USED) == 0) &&
            ((a_flags & TSK_FS_META_FLAG_UNUSED) == 0)) {
            a_flags |= (TSK_FS_META_FLAG_USED | TSK_FS_META_FLAG_UNUSED);
        }
    }



    /* If we are looking for orphan files and have not yet filled
     * in the list of unalloc inodes that are pointed to, then fill
     * in the list
     * */
    if ((a_flags & TSK_FS_META_FLAG_ORPHAN)) {
        if (tsk_fs_dir_load_inum_named(fs) != TSK_OK) {
            tsk_error_errstr2_concat
                ("- ffs_inode_walk: identifying inodes allocated by file names");
            return 1;
        }
    }

    if ((fs_file = tsk_fs_file_alloc(fs)) == NULL)
        return 1;

    if ((fs_file->meta = tsk_fs_meta_alloc(FFS_FILE_CONTENT_LEN)) == NULL)
        return 1;

    // we need to handle fs->last_inum specially because it is for the
    // virtual ORPHANS directory.  Handle it outside of the loop.
    if (end_inum == TSK_FS_ORPHANDIR_INUM(fs))
        end_inum_tmp = end_inum - 1;
    else
        end_inum_tmp = end_inum;

    if ((dino_buf = (ffs_inode *) tsk_malloc(sizeof(ffs_inode2))) == NULL)
        return 1;

    /*
     * Iterate. This is easy because inode numbers are contiguous, unlike
     * data blocks which are interleaved with cylinder group blocks.
     */
    for (inum = start_inum; inum <= end_inum_tmp; inum++) {
        int retval;

        /*
         * Be sure to use the proper cylinder group data.
         */
        grp_num = itog_lcl(fs, ffs->fs.sb1, inum);

        tsk_take_lock(&ffs->lock);
        if (ffs_group_load(ffs, grp_num)) {
            tsk_release_lock(&ffs->lock);
            free(dino_buf);
            return 1;
        }
        cg = (ffs_cgd *) ffs->grp_buf;
        inosused = (unsigned char *) cg_inosused_lcl(fs, cg);
        ibase =
            grp_num * tsk_gets32(fs->endian, ffs->fs.sb1->cg_inode_num);

        /*
         * Apply the allocated/unallocated restriction.
         */
        myflags = (isset(inosused, inum - ibase) ?
            TSK_FS_META_FLAG_ALLOC : TSK_FS_META_FLAG_UNALLOC);

        tsk_release_lock(&ffs->lock);

        if ((a_flags & myflags) != myflags)
            continue;


        if (ffs_dinode_load(ffs, inum, dino_buf)) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }


        if ((fs->ftype == TSK_FS_TYPE_FFS1)
            || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
            /* both inode forms are the same for the required fields */
            ffs_inode1 *in1 = (ffs_inode1 *) dino_buf;

            /*
             * Apply the used/unused restriction.
             */
            myflags |= (tsk_gets32(fs->endian, in1->di_ctime) ?
                TSK_FS_META_FLAG_USED : TSK_FS_META_FLAG_UNUSED);
            if ((a_flags & myflags) != myflags)
                continue;
        }
        else {
            ffs_inode2 *in2 = (ffs_inode2 *) dino_buf;

            /*
             * Apply the used/unused restriction.
             */
            myflags |= (tsk_gets64(fs->endian, in2->di_ctime) ?
                TSK_FS_META_FLAG_USED : TSK_FS_META_FLAG_UNUSED);
            if ((a_flags & myflags) != myflags)
                continue;
        }

        /* If we want only orphans, then check if this
         * inode is in the seen list
         */
        if ((myflags & TSK_FS_META_FLAG_UNALLOC) &&
            (a_flags & TSK_FS_META_FLAG_ORPHAN) &&
            (tsk_fs_dir_find_inum_named(fs, inum))) {
            continue;
        }


        /*
         * Fill in a file system-independent inode structure and pass control
         * to the application.
         */
        if (ffs_dinode_copy(ffs, fs_file->meta, inum, dino_buf)) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }

        retval = action(fs_file, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }
    }

    // handle the virtual orphans folder if they asked for it
    if ((end_inum == TSK_FS_ORPHANDIR_INUM(fs))
        && (a_flags & TSK_FS_META_FLAG_ALLOC)
        && (a_flags & TSK_FS_META_FLAG_USED)) {
        int retval;

        if (tsk_fs_dir_make_orphan_dir_meta(fs, fs_file->meta)) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }
        /* call action */
        retval = action(fs_file, ptr);
        if (retval == TSK_WALK_STOP) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 0;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_file_close(fs_file);
            free(dino_buf);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_file_close(fs_file);
    free(dino_buf);

    return 0;
}


TSK_FS_BLOCK_FLAG_ENUM
ffs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    FFS_INFO *ffs = (FFS_INFO *) a_fs;
    FFS_GRPNUM_T grp_num;
    ffs_cgd *cg = 0;
    TSK_DADDR_T frag_base = 0;
    TSK_DADDR_T dblock_addr = 0;        /* first data block in group */
    TSK_DADDR_T sblock_addr = 0;        /* super block in group */
    unsigned char *freeblocks = NULL;
    int flags;

    // sparse
    if (a_addr == 0)
        return TSK_FS_BLOCK_FLAG_CONT | TSK_FS_BLOCK_FLAG_ALLOC;

    grp_num = dtog_lcl(a_fs, ffs->fs.sb1, a_addr);

    tsk_take_lock(&ffs->lock);
    if (ffs_group_load(ffs, grp_num)) {
        tsk_release_lock(&ffs->lock);
        return 0;
    }

    cg = (ffs_cgd *) ffs->grp_buf;
    freeblocks = (unsigned char *) cg_blksfree_lcl(a_fs, cg);

    // get the base fragment for the group
    frag_base = cgbase_lcl(a_fs, ffs->fs.sb1, grp_num);

    // address of first data block in group
    dblock_addr = cgdmin_lcl(a_fs, ffs->fs.sb1, grp_num);

    // address of super block in group
    sblock_addr = cgsblock_lcl(a_fs, ffs->fs.sb1, grp_num);

    /* get the flags for this fragment
     *
     * Beware: FFS stores file data in the blocks between the start of a
     * cylinder group and the start of its super block.
     */
    flags = (isset(freeblocks, a_addr - frag_base) ?
        TSK_FS_BLOCK_FLAG_UNALLOC : TSK_FS_BLOCK_FLAG_ALLOC);

    tsk_release_lock(&ffs->lock);

    if (a_addr >= sblock_addr && a_addr < dblock_addr)
        flags |= TSK_FS_BLOCK_FLAG_META;
    else
        flags |= TSK_FS_BLOCK_FLAG_CONT;

    return flags;
}

/**************************************************************************
 *
 * BLOCK WALKING
 *
 **************************************************************************/

/* ffs_block_walk - block iterator
 *
 * flags: TSK_FS_BLOCK_FLAG_ALLOC, TSK_FS_BLOCK_FLAG_UNALLOC, TSK_FS_BLOCK_FLAG_CONT,
 *  TSK_FS_BLOCK_FLAG_META
 *
 *  return 1 on error and 0 on success
 */

uint8_t
ffs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB action, void *ptr)
{
    char *myname = "ffs_block_walk";
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    char *cache_blk_buf;        // buffer used for local read cache
    TSK_DADDR_T cache_addr;     // base address in local cache
    int cache_len_f;            // amount of data read into cache (in fragments)

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks on input bounds
     */
    if (a_start_blk < fs->first_block || a_start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: Start block: %" PRIuDADDR "", myname,
            a_start_blk);
        return 1;
    }

    if (a_end_blk < fs->first_block || a_end_blk > fs->last_block
        || a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("%s: End block: %" PRIuDADDR "", myname,
            a_end_blk);
        return 1;
    }

    /* Sanity check on flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_META) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_CONT | TSK_FS_BLOCK_WALK_FLAG_META);
    }


    /* Other initialization */
    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }
    if ((cache_blk_buf = tsk_malloc(ffs->ffsbsize_b)) == NULL) {
        return 1;
    }
    cache_len_f = 0;
    cache_addr = 0;

    /* Cycle through the fragment range requested */
    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;
        size_t cache_offset = 0;
        int myflags = ffs_block_getflags(fs, addr);

        if ((tsk_verbose) && (myflags & TSK_FS_BLOCK_FLAG_META)
            && (myflags & TSK_FS_BLOCK_FLAG_UNALLOC))
            tsk_fprintf(stderr,
                "impossible: unallocated meta block %" PRIuDADDR, addr);

        // test if we should call the callback with this one
        if ((myflags & TSK_FS_BLOCK_FLAG_META)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_META)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_CONT)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_CONT)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_ALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC)))
            continue;
        else if ((myflags & TSK_FS_BLOCK_FLAG_UNALLOC)
            && (!(a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC)))
            continue;


        if ((a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY) == 0) {
            /* we read in block-sized chunks and cache the result for later
             * calls.  See if this fragment is in our cache */
            if ((cache_len_f == 0) || (addr >= cache_addr + cache_len_f)) {
                ssize_t cnt;
                int frags;

                /* Ideally, we want to read in block sized chunks, verify we can do that */
                frags = (a_end_blk > addr + ffs->ffsbsize_f - 1 ?
                    ffs->ffsbsize_f : (int) (a_end_blk + 1 - addr));

                cnt =
                    tsk_fs_read_block(fs, addr, cache_blk_buf,
                    fs->block_size * frags);
                if (cnt != fs->block_size * frags) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2("ffs_block_walk: Block %"
                        PRIuDADDR, addr);
                    tsk_fs_block_free(fs_block);
                    free(cache_blk_buf);
                    return 1;
                }
                cache_len_f = frags;
                cache_addr = addr;
            }
            cache_offset = (size_t) ((addr - cache_addr) * fs->block_size);
        }

        if (a_flags & TSK_FS_BLOCK_WALK_FLAG_AONLY)
            myflags |= TSK_FS_BLOCK_FLAG_AONLY;

        // call the callback
        tsk_fs_block_set(fs, fs_block, addr,
            myflags | TSK_FS_BLOCK_FLAG_RAW, &cache_blk_buf[cache_offset]);
        retval = action(fs_block, ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            free(cache_blk_buf);
            return 1;
        }
    }

    /* Cleanup */
    tsk_fs_block_free(fs_block);
    free(cache_blk_buf);
    return 0;
}



/*
 * return 1 on error and 0 on success
 */
static uint8_t
ffs_fscheck(TSK_FS_INFO * fs, FILE * hFile)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("fscheck not implemented for ffs yet");
    return 1;
}


/**
 * Print details about the file system to a file handle.
 *
 * @param fs File system to print details on
 * @param hFile File handle to print text to
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
ffs_fsstat(TSK_FS_INFO * fs, FILE * hFile)
{
    unsigned int i;
    time_t tmptime;
    ffs_csum1 *csum1 = NULL;
    ffs_cgd *cgd = NULL;

    FFS_INFO *ffs = (FFS_INFO *) fs;
    ffs_sb1 *sb1 = ffs->fs.sb1;
    ffs_sb2 *sb2 = ffs->fs.sb2;
    int flags;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    tsk_fprintf(hFile, "FILE SYSTEM INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    if ((fs->ftype == TSK_FS_TYPE_FFS1)
        || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
        tsk_fprintf(hFile, "File System Type: UFS 1\n");
        tmptime = tsk_getu32(fs->endian, sb1->wtime);
        tsk_fprintf(hFile, "Last Written: %s\n",
            (tmptime > 0) ? tsk_fs_time_to_str(tmptime,
                timeBuf) : "empty");
        tsk_fprintf(hFile, "Last Mount Point: %s\n", sb1->last_mnt);

        flags = sb1->fs_flags;
    }
    else {
        tsk_fprintf(hFile, "File System Type: UFS 2\n");
        tmptime = tsk_getu32(fs->endian, sb2->wtime);
        tsk_fprintf(hFile, "Last Written: %s\n",
            (tmptime > 0) ? tsk_fs_time_to_str(tmptime,
                timeBuf) : "empty");
        tsk_fprintf(hFile, "Last Mount Point: %s\n", sb2->last_mnt);
        tsk_fprintf(hFile, "Volume Name: %s\n", sb2->volname);
        tsk_fprintf(hFile, "System UID: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->swuid));
        flags = tsk_getu32(fs->endian, sb2->fs_flags);
    }

    if (flags) {
        int cnt = 0;

        tsk_fprintf(hFile, "Flags: ");

        if (flags & FFS_SB_FLAG_UNCLEAN)
            tsk_fprintf(hFile, "%s Unclean", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_SOFTDEP)
            tsk_fprintf(hFile, "%s Soft Dependencies",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_NEEDFSCK)
            tsk_fprintf(hFile, "%s Needs fsck", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_INDEXDIR)
            tsk_fprintf(hFile, "%s Index directories",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_ACL)
            tsk_fprintf(hFile, "%s ACLs", (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_MULTILABEL)
            tsk_fprintf(hFile, "%s TrustedBSD MAC Multi-label",
                (cnt++ == 0 ? "" : ","));

        if (flags & FFS_SB_FLAG_UPDATED)
            tsk_fprintf(hFile, "%s Updated Flag Location",
                (cnt++ == 0 ? "" : ","));

        tsk_fprintf(hFile, "\n");
    }



    tsk_fprintf(hFile, "\nMETADATA INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Inode Range: %" PRIuINUM " - %" PRIuINUM "\n",
        fs->first_inum, fs->last_inum);
    tsk_fprintf(hFile, "Root Directory: %" PRIuINUM "\n", fs->root_inum);
    if ((fs->ftype == TSK_FS_TYPE_FFS1)
        || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
        tsk_fprintf(hFile, "Num of Avail Inodes: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.ino_free));
        tsk_fprintf(hFile, "Num of Directories: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.dir_num));
    }
    else {
        tsk_fprintf(hFile, "Num of Avail Inodes: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.ino_free));
        tsk_fprintf(hFile, "Num of Directories: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.dir_num));
    }


    tsk_fprintf(hFile, "\nCONTENT INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
        fs->first_block, fs->last_block);

    if (fs->last_block != fs->last_block_act)
        tsk_fprintf(hFile,
            "Total Range in Image: %" PRIuDADDR " - %" PRIuDADDR "\n",
            fs->first_block, fs->last_block_act);

    tsk_fprintf(hFile, "Block Size: %u\n", ffs->ffsbsize_b);
    tsk_fprintf(hFile, "Fragment Size: %u\n", fs->block_size);

    if ((fs->ftype == TSK_FS_TYPE_FFS1)
        || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
        tsk_fprintf(hFile, "Num of Avail Full Blocks: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.blk_free));
        tsk_fprintf(hFile, "Num of Avail Fragments: %" PRIu32 "\n",
            tsk_getu32(fs->endian, sb1->cstotal.frag_free));
    }
    else {
        tsk_fprintf(hFile, "Num of Avail Full Blocks: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.blk_free));
        tsk_fprintf(hFile, "Num of Avail Fragments: %" PRIu64 "\n",
            tsk_getu64(fs->endian, sb2->cstotal.frag_free));
    }

    tsk_fprintf(hFile, "\nCYLINDER GROUP INFORMATION\n");
    tsk_fprintf(hFile, "--------------------------------------------\n");

    tsk_fprintf(hFile, "Number of Cylinder Groups: %" PRIu32 "\n",
        ffs->groups_count);
    tsk_fprintf(hFile, "Inodes per group: %" PRId32 "\n",
        tsk_gets32(fs->endian, sb1->cg_inode_num));
    tsk_fprintf(hFile, "Fragments per group: %" PRId32 "\n",
        tsk_gets32(fs->endian, sb1->cg_frag_num));


    /* UFS 1 and 2 use the same ssize field  and use the same csum1 */
    if (tsk_getu32(fs->endian, sb1->cg_ssize_b)) {
        ssize_t cnt;
        csum1 =
            (ffs_csum1 *) tsk_malloc(tsk_getu32(fs->endian,
                sb1->cg_ssize_b));
        if (csum1 == NULL)
            return 1;

        if ((fs->ftype == TSK_FS_TYPE_FFS1)
            || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
            cnt =
                tsk_fs_read_block(fs, (TSK_DADDR_T) tsk_getu32(fs->endian,
                    sb1->cg_saddr), (char *) csum1, tsk_getu32(fs->endian,
                    sb1->cg_ssize_b));

            if (cnt != tsk_getu32(fs->endian, sb1->cg_ssize_b)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("ffs_fsstat: FFS1 group descriptor at %" PRIu32,
                    tsk_getu32(fs->endian, sb1->cg_saddr));
                return 1;
            }
        }
        else {
            cnt = tsk_fs_read_block
                (fs, (TSK_DADDR_T) tsk_getu64(fs->endian,
                    sb2->cg_saddr), (char *) csum1, tsk_getu32(fs->endian,
                    sb2->cg_ssize_b));
            if (cnt != tsk_getu32(fs->endian, sb2->cg_ssize_b)) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2
                    ("ffs_fsstat: FFS2 group descriptor at %" PRIu64,
                    tsk_getu64(fs->endian, sb2->cg_saddr));
                return 1;
            }
        }
    }

    for (i = 0; i < ffs->groups_count; i++) {

        tsk_take_lock(&ffs->lock);
        if (ffs_group_load(ffs, i)) {
            tsk_release_lock(&ffs->lock);
            return 1;
        }
        cgd = (ffs_cgd *) ffs->grp_buf;

        tsk_fprintf(hFile, "\nGroup %d:\n", i);
        if (cgd) {
            if ((fs->ftype == TSK_FS_TYPE_FFS1)
                || (fs->ftype == TSK_FS_TYPE_FFS1B)) {
                tmptime = tsk_getu32(fs->endian, cgd->wtime);
            }
            else {
                ffs_cgd2 *cgd2 = (ffs_cgd2 *) cgd;
                tmptime = (uint32_t) tsk_getu64(fs->endian, cgd2->wtime);
            }
            tsk_fprintf(hFile, "  Last Written: %s\n",
                (tmptime > 0) ? tsk_fs_time_to_str(tmptime,
                    timeBuf) : "empty");
        }
        tsk_release_lock(&ffs->lock);

        tsk_fprintf(hFile, "  Inode Range: %" PRIu32 " - %" PRIu32 "\n",
            (tsk_gets32(fs->endian, sb1->cg_inode_num) * i),
            ((uint32_t) ((tsk_gets32(fs->endian,
                            sb1->cg_inode_num) * (i + 1)) - 1)
                < fs->last_inum) ? (uint32_t) ((tsk_gets32(fs->endian,
                        sb1->cg_inode_num) * (i + 1)) -
                1) : (uint32_t) fs->last_inum);

        tsk_fprintf(hFile,
            "  Fragment Range: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgbase_lcl(fs, sb1, i),
            ((cgbase_lcl(fs, sb1, i + 1) - 1) <
                fs->last_block) ? (cgbase_lcl(fs, sb1,
                    i + 1) - 1) : fs->last_block);

        /* The first group is special because the first 16 sectors are
         * reserved for the boot block.
         * the next contains the primary Super Block
         */
        if (!i) {
            tsk_fprintf(hFile, "    Boot Block: 0 - %" PRIu32 "\n",
                (uint32_t) (15 * 512 / fs->block_size));


            tsk_fprintf(hFile,
                "    Super Block: %" PRIu32 " - %" PRIu32 "\n",
                (uint32_t) (16 * 512 / fs->block_size),
                (uint32_t) ((16 * 512 / fs->block_size) + ffs->ffsbsize_f -
                    1));
        }

        tsk_fprintf(hFile,
            "    Super Block: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgsblock_lcl(fs, sb1, i),
            (cgsblock_lcl(fs, sb1, i) + ffs->ffsbsize_f - 1));


        tsk_fprintf(hFile,
            "    Group Desc: %" PRIuDADDR " - %" PRIuDADDR "\n",
            cgtod_lcl(fs, sb1, i), (cgtod_lcl(fs, sb1,
                    i) + ffs->ffsbsize_f - 1));


        if (fs->ftype == TSK_FS_TYPE_FFS2) {
            tsk_fprintf(hFile,
                "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
                cgimin_lcl(fs, sb1, i),
                (cgimin_lcl(fs, sb1, i) +
                    ((roundup
                            (tsk_gets32(fs->endian,
                                    sb1->cg_inode_num) *
                                sizeof(ffs_inode2), fs->block_size)
                            / fs->block_size) - 1)));
        }
        else {
            tsk_fprintf(hFile,
                "    Inode Table: %" PRIuDADDR " - %" PRIuDADDR "\n",
                cgimin_lcl(fs, sb1, i),
                (cgimin_lcl(fs, sb1, i) +
                    ((roundup
                            (tsk_gets32(fs->endian,
                                    sb1->cg_inode_num) *
                                sizeof(ffs_inode1), fs->block_size)
                            / fs->block_size) - 1)));
        }

        tsk_fprintf(hFile, "    Data Fragments: ");

        /* For all groups besides the first, the space before the
         * super block is also used for data
         */
        if (i)
            tsk_fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR ", ",
                cgbase_lcl(fs, sb1, i), cgsblock_lcl(fs, sb1, i) - 1);

        tsk_fprintf(hFile, "%" PRIuDADDR " - %" PRIuDADDR "\n",
            cgdmin_lcl(fs, sb1, i),
            ((cgbase_lcl(fs, sb1, i + 1) - 1) < fs->last_block) ?
            (cgbase_lcl(fs, sb1, i + 1) - 1) : fs->last_block);


        if ((csum1)
            && ((i + 1) * sizeof(ffs_csum1) < tsk_getu32(fs->endian,
                    sb1->cg_ssize_b))) {
            tsk_fprintf(hFile,
                "  Global Summary (from the superblock summary area):\n");
            tsk_fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].dir_num));
            tsk_fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].blk_free));
            tsk_fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].ino_free));
            tsk_fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &csum1[i].frag_free));
        }

        if (cgd) {
            tsk_fprintf(hFile,
                "  Local Summary (from the group descriptor):\n");
            tsk_fprintf(hFile, "    Num of Dirs: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.dir_num));
            tsk_fprintf(hFile, "    Num of Avail Blocks: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.blk_free));
            tsk_fprintf(hFile, "    Num of Avail Inodes: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.ino_free));
            tsk_fprintf(hFile, "    Num of Avail Frags: %" PRIu32 "\n",
                tsk_getu32(fs->endian, &cgd->cs.frag_free));
            tsk_fprintf(hFile,
                "    Last Block Allocated: %" PRIuDADDR "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_blk) + cgbase_lcl(fs, sb1, i));
            tsk_fprintf(hFile,
                "    Last Fragment Allocated: %" PRIuDADDR "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_frag) + cgbase_lcl(fs, sb1, i));
            tsk_fprintf(hFile, "    Last Inode Allocated: %" PRIu32 "\n",
                tsk_getu32(fs->endian,
                    &cgd->last_alloc_ino) + (tsk_gets32(fs->endian,
                        sb1->cg_inode_num) * i));
        }
    }
    return 0;
}



/************************* istat *******************************/

typedef struct {
    FILE *hFile;
    int idx;
} FFS_PRINT_ADDR;


static TSK_WALK_RET_ENUM
print_addr_act(TSK_FS_FILE * fs_file, TSK_OFF_T a_off, TSK_DADDR_T addr,
    char *buf, size_t size, TSK_FS_BLOCK_FLAG_ENUM a_flags, void *ptr)
{
    TSK_FS_INFO *fs = fs_file->fs_info;
    FFS_PRINT_ADDR *print = (FFS_PRINT_ADDR *) ptr;

    if (a_flags & TSK_FS_BLOCK_FLAG_CONT) {
        int i, s;
        /* cycle through the fragments if they exist */
        for (i = 0, s = (int) size; s > 0; s -= fs->block_size, i++) {

            /* sparse file */
            if (addr)
                tsk_fprintf(print->hFile, "%" PRIuDADDR " ", addr + i);
            else
                tsk_fprintf(print->hFile, "0 ");

            if (++(print->idx) == 8) {
                tsk_fprintf(print->hFile, "\n");
                print->idx = 0;
            }
        }
    }

    return TSK_WALK_CONT;
}



/**
 * Print details on a specific file to a file handle.
 *
 * @param fs File system file is located in
 * @param hFile File handle to print text to
 * @param inum Address of file in file system
 * @param numblock The number of blocks in file to force print (can go beyond file size)
 * @param sec_skew Clock skew in seconds to also print times in
 *
 * @returns 1 on error and 0 on success
 */
static uint8_t
ffs_istat(TSK_FS_INFO * fs, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;
    TSK_FS_META *fs_meta;
    TSK_FS_FILE *fs_file;
    char ls[12];
    FFS_PRINT_ADDR print;
    const TSK_FS_ATTR *fs_attr_indir;
    char *dino_buf;
    char timeBuf[128];

    // clean up any error messages that are lying around
    tsk_error_reset();

    if ((fs_file = tsk_fs_file_open_meta(fs, NULL, inum)) == NULL) {
        return 1;
    }
    fs_meta = fs_file->meta;

    tsk_fprintf(hFile, "inode: %" PRIuINUM "\n", inum);
    tsk_fprintf(hFile, "%sAllocated\n",
        (fs_meta->flags & TSK_FS_META_FLAG_ALLOC) ? "" : "Not ");

    tsk_take_lock(&ffs->lock);
    tsk_fprintf(hFile, "Group: %" PRI_FFSGRP "\n", ffs->grp_num);
    tsk_release_lock(&ffs->lock);

    if (fs_meta->link)
        tsk_fprintf(hFile, "symbolic link to: %s\n", fs_meta->link);

    tsk_fprintf(hFile, "uid / gid: %" PRIuUID " / %" PRIuGID "\n",
        fs_meta->uid, fs_meta->gid);


    tsk_fs_meta_make_ls(fs_meta, ls, sizeof(ls));
    tsk_fprintf(hFile, "mode: %s\n", ls);

    tsk_fprintf(hFile, "size: %" PRIuOFF "\n", fs_meta->size);
    tsk_fprintf(hFile, "num of links: %u\n", fs_meta->nlink);


    if (sec_skew != 0) {
        tsk_fprintf(hFile, "\nAdjusted Inode Times:\n");
        if (fs_meta->mtime)
            fs_meta->mtime -= sec_skew;
        if (fs_meta->atime)
            fs_meta->atime -= sec_skew;
        if (fs_meta->ctime)
            fs_meta->ctime -= sec_skew;

        tsk_fprintf(hFile, "Accessed:\t%s\n",
            tsk_fs_time_to_str(fs_meta->atime, timeBuf));
        tsk_fprintf(hFile, "File Modified:\t%s\n",
            tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
        tsk_fprintf(hFile, "Inode Modified:\t%s\n",
            tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

        if (fs_meta->mtime == 0)
            fs_meta->mtime += sec_skew;
        if (fs_meta->atime == 0)
            fs_meta->atime += sec_skew;
        if (fs_meta->ctime == 0)
            fs_meta->ctime += sec_skew;

        tsk_fprintf(hFile, "\nOriginal Inode Times:\n");
    }
    else {
        tsk_fprintf(hFile, "\nInode Times:\n");
    }

    tsk_fprintf(hFile, "Accessed:\t%s\n",
        tsk_fs_time_to_str(fs_meta->atime, timeBuf));
    tsk_fprintf(hFile, "File Modified:\t%s\n",
        tsk_fs_time_to_str(fs_meta->mtime, timeBuf));
    tsk_fprintf(hFile, "Inode Modified:\t%s\n",
        tsk_fs_time_to_str(fs_meta->ctime, timeBuf));

    if ((dino_buf = (char *) tsk_malloc(sizeof(ffs_inode2))) == NULL)
        return 1;
    // we won't have dino_buf for "virtual" files
    if ((fs->ftype == TSK_FS_TYPE_FFS2) && (dino_buf)) {
        ffs_inode2 *in = (ffs_inode2 *) dino_buf;
        /* Are there extended attributes */
        if (tsk_getu32(fs->endian, in->di_extsize) > 0) {
            ffs_extattr *ea;
            uint32_t size;
            char name[257];
            char *blk_buf;

            if ((blk_buf = tsk_malloc(ffs->ffsbsize_b)) == NULL) {
                tsk_fs_file_close(fs_file);
                free(dino_buf);
                return 1;
            }

            size = tsk_getu32(fs->endian, in->di_extsize);
            tsk_fprintf(hFile, "\nExtended Attributes:\n");
            tsk_fprintf(hFile,
                "Size: %" PRIu32 " (%" PRIu64 ", %" PRIu64 ")\n", size,
                tsk_getu64(fs->endian, in->di_extb[0]),
                tsk_getu64(fs->endian, in->di_extb[1]));


            /* Process first block */
            // @@@ Incorporate values into this as well
            if ((tsk_getu64(fs->endian, in->di_extb[0]) >= fs->first_block)
                && (tsk_getu64(fs->endian,
                        in->di_extb[0]) <= fs->last_block)) {
                uintptr_t end;
                ssize_t cnt;

                cnt =
                    tsk_fs_read_block(fs, tsk_getu64(fs->endian,
                        in->di_extb[0]), blk_buf, ffs->ffsbsize_b);
                if (cnt != ffs->ffsbsize_b) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_READ);
                    }
                    tsk_error_set_errstr2
                        ("ffs_istat: FFS2 extended attribute 0 at %"
                        PRIu64, tsk_getu64(fs->endian, in->di_extb[0]));
                    tsk_fs_file_close(fs_file);
                    free(blk_buf);
                    free(dino_buf);
                    return 1;
                }

                ea = (ffs_extattr *) blk_buf;

                if (size > ffs->ffsbsize_b) {
                    end = (uintptr_t) ea + ffs->ffsbsize_b;
                    size -= ffs->ffsbsize_b;
                }
                else {
                    end = (uintptr_t) ea + size;
                    size = 0;
                }

                for (; (uintptr_t) ea < end;
                    ea =
                    (ffs_extattr *) ((uintptr_t) ea +
                        tsk_getu32(fs->endian, ea->reclen))) {
                    memcpy(name, ea->name, ea->nlen);
                    name[ea->nlen] = '\0';
                    tsk_fprintf(hFile, "%s\n", name);
                }
            }
            if ((tsk_getu64(fs->endian, in->di_extb[1]) >= fs->first_block)
                && (tsk_getu64(fs->endian,
                        in->di_extb[1]) <= fs->last_block)) {
                uintptr_t end;
                ssize_t cnt;

                cnt =
                    tsk_fs_read_block(fs, tsk_getu64(fs->endian,
                        in->di_extb[1]), blk_buf, ffs->ffsbsize_b);
                if (cnt != ffs->ffsbsize_b) {
                    if (cnt >= 0) {
                        tsk_error_reset();
                        tsk_error_set_errno(TSK_ERR_FS_INODE_COR);
                    }
                    tsk_error_set_errstr2
                        ("ffs_istat: FFS2 extended attribute 1 at %"
                        PRIu64, tsk_getu64(fs->endian, in->di_extb[1]));
                    tsk_fs_file_close(fs_file);
                    free(blk_buf);
                    free(dino_buf);
                    return 1;
                }

                ea = (ffs_extattr *) blk_buf;

                if (size > ffs->ffsbsize_b)
                    end = (uintptr_t) ea + ffs->ffsbsize_b;
                else
                    end = (uintptr_t) ea + size;

                for (; (uintptr_t) ea < end;
                    ea =
                    (ffs_extattr *) ((uintptr_t) ea +
                        tsk_getu32(fs->endian, ea->reclen))) {
                    memcpy(name, ea->name, ea->nlen);
                    name[ea->nlen] = '\0';
                    tsk_fprintf(hFile, "%s\n", name);
                }
            }
            free(blk_buf);
        }
        free(dino_buf);
    }


    /* A bad hack to force a specified number of blocks */
    if (numblock > 0)
        fs_meta->size = numblock * ffs->ffsbsize_b;

    tsk_fprintf(hFile, "\nDirect Blocks:\n");

    print.idx = 0;
    print.hFile = hFile;

    if (tsk_fs_file_walk(fs_file, TSK_FS_FILE_WALK_FLAG_AONLY,
            print_addr_act, (void *) &print)) {
        tsk_fprintf(hFile, "\nError reading blocks in file\n");
        tsk_error_print(hFile);
        tsk_fs_file_close(fs_file);
        return 1;
    }

    if (print.idx != 0)
        tsk_fprintf(hFile, "\n");

    fs_attr_indir = tsk_fs_file_attr_get_type(fs_file,
        TSK_FS_ATTR_TYPE_UNIX_INDIR, 0, 0);
    if (fs_attr_indir) {
        tsk_fprintf(hFile, "\nIndirect Blocks:\n");

        print.idx = 0;

        if (tsk_fs_attr_walk(fs_attr_indir, TSK_FS_FILE_WALK_FLAG_AONLY,
                print_addr_act, (void *) &print)) {
            tsk_fprintf(hFile, "\nError reading indirect attribute:  ");
            tsk_error_print(hFile);
            tsk_error_reset();
        }
        else if (print.idx != 0) {
            tsk_fprintf(hFile, "\n");
        }
    }

    tsk_fs_file_close(fs_file);
    return 0;
}

/* Return 1 on error and 0 on success */
uint8_t
ffs_jopen(TSK_FS_INFO * fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("UFS does not have a journal");
    return 1;
}

uint8_t
ffs_jentry_walk(TSK_FS_INFO * fs, int a_flags,
    TSK_FS_JENTRY_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("UFS does not have a journal");
    return 1;
}


uint8_t
ffs_jblk_walk(TSK_FS_INFO * fs, TSK_DADDR_T start, TSK_DADDR_T end,
    int a_flags, TSK_FS_JBLK_WALK_CB action, void *ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("UFS does not have a journal");
    return 1;
}


/* ffs_close - close a fast file system */
static void
ffs_close(TSK_FS_INFO * fs)
{
    FFS_INFO *ffs = (FFS_INFO *) fs;

    fs->tag = 0;

    if (ffs->grp_buf)
        free(ffs->grp_buf);

    if (ffs->itbl_buf)
        free(ffs->itbl_buf);

    tsk_deinit_lock(&ffs->lock);

    free((char *) ffs->fs.sb1);
    tsk_fs_free(fs);
}

/**
 * \internal
 * Open part of a disk image as a FFS/UFS file system.
 *
 * @param img_info Disk image to analyze
 * @param offset Byte offset where file system starts
 * @param ftype Specific type of file system
 * @returns NULL on error or if data is not a FFS file system
 */
TSK_FS_INFO *
ffs_open(TSK_IMG_INFO * img_info, TSK_OFF_T offset, TSK_FS_TYPE_ENUM ftype)
{
    char *myname = "ffs_open";
    FFS_INFO *ffs;
    unsigned int len;
    TSK_FS_INFO *fs;
    ssize_t cnt;

    // clean up any error messages that are lying around
    tsk_error_reset();

    if (TSK_FS_TYPE_ISFFS(ftype) == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("Invalid FS Type in ffs_open");
        return NULL;
    }

    if ((ffs = (FFS_INFO *) tsk_fs_malloc(sizeof(*ffs))) == NULL)
        return NULL;

    fs = &(ffs->fs_info);

    fs->ftype = ftype;
    fs->flags = 0;
    fs->duname = "Fragment";
    fs->tag = TSK_FS_INFO_TAG;

    fs->img_info = img_info;
    fs->offset = offset;

    /* Both sbs are the same size */
    len = roundup(sizeof(ffs_sb1), img_info->sector_size);
    ffs->fs.sb1 = (ffs_sb1 *) tsk_malloc(len);
    if (ffs->fs.sb1 == NULL) {
        fs->tag = 0;
        tsk_fs_free((TSK_FS_INFO *)ffs);
        return NULL;
    }

    /* check the magic and figure out the endian ordering */

    /* Try UFS2 first - I read somewhere that some upgrades
     * kept the original UFS1 superblock in addition to
     * the new one */
    cnt = tsk_fs_read
        (fs, (TSK_OFF_T) UFS2_SBOFF, (char *) ffs->fs.sb2,
        sizeof(ffs_sb2));
    if (cnt != sizeof(ffs_sb2)) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_READ);
        }
        tsk_error_set_errstr("%s: Superblock at %" PRIuDADDR, myname,
            (TSK_OFF_T) UFS2_SBOFF);
        fs->tag = 0;
        free(ffs->fs.sb1);
        tsk_fs_free((TSK_FS_INFO *)ffs);
        return NULL;
    }

    /* If that didn't work, try the 256KB UFS2 location */
    if (tsk_fs_guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
        if (tsk_verbose)
            fprintf(stderr, "ufs_open: Trying 256KB UFS2 location\n");

        cnt = tsk_fs_read
            (fs, (TSK_OFF_T) UFS2_SBOFF2, (char *) ffs->fs.sb2,
            sizeof(ffs_sb2));
        if (cnt != sizeof(ffs_sb2)) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_READ);
            }
            tsk_error_set_errstr2("%s: Superblock at %" PRIuDADDR,
                myname, (TSK_OFF_T) UFS2_SBOFF2);
            fs->tag = 0;
            free(ffs->fs.sb1);
            tsk_fs_free((TSK_FS_INFO *)ffs);
            return NULL;
        }

        /* Try UFS1 if that did not work */
        if (tsk_fs_guessu32(fs, ffs->fs.sb2->magic, UFS2_FS_MAGIC)) {
            if (tsk_verbose)
                fprintf(stderr, "ufs_open: Trying UFS1 location\n");

            cnt = tsk_fs_read
                (fs, (TSK_OFF_T) UFS1_SBOFF, (char *) ffs->fs.sb1, len);
            if (cnt != len) {
                if (cnt >= 0) {
                    tsk_error_reset();
                    tsk_error_set_errno(TSK_ERR_FS_READ);
                }
                tsk_error_set_errstr2("%s: Superblock at %" PRIuDADDR,
                    myname, (TSK_OFF_T) UFS1_SBOFF);
                fs->tag = 0;
                free(ffs->fs.sb1);
                tsk_fs_free((TSK_FS_INFO *)ffs);
                return NULL;
            }
            if (tsk_fs_guessu32(fs, ffs->fs.sb1->magic, UFS1_FS_MAGIC)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_MAGIC);
                tsk_error_set_errstr("No UFS Magic Found");
                if (tsk_verbose)
                    fprintf(stderr, "ufs_open: No UFS magic found\n");
                fs->tag = 0;
                free(ffs->fs.sb1);
                tsk_fs_free((TSK_FS_INFO *)ffs);
                return NULL;
            }
            else {
                // @@@ NEED TO DIFFERENTIATE BETWEEN A & B - UID/GID location in inode
                fs->ftype = TSK_FS_TYPE_FFS1;
            }
        }
        else {
            fs->ftype = TSK_FS_TYPE_FFS2;
        }
    }
    else {
        fs->ftype = TSK_FS_TYPE_FFS2;
    }


    /*
     * Translate some filesystem-specific information to generic form.
     */

    if (fs->ftype == TSK_FS_TYPE_FFS2) {
        fs->block_count = tsk_gets64(fs->endian, ffs->fs.sb2->frag_num);
        fs->block_size = tsk_gets32(fs->endian, ffs->fs.sb2->fsize_b);
        ffs->ffsbsize_b = tsk_gets32(fs->endian, ffs->fs.sb2->bsize_b);
        ffs->ffsbsize_f = tsk_gets32(fs->endian, ffs->fs.sb2->bsize_frag);
        ffs->groups_count = tsk_gets32(fs->endian, ffs->fs.sb2->cg_num);
    }
    else {
        fs->block_count = tsk_gets32(fs->endian, ffs->fs.sb1->frag_num);
        fs->block_size = tsk_gets32(fs->endian, ffs->fs.sb1->fsize_b);
        ffs->ffsbsize_b = tsk_gets32(fs->endian, ffs->fs.sb1->bsize_b);
        ffs->ffsbsize_f = tsk_gets32(fs->endian, ffs->fs.sb1->bsize_frag);
        ffs->groups_count = tsk_gets32(fs->endian, ffs->fs.sb1->cg_num);
    }


    /*
     * Block calculations
     */
    fs->first_block = 0;
    fs->last_block = fs->last_block_act = fs->block_count - 1;
    fs->dev_bsize = img_info->sector_size;

    // determine the last block we have in this image
    if ((TSK_DADDR_T) ((img_info->size - offset) / fs->block_size) <
        fs->block_count)
        fs->last_block_act =
            (img_info->size - offset) / fs->block_size - 1;

    if ((fs->block_size % 512) || (ffs->ffsbsize_b % 512)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr
            ("Not a UFS FS (invalid fragment or block size)");
        if (tsk_verbose)
            fprintf(stderr, "ufs_open: invalid fragment or block size\n");
        fs->tag = 0;
        free(ffs->fs.sb1);
        tsk_fs_free((TSK_FS_INFO *)ffs);
        return NULL;
    }

    if ((ffs->ffsbsize_b / fs->block_size) != ffs->ffsbsize_f) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_MAGIC);
        tsk_error_set_errstr("Not a UFS FS (frag / block size mismatch)");
        if (tsk_verbose)
            fprintf(stderr, "ufs_open: fragment / block size mismatch\n");
        fs->tag = 0;
        free(ffs->fs.sb1);
        tsk_fs_free((TSK_FS_INFO *)ffs);
        return NULL;
    }

    // Inode / meta data calculations
    if (fs->ftype == TSK_FS_TYPE_FFS2) {
        fs->inum_count = ffs->groups_count * tsk_gets32(fs->endian, ffs->fs.sb2->cg_inode_num) + 1;     // we are adding 1 in this calc to account for Orphans directory
    }
    else {
        fs->inum_count = ffs->groups_count * tsk_gets32(fs->endian, ffs->fs.sb1->cg_inode_num) + 1;     // we are adding 1 in this calc to account for Orphans directory
    }

    fs->root_inum = FFS_ROOTINO;
    fs->first_inum = FFS_FIRSTINO;
    fs->last_inum = fs->inum_count - 1;

    /* Volume ID - in the same place for both types */
    for (fs->fs_id_used = 0; fs->fs_id_used < 8; fs->fs_id_used++) {
        fs->fs_id[fs->fs_id_used] = ffs->fs.sb1->fs_id[fs->fs_id_used];
    }

    // set the function pointers
    fs->inode_walk = ffs_inode_walk;
    fs->block_walk = ffs_block_walk;
    fs->block_getflags = ffs_block_getflags;

    fs->get_default_attr_type = tsk_fs_unix_get_default_attr_type;
    fs->load_attrs = tsk_fs_unix_make_data_run;
    fs->name_cmp = tsk_fs_unix_name_cmp;

    fs->file_add_meta = ffs_inode_lookup;
    fs->dir_open_meta = ffs_dir_open_meta;
    fs->fsstat = ffs_fsstat;
    fs->fscheck = ffs_fscheck;
    fs->istat = ffs_istat;
    fs->close = ffs_close;
    fs->jblk_walk = ffs_jblk_walk;
    fs->jentry_walk = ffs_jentry_walk;
    fs->jopen = ffs_jopen;
    fs->journ_inum = 0;

    // initialize caches
    ffs->grp_buf = NULL;
    ffs->grp_num = 0xffffffff;
    ffs->grp_addr = 0;

    ffs->itbl_buf = NULL;
    ffs->itbl_addr = 0;

    /*
     * Print some stats.
     */
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "inodes %" PRIuINUM " root ino %" PRIuINUM " cyl groups %"
            PRId32 " blocks %" PRIuDADDR "\n", fs->inum_count,
            fs->root_inum, ffs->groups_count, fs->block_count);

    tsk_init_lock(&ffs->lock);

    return (fs);
}
