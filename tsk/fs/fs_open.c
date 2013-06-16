/*
** tsk_fs_open_img
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
**
** Copyright (c) 1997,1998,1999, International Business Machines
** Corporation and others. All Rights Reserved.
*/

/* TCT */
/*++
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
 --*/

#include "tsk_fs_i.h"

/**
 * \file fs_open.c
 * Contains the general code to open a file system -- this calls
 * the file system -specific opening routines.
 */


/**
 * \ingroup fslib
 * Tries to process data in a volume as a file system.
 * Returns a structure that can be used for analysis and reporting.
 *
 * @param a_part_info Open volume to read from and analyze
 * @param a_ftype Type of file system (or autodetect)
 *
 * @return NULL on error
 */
TSK_FS_INFO *
tsk_fs_open_vol(const TSK_VS_PART_INFO * a_part_info,
    TSK_FS_TYPE_ENUM a_ftype)
{
    TSK_OFF_T offset;
    if (a_part_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_open_vol: Null vpart handle");
        return NULL;
    }
    else if ((a_part_info->vs == NULL)
        || (a_part_info->vs->tag != TSK_VS_INFO_TAG)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_open_vol: Null vs handle");
        return NULL;
    }

    offset =
        a_part_info->start * a_part_info->vs->block_size +
        a_part_info->vs->offset;
    return tsk_fs_open_img(a_part_info->vs->img_info, offset, a_ftype);
}

/**
 * \ingroup fslib
 * Tries to process data in a disk image at a given offset as a file system.
 * Returns a structure that can be used for analysis and reporting.
 *
 * @param a_img_info Disk image to analyze
 * @param a_offset Byte offset to start analyzing from
 * @param a_ftype Type of file system (or autodetect)
 *
 * @return NULL on error
 */
TSK_FS_INFO *
tsk_fs_open_img(TSK_IMG_INFO * a_img_info, TSK_OFF_T a_offset,
    TSK_FS_TYPE_ENUM a_ftype)
{
    if (a_img_info == NULL) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("tsk_fs_open_img: Null image handle");
        return NULL;
    }

    /* We will try different file systems ...
     * We need to try all of them in case more than one matches
     */
    if (a_ftype == TSK_FS_TYPE_DETECT) {
        TSK_FS_INFO *fs_info, *fs_set = NULL;
        char *set = NULL;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "fsopen: Auto detection mode at offset %" PRIuOFF "\n",
                a_offset);

        if ((fs_info =
                ntfs_open(a_img_info, a_offset, TSK_FS_TYPE_NTFS_DETECT,
                    1)) != NULL) {
            set = "NTFS";
            fs_set = fs_info;
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                fatfs_open(a_img_info, a_offset, TSK_FS_TYPE_FAT_DETECT,
                    1)) != NULL) {
            if (set == NULL) {
                set = "FAT";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("FAT or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                ext2fs_open(a_img_info, a_offset, TSK_FS_TYPE_EXT_DETECT,
                    1)) != NULL) {
            if (set == NULL) {
                set = "EXT2/3";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("EXT2/3 or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                ffs_open(a_img_info, a_offset,
                    TSK_FS_TYPE_FFS_DETECT)) != NULL) {
            if (set == NULL) {
                set = "UFS";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("UFS or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }

        if ((fs_info =
                yaffs2_open(a_img_info, a_offset,
                    TSK_FS_TYPE_YAFFS2_DETECT, 1)) != NULL) {
            if (set == NULL) {
                set = "YAFFS2";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("YAFFS2 or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }


#if TSK_USE_HFS
        if ((fs_info =
                hfs_open(a_img_info, a_offset, TSK_FS_TYPE_HFS_DETECT,
                    1)) != NULL) {
            if (set == NULL) {
                set = "HFS";
                fs_set = fs_info;
            }
            else {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("HFS or %s", set);
                return NULL;
            }
        }
        else {
            tsk_error_reset();
        }
#endif

        if ((fs_info =
                iso9660_open(a_img_info, a_offset,
                    TSK_FS_TYPE_ISO9660_DETECT, 1)) != NULL) {
            if (set != NULL) {
                fs_set->close(fs_set);
                fs_info->close(fs_info);
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
                tsk_error_set_errstr("ISO9660 or %s", set);
                return NULL;
            }
            fs_set = fs_info;
        }
        else {
            tsk_error_reset();
        }


        if (fs_set == NULL) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNKTYPE);
            return NULL;
        }
        return fs_set;
    }
    else {
        if (TSK_FS_TYPE_ISNTFS(a_ftype))
            return ntfs_open(a_img_info, a_offset, a_ftype, 0);
        else if (TSK_FS_TYPE_ISFAT(a_ftype))
            return fatfs_open(a_img_info, a_offset, a_ftype, 0);
        else if (TSK_FS_TYPE_ISFFS(a_ftype))
            return ffs_open(a_img_info, a_offset, a_ftype);
        else if (TSK_FS_TYPE_ISEXT(a_ftype))
            return ext2fs_open(a_img_info, a_offset, a_ftype, 0);
        else if (TSK_FS_TYPE_ISHFS(a_ftype))
            return hfs_open(a_img_info, a_offset, a_ftype, 0);
        else if (TSK_FS_TYPE_ISISO9660(a_ftype))
            return iso9660_open(a_img_info, a_offset, a_ftype, 0);
        else if (TSK_FS_TYPE_ISRAW(a_ftype))
            return rawfs_open(a_img_info, a_offset);
        else if (TSK_FS_TYPE_ISSWAP(a_ftype))
            return swapfs_open(a_img_info, a_offset);
        else if (TSK_FS_TYPE_ISYAFFS2(a_ftype))
            return yaffs2_open(a_img_info, a_offset, a_ftype, 0);
        else {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_FS_UNSUPTYPE);
            tsk_error_set_errstr("%X", (int) a_ftype);
            return NULL;
        }
    }
}

/**
 * \ingroup fslib
 * Close an open file system.
 * @param a_fs File system to close.
 */
void
tsk_fs_close(TSK_FS_INFO * a_fs)
{
    if ((a_fs == NULL) || (a_fs->tag != TSK_FS_INFO_TAG))
        return;

    // each file system is supposed to call tsk_fs_free() 

    a_fs->close(a_fs);
}

/* tsk_fs_malloc - init lock after tsk_malloc 
 * This is for fs module and all it's inheritances
 */
TSK_FS_INFO *
tsk_fs_malloc(size_t a_len)
{
    TSK_FS_INFO *fs_info;
    if ((fs_info = (TSK_FS_INFO *) tsk_malloc(a_len)) == NULL)
        return NULL;
    tsk_init_lock(&fs_info->list_inum_named_lock);
    tsk_init_lock(&fs_info->orphan_dir_lock);

    fs_info->list_inum_named = NULL;

    return fs_info;
}

/* tsk_fs_free - deinit lock before free memory 
 * This is for fs module and all it's inheritances
 */
void
tsk_fs_free(TSK_FS_INFO * a_fs_info)
{
    if (a_fs_info->list_inum_named) {
        tsk_list_free(a_fs_info->list_inum_named);
        a_fs_info->list_inum_named = NULL;
    }

    /* we should probably get the lock, but we're 
     * about to kill the entire object so there are
     * bigger problems if another thread is still 
     * using the fs */
    if (a_fs_info->orphan_dir) {
        tsk_fs_dir_close(a_fs_info->orphan_dir);
        a_fs_info->orphan_dir = NULL;
    }


    tsk_deinit_lock(&a_fs_info->list_inum_named_lock);
    tsk_deinit_lock(&a_fs_info->orphan_dir_lock);

    free(a_fs_info);
}
