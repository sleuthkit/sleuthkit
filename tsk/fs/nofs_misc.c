/*
** The Sleuth Kit 
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
** Copyright (c) 2004-2005 Brian Carrier.  All rights reserved 
**
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "tsk_fs_i.h"


/**
 *\file nofs_misc.c
 * Contains internal functions that are common to the "non-file system" file systems, such as
 * raw and swap. Many of the functions in this file simply give an error that the functionality
 * is not supported for the given file system type.
 */


/** \internal
 * Print details about the file system to a file handle. 
 *
 * @param a_fs File system to print details on
 * @param hFile File handle to print text to
 * 
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_fs_nofs_fsstat(TSK_FS_INFO * a_fs, FILE * hFile)
{
    tsk_fprintf(hFile, "%s Data\n", tsk_fs_type_toname(a_fs->ftype));
    tsk_fprintf(hFile, "Block Size: %d\n", a_fs->block_size);
    tsk_fprintf(hFile, "Block Range: 0 - %" PRIuDADDR "\n",
        a_fs->last_block);
    return 0;
}


/** \internal
 */
TSK_FS_ATTR_TYPE_ENUM
tsk_fs_nofs_get_default_attr_type(const TSK_FS_FILE * a_fs_file)
{
    return TSK_FS_ATTR_TYPE_DEFAULT;
}


/** \internal
 */
uint8_t
tsk_fs_nofs_make_data_run(TSK_FS_FILE * a_fs_file)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        (a_fs_file->fs_info) ? tsk_fs_type_toname(a_fs_file->
            fs_info->ftype) : "");
    return 1;
}



/** \internal
 */
void
tsk_fs_nofs_close(TSK_FS_INFO * a_fs)
{
    a_fs->tag = 0;
    tsk_fs_free(a_fs);
}

/************* BLOCKS *************/

/** \internal
 */
TSK_FS_BLOCK_FLAG_ENUM
tsk_fs_nofs_block_getflags(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr)
{
    return TSK_FS_BLOCK_FLAG_ALLOC | TSK_FS_BLOCK_FLAG_CONT;
}


/** \internal
 *
 * return 1 on error and 0 on success
 */
uint8_t
tsk_fs_nofs_block_walk(TSK_FS_INFO * fs, TSK_DADDR_T a_start_blk,
    TSK_DADDR_T a_end_blk, TSK_FS_BLOCK_WALK_FLAG_ENUM a_flags,
    TSK_FS_BLOCK_WALK_CB a_action, void *a_ptr)
{
    TSK_FS_BLOCK *fs_block;
    TSK_DADDR_T addr;

    // clean up any error messages that are lying around
    tsk_error_reset();

    /*
     * Sanity checks.
     */
    if (a_start_blk < fs->first_block || a_start_blk > fs->last_block) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("nofs_block_walk: Start block number: %"
            PRIuDADDR, a_start_blk);
        return 1;
    }

    if (a_end_blk < fs->first_block || a_end_blk > fs->last_block
        || a_end_blk < a_start_blk) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_WALK_RNG);
        tsk_error_set_errstr("nofs_block_walk: Last block number: %"
            PRIuDADDR, a_end_blk);
        return 1;
    }

    /* Sanity check on a_flags -- make sure at least one ALLOC is set */
    if (((a_flags & TSK_FS_BLOCK_WALK_FLAG_ALLOC) == 0) &&
        ((a_flags & TSK_FS_BLOCK_WALK_FLAG_UNALLOC) == 0)) {
        a_flags |=
            (TSK_FS_BLOCK_WALK_FLAG_ALLOC |
            TSK_FS_BLOCK_WALK_FLAG_UNALLOC);
    }

    /* All swap has is allocated blocks... exit if not wanted */
    if (!(a_flags & TSK_FS_BLOCK_FLAG_ALLOC)) {
        return 0;
    }

    if ((fs_block = tsk_fs_block_alloc(fs)) == NULL) {
        return 1;
    }

    for (addr = a_start_blk; addr <= a_end_blk; addr++) {
        int retval;

        if (tsk_fs_block_get(fs, fs_block, addr) == NULL) {
            tsk_error_set_errstr2("nofs_block_walk: Block %" PRIuDADDR,
                addr);
            tsk_fs_block_free(fs_block);
            return 1;
        }

        retval = a_action(fs_block, a_ptr);
        if (retval == TSK_WALK_STOP) {
            break;
        }
        else if (retval == TSK_WALK_ERROR) {
            tsk_fs_block_free(fs_block);
            return 1;
        }
    }

    /*
     * Cleanup.
     */
    tsk_fs_block_free(fs_block);
    return 0;
}


/************ META / FILES ************/


/** \internal
 */
uint8_t
tsk_fs_nofs_inode_walk(TSK_FS_INFO * a_fs, TSK_INUM_T a_start_inum,
    TSK_INUM_T a_end_inum, TSK_FS_META_FLAG_ENUM a_flags,
    TSK_FS_META_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}

/** \internal
 */
uint8_t
tsk_fs_nofs_file_add_meta(TSK_FS_INFO * a_fs, TSK_FS_FILE * a_fs_file,
    TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}

/** \internal
 */
uint8_t
tsk_fs_nofs_istat(TSK_FS_INFO * a_fs, TSK_FS_ISTAT_FLAG_ENUM istat_flags, FILE * hFile, TSK_INUM_T inum,
    TSK_DADDR_T numblock, int32_t sec_skew)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}



/************ DIR **************/

/** \internal
 */
TSK_RETVAL_ENUM
tsk_fs_nofs_dir_open_meta(TSK_FS_INFO * a_fs, TSK_FS_DIR ** a_fs_dir,
    TSK_INUM_T a_addr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return TSK_ERR;
}

/******** JOURNAL **********/

/** \internal
 */
uint8_t
tsk_fs_nofs_jopen(TSK_FS_INFO * a_fs, TSK_INUM_T inum)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}

/** \internal
 */
uint8_t
tsk_fs_nofs_jentry_walk(TSK_FS_INFO * a_fs, int a_flags,
    TSK_FS_JENTRY_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}


/** \internal
 */
uint8_t
tsk_fs_nofs_jblk_walk(TSK_FS_INFO * a_fs, TSK_INUM_T start, TSK_INUM_T end,
    int a_flags, TSK_FS_JBLK_WALK_CB a_action, void *a_ptr)
{
    tsk_error_reset();
    tsk_error_set_errno(TSK_ERR_FS_UNSUPFUNC);
    tsk_error_set_errstr("Illegal analysis method for %s data ",
        tsk_fs_type_toname(a_fs->ftype));
    return 1;
}

int
tsk_fs_nofs_name_cmp(TSK_FS_INFO * a_fs_info, const char *s1,
    const char *s2)
{
    return strcmp(s1, s2);
}
