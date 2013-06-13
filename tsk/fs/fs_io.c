/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All Rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 * 
 * Copyright (c) 1997,1998,1999, International Business Machines          
 * Corporation and others. All Rights Reserved.
 *
 *
 * LICENSE
 *	This software is distributed under the IBM Public License.
 * AUTHOR(S)
 *	Wietse Venema
 *	IBM T.J. Watson Research
 *	P.O. Box 704
 *	Yorktown Heights, NY 10598, USA
--*/

/** \file fs_io.c
 * Contains functions to read data from a disk image and wrapper functions to read file content.
 */

#include <errno.h>
#include "tsk_fs_i.h"



/** \internal
 * Internal method to deal with calculating correct offset when we have pre and post bytes
 * in teh file system blocks (i.e. RAW Cds)
 * @param a_fs File system being analyzed
 * @param a_off Byte offset into file system (i.e. not offset into image)
 * @param a_buf Buffer to write data into
 * @param a_len Number of bytes to read
 * @retuns Number of bytes read or -1 on error
 */
static ssize_t
fs_prepost_read(TSK_FS_INFO * a_fs, TSK_OFF_T a_off, char *a_buf,
    size_t a_len)
{
    TSK_OFF_T cur_off = a_off;
    TSK_OFF_T end_off = a_off + a_len;
    ssize_t cur_idx = 0;

    // we need to read block by block so that we can skip the needed pre and post bytes
    while (cur_off < end_off) {
        TSK_OFF_T read_off;
        ssize_t retval2 = 0;
        TSK_DADDR_T blk = cur_off / a_fs->block_size;
        size_t read_len = a_fs->block_size - cur_off % a_fs->block_size;

        if (read_len + cur_off > end_off)
            read_len = (size_t) (end_off - cur_off);

        read_off =
            a_fs->offset + cur_off + blk * (a_fs->block_pre_size +
            a_fs->block_post_size) + a_fs->block_pre_size;
        if (tsk_verbose)
            fprintf(stderr,
                "fs_prepost_read: Mapped %" PRIuOFF " to %" PRIuOFF "\n",
                cur_off, read_off);

        retval2 =
            tsk_img_read(a_fs->img_info, read_off, &a_buf[cur_idx],
            read_len);
        if (retval2 == -1)
            return -1;
        else if (retval2 == 0)
            break;
        cur_idx += retval2;
        cur_off += retval2;
    }
    return cur_idx;
}


/**
 * \ingroup fslib
 * Read arbitrary data from inside of the file system. 
 * @param a_fs The file system handle.
 * @param a_off The byte offset to start reading from (relative to start of file system)
 * @param a_buf The buffer to store the block in.
 * @param a_len The number of bytes to read
 * @return The number of bytes read or -1 on error. 
 */
ssize_t
tsk_fs_read(TSK_FS_INFO * a_fs, TSK_OFF_T a_off, char *a_buf, size_t a_len)
{
    // do a sanity check on the read bounds, but only if the block
    // value has been set. 
    // note that this could prevent us from viewing the FS slack...
    if ((a_fs->last_block_act > 0)
        && ((TSK_DADDR_T) a_off >=
            ((a_fs->last_block_act + 1) * a_fs->block_size))) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        if ((TSK_DADDR_T) a_off <
            ((a_fs->last_block + 1) * a_fs->block_size))
            tsk_error_set_errstr
                ("tsk_fs_read: Offset missing in partial image: %"
                PRIuDADDR ")", a_off);
        else
            tsk_error_set_errstr
                ("tsk_fs_read: Offset is too large for image: %" PRIuDADDR
                ")", a_off);
        return -1;
    }

    if (((a_fs->block_pre_size) || (a_fs->block_post_size))
        && (a_fs->block_size)) {
        return fs_prepost_read(a_fs, a_off, a_buf, a_len);
    }
    else {
        return tsk_img_read(a_fs->img_info, a_off + a_fs->offset, a_buf,
            a_len);
    }
}


/**
 * \ingroup fslib
 * Read a file system block into a char* buffer.  
 * This is actually a wrapper around the fs_read_random function,
 * but it allows the starting location to be specified as a block address. 
 *
 * @param a_fs The file system structure.
 * @param a_addr The starting block file system address. 
 * @param a_buf The char * buffer to store the block data in.
 * @param a_len The number of bytes to read (must be a multiple of the block size)
 * @return The number of bytes read or -1 on error. 
 */
ssize_t
tsk_fs_read_block(TSK_FS_INFO * a_fs, TSK_DADDR_T a_addr, char *a_buf,
    size_t a_len)
{
    if (a_len % a_fs->block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        tsk_error_set_errstr("tsk_fs_read_block: length %" PRIuSIZE ""
            " not a multiple of %d", a_len, a_fs->block_size);
        return -1;
    }

    if (a_addr > a_fs->last_block_act) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_READ);
        if (a_addr <= a_fs->last_block)
            tsk_error_set_errstr
                ("tsk_fs_read_block: Address missing in partial image: %"
                PRIuDADDR ")", a_addr);
        else
            tsk_error_set_errstr
                ("tsk_fs_read_block: Address is too large for image: %"
                PRIuDADDR ")", a_addr);
        return -1;
    }


    if ((a_fs->block_pre_size == 0) && (a_fs->block_post_size == 0)) {
        TSK_OFF_T off =
            a_fs->offset + (TSK_OFF_T) (a_addr) * a_fs->block_size;
        return tsk_img_read(a_fs->img_info, off, a_buf, a_len);
    }
    else {
        TSK_OFF_T off = (TSK_OFF_T) (a_addr) * a_fs->block_size;
        return fs_prepost_read(a_fs, off, a_buf, a_len);
    }
}
