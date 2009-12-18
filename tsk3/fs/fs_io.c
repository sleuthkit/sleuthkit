/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2008 Brian Carrier, Basis Technology.  All Rights reserved
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
    TSK_OFF_T off;

    // do a sanity check on the read bounds, but only if the block
    // value has been set. 
    // note that this could prevent us from viewing the FS slack...
    if ((a_fs->last_block_act > 0)
        && ((TSK_DADDR_T) a_off >=
            ((a_fs->last_block_act + 1) * a_fs->block_size))) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_READ;
        if ((TSK_DADDR_T) a_off <
            ((a_fs->last_block + 1) * a_fs->block_size))
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_fs_read: Offset missing in partial image: %" PRIuDADDR
                ")", a_off);
        else
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_fs_read: Offset is too large for image: %"
                PRIuDADDR ")", a_off);
        return -1;
    }

    off = a_off + a_fs->offset;
    return tsk_img_read(a_fs->img_info, off, a_buf, a_len);
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
        tsk_errno = TSK_ERR_FS_READ;
        snprintf(tsk_errstr, TSK_ERRSTR_L,
            "tsk_fs_read_block: length %" PRIuSIZE ""
            " not a multiple of %d", a_len, a_fs->block_size);
        return -1;
    }

    if (a_addr > a_fs->last_block_act) {
        tsk_error_reset();
        tsk_errno = TSK_ERR_FS_READ;
        if (a_addr <= a_fs->last_block)
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_fs_read_block: Address missing in partial image: %"
                PRIuDADDR ")", a_addr);
        else
            snprintf(tsk_errstr, TSK_ERRSTR_L,
                "tsk_fs_read_block: Address is too large for image: %"
                PRIuDADDR ")", a_addr);
        return -1;
    }

    return tsk_img_read(a_fs->img_info,
        a_fs->offset + (TSK_OFF_T) a_addr * a_fs->block_size, a_buf,
        a_len);
}
