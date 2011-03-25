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
    TSK_OFF_T off = 0;

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
    
    if (((a_fs->block_pre_size) || (a_fs->block_post_size)) && (a_fs->block_size)) {
        TSK_OFF_T cur_off = a_off;
        ssize_t retval = 0;
        TSK_OFF_T end_addr = a_off + a_len;

        // we need to read block by block so that we can skip the needed pre and post bytes
        while (cur_off < end_addr) {
            TSK_DADDR_T blk = cur_off / a_fs->block_size;
            TSK_OFF_T read_off = off;
            ssize_t retval2 = 0;
            size_t read_len = a_fs->block_size - cur_off % a_fs->block_size;
            
            if (read_len + cur_off > end_addr) 
                read_len = end_addr - cur_off;
                        
            if (a_fs->block_pre_size)
                read_off += ((blk+1) * a_fs->block_pre_size);
            if (a_fs->block_post_size) 
                read_off += (blk * a_fs->block_post_size);
            
            retval2 = tsk_img_read(a_fs->img_info, read_off, &a_buf[retval], read_len);
            if (retval2 == -1) 
                return -1;
            else if (retval2 == 0)
                break;
            retval += retval2;
            cur_off += retval2;
        }
        return retval;
    }
    else {
        return tsk_img_read(a_fs->img_info, off, a_buf, a_len);
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
    TSK_OFF_T off = 0;

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
    
    off = a_fs->offset + (TSK_OFF_T) (a_addr) * a_fs->block_size;
    if ((a_fs->block_pre_size == 0) && (a_fs->block_post_size == 0)) {
        return tsk_img_read(a_fs->img_info, off, a_buf, a_len);
    }
    else {
        size_t i;
        ssize_t retval = 0;

        for (i = 0; i < a_len; i++) {
            ssize_t retval2;
            TSK_OFF_T off2 = off + i*a_fs->block_size;
            off += ((a_addr+1) * a_fs->block_pre_size);
            off += (a_addr * a_fs->block_post_size);
            
            retval2 = tsk_img_read(a_fs->img_info, off2, &a_buf[retval], a_fs->block_size);
            if (retval2 == -1)
                return -1;
            else if (retval2 == 0)
                break;

            retval += retval2;
        }
        return retval;
    }


}
