/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mm_io.c
 * Contains the wrapper code that allows one to read sectors from 
 * a TSK_VS_INFO or TSK_VS_PART_INFO structure.  These functions
 * call the underlying TSK_IMG_INFO functions.
 */
#include <errno.h>
#include "tsk_vs_i.h"


/**
 * \ingroup vslib
 * Reads one or more blocks of data with an address relative to the start of the volume system.
 *
 * @param a_vs Pointer to open volume system
 * @param a_addr Sector address to read from, relative to start of VOLUME SYSTEM.
 * @param a_buf Buffer to store data in
 * @param a_len Amount of data to read (in bytes - must be a multiple of block_size)
 * @returns Number of bytes read or -1 on error 
 */
ssize_t
tsk_vs_read_block(TSK_VS_INFO * a_vs, TSK_DADDR_T a_addr, char *a_buf,
    size_t a_len)
{
    if (a_len % a_vs->block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_READ);
        tsk_error_set_errstr("tsk_vs_read_block: length %" PRIuSIZE ""
            " not a multiple of %d", a_len, a_vs->block_size);
        return -1;
    }

    return tsk_img_read(a_vs->img_info,
        a_vs->offset + (TSK_OFF_T) (a_addr * a_vs->block_size),
        a_buf, a_len);
}


/**
 * \ingroup vslib
 * Reads data starting at a byte address relative to the start of a VOLUME in a volume system.
 *
 * @param a_vs_part info Pointer to open volume in a volume system
 * @param a_off Byte offset to read from, relative to start of VOLUME in volume system.
 * @param a_buf Buffer to store data in
 * @param a_len Amount of data to read (in bytes)
 * @returns Number of bytes read or -1 on error 
 */
ssize_t
tsk_vs_part_read(const TSK_VS_PART_INFO * a_vs_part, TSK_OFF_T a_off,
    char *a_buf, size_t a_len)
{
    TSK_VS_INFO *vs = a_vs_part->vs;

    return tsk_img_read(vs->img_info,
        vs->offset + (TSK_OFF_T) a_vs_part->start * vs->block_size +
        a_off, a_buf, a_len);
}

/**
 * \ingroup vslib
 * Reads one or more blocks of data with an address relative to the start of a VOLUME in a volume system.
 *
 * @param a_vs_part info Pointer to open volume in a volume system
 * @param a_addr Block address to start reading from, relative to start of VOLUME in volume system.
 * @param a_buf Buffer to store data in
 * @param a_len Amount of data to read (in bytes - must be a multiple of block_size)
 * @returns Number of bytes read or -1 on error 
 */
ssize_t
tsk_vs_part_read_block(const TSK_VS_PART_INFO * a_vs_part,
    TSK_DADDR_T a_addr, char *a_buf, size_t a_len)
{
    TSK_VS_INFO *vs = a_vs_part->vs;

    if (a_len % vs->block_size) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_READ);
        tsk_error_set_errstr("tsk_vs_part_read_block: length %" PRIuSIZE ""
            " not a multiple of %d", a_len, vs->block_size);
        return -1;
    }

    return tsk_img_read(vs->img_info,
        vs->offset + (TSK_OFF_T) (a_vs_part->start +
            a_addr) * vs->block_size, a_buf, a_len);
}
