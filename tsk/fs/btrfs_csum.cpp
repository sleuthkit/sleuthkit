/*
** The Sleuth Kit
**
** Brian Carrier [carrier <at> sleuthkit [dot] org]
** Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
**
** TASK
** Copyright (c) 2015 Stefan Pöschel.  All rights reserved
**
** This software is distributed under the Common Public License 1.0
*/

/*
 * Contains the checksum part for Btrfs file system support.
 */

#include "tsk/base/crc.h"

/**
 * Returns the CRC32C checksum of a specific amount of data.
 * @param a_data pointer to data
 * @param a_len data len
 * @return calculated checksum
 */
extern "C" unsigned long
btrfs_csum_crc32c(const unsigned char *a_data, const int a_len)
{
    cm_t cm;
    cm.cm_width = 32;
    cm.cm_poly = 0x1EDC6F41;
    cm.cm_init = 0xFFFFFFFF;
    cm.cm_refin = true;
    cm.cm_refot = true;
    cm.cm_xorot = 0xFFFFFFFF;

    cm_ini(&cm);
    cm_blk(&cm, (unsigned char *) a_data, a_len);
    return cm_crc(&cm);
}
