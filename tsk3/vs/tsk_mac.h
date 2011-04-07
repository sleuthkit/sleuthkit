/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

  /*
   * C header file with Mac and internal data structures. 
   */

#ifndef _TSK_MAC_H
#define _TSK_MAC_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint8_t magic[2];
        uint8_t reserved[2];
        uint8_t pmap_size[4];
        uint8_t start_sec[4];
        uint8_t size_sec[4];
        uint8_t name[32];
        uint8_t type[32];
        uint8_t data_start_sec[4];
        uint8_t data_size_sec[4];
        uint8_t status[4];
        uint8_t boot_start_sec[4];
        uint8_t boot_size_sec[4];
        uint8_t boot_load_addr[4];
        uint8_t reserved2[4];
        uint8_t boot_entry[4];
        uint8_t reserved3[4];
        uint8_t boot_checksum[4];
        uint8_t proc_type[16];
        uint8_t reserved4[376];
    } mac_part;

#define MAC_MAGIC	0x504d
#define MAC_PART_SOFFSET	1

#define MAC_STAT_VALID		0x00
#define MAC_STAT_ALLOC		0x01
#define MAC_STAT_INUSE		0x02
#define MAC_STAT_BOOT		0x04
#define MAC_STAT_READ		0x08

#ifdef __cplusplus
}
#endif
#endif
