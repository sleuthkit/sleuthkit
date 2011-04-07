/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 * 
 */

 /*
  * C header file with Sun and internal data structures. 
  */

#ifndef _TSK_SUN_H
#define _TSK_SUN_H

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct {
        uint8_t asciilabel[128];

        /* VTOC */
        uint8_t version[4];
        uint8_t vol_name[8];
        uint8_t num_parts[2];

        struct {
            uint8_t type[2];
            uint8_t flag[2];
        } part_meta[8];

        uint8_t bootinfo[4][3];
        uint8_t reserved0[2];
        uint8_t sanity[4];
        uint8_t reserved1[38];
        uint8_t timestamp[8][4];
        /* End VTOC */


        uint8_t write_reinstruct[2];
        uint8_t read_reinstruct[2];
        uint8_t reserved2[154];
        uint8_t rpm[2];
        uint8_t num_ph_cyl[2];
        uint8_t alt_per_cyl[2];
        uint8_t reserved3[4];
        uint8_t interleave[2];
        uint8_t num_cyl[2];
        uint8_t num_alt_cyl[2];
        uint8_t num_head[2];
        uint8_t sec_per_tr[2];
        uint8_t reserved5[4];

        struct {
            uint8_t start_cyl[4];
            uint8_t size_blk[4];
        } part_layout[8];

        uint8_t magic[2];
        uint8_t checksum[2];

    } sun_dlabel_sparc;


    typedef struct {

        /* VTOC */
        uint8_t bootinfo[3][4];
        uint8_t sanity[4];
        uint8_t version[4];
        uint8_t vol_name[8];
        uint8_t sec_size[2];
        uint8_t num_parts[2];
        uint8_t reserved0[40];

        struct {
            uint8_t type[2];
            uint8_t flag[2];
            uint8_t start_sec[4];
            uint8_t size_sec[4];
        } part[16];

        uint8_t timestamp[16][4];
        uint8_t asciilabel[128];
        /* END of VTOC */

        uint8_t num_ph_cyl[4];
        uint8_t num_cyl[4];
        uint8_t num_alt_cyl[2];
        uint8_t cyl_offset[2];
        uint8_t num_head[4];
        uint8_t sec_per_tr[4];
        uint8_t interleave[2];
        uint8_t skew[2];
        uint8_t alt_per_cyl[2];
        uint8_t rpm[2];
        uint8_t write_reinstruct[2];
        uint8_t read_reinstruct[2];
        uint8_t reserved1[8];
        uint8_t reserved2[12];
        uint8_t magic[2];
        uint8_t checksum[2];

    } sun_dlabel_i386;

#define SUN_MAGIC	0xDABE
#define SUN_SANITY	0x600DDEEE

#define SUN_FLAG_UNMNT	0x01
#define SUN_FLAG_RO		0x10

#define SUN_SPARC_PART_SOFFSET	0
#define SUN_I386_PART_SOFFSET	1

#ifdef __cplusplus
}
#endif
#endif
