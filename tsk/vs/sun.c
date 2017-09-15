/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * SUN - Sun VTOC code
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file sun.c
 * Contains the internal SUN VTOC volume system processing code.
 */
#include "tsk_vs_i.h"
#include "tsk_sun.h"


/*
 * Return a buffer with a description of the partition type
 */
static char *
sun_get_desc(uint16_t fstype)
{
    char *str = tsk_malloc(64);
    if (str == NULL)
        return "";
    switch (fstype) {

    case 0:
        strncpy(str, "Unassigned (0x00)", 64);
        break;
    case 1:
        strncpy(str, "boot (0x01)", 64);
        break;
    case 2:
        strncpy(str, "/ (0x02)", 64);
        break;
    case 3:
        strncpy(str, "swap (0x03)", 64);
        break;
    case 4:
        strncpy(str, "/usr/ (0x04)", 64);
        break;
    case 5:
        strncpy(str, "backup (0x05)", 64);
        break;
    case 6:
        strncpy(str, "stand (0x06)", 64);
        break;
    case 7:
        strncpy(str, "/var/ (0x07)", 64);
        break;
    case 8:
        strncpy(str, "/home/ (0x08)", 64);
        break;
    case 9:
        strncpy(str, "alt sector (0x09)", 64);
        break;
    case 10:
        strncpy(str, "cachefs (0x0A)", 64);
        break;
    default:
        snprintf(str, 64, "Unknown Type (0x%.4x)", fstype);
        break;
    }

    return str;
}


/* 
 * Load an Intel disk label, this is called by sun_load_table 
 */

static uint8_t
sun_load_table_i386(TSK_VS_INFO * vs, sun_dlabel_i386 * dlabel_x86)
{
    uint32_t idx = 0;
    uint16_t num_parts;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr, "load_table_i386: Number of partitions: %d\n",
            tsk_getu16(vs->endian, dlabel_x86->num_parts));

    num_parts = tsk_getu16(vs->endian, dlabel_x86->num_parts);
    if (num_parts > 16) {
        num_parts = 16;
    }

    /* Cycle through the partitions, there are 16 for i386 */
    for (idx = 0; idx < num_parts; idx++) {
        TSK_VS_PART_FLAG_ENUM ptype = TSK_VS_PART_FLAG_ALLOC;

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "load_table_i386: %" PRIu32
                "  Starting Sector: %" PRIu32 "  Size: %" PRIu32
                "  Type: %" PRIu16 "\n", idx, tsk_getu32(vs->endian,
                    dlabel_x86->part[idx].start_sec),
                tsk_getu32(vs->endian, dlabel_x86->part[idx].size_sec),
                tsk_getu16(vs->endian, dlabel_x86->part[idx].type));

        if (tsk_getu32(vs->endian, dlabel_x86->part[idx].size_sec) == 0)
            continue;

        // make sure the first couple are in the image bounds
        if ((idx < 2) && (tsk_getu32(vs->endian,
                    dlabel_x86->part[idx].start_sec) > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("sun_load_i386: Starting sector too large for image");
            return 1;
        }

        // set the entry that covers the entire disk image as DESC
        if ((tsk_getu16(vs->endian, dlabel_x86->part[idx].type) == 5)
            && (tsk_getu32(vs->endian,
                    dlabel_x86->part[idx].start_sec) == 0))
            ptype = TSK_VS_PART_FLAG_META;

        /* Add the partition to the internal sorted list */
        if (NULL == tsk_vs_part_add(vs,
                (TSK_DADDR_T) tsk_getu32(vs->endian,
                    dlabel_x86->part[idx].start_sec),
                (TSK_DADDR_T) tsk_getu32(vs->endian,
                    dlabel_x86->part[idx].size_sec), ptype,
                sun_get_desc(tsk_getu16(vs->endian,
                        dlabel_x86->part[idx].type)), -1, idx)) {
            return 1;
        }
    }

    return 0;
}


/* load a sparc disk label, this is called from the general
 * sun_load_table
 */
static uint8_t
sun_load_table_sparc(TSK_VS_INFO * vs, sun_dlabel_sparc * dlabel_sp)
{
    uint32_t idx = 0;
    uint32_t cyl_conv;
    uint16_t num_parts;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    /* The value to convert cylinders to sectors */
    cyl_conv = tsk_getu16(vs->endian, dlabel_sp->sec_per_tr) *
        tsk_getu16(vs->endian, dlabel_sp->num_head);

    if (tsk_verbose)
        tsk_fprintf(stderr, "load_table_sparc: Number of partitions: %d\n",
            tsk_getu16(vs->endian, dlabel_sp->num_parts));

    num_parts = tsk_getu16(vs->endian, dlabel_sp->num_parts);
    if (num_parts > 8) {
        num_parts = 8;
    }

    /* Cycle through the partitions, there are 8 for sparc */
    for (idx = 0; idx < num_parts; idx++) {
        TSK_VS_PART_FLAG_ENUM ptype = TSK_VS_PART_FLAG_ALLOC;
        uint32_t part_start = cyl_conv * tsk_getu32(vs->endian,
            dlabel_sp->part_layout[idx].start_cyl);

        uint32_t part_size = tsk_getu32(vs->endian,
            dlabel_sp->part_layout[idx].size_blk);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "load_table_sparc: %" PRIu32
                "  Starting Sector: %" PRIu32 "  Size: %" PRIu32
                "  Type: %" PRIu16 "\n", idx, part_start, part_size,
                tsk_getu16(vs->endian, dlabel_sp->part_meta[idx].type));

        if (part_size == 0)
            continue;

        // make sure the first couple are in the image bounds
        if ((idx < 2) && (part_start > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("sun_load_sparc: Starting sector too large for image");
            return 1;
        }

        // set the entry that covers the entire disk image as DESC
        if ((tsk_getu16(vs->endian, dlabel_sp->part_meta[idx].type) == 5)
            && (part_start == 0))
            ptype = TSK_VS_PART_FLAG_META;

        /* Add the partition to the internal sorted list */
        if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) part_start,
                (TSK_DADDR_T) part_size, ptype,
                sun_get_desc(tsk_getu16(vs->endian,
                        dlabel_sp->part_meta[idx].type)), -1, idx))
            return 1;

    }

    return 0;
}


/* 
 * Process the partition table at the sector address 
 *
 * This method just finds out if it is sparc or Intel and then
 * calls the appropriate method
 *
 * Return 0 on success and 1 on error
 */
static uint8_t
sun_load_table(TSK_VS_INFO * vs)
{
    sun_dlabel_sparc *dlabel_sp;
    sun_dlabel_i386 *dlabel_x86;
    char *buf;
    ssize_t cnt;
    TSK_DADDR_T taddr =
        vs->offset / vs->block_size + SUN_SPARC_PART_SOFFSET;
    int result = 0;


    /* Sanity check in case label sizes change */
    if ((sizeof(*dlabel_sp) > vs->block_size) ||
        (sizeof(*dlabel_x86) > vs->block_size)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_BUF);
        tsk_error_set_errstr
            ("sun_load_table: disk labels bigger than block size");
        return 1;
    }

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "sun_load_table: Trying sector: %" PRIuDADDR "\n", taddr);

    if ((buf = tsk_malloc(vs->block_size)) == NULL) {
        goto on_error;
    }

    /* Try the given offset */
    cnt = tsk_vs_read_block
        (vs, SUN_SPARC_PART_SOFFSET, buf, vs->block_size);

    /* If -1 is returned, tsk_errno is already set */
    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("SUN Disk Label in Sector: %" PRIuDADDR,
            taddr);
        goto on_error;
    }


    /* Check the magic value 
     * Both intel and sparc have the magic value in the same location
     *
     * We try both in case someone specifies the exact location of the
     * intel disk label.
     * */
    dlabel_sp = (sun_dlabel_sparc *) buf;
    dlabel_x86 = (sun_dlabel_i386 *) buf;
    if (tsk_vs_guessu16(vs, dlabel_sp->magic, SUN_MAGIC) == 0) {
        if (tsk_getu32(vs->endian, dlabel_sp->sanity) == SUN_SANITY) {
            result = sun_load_table_sparc(vs, dlabel_sp);
            // TODO: I assume based on the existing free that the previous function
            // does not take ownership of buf.
            free(buf);
            return result;
        }
        else if (tsk_getu32(vs->endian, dlabel_x86->sanity) == SUN_SANITY) {
            result = sun_load_table_i386(vs, dlabel_x86);
            // TODO: I assume based on the existing free that the previous function
            // does not take ownership of buf.
            free(buf);
            return result;
        }
    }


    /* Now try the next sector, which is where the intel 
     * could be stored */

    taddr = vs->offset / vs->block_size / SUN_I386_PART_SOFFSET;
    if (tsk_verbose)
        tsk_fprintf(stderr,
            "sun_load_table: Trying sector: %" PRIuDADDR "\n", taddr + 1);

    cnt = tsk_vs_read_block
        (vs, SUN_I386_PART_SOFFSET, buf, vs->block_size);

    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("SUN (Intel) Disk Label in Sector: %"
            PRIuDADDR, taddr);
        goto on_error;
    }

    dlabel_x86 = (sun_dlabel_i386 *) buf;
    if (tsk_vs_guessu16(vs, dlabel_x86->magic, SUN_MAGIC)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("SUN (intel) partition table (Sector: %"
            PRIuDADDR ") %x", taddr, tsk_getu16(vs->endian,
                dlabel_sp->magic));
        goto on_error;
    }

    if (tsk_getu32(vs->endian, dlabel_x86->sanity) != SUN_SANITY) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("SUN (intel) sanity value (Sector: %"
            PRIuDADDR ") %x", taddr, tsk_getu16(vs->endian,
                dlabel_sp->magic));
        goto on_error;
    }

    result = sun_load_table_i386(vs, dlabel_x86);
    // TODO: I assume based on the existing free that the previous function
    // does not take ownership of buf.
    free(buf);
    return result;

on_error:
    if( buf != NULL ) {
        free( buf );
    }
    return 1;
}


static void
sun_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

TSK_VS_INFO *
tsk_vs_sun_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_sun_open: sector size is 0");
        return NULL;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_SUN;
    vs->tag = TSK_VS_INFO_TAG;

    vs->offset = offset;

    /* initialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;

    /* Assign functions */
    vs->close = sun_close;

    /* Load the partitions into the sorted list */
    if (sun_load_table(vs)) {
        sun_close(vs);
        return NULL;
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        sun_close(vs);
        return NULL;
    }

    return vs;
}
