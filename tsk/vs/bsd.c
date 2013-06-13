/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file bsd.c
 * Contains the internal functions required to process BSD disk labels.
 */
#include "tsk_vs_i.h"
#include "tsk_bsd.h"


/*
 * Return a buffer with a description of the partition type.  The buffer
 * must be freed by the caller.
 */
static char *
bsd_get_desc(uint8_t fstype)
{
    char *str = tsk_malloc(64);
    if (str == NULL)
        return "";

    switch (fstype) {

    case 0:
        strncpy(str, "Unused (0x00)", 64);
        break;
    case 1:
        strncpy(str, "Swap (0x01)", 64);
        break;
    case 2:
        strncpy(str, "Version 6 (0x02)", 64);
        break;
    case 3:
        strncpy(str, "Version 7 (0x03)", 64);
        break;
    case 4:
        strncpy(str, "System V (0x04)", 64);
        break;
    case 5:
        strncpy(str, "4.1BSD (0x05)", 64);
        break;
    case 6:
        strncpy(str, "Eighth Edition (0x06)", 64);
        break;
    case 7:
        strncpy(str, "4.2BSD (0x07)", 64);
        break;
    case 8:
        strncpy(str, "MSDOS (0x08)", 64);
        break;
    case 9:
        strncpy(str, "4.4LFS (0x09)", 64);
        break;
    case 10:
        strncpy(str, "Unknown (0x0A)", 64);
        break;
    case 11:
        strncpy(str, "HPFS (0x0B)", 64);
        break;
    case 12:
        strncpy(str, "ISO9660 (0x0C)", 64);
        break;
    case 13:
        strncpy(str, "Boot (0x0D)", 64);
        break;
    case 14:
        strncpy(str, "Vinum (0x0E)", 64);
        break;
    default:
        snprintf(str, 64, "Unknown Type (0x%.2x)", fstype);
        break;
    }

    return str;
}

/*
 * Process the partition table at the sector address
 *
 * Return 1 on error and 0 if no error
 */
static uint8_t
bsd_load_table(TSK_VS_INFO * a_vs)
{
    char *sect_buf;
    bsd_disklabel *dlabel;
    uint32_t idx = 0;
    ssize_t cnt;
    char *table_str;
    TSK_DADDR_T laddr = a_vs->offset / a_vs->block_size + BSD_PART_SOFFSET;     // used for printing only
    TSK_DADDR_T max_addr = (a_vs->img_info->size - a_vs->offset) / a_vs->block_size;    // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr,
            "bsd_load_table: Table Sector: %" PRIuDADDR "\n", laddr);

    if ((sect_buf = tsk_malloc(a_vs->block_size)) == NULL)
        return 1;
    dlabel = (bsd_disklabel *) sect_buf;

    /* read the block */
    cnt = tsk_vs_read_block
        (a_vs, BSD_PART_SOFFSET, sect_buf, a_vs->block_size);
    if (cnt != a_vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("BSD Disk Label in Sector: %" PRIuDADDR,
            laddr);
        free(sect_buf);
        return 1;
    }

    /* Check the magic  */
    if (tsk_vs_guessu32(a_vs, dlabel->magic, BSD_MAGIC)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("BSD partition table (magic #1) (Sector: %"
            PRIuDADDR ") %" PRIx32, laddr, tsk_getu32(a_vs->endian,
                dlabel->magic));
        free(sect_buf);
        return 1;
    }

    /* Check the second magic value */
    if (tsk_getu32(a_vs->endian, dlabel->magic2) != BSD_MAGIC) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("BSD disk label (magic #2) (Sector: %"
            PRIuDADDR ")  %" PRIx32, laddr, tsk_getu32(a_vs->endian,
                dlabel->magic2));
        free(sect_buf);
        return 1;
    }

    /* Add an entry of 1 length for the table  to the internal structure */
    if ((table_str = tsk_malloc(32)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(table_str, 32, "Partition Table");
    if (NULL == tsk_vs_part_add(a_vs, BSD_PART_SOFFSET,
            (TSK_DADDR_T) 1, TSK_VS_PART_FLAG_META, table_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }

    /* Cycle through the partitions, there are either 8 or 16 */
    for (idx = 0; idx < tsk_getu16(a_vs->endian, dlabel->num_parts); idx++) {

        uint32_t part_start;
        uint32_t part_size;

        part_start = tsk_getu32(a_vs->endian, dlabel->part[idx].start_sec);
        part_size = tsk_getu32(a_vs->endian, dlabel->part[idx].size_sec);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "load_table: %" PRIu32 "  Starting Sector: %" PRIu32
                "  Size: %" PRIu32 "  Type: %d\n", idx, part_start,
                part_size, dlabel->part[idx].fstype);

        if (part_size == 0)
            continue;

        // make sure the first couple are in the image bounds
        if ((idx < 2) && (part_start > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("bsd_load_table: Starting sector too large for image");
            free(sect_buf);
            return 1;
        }


        /* Add the partition to the internal sorted list */
        if (NULL == tsk_vs_part_add(a_vs, (TSK_DADDR_T) part_start,
                (TSK_DADDR_T) part_size, TSK_VS_PART_FLAG_ALLOC,
                bsd_get_desc(dlabel->part[idx].fstype), -1, idx)) {
            free(sect_buf);
            return 1;
        }
    }

    free(sect_buf);
    return 0;
}


static void
bsd_close(TSK_VS_INFO * a_vs)
{
    a_vs->tag = 0;
    tsk_vs_part_free(a_vs);
    free(a_vs);
}

/*
 * analyze the image in img_info and process it as BSD
 * Initialize the TSK_VS_INFO structure
 *
 * Return TSK_VS_INFO or NULL if not BSD or an error
 */
TSK_VS_INFO *
tsk_vs_bsd_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_BSD;
    vs->tag = TSK_VS_INFO_TAG;

    /* use the offset provided */
    vs->offset = offset;

    /* inititialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;

    /* Assign functions */
    vs->close = bsd_close;

    /* Load the partitions into the sorted list */
    if (bsd_load_table(vs)) {
        bsd_close(vs);
        return NULL;
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        bsd_close(vs);
        return NULL;
    }

    return vs;
}
