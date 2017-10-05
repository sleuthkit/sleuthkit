/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2003-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mac.c
 * Contains the internal functions to process and load a Mac partition table.
 */
#include "tsk_vs_i.h"
#include "tsk_mac.h"


/* 
 * Process the partition table at the sector address 
 * 
 * It is loaded into the internal sorted list 
 *
 * Return 1 on error and 0 on success
 */
static uint8_t
mac_load_table(TSK_VS_INFO * vs)
{
    char *part_buf;
    mac_part *part;
    char *table_str;
    uint32_t idx, max_part;
    TSK_DADDR_T taddr = vs->offset / vs->block_size + MAC_PART_SOFFSET;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr, "mac_load_table: Sector: %" PRIuDADDR "\n",
            taddr);

    /* The table can be variable length, so we loop on it 
     * The idx variable shows which round it is
     * Each structure is a block size
     */
    if ((part_buf = tsk_malloc(vs->block_size)) == NULL)
        return 1;
    part = (mac_part *) part_buf;

    max_part = 1;               /* set it to 1 and it will be set in the first loop */
    for (idx = 0; idx < max_part; idx++) {
        uint32_t part_start;
        uint32_t part_size;
        uint32_t part_status;
        char *str;
        ssize_t cnt;
        int flag = 0;


        /* Read the entry */
        cnt = tsk_vs_read_block
            (vs, MAC_PART_SOFFSET + idx, part_buf, vs->block_size);

        /* If -1, then tsk_errno is already set */
        if (cnt != vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2("MAC Partition entry %" PRIuDADDR,
                taddr + idx);
            free(part_buf);
            return 1;
        }


        /* Sanity Check */
        if (idx == 0) {
            /* Set the endian ordering the first time around */
            if (tsk_vs_guessu16(vs, part->magic, MAC_MAGIC)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_MAGIC);
                tsk_error_set_errstr("Mac partition table entry (Sector: %"
                    PRIuDADDR ") %" PRIx16,
                    (taddr + idx), tsk_getu16(vs->endian, part->magic));
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "mac_load: Missing initial magic value\n");
                free(part_buf);
                return 1;
            }

            /* Get the number of partitions */
            max_part = tsk_getu32(vs->endian, part->pmap_size);
        }
        else if (tsk_getu16(vs->endian, part->magic) != MAC_MAGIC) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_MAGIC);
            tsk_error_set_errstr("Mac partition table entry (Sector: %"
                PRIuDADDR ") %" PRIx16, (taddr + idx),
                tsk_getu16(vs->endian, part->magic));
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "mac_load: Missing magic value in entry %" PRIu32 "\n",
                    idx);
            free(part_buf);
            return 1;
        }


        part_start = tsk_getu32(vs->endian, part->start_sec);
        part_size = tsk_getu32(vs->endian, part->size_sec);
        part_status = tsk_getu32(vs->endian, part->status);

        if (tsk_verbose)
            tsk_fprintf(stderr,
                "mac_load: %" PRIu32 "  Starting Sector: %" PRIu32
                "  Size: %" PRIu32 " Type: %s Status: %"PRIu32"\n", idx, part_start,
                part_size, part->type, part_status);

        if (part_size == 0)
            continue;

        if (part_status == 0)
            flag = TSK_VS_PART_FLAG_UNALLOC;
        else
            flag = TSK_VS_PART_FLAG_ALLOC;

        // make sure the first couple are within the bounds of the image.
        if ((idx < 2) && (part_start > max_addr)) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
            tsk_error_set_errstr
                ("mac_load_table: Starting sector too large for image");
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "mac_load: Starting sector too large for image (%"
                    PRIu32 " vs %" PRIu32 ")\n", part_start, max_addr);
            free(part_buf);
            return 1;
        }


        if ((str = tsk_malloc(sizeof(part->name))) == NULL) {
            free(part_buf);
            return 1;
        }

        strncpy(str, (char *) part->type, sizeof(part->name));

        if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) part_start,
                (TSK_DADDR_T) part_size, (TSK_VS_PART_FLAG_ENUM)flag, str, -1,
                idx)) {
            free(part_buf);
            return 1;
        }
    }
    free(part_buf);
    part_buf = NULL;

    // Bail if we didn't find any valid entries
    if (vs->part_count == 0) {
        return 1;
    }

    /* Add an entry for the table length */
    if ((table_str = tsk_malloc(16)) == NULL) {
        return 1;
    }

    snprintf(table_str, 16, "Table");
    if (NULL == tsk_vs_part_add(vs, taddr, max_part, TSK_VS_PART_FLAG_META,
            table_str, -1, -1)) {
        return 1;
    }

    return 0;
}


static void
mac_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

/* 
 * Process img_info as a Mac disk.  Initialize TSK_VS_INFO or return
 * NULL on error
 * */
TSK_VS_INFO *
tsk_vs_mac_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    if (img_info->sector_size == 0) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_mac_open: sector size is 0");
        return NULL;
    }

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_MAC;
    vs->tag = TSK_VS_INFO_TAG;

    /* If an offset was given, then use that too */
    vs->offset = offset;

    //vs->sect_offset = offset + MAC_PART_OFFSET;

    /* initialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;

    /* Assign functions */
    vs->close = mac_close;

    /* Load the partitions into the sorted list */
    if (mac_load_table(vs)) {

        // try some other sector sizes
        uint8_t returnNull = 1;
        if (vs->block_size == 512) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "mac_open: Trying 4096-byte sector size instead of 512-byte\n");
            vs->block_size = 4096;
            returnNull = mac_load_table(vs);
        }
        else if (vs->block_size == 4096) {
            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "mac_open: Trying 512-byte sector size instead of 4096-byte\n");
            vs->block_size = 512;
            returnNull = mac_load_table(vs);
        }

        if (returnNull) {
            mac_close(vs);
            return NULL;
        }
    }

    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        mac_close(vs);
        return NULL;
    }

    return vs;
}
