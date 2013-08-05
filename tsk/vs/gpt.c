/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2006-2011 Brian Carrier, Basis Technology.  All rights reserved
 * Copyright (c) 2004-2005 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file gpt.c
 * The internal functions required to process the GPT GUID Partiition Table.
 */
#include "tsk_vs_i.h"
#include "tsk_gpt.h"
#include "tsk_dos.h"


/* 
 * Process the partition table at the sector address 
 * 
 * It is loaded into the internal sorted list 
 */
static uint8_t
gpt_load_table(TSK_VS_INFO * vs)
{
    gpt_head *head;
    gpt_entry *ent;
    dos_sect *dos_part;
    unsigned int i, a;
    uint32_t ent_size;
    char *safe_str, *head_str, *tab_str, *ent_buf;
    ssize_t cnt;
    char *sect_buf;
    TSK_DADDR_T taddr = vs->offset / vs->block_size + GPT_PART_SOFFSET;
    TSK_DADDR_T max_addr = (vs->img_info->size - vs->offset) / vs->block_size;  // max sector

    if (tsk_verbose)
        tsk_fprintf(stderr, "gpt_load_table: Sector: %" PRIuDADDR "\n",
            taddr);

    if ((sect_buf = tsk_malloc(vs->block_size)) == NULL)
        return 1;
    dos_part = (dos_sect *) sect_buf;

    cnt = tsk_vs_read_block
        (vs, GPT_PART_SOFFSET, sect_buf, vs->block_size);
    /* if -1, then tsk_errno is already set */
    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2
            ("Error reading DOS safety partition table in Sector: %"
            PRIuDADDR, taddr);
        free(sect_buf);
        return 1;
    }

    /* Sanity Check */
    if (tsk_vs_guessu16(vs, dos_part->magic, DOS_MAGIC)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr
            ("Missing DOS safety partition (invalid magic) (Sector: %"
            PRIuDADDR ")", taddr);
        free(sect_buf);
        return 1;
    }

    if (dos_part->ptable[0].ptype != GPT_DOS_TYPE) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr
            ("Missing DOS safety partition (invalid type in table: %d)",
            dos_part->ptable[0].ptype);
        free(sect_buf);
        return 1;
    }

    /* Read the GPT header */
    head = (gpt_head *) sect_buf;
    cnt = tsk_vs_read_block
        (vs, GPT_PART_SOFFSET + 1, sect_buf, vs->block_size);
    if (cnt != vs->block_size) {
        if (cnt >= 0) {
            tsk_error_reset();
            tsk_error_set_errno(TSK_ERR_VS_READ);
        }
        tsk_error_set_errstr2("GPT Header structure in Sector: %"
            PRIuDADDR, taddr + 1);
        free(sect_buf);
        return 1;
    }

    if (tsk_getu64(vs->endian, &head->signature) != GPT_HEAD_SIG) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("GPT Header: %" PRIx64, tsk_getu64(vs->endian,
                &head->signature));
        free(sect_buf);
        return 1;
    }

    // now that we checked the sig, lets make the meta  entries
    if ((safe_str = tsk_malloc(16)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(safe_str, 16, "Safety Table");
    if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) 0, (TSK_DADDR_T) 1,
            TSK_VS_PART_FLAG_META, safe_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }


    if ((head_str = tsk_malloc(16)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(head_str, 16, "GPT Header");
    if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) 1,
            (TSK_DADDR_T) ((tsk_getu32(vs->endian,
                        &head->head_size_b) + (vs->block_size -
                        1)) / vs->block_size), TSK_VS_PART_FLAG_META,
            head_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }

    /* Allocate a buffer for each table entry */
    ent_size = tsk_getu32(vs->endian, &head->tab_size_b);
    if (ent_size < sizeof(gpt_entry)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_MAGIC);
        tsk_error_set_errstr("Header reports partition entry size of %"
            PRIu32 " and not %" PRIuSIZE "", ent_size, sizeof(gpt_entry));
        free(sect_buf);
        return 1;
    }

    if ((tab_str = tsk_malloc(20)) == NULL) {
        free(sect_buf);
        return 1;
    }

    snprintf(tab_str, 20, "Partition Table");
    if (NULL == tsk_vs_part_add(vs, (TSK_DADDR_T) tsk_getu64(vs->endian,
                &head->tab_start_lba),
            (TSK_DADDR_T) ((ent_size * tsk_getu32(vs->endian,
                        &head->tab_num_ent) + (vs->block_size -
                        1)) / vs->block_size), TSK_VS_PART_FLAG_META,
            tab_str, -1, -1)) {
        free(sect_buf);
        return 1;
    }


    /* Process the partition table */
    if ((ent_buf = tsk_malloc(vs->block_size)) == NULL) {
        free(sect_buf);
        return 1;
    }

    i = 0;
    for (a = 0; i < tsk_getu32(vs->endian, &head->tab_num_ent); a++) {
        char *name;

        /* Read a sector */
        cnt = tsk_vs_read_block(vs,
            tsk_getu64(vs->endian, &head->tab_start_lba) + a,
            ent_buf, vs->block_size);
        if (cnt != vs->block_size) {
            if (cnt >= 0) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_READ);
            }
            tsk_error_set_errstr2
                ("Error reading GPT partition table sector : %" PRIuDADDR,
                tsk_getu64(vs->endian, &head->tab_start_lba) + a);
            free(ent_buf);
            free(sect_buf);
            return 1;
        }

        /* Process the sector */
        ent = (gpt_entry *) ent_buf;
        for (; (uintptr_t) ent < (uintptr_t) ent_buf + vs->block_size &&
            i < tsk_getu32(vs->endian, &head->tab_num_ent); i++) {

            UTF16 *name16;
            UTF8 *name8;
            int retVal;

            if (tsk_verbose)
                tsk_fprintf(stderr,
                    "gpt_load: %d  Starting Sector: %" PRIu64
                    "  End: %" PRIu64 " Flag: %" PRIx64 "\n", i,
                    tsk_getu64(vs->endian, ent->start_lba),
                    tsk_getu64(vs->endian, ent->end_lba),
                    tsk_getu64(vs->endian, ent->flags));


            if (tsk_getu64(vs->endian, ent->start_lba) == 0) {
                ent++;
                continue;
            }

            // make sure the first couple are in the image bounds
            if ((i < 2)
                && (tsk_getu64(vs->endian, ent->start_lba) > max_addr)) {
                tsk_error_reset();
                tsk_error_set_errno(TSK_ERR_VS_BLK_NUM);
                tsk_error_set_errstr
                    ("gpt_load_table: Starting sector too large for image");
                free(sect_buf);
                free(ent_buf);
                return 1;
            }


            if ((name = tsk_malloc(256)) == NULL) {
                free(sect_buf);
                free(ent_buf);
                return 1;
            }

            name16 = (UTF16 *) ((uintptr_t) ent->name);
            name8 = (UTF8 *) name;

            retVal =
                tsk_UTF16toUTF8(vs->endian, (const UTF16 **) &name16,
                (UTF16 *) ((uintptr_t) name16 + sizeof(ent->name)),
                &name8,
                (UTF8 *) ((uintptr_t) name8 + 256), TSKlenientConversion);

            if (retVal != TSKconversionOK) {
                if (tsk_verbose)
                    tsk_fprintf(stderr,
                        "gpt_load_table: Error converting name to UTF8: %d\n",
                        retVal);
                *name = '\0';
            }

            if (NULL == tsk_vs_part_add(vs,
                    (TSK_DADDR_T) tsk_getu64(vs->endian, ent->start_lba),
                    (TSK_DADDR_T) (tsk_getu64(vs->endian,
                            ent->end_lba) - tsk_getu64(vs->endian,
                            ent->start_lba) + 1), TSK_VS_PART_FLAG_ALLOC,
                    name, -1, i)) {
                free(sect_buf);
                free(ent_buf);
                return 1;
            }

            ent++;
        }
    }

    free(sect_buf);
    free(ent_buf);
    return 0;
}

static void
gpt_close(TSK_VS_INFO * vs)
{
    vs->tag = 0;
    tsk_vs_part_free(vs);
    free(vs);
}

TSK_VS_INFO *
tsk_vs_gpt_open(TSK_IMG_INFO * img_info, TSK_DADDR_T offset)
{
    TSK_VS_INFO *vs;

    // clean up any errors that are lying around
    tsk_error_reset();

    vs = (TSK_VS_INFO *) tsk_malloc(sizeof(*vs));
    if (vs == NULL)
        return NULL;

    vs->img_info = img_info;
    vs->vstype = TSK_VS_TYPE_GPT;
    vs->tag = TSK_VS_INFO_TAG;

    /* If an offset was given, then use that too */
    vs->offset = offset;

    /* inititialize settings */
    vs->part_list = NULL;
    vs->part_count = 0;
    vs->endian = 0;
    vs->block_size = img_info->sector_size;

    /* Assign functions */
    vs->close = gpt_close;

    /* Load the partitions into the sorted list */
    if (gpt_load_table(vs)) {
        int found = 0;
        if (tsk_verbose)
            tsk_fprintf(stderr, "gpt_open: Trying other sector sizes\n");

        /* Before we give up, lets try some other sector sizes */
        vs->block_size = 512;
        while (vs->block_size <= 8192) {
            if (tsk_verbose)
                tsk_fprintf(stderr, "gpt_open: Trying sector size: %d\n",
                    vs->block_size);

            if (gpt_load_table(vs)) {
                vs->block_size *= 2;
                continue;
            }
            found = 1;
            break;
        }

        if (found == 0) {
            gpt_close(vs);
            return NULL;
        }
    }


    /* fill in the sorted list with the 'unknown' values */
    if (tsk_vs_part_unused(vs)) {
        gpt_close(vs);
        return NULL;
    }

    return vs;
}
