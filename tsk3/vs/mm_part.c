/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/** \file mm_part.c
 * Contains the functions need to create, maintain, and access the linked list of
 * partitions in a volume.
 */
#include "tsk_vs_i.h"


/** 
 * Add a partition to a sorted list 
 * @param a_vs Volume system that partition belongs to
 * @param a_start Starting sector address of volume (relative to start of volume)
 * @param len Length of volume in sectors
 * @param type Type of volume
 * @param desc Text description of partition.  Note that this is not copied
 * and must not be freed until the volume system has been closed.
 * @param table The table ID that the volume was located in or -1 for volumes not in a partition table.
 * @param slot The slot number in the partition table that the volume was located in or -1 for volumes not in a partition table.
 * @returns Pointer to structure that was created for the partition or NULL on error.
 */
TSK_VS_PART_INFO *
tsk_vs_part_add(TSK_VS_INFO * a_vs, TSK_DADDR_T a_start, TSK_DADDR_T len,
    TSK_VS_PART_FLAG_ENUM type, char *desc, int8_t table, int8_t slot)
{
    TSK_VS_PART_INFO *part;
    TSK_VS_PART_INFO *cur_part;

    if ((part =
            (TSK_VS_PART_INFO *) tsk_malloc(sizeof(TSK_VS_PART_INFO))) ==
        NULL) {
        return NULL;
    }

    /* set the values */
    part->next = NULL;
    part->prev = NULL;
    part->start = a_start;
    part->len = len;
    part->desc = desc;
    part->table_num = table;
    part->slot_num = slot;
    part->flags = type;
    part->vs = a_vs;
    part->addr = 0;
    part->tag = TSK_VS_PART_INFO_TAG;

    /* is this the first entry in the list */
    if (a_vs->part_list == NULL) {
        a_vs->part_list = part;
        a_vs->part_count = 1;
        return part;
    }

    /* Cycle through to find the correct place to put it into */
    for (cur_part = a_vs->part_list; cur_part != NULL;
        cur_part = cur_part->next) {
        /* The one to add starts before this partition */
        if (cur_part->start > part->start) {
            part->next = cur_part;
            part->prev = cur_part->prev;
            if (part->prev)
                part->prev->next = part;
            cur_part->prev = part;

            /* If we are now the head update a_vs */
            if (part->prev == NULL)
                a_vs->part_list = part;

            /* update the count and address numbers */
            a_vs->part_count++;
            part->addr = cur_part->addr;
            for (; cur_part != NULL; cur_part = cur_part->next)
                cur_part->addr++;

            return part;
        }

        /* the one to add is bigger then current and the list is done */
        else if (cur_part->next == NULL) {
            cur_part->next = part;
            part->prev = cur_part;

            /* Update partition counts and addresses */
            a_vs->part_count++;
            part->addr = cur_part->addr + 1;
            return part;
        }

        /* The one to add fits in between this and the next */
        else if (cur_part->next->start > part->start) {
            part->prev = cur_part;
            part->next = cur_part->next;
            cur_part->next->prev = part;
            cur_part->next = part;

            /* Update partition counts and addresses */
            a_vs->part_count++;
            part->addr = cur_part->addr + 1;
            for (cur_part = part->next; cur_part != NULL;
                cur_part = cur_part->next)
                cur_part->addr++;
            return part;
        }
    }
    return NULL;
}

/**
 * Identify regions in the partition list where there are unused sectors
 * and create new entries for them.
 *
 * @param a_vs Pointer to open volume system
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_vs_part_unused(TSK_VS_INFO * a_vs)
{
    TSK_VS_PART_INFO *part = a_vs->part_list;
    TSK_DADDR_T prev_end = 0;

    /* prev_ent is set to where the previous entry stopped  plus 1 */
    for (part = a_vs->part_list; part != NULL; part = part->next) {

        // ignore the META volume
        if (part->flags & TSK_VS_PART_FLAG_META)
            continue;

        // there is space before current and previous volume
        if (part->start > prev_end) {
            char *str;
            if ((str = tsk_malloc(12)) == NULL)
                return 1;

            snprintf(str, 12, "Unallocated");
            if (NULL == tsk_vs_part_add(a_vs, prev_end,
                    part->start - prev_end, TSK_VS_PART_FLAG_UNALLOC, str,
                    -1, -1)) {
                free(str);
                return 1;
            }
        }

        prev_end = part->start + part->len;
    }

    /* Is there unallocated space at the end? */
    if (prev_end < (TSK_DADDR_T) (a_vs->img_info->size / a_vs->block_size)) {
        char *str;
        if ((str = tsk_malloc(12)) == NULL)
            return 1;

        snprintf(str, 12, "Unallocated");
        if (NULL == tsk_vs_part_add(a_vs, prev_end,
                a_vs->img_info->size / a_vs->block_size - prev_end,
                TSK_VS_PART_FLAG_UNALLOC, str, -1, -1)) {
            free(str);
            return 1;
        }
    }

    return 0;
}

/* 
 * free the buffer with the description 
 */
void
tsk_vs_part_free(TSK_VS_INFO * a_vs)
{
    TSK_VS_PART_INFO *part = a_vs->part_list;
    TSK_VS_PART_INFO *part2;

    while (part) {
        if (part->desc)
            free(part->desc);
        part->tag = 0;
        part2 = part->next;
        free(part);
        part = part2;
    }
    a_vs->part_list = NULL;

    return;
}

/**
 * \ingroup vslib
 * Return handle to a volume in the volume system. 
 *
 * @param a_vs Open volume system
 * @param a_idx Index for volume to return (0-based)
 * @returns Handle to volume or NULL on error
 */
const TSK_VS_PART_INFO *
tsk_vs_part_get(const TSK_VS_INFO * a_vs, TSK_PNUM_T a_idx)
{
    TSK_VS_PART_INFO *part;

    if ((a_vs == NULL) || (a_vs->tag != TSK_VS_INFO_TAG)) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr
            ("tsk_vs_part_get: pointer is NULL or has unallocated structures");
        return NULL;
    }

    if (a_idx >= a_vs->part_count) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_ARG);
        tsk_error_set_errstr("tsk_vs_part_get: Volume address is too big");
        return NULL;
    }

    for (part = a_vs->part_list; part != NULL; part = part->next) {
        if (part->addr == a_idx)
            return part;
    }

    return NULL;
}


/** 
 * \ingroup vslib
 * Walk a range of partitions and pass the data to a callback function. 
 * 
 * @param a_vs Pointer to open volume system
 * @param a_start Address of first partition to walk from.
 * @param a_last Address of last partition to walk to.
 * @param a_flags Flags that are used to identify which of the partitions in the range should be returned (if 0, all partitions will be returned).
 * @param a_action Callback action to call for each partition.
 * @param a_ptr Pointer to data that will be passed to callback.
 * @returns 1 on error and 0 on success
 */
uint8_t
tsk_vs_part_walk(TSK_VS_INFO * a_vs, TSK_PNUM_T a_start, TSK_PNUM_T a_last,
    TSK_VS_PART_FLAG_ENUM a_flags, TSK_VS_PART_WALK_CB a_action,
    void *a_ptr)
{
    TSK_VS_PART_INFO *part;

    if (a_start >= a_vs->part_count) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_WALK_RNG);
        tsk_error_set_errstr
            ("tsk_vs_part_walk: Start partition too large: %" PRIuPNUM "",
            a_start);
        return 1;
    }

    if (a_last >= a_vs->part_count) {
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_VS_WALK_RNG);
        tsk_error_set_errstr("tsk_vs_part_walk: End partition too large: %"
            PRIuPNUM "", a_last);
        return 1;
    }

    if (a_flags == 0) {
        a_flags |=
            (TSK_VS_PART_FLAG_ALLOC | TSK_VS_PART_FLAG_UNALLOC |
            TSK_VS_PART_FLAG_META);
    }

    for (part = a_vs->part_list; part != NULL; part = part->next) {
        if ((part->addr >= a_start) && ((part->flags & a_flags) != 0)) {
            int retval;
            retval = a_action(a_vs, part, a_ptr);
            if (retval == TSK_WALK_STOP) {
                return 0;
            }
            else if (retval == TSK_WALK_ERROR) {
                return 1;
            }
        }

        if (part->addr >= a_last)
            break;
    }
    return 0;
}
