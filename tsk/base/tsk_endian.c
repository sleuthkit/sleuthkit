/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved 
 *
 * Copyright (c) 2002 Brian Carrier, @stake Inc.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 *
 */

#include "tsk_base_i.h"

/** \file tsk_endian.c
 * Contains the routines to read data in different endian orderings. 
 */

/* A temporary data structure with an endian field */
typedef struct {
    uint8_t endian;
} tmp_ds;

/** \internal
 * Analyze an array of bytes and compare it to a target value to
 * determine which byte order the array is stored in. 
 *
 * @param flag Pointer to location where proper endian flag should be stored.
 * @param x Pointer to array of bytes to analyze.
 * @param val Target value to compare to
 * @returns 1 if match cannot be made, 0 if it can. 
 */
uint8_t
tsk_guess_end_u16(TSK_ENDIAN_ENUM * flag, uint8_t * x, uint16_t val)
{
    /* try little */
    if (tsk_getu16(TSK_LIT_ENDIAN, x) == val) {
        *flag = TSK_LIT_ENDIAN;
        return 0;
    }

    /* ok, big now */
    if (tsk_getu16(TSK_BIG_ENDIAN, x) == val) {
        *flag = TSK_BIG_ENDIAN;
        return 0;
    }

    /* didn't find it */
    return 1;
}

/** \internal
 * same idea as tsk_guess_end_u16 except that val is a 32-bit value
 *
* @param flag Pointer to location where proper endian flag should be stored.
* @param x Pointer to array of bytes to analyze.
* @param val Target value to compare to
* @returns 1 if match cannot be made, 0 if it can. 
 */
uint8_t
tsk_guess_end_u32(TSK_ENDIAN_ENUM * flag, uint8_t * x, uint32_t val)
{
    /* try little */
    if (tsk_getu32(TSK_LIT_ENDIAN, x) == val) {
        *flag = TSK_LIT_ENDIAN;
        return 0;
    }

    /* ok, big now */
    if (tsk_getu32(TSK_BIG_ENDIAN, x) == val) {
        *flag = TSK_BIG_ENDIAN;
        return 0;
    }

    return 1;
}
