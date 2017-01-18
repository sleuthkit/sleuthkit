/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2003-2011 Brian Carrier.  All rights reserved
 *
 * This software is distributed under the Common Public License 1.0
 */

/**
 * \file tsk_vs_i.h
 * Contains the internal library definitions for the volume system functions.  This should
 * be included by the code in the volume system library.
 */
#ifndef _TSK_VS_I_H
#define _TSK_VS_I_H

// Include the other internal TSK header files
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"

// include the external vs header file
#include "tsk_vs.h"

#include <sys/types.h>

extern TSK_VS_INFO *tsk_vs_dos_open(TSK_IMG_INFO *, TSK_DADDR_T, uint8_t);
extern TSK_VS_INFO *tsk_vs_mac_open(TSK_IMG_INFO *, TSK_DADDR_T);
extern TSK_VS_INFO *tsk_vs_bsd_open(TSK_IMG_INFO *, TSK_DADDR_T);
extern TSK_VS_INFO *tsk_vs_sun_open(TSK_IMG_INFO *, TSK_DADDR_T);
extern TSK_VS_INFO *tsk_vs_gpt_open(TSK_IMG_INFO *, TSK_DADDR_T);

extern uint8_t tsk_vs_part_unused(TSK_VS_INFO *);
extern TSK_VS_PART_INFO *tsk_vs_part_add(TSK_VS_INFO *, TSK_DADDR_T,
    TSK_DADDR_T, TSK_VS_PART_FLAG_ENUM, char *, int8_t, int8_t);
extern void tsk_vs_part_free(TSK_VS_INFO *);

// Endian macros - actual functions in misc/
#define tsk_vs_guessu16(vs, x, mag)   \
    tsk_guess_end_u16(&(vs->endian), (x), (mag))

#define tsk_vs_guessu32(vs, x, mag)   \
    tsk_guess_end_u32(&(vs->endian), (x), (mag))

#define tsk_vs_guessu64(vs, x, mag)   \
    tsk_guess_end_u64(&(vs->endian), (x), (mag))

#endif
