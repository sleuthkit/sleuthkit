/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */

/* 
 * Header files for AFF-specific data structures and functions. 
 */

#ifndef _AFF_H
#define _AFF_H

#if HAVE_LIBAFFLIB

#include <afflib/afflib.h>
// mingw's pthread.h will try to read a config.h if HAVE_CONFIG_H
#if HAVE_CONFIG_H
#undef HAVE_CONFIG_H
#include <afflib/afflib_i.h>
#define HAVE_CONFIG_H 1
#else
#include <afflib/afflib_i.h>
#endif

extern TSK_IMG_INFO *aff_open(const TSK_TCHAR * const images[],
    unsigned int a_ssize);

/** \internal
 * Stores AFF-specific data
 */
typedef struct {
    TSK_IMG_INFO img_info;
    AFFILE *af_file;
    TSK_OFF_T seek_pos;         // shared and protected by cache_lock in IMG_INFO
    uint16_t type;              /* TYPE - uses AF_IDENTIFY_x values */
} IMG_AFF_INFO;

#endif
#endif
