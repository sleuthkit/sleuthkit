/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */

/* 
 * Contains the single raw data file-specific functions and structures.
 */

#ifndef _RAW_H
#define _RAW_H

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *raw_open(const TSK_TCHAR *, unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
#ifdef TSK_WIN32
        HANDLE fd;
#else
        int fd;
#endif
        TSK_OFF_T seek_pos;
    } IMG_RAW_INFO;

#ifdef __cplusplus
}
#endif
#endif
