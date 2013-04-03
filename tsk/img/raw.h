/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
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

    extern TSK_IMG_INFO *raw_open(int a_num_img,
        const TSK_TCHAR * const a_images[], unsigned int a_ssize);

#define SPLIT_CACHE	15

    typedef struct {
#ifdef TSK_WIN32
        HANDLE fd;
#else
        int fd;
#endif
        int image;
        TSK_OFF_T seek_pos;
    } IMG_SPLIT_CACHE;

    typedef struct {
        TSK_IMG_INFO img_info;
        int num_img;
        uint8_t is_winobj;

        // the following are protected by cache_lock in IMG_INFO
        TSK_TCHAR **images;
        TSK_OFF_T *max_off;
        int *cptr;              /* exists for each image - points to entry in cache */
        IMG_SPLIT_CACHE cache[SPLIT_CACHE];     /* small number of fds for open images */
        int next_slot;
    } IMG_RAW_INFO;

#ifdef __cplusplus
}
#endif
#endif
