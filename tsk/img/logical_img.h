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

#ifndef _LOGICAL_H
#define _LOGICAL_H

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *logical_open(int a_num_img,
        const TSK_TCHAR * const a_images[], unsigned int a_ssize);

    typedef struct {
		TSK_IMG_INFO img_info;
		TSK_TCHAR * base_path;
		uint8_t is_winobj;
    } IMG_LOGICAL_INFO;

#ifdef __cplusplus
}
#endif
#endif
