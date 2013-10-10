/*
 * The Sleuth Kit
 *
 * Brian Carrier [carrier <at> sleuthkit [dot] org]
 * Copyright (c) 2005-2011 Brian Carrier.  All rights reserved 
 *
 * This software is distributed under the Common Public License 1.0
 */
#ifndef _TSK_IMG_I_H
#define _TSK_IMG_I_H

/*
 * Contains the internal library definitions for the disk image functions.  This should
 * be included by the code in the img library. 
 */

// include the base internal header file
#include "tsk/base/tsk_base_i.h"

// include the external disk image header file
#include "tsk_img.h"

// other standard includes
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __cplusplus
extern "C" {
#endif

// Cygwin needs this, but not everyone defines it
#ifndef O_BINARY
#define O_BINARY 0
#endif
extern void *tsk_img_malloc(size_t);
extern void tsk_img_free(void *);
extern TSK_TCHAR **tsk_img_findFiles(const TSK_TCHAR * a_startingName,
    int *a_numFound);

extern const TSK_TCHAR **
    tsk_img_get_names(TSK_IMG_INFO *a_img_info, int *a_num_imgs); 

#ifdef __cplusplus
}
#endif

#endif
