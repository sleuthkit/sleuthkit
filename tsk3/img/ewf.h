/*
 * The Sleuth Kit - Add on for EWF image support
 * Eye Witness Compression Format Support
 *
 * Joachim Metz <metz@studenten.net>
 * Copyright (c) 2006 Joachim Metz.  All rights reserved 
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/* 
 * Header files for EWF-specific data structures and functions. 
 */

#ifndef _EWF_H
#define _EWF_H

#if HAVE_LIBEWF

#if defined(TSK_WIN32)
#include <config_msc.h>
#endif

#include <libewf.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *ewf_open(int, const TSK_TCHAR * const images[],
        unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
        LIBEWF_HANDLE *handle;
        char md5hash[33];
        int md5hash_isset;
    } IMG_EWF_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
