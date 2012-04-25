/*
 * The Sleuth Kit - Add on for Expert Witness Compression Format (EWF) image support
 *
 * Copyright (c) 2006, 2011 Joachim Metz <jbmetz@users.sourceforge.net>
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/* 
 * Header files for EWF-specific data structures and functions. 
 */

#ifndef _TSK_IMG_EWF_H
#define _TSK_IMG_EWF_H

#if HAVE_LIBEWF

// we used to check only for TSK_WIN32, but that fails on mingw
#if defined(_MSC_VER)
#include <config_msc.h>
#endif

#include <libewf.h>

// libewf version 2 no longer defines LIBEWF_HANDLE
#undef HAVE_LIBEWF_V2_API
#if !defined( LIBEWF_HANDLE )
#define HAVE_LIBEWF_V2_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *ewf_open(int, const TSK_TCHAR * const images[],
        unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
        libewf_handle_t *handle;
        char md5hash[33];
        int md5hash_isset;
        TSK_TCHAR **images;
        int num_imgs;
        uint8_t used_ewf_glob;  // 1 if libewf_glob was used during open
        tsk_lock_t read_lock;   ///< Lock for reads since libewf is not thread safe -- only works if you have a single instance of EWF_INFO for all threads.
    } IMG_EWF_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
