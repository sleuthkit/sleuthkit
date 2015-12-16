/*
 * The Sleuth Kit - Add on for VMDK (Virtual Machine Disk) image support
 *
 * Copyright (c) 2006, 2011 Joachim Metz <jbmetz@users.sourceforge.net>
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/* 
 * Header files for VMDK-specific data structures and functions. 
 */

#ifndef _TSK_IMG_VMDK_H
#define _TSK_IMG_VMDK_H

#if HAVE_LIBVMDK

// we used to check only for TSK_WIN32, but that fails on mingw
//#if defined(_MSC_VER)
//#include <config_msc.h>
//#endif

#if defined( TSK_WIN32 )
#define LIBVMDK_HAVE_WIDE_CHARACTER_TYPE 1
#endif

#include <libvmdk.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *vmdk_open(int, const TSK_TCHAR * const images[],
        unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
        libvmdk_handle_t *handle;
        TSK_TCHAR **images;
        int num_imgs;
        tsk_lock_t read_lock;   // Lock for reads since according to documentation libvmdk is not fully thread safe yet
    } IMG_VMDK_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
