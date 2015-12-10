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
#if defined(_MSC_VER)
#include <config_msc.h>
#endif

// ELTODO perhaps undefine HAVE_MULTI_THREAD_SUPPORT
// ELTODO - are all of these neccessary? I guess there is no downside to having them...
#define HAVE_LOCAL_LIBCSTRING 1
#define HAVE_LOCAL_LIBCERROR 1
#define HAVE_LOCAL_LIBCTHREADS 1
#define HAVE_LOCAL_LIBCDATA 1
#define HAVE_LOCAL_LIBCLOCALE 1
#define HAVE_LOCAL_LIBCNOTIFY 1
#define HAVE_LOCAL_LIBCSPLIT 1
#define HAVE_LOCAL_LIBUNA 1
#define HAVE_LOCAL_LIBCFILE 1
#define HAVE_LOCAL_LIBCPATH 1
#define HAVE_LOCAL_LIBBFIO 1
#define HAVE_LOCAL_LIBFCACHE 1
#define HAVE_LOCAL_LIBFDATA 1
#define HAVE_LOCAL_LIBFVALUE 1
#define ZLIB_DLL 1
#define LIBVMDK_DLL_EXPORT 1

#include <common.h>
#include <libcerror_definitions.h>
#include <libcerror_error.h>
#include <libcerror_system.h>
#include <libcerror_types.h>
#include <libcstring_definitions.h>
#include <libcstring_narrow_string.h>
#include <libcstring_system_string.h>
#include <libcstring_types.h>
#include <libcstring_wide_string.h>
#include <libvmdk.h>        // libvmdk.h needs to be last to take into account all #defines from other header files

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
        tsk_lock_t read_lock;   ///< Lock for reads since libvmdk is not thread safe -- only works if you have a single instance of VMDK_INFO for all threads.
    } IMG_VMDK_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
