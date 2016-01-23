/*
 * The Sleuth Kit - Add on for Virtual Hard Disk (VHD) image support
 *
 * Copyright (c) 2006, 2011 Joachim Metz <jbmetz@users.sourceforge.net>
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on raw image support of the Sleuth Kit from
 * Brian Carrier.
 */

/* 
 * Header files for VHD-specific data structures and functions. 
 */

#ifndef _TSK_IMG_VHDI_H
#define _TSK_IMG_VHDI_H

#if HAVE_LIBVHDI

#if defined( TSK_WIN32 )
#define LIBVHDI_HAVE_WIDE_CHARACTER_TYPE 1
#endif

#include <libvhdi.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *vhdi_open(int, const TSK_TCHAR * const images[],
        unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
        libvhdi_file_t *handle;
        TSK_TCHAR **images;
        int num_imgs;
        tsk_lock_t read_lock;   // Lock for reads since according to documentation libvhdi is not fully thread safe yet
    } IMG_VHDI_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif // _TSK_IMG_VHDI_H
