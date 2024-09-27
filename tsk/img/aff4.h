/*
 * The Sleuth Kit - Add on for AFF4 image support
 *
 * This software is distributed under the Common Public License 1.0
 *
 * Based on EWF image support of the Sleuth Kit from
 * Brian Carrier.
 */

/*
 * Header files for AFF4-specific data structures and functions.
 */

#ifndef _TSK_IMG_AFF4_H
#define _TSK_IMG_AFF4_H

#if HAVE_LIBAFF4

#include <aff4/libaff4-c.h>

#ifdef __cplusplus
extern "C" {
#endif

    extern TSK_IMG_INFO *aff4_open(int, const TSK_TCHAR * const images[], unsigned int a_ssize);

    typedef struct {
        TSK_IMG_INFO img_info;
        AFF4_Handle* handle;
        tsk_lock_t read_lock;   ///< Lock for the handle
    } IMG_AFF4_INFO;

#ifdef __cplusplus
}
#endif
#endif
#endif
