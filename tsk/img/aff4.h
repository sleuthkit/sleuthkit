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

#if HAVE_CONFIG_H
#include "../tsk_config.h"
#endif

#if HAVE_LIBAFF4

#include "tsk_img_i.h"

#include <string>

struct AFF4_Handle;
struct AFF4_Message;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  IMG_INFO img_info;
  AFF4_Handle* handle;
  tsk_lock_t read_lock;   ///< Lock for the handle
} IMG_AFF4_INFO;

TSK_IMG_INFO *aff4_open(int, const TSK_TCHAR * const images[], unsigned int a_ssize);

#ifdef __cplusplus
}
#endif

std::string get_messages(const AFF4_Message* msg);

#endif
#endif
