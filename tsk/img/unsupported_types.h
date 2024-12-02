/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#ifndef _UNSUPPORTED_TYPES_H_
#define _UNSUPPORTED_TYPES_H_

#include "tsk/base/tsk_base.h"
#include "tsk/img/tsk_img.h"
#include "tsk/base/tsk_base_i.h"

#ifdef __cplusplus
extern "C" {
#endif
extern char* detectUnsupportedImageType(TSK_IMG_INFO * img_info);
#ifdef __cplusplus
}
#endif

#endif