/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#ifndef _DETECT_ENCRYPTION_H_
#define _DETECT_ENCRYPTION_H_

#include "tsk/base/tsk_base.h"
#include "tsk/img/tsk_img.h"
#include "tsk/base/tsk_base_i.h"
#include <math.h>

// Enum for the type of encryption detected
typedef enum {
    ENCRYPTION_DETECTED_NONE = 0,
    ENCRYPTION_DETECTED_SIGNATURE = 1,
    ENCRYPTION_DETECTED_ENTROPY = 2
} encryption_detected_type;

// Struct for storing the result of the encryption detection
typedef struct encryption_detected_result {
    encryption_detected_type encryptionType;
    char desc[TSK_ERROR_STRING_MAX_LENGTH];
} encryption_detected_result;

encryption_detected_result* detectVolumeEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset);

encryption_detected_result* detectDiskEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset);

#endif