/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#pragma once

#ifdef HAVE_LIBMBEDTLS

#include "tsk/base/tsk_base_i.h"
#include <string>

using namespace std;

#define SHA256_DIGEST_LENGTH 32

enum class BITLOCKER_METADATA_ENTRY_TYPE {
    PROPERTY,
    VOLUME_MASTER_KEY,
    FULL_VOLUME_ENCRYPTION_KEY,
    VALIDATION,
    STARTUP_KEY,
    DESCRIPTION,
    VOLUME_HEADER_BLOCK,
    UNKNOWN
};
BITLOCKER_METADATA_ENTRY_TYPE getMetadataEntryTypeEnum(uint16_t val);
string convertMetadataEntryTypeToString(BITLOCKER_METADATA_ENTRY_TYPE type);

enum class BITLOCKER_METADATA_VALUE_TYPE {
    ERASED,
    KEY,
    UNICODE_STRING,
    STRETCH_KEY,
    USE_KEY,
    AES_CCM_ENCRYPTED_KEY,
    TPM_ENCODED_KEY,
    VALIDATION,
    VOLUME_MASTER_KEY,
    EXTERNAL_KEY,
    UPDATE,
    ERROR_VAL,
    OFFSET_AND_SIZE,
    UNKNOWN
};
BITLOCKER_METADATA_VALUE_TYPE getMetadataValueTypeEnum(uint16_t val);
string convertMetadataValueTypeToString(BITLOCKER_METADATA_VALUE_TYPE type);

enum class BITLOCKER_KEY_PROTECTION_TYPE {
    CLEAR_KEY,
    TPM,
    STARTUP_KEY,
    TPM_AND_PIN,
    RECOVERY_PASSWORD,
    PASSWORD,
    UNKNOWN
};
BITLOCKER_KEY_PROTECTION_TYPE getKeyProtectionTypeEnum(uint16_t val);
string convertKeyProtectionTypeToString(BITLOCKER_KEY_PROTECTION_TYPE type);

enum class BITLOCKER_ENCRYPTION_TYPE {
    STRETCH_KEY,
    AES_CCM_256,
    EXTERN_KEY,
    VMK,
    HASH_256,
    AES_CBC_128_DIFF,
    AES_CBC_256_DIFF,
    AES_CBC_128,
    AES_CBC_256,
    AES_XTS_128,
    AES_XTS_256,
    UNKNOWN
};
BITLOCKER_ENCRYPTION_TYPE getEncryptionTypeEnum(uint16_t val);
string convertEncryptionTypeToString(BITLOCKER_ENCRYPTION_TYPE type);
bool isAESCBC(BITLOCKER_ENCRYPTION_TYPE type);
bool isAESXTS(BITLOCKER_ENCRYPTION_TYPE type);
bool usesDiffuser(BITLOCKER_ENCRYPTION_TYPE type);

enum class BITLOCKER_STATUS {
    SUCCESS,
    NOT_BITLOCKER,
    WRONG_PASSWORD,
    NEED_PASSWORD,
    UNSUPPORTED_KEY_PROTECTION_TYPE,
    GENERAL_ERROR
};

#endif