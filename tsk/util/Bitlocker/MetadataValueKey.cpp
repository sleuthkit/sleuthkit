/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueKey.h"

MetadataValueKey::MetadataValueKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {

    if (bufLen < 4) {
        registerError("MetadataValueKey::MetadataValueKey(): Buffer for creating MetadataValueKey was too short");
        return;
    }

    // We expect 4 bytes for the encryption type (though we only use two bytes) followed by the key
    encryptionType = getEncryptionTypeEnum(tsk_getu32(TSK_LIT_ENDIAN, &(buf[0])) & 0xffff);

    keyLen = bufLen - 4;
    key = (uint8_t*)tsk_malloc(keyLen);
    if (key == nullptr) {
        registerError("MetadataValueKey::MetadataValueKey(): Failed to allocate buffer for key");
        return;
    }

    memcpy(key, &(buf[4]), keyLen);
};

#endif