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

#include "MetadataValueVolumeMasterKey.h"

MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {

    if (bufLen < headerLen) {
        registerError("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): Buffer for creating MetadataValueVolumeMasterKey was too short");
        memset(guid, 0, 16);
        return;
    }

    // Format should be:
    // - 16 byte GUID
    // - 8 byte last modification timestamp
    // - 2 byte unknown
    // - 2 byte key protection type
    // - list of metadata entries
    memcpy(guid, buf, 16);
    lastModificationTime = tsk_getu64(TSK_LIT_ENDIAN, &(buf[16]));
    unknown = tsk_getu16(TSK_LIT_ENDIAN, &(buf[24]));
    keyProtectionType = getKeyProtectionTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[26])));

    if (BITLOCKER_STATUS::SUCCESS != readMetadataEntries(&(buf[headerLen]), bufLen - headerLen, properties)) {
        registerError("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): Error reading metadata entries");
    }
};

MetadataValueVolumeMasterKey::~MetadataValueVolumeMasterKey() {
    for (auto it = properties.begin(); it != properties.end(); ++it) {
        if (*it != NULL) {
            delete(*it);
        }
    }
}

#endif