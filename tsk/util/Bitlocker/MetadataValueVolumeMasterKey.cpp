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

MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen) : MetadataValue(valueType) {

    if (bufLen < m_headerLen) {
        registerError("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): Buffer for creating MetadataValueVolumeMasterKey was too short");
        memset(m_guid, 0, 16);
        return;
    }

    // Format should be:
    // - 16 byte GUID
    // - 8 byte last modification timestamp
    // - 2 byte unknown
    // - 2 byte key protection type
    // - list of metadata entries
    memcpy(m_guid, buf, 16);
    writeDebug("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): GUID: " + convertByteArrayToString(m_guid, 16));
    m_lastModificationTime = tsk_getu64(TSK_LIT_ENDIAN, &(buf[16]));
    writeDebug("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): Last modification time: " + convertUint64ToString(m_lastModificationTime));
    m_unknown = tsk_getu16(TSK_LIT_ENDIAN, &(buf[24]));
    m_keyProtectionType = getKeyProtectionTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[26])));

    if (BITLOCKER_STATUS::SUCCESS != readMetadataEntries(&(buf[m_headerLen]), bufLen - m_headerLen, m_properties)) {
        registerError("MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(): Error reading metadata entries");
    }
};

MetadataValueVolumeMasterKey::~MetadataValueVolumeMasterKey() {
    for (auto it = m_properties.begin(); it != m_properties.end(); ++it) {
        if (*it != NULL) {
            delete *it;
        }
    }
}

#endif