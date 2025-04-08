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

#include "MetadataEntry.h"
#include "MetadataValue.h"

/**
* Create a MetadataEntry from the given buffer.
*
* @param buf     Data buffer
* @param bufLen  Size of data buffer
*
* @return The new MetadataEntry (must be freed by caller). Will return nullptr on failure.
*/
MetadataEntry* MetadataEntry::createMetadataEntry(uint8_t* buf, size_t bufLen) {
    if (bufLen < HEADER_SIZE) {
        writeError("MetadataEntry::createMetadataEntry: Insufficient bytes to read header");
        return nullptr;
    }

    // Read the header
    uint16_t size = tsk_getu32(TSK_LIT_ENDIAN, &(buf[0]));
    BITLOCKER_METADATA_ENTRY_TYPE entryType = getMetadataEntryTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[2])));
    BITLOCKER_METADATA_VALUE_TYPE valueType = getMetadataValueTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[4])));

    // Validation
    if (size < HEADER_SIZE) {
        writeError("MetadataEntry::createMetadataEntry: Size field is too small");
        return nullptr;
    }
    if (size > bufLen) {
        writeError("MetadataEntry::createMetadataEntry: Insufficient bytes to read property value");
        return nullptr;
    }
    if (valueType == BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN) {
        writeDebug(string("MetadataEntry::createMetadataEntry: Unhandled value type " + to_string(tsk_getu16(TSK_LIT_ENDIAN, &(buf[4])))));
        writeDebug("MetadataEntry::createMetadataEntry:  Contents: " + convertByteArrayToString(&(buf[8]), size - HEADER_SIZE));
    }

    // Read and create the value
    MetadataValue* metadataValue = createMetadataValue(valueType, &(buf[8]), size - HEADER_SIZE);
    if (metadataValue == nullptr) {
        return nullptr;
    }
    if (!metadataValue->wasLoadedSuccessfully()) {
        delete metadataValue;
        return nullptr;
    }

    // Create the entry
    MetadataEntry* entry = new MetadataEntry();
    if (entry == nullptr) {
        writeError("MetadataEntry::createMetadataEntry: Error allocating memory");
        delete metadataValue;
        return nullptr;
    }

    entry->m_size = size;
    entry->m_entryType = entryType;
    entry->m_valueType = valueType;
    entry->m_version = tsk_getu16(TSK_LIT_ENDIAN, &(buf[6]));
    entry->m_metadataValue = metadataValue;

    return entry;
}

MetadataEntry::MetadataEntry() {
    m_size = 0;
    m_entryType = BITLOCKER_METADATA_ENTRY_TYPE::UNKNOWN;
    m_valueType = BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN;
    m_version = 0;
    m_metadataValue = nullptr;
}

MetadataEntry::~MetadataEntry() {
    if (m_metadataValue != nullptr) {
        delete m_metadataValue;
        m_metadataValue = nullptr;
    }
}

#endif