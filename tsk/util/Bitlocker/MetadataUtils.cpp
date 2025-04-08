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

#include "MetadataUtils.h"

#include "MetadataEntry.h"
#include "MetadataValueStretchKey.h"
#include "MetadataValueVolumeMasterKey.h"
#include "MetadataValueAesCcmEncryptedKey.h"
#include "MetadataValueOffsetAndSize.h"
#include "MetadataValueUnicode.h"
#include "MetadataValueKey.h"
#include "BitlockerUtils.h"

/**
* Parse metadata entries from the given buffer.
*
* @param metadataEntryBuffer     Data buffer
* @param metadataEntriesBufSize  Size of metadataEntryBuffer
* @param entries                 Will hold the parsed entries
*
* @return SUCCESS if all entries were parsed successfully, GENERAL_ERROR otherwise
*/
BITLOCKER_STATUS readMetadataEntries(uint8_t* metadataEntryBuffer, size_t metadataEntriesBufSize, list<MetadataEntry*>& entries) {
    size_t index = 0;
    while (index < metadataEntriesBufSize) {

        MetadataEntry* entry = MetadataEntry::createMetadataEntry(&(metadataEntryBuffer[index]), metadataEntriesBufSize - index);
        if (entry == NULL) {
            writeError("readMetadataEntries: Error creating metadata entry");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        if (entry->getSize() == 0) {
            // Protect against infinite loop - size should not be zero.
            writeError("readMetadataEntries: Entry size was zero");
            delete entry; // Don't save this
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        entries.push_back(entry);
        index += entry->getSize();
    }
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Get all metadata entries matching the given type and value type.
*
* @param entries     Entries to search
* @param entryType   Entry type
* @param valueType   Value type
* @param results     Will hold any matching entries found
*/
void getMetadataEntries(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_ENTRY_TYPE entryType,
    BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataEntry*>& results) {

    results.clear();
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if ((*it)->getEntryType() == entryType && (*it)->getValueType() == valueType) {
            results.push_back(*it);
        }
    }
}

/**
* Get all metadata entries matching the given value type.
*
* @param entries     Entries to search
* @param valueType   Value type
* @param results     Will hold any matching entries found
*/
void getMetadataValues(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataValue*>& results) {
    results.clear();
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if ((*it)->getValueType() == valueType) {
            results.push_back((*it)->getValue());
        }
    }
}

/**
* Create a metadata value of the given type from the buffer.
* Many of the types will just return a generic object since we don't
* currently use them in the parser.
*
* @param a_valueType  Value type
* @param buf          Data buffer
* @param bufLen       Size of the data buffer
*
* @return The newly created MetadataValue or NULL if an error occurs
*/
MetadataValue* createMetadataValue(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen) {
    switch (valueType) {

    // These are the valid types we currently process
    case BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY:
        return new MetadataValueVolumeMasterKey(valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::STRETCH_KEY:
        return new MetadataValueStretchKey(valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::KEY:
        return new MetadataValueKey(valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY:
        return new MetadataValueAesCcmEncryptedKey(valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::OFFSET_AND_SIZE:
        return new MetadataValueOffsetAndSize(valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::UNICODE_STRING:
        return new MetadataValueUnicode(valueType, buf, bufLen);

    // These are valid types but we don't currently use them
    case BITLOCKER_METADATA_VALUE_TYPE::ERASED:
    case BITLOCKER_METADATA_VALUE_TYPE::USE_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::TPM_ENCODED_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::VALIDATION:
    case BITLOCKER_METADATA_VALUE_TYPE::EXTERNAL_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::UPDATE:
    case BITLOCKER_METADATA_VALUE_TYPE::ERROR_VAL:
        return new MetadataValueGeneric(valueType, buf, bufLen);

    // These are invalid types
    case BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN:
    default:
        // Make an unknown entry so we can at least read the entry size to continue parsing
        return new MetadataValueUnknown(valueType, buf, bufLen);
    }
}

#endif