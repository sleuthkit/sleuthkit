#ifdef HAVE_LIBMBEDTLS

#include "MetadataUtils.h"

#include "MetadataEntry.h"
#include "MetadataValueStretchKey.h"
#include "MetadataValueVolumeMasterKey.h"
#include "MetadataValueAesCcmEncryptedKey.h"
#include "MetadataValueOffsetAndSize.h"
#include "MetadataValueKey.h"

#include <sstream>
#include <iomanip>

/**
* Record an error message.
*/
void writeError(string errMes) {
    /* TODO - switch to this once the code is in TSK
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_open: sector size is 0");
    */
    printf("writeError: %s\n", errMes.c_str());
    fflush(stdout);
}

/**
* Record a warning message.
*/
void writeWarning(string errMes) {
    /* TODO - switch to this once the code is in TSK
        tsk_error_reset();
        tsk_error_set_errno(TSK_ERR_FS_ARG);
        tsk_error_set_errstr("fatfs_open: sector size is 0");
    */
    printf("writeWarning: %s\n", errMes.c_str());
    fflush(stdout);
}

void writeDebug(string msg) {
    printf("Debug: %s\n", msg.c_str());
    fflush(stdout);
}

void readMetadataEntries(uint8_t* metadataEntryBuffer, size_t metadataEntriesBufSize, list<MetadataEntry*>& entries, list<string>& errorList) {
    size_t index = 0;
    while (index < metadataEntriesBufSize) {

        MetadataEntry* entry = MetadataEntry::createMetadataEntry(&(metadataEntryBuffer[index]), metadataEntriesBufSize - index);
        if (entry == NULL) {
            errorList.push_back("readMetadataEntries(): Error creating metadata entry");
            return;
        }

        if (entry->getSize() == 0) {
            // Protect against infinite loop - size should not be zero.
            errorList.push_back("readMetadataEntries(): Entry size was zero");
            delete(entry); // Don't save this
            return;
        }

        entries.push_back(entry);
        index += entry->getSize();
    }
}

void getMetadataEntries(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_ENTRY_TYPE entryType, BITLOCKER_METADATA_VALUE_TYPE valueType,
    list<MetadataEntry*>& results) {

    results.clear();
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if ((*it)->getEntryType() == entryType && (*it)->getValueType() == valueType) {
            results.push_back(*it);
        }
    }
}

void getMetadataValues(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataValue*>& results) {
    results.clear();
    for (auto it = entries.begin(); it != entries.end(); ++it) {
        if ((*it)->getValueType() == valueType) {
            results.push_back((*it)->getValue());
        }
    }
}

MetadataValue* createMetadataValue(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) {
    switch (a_valueType) {
        // These are the valid types we currently process
    case BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY:
        return new MetadataValueVolumeMasterKey(a_valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::STRETCH_KEY:
        return new MetadataValueStretchKey(a_valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::KEY:
        return new MetadataValueKey(a_valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY:
        return new MetadataValueAesCcmEncryptedKey(a_valueType, buf, bufLen);
    case BITLOCKER_METADATA_VALUE_TYPE::OFFSET_AND_SIZE:
        return new MetadataValueOffsetAndSize(a_valueType, buf, bufLen);

        // These are valid types but we don't currently use them
    case BITLOCKER_METADATA_VALUE_TYPE::ERASED:
    case BITLOCKER_METADATA_VALUE_TYPE::UNICODE_STRING:
    case BITLOCKER_METADATA_VALUE_TYPE::USE_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::TPM_ENCODED_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::VALIDATION:
    case BITLOCKER_METADATA_VALUE_TYPE::EXTERNAL_KEY:
    case BITLOCKER_METADATA_VALUE_TYPE::UPDATE:
    case BITLOCKER_METADATA_VALUE_TYPE::ERROR_VAL:
        return new MetadataValueGeneric(a_valueType, buf, bufLen);

        // These are invalid types 
    case BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN:
    default:
        // Make an unknown entry so we can at least read the entry size to continue parsing
        return new MetadataValueUnknown(a_valueType, buf, bufLen);
    }
}

string convertByteArrayToString(uint8_t* bytes, size_t len) {
    std::stringstream ss;
    for (size_t i = 0; i < len; i++) {
        ss << std::setfill('0') << std::setw(2) << std::hex << (bytes[i] & 0xff);
    }
    return ss.str();
}

string convertUint32ToString(uint32_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(8) << std::hex << val;
    return ss.str();
}

string convertUint64ToString(uint64_t val) {
    std::stringstream ss;
    ss << "0x" << std::setfill('0') << std::setw(16) << std::hex << val;
    return ss.str();
}

#endif