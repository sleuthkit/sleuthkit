#pragma once

#ifdef HAVE_LIBMBEDTLS

class MetadataValue;

#include "tsk/base/tsk_base_i.h"
#include "MetadataUtils.h"
#include <inttypes.h>

class MetadataEntry {
public:
    static MetadataEntry* createMetadataEntry(uint8_t* buf, size_t bufLen);

    uint16_t getSize() {
        return size;
    }

    BITLOCKER_METADATA_ENTRY_TYPE getEntryType() {
        return entryType;
    }

    BITLOCKER_METADATA_VALUE_TYPE getValueType() {
        return valueType;
    }

    MetadataValue* getValue() {
        return metadataValue;
    }

    void print();
    ~MetadataEntry();

private:
    MetadataEntry();

    static const size_t HEADER_SIZE = 8; // Size in bytes of the next four entries
    uint16_t size;
    BITLOCKER_METADATA_ENTRY_TYPE entryType;
    BITLOCKER_METADATA_VALUE_TYPE valueType;
    uint16_t version;
    MetadataValue* metadataValue;
};


#endif