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