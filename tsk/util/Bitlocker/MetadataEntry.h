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
        return m_size;
    }

    BITLOCKER_METADATA_ENTRY_TYPE getEntryType() {
        return m_entryType;
    }

    BITLOCKER_METADATA_VALUE_TYPE getValueType() {
        return m_valueType;
    }

    MetadataValue* getValue() {
        return m_metadataValue;
    }

    ~MetadataEntry();

private:
    MetadataEntry();

    static const size_t HEADER_SIZE = 8; // Size in bytes of the next four entries
    uint16_t m_size;
    BITLOCKER_METADATA_ENTRY_TYPE m_entryType;
    BITLOCKER_METADATA_VALUE_TYPE m_valueType;
    uint16_t m_version;
    MetadataValue* m_metadataValue;
};


#endif