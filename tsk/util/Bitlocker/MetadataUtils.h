/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

// Utility methods for parsing the BitLocker metadata entries

#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <string>
#include <list>

class MetadataEntry;
class MetadataValue;
#include "tsk/base/tsk_base_i.h"
#include "DataTypes.h"

using namespace std;

BITLOCKER_STATUS readMetadataEntries(uint8_t* metadataEntryBuffer, size_t metadataEntriesSize, list<MetadataEntry*>& properties);
void getMetadataEntries(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_ENTRY_TYPE entryType, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataEntry*>& results);
void getMetadataValues(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataValue*>& results);
MetadataValue* createMetadataValue(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen);

#endif
