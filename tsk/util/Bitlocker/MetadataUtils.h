#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <string>
#include <list>

class MetadataEntry;
class MetadataValue;
#include "tsk/base/tsk_base_i.h"
#include "DataTypes.h"

using namespace std;

void readMetadataEntries(uint8_t* metadataEntryBuffer, size_t metadataEntriesSize, list<MetadataEntry*>& properties, list<string>& errorList);
void getMetadataEntries(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_ENTRY_TYPE entryType, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataEntry*>& results);
void getMetadataValues(const list<MetadataEntry*>& entries, BITLOCKER_METADATA_VALUE_TYPE valueType, list<MetadataValue*>& results);
MetadataValue* createMetadataValue(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen);

void writeError(string errMes);
void writeWarning(string errMes);
void writeDebug(string msg);

string convertUint64ToString(uint64_t val);
string convertUint32ToString(uint32_t val);
string convertByteArrayToString(uint8_t* bytes, size_t len);

#endif
