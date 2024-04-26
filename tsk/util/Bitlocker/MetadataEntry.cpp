#include "MetadataEntry.h"
#include "MetadataValue.h"

/**
* Create a MetadataEntry from the given buffer.
* Will return null on failure.
*/
MetadataEntry* MetadataEntry::createMetadataEntry(uint8_t* buf, size_t bufLen) {
    if (bufLen < HEADER_SIZE) {
        writeError("MetadataEntry::createMetadataEntry: Insufficient bytes to read header");
        return NULL;
    }

    // Read the header
    uint16_t size = tsk_getu32(TSK_LIT_ENDIAN, &(buf[0]));
    BITLOCKER_METADATA_ENTRY_TYPE entryType = getMetadataEntryTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[2])));
    BITLOCKER_METADATA_VALUE_TYPE valueType = getMetadataValueTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[4])));

    // Validation
    if (size < HEADER_SIZE) {
        writeError("MetadataEntry::createMetadataEntry: Size field is too small");
        return NULL;
    }
    if (size > bufLen) {
        writeError("MetadataEntry::createMetadataEntry: Insufficient bytes to read property value");
        return NULL;
    }
    if (valueType == BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN) {
        writeWarning(string("MetadataEntry::createMetadataEntry: Unhandled value type " + to_string(tsk_getu16(TSK_LIT_ENDIAN, &(buf[4])))));
    }

    MetadataValue* metadataValue = createMetadataValue(valueType, &(buf[8]), size - HEADER_SIZE);
    if (metadataValue == NULL || !metadataValue->wasLoadedSuccessfully()) {
        return NULL;
    }

    MetadataEntry* entry = new MetadataEntry();
    if (entry == NULL) {
        writeError("MetadataEntry::createMetadataEntry: Error allocating memory");
        return NULL;
    }

    entry->size = size;
    entry->entryType = entryType;
    entry->valueType = valueType;
    entry->version = tsk_getu16(TSK_LIT_ENDIAN, &(buf[6]));
    entry->metadataValue = metadataValue;

    return entry;
}

void MetadataEntry::print() {
    printf("\nMetadataEntry\n");
    printf("Size: 0x%" PRIx16 "\n", size);
    printf("Type: %s\n", convertMetadataEntryTypeToString(entryType).c_str());
    if (metadataValue != NULL) {
        printf("Value type: ");
        metadataValue->print();
        printf("\n"); // TEMP change after making print better
    }
    else {
        printf("Value data is null\n");
    }
}

MetadataEntry::MetadataEntry() {
    size = 0;
    entryType = BITLOCKER_METADATA_ENTRY_TYPE::UNKNOWN;
    valueType = BITLOCKER_METADATA_VALUE_TYPE::UNKNOWN;
    version = 0;
    metadataValue = NULL;
}

MetadataEntry::~MetadataEntry() {
    if (metadataValue != NULL) {
        delete(metadataValue);
    }
}