#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueVolumeMasterKey.h"

MetadataValueVolumeMasterKey::MetadataValueVolumeMasterKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {

    if (bufLen < headerLen) {
        registerError("Buffer for creating MetadataValueVolumeMasterKey was too short");
        memset(guid, 0, 16);
        return;
    }

    memcpy(guid, buf, 16);
    lastModificationTime = tsk_getu64(TSK_LIT_ENDIAN, &(buf[16]));
    unknown = tsk_getu16(TSK_LIT_ENDIAN, &(buf[24]));
    keyProtectionType = getKeyProtectionTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[26])));

    list<string> errors;
    readMetadataEntries(&(buf[headerLen]), bufLen - headerLen, properties, errors);
    if (!errors.empty()) {
        for (auto it = errors.begin(); it != errors.end(); ++it) {
            registerError(*it);
        }
    }
};

void MetadataValueVolumeMasterKey::print() {
    printf("VolumeMasterKey\n");
    printf("GUID: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", guid[i]);
    }
    printf("\nLast Modification Time: 0x%" PRIx64 "\n", lastModificationTime);
    printf("Key Protection Type: %s\n", convertKeyProtectionTypeToString(keyProtectionType).c_str());
    printf("Properties:\n");
    for (auto it = properties.begin(); it != properties.end(); ++it) {
        if (*it != NULL) {
            (*it)->print();
        }
    }
}

MetadataValueVolumeMasterKey::~MetadataValueVolumeMasterKey() {
    for (auto it = properties.begin(); it != properties.end(); ++it) {
        if (*it != NULL) {
            delete(*it);
        }
    }
}

#endif