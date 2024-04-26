#include "MetadataValueKey.h"

MetadataValueKey::MetadataValueKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {

    if (bufLen < 4) {
        registerError("Buffer for creating MetadataValueKey was too short");
        return;
    }

    encryptionType = getEncryptionTypeEnum(tsk_getu32(TSK_LIT_ENDIAN, &(buf[0])) & 0xffff);

    keyLen = bufLen - 4;
    key = (uint8_t*)malloc(keyLen);
    if (key == NULL) {
        registerError("Failed to allocated buffer for key");
        return;
    }

    memcpy(key, &(buf[4]), keyLen);
};