#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueStretchKey.h"

#include "mbedtls/sha256.h" 

MetadataValueStretchKey::MetadataValueStretchKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen) : MetadataValue(a_valueType) {

    if (bufLen < headerLen) {
        registerError("Buffer for creating MetadataValueStretchKey was too short");
        memset(salt, 0, 16);
        return;
    }

    encryptionType = getEncryptionTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[0])));
    memcpy(salt, &(buf[4]), 16);

    encryptedKeyEntry = MetadataEntry::createMetadataEntry(&(buf[headerLen]), bufLen - headerLen);
}

int MetadataValueStretchKey::parseStretchKeyUsingPassword(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* stretchKey, size_t stretchKeyLen) {
    writeDebug("MetadataValueStretchKey::parseStretchKeyUsingPassword");

    // Generate stretch key
    if (stretchKeyLen != BITLOCKER_STRETCH_KEY_SHA256_LEN) {
        registerError("parseStretchKeyUsingPassword(): Incorrect stretch key length");
        return -1;
    }

    int ret = generateStretchedKey(passwordHash, passwordHashLen, salt, 16, stretchKey, BITLOCKER_STRETCH_KEY_SHA256_LEN);
    writeDebug("  Stretched key: " + convertByteArrayToString(stretchKey, BITLOCKER_STRETCH_KEY_SHA256_LEN));

    // There's an encrypted key entry in here but it's unclear how to decrypt it. Ignore for now.
    return 0;
}

// Generate stretch key from password hash
// 
// passwordHash is expected to have length BITLOCKER_STRETCH_KEY_SHA256_LEN
// salt is expected to have length BITLOCKER_STRETCH_KEY_SALT_LEN
// result is expected to have length BITLOCKER_STRETCH_KEY_SHA256_LEN
int MetadataValueStretchKey::generateStretchedKey(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* salt, size_t saltLen, uint8_t* result, size_t resultLen) {

    writeDebug("MetadataValueStretchKey::generateStretchedKey()");

    if (passwordHashLen != BITLOCKER_STRETCH_KEY_SHA256_LEN
        || saltLen != BITLOCKER_STRETCH_KEY_SALT_LEN
        || resultLen != BITLOCKER_STRETCH_KEY_SHA256_LEN) {
        writeError("Incorrect buffer lengths given to generateStretchKey()");
        return -1;
    }

    writeDebug("  PasswordHash: " + convertByteArrayToString(passwordHash, passwordHashLen));
    writeDebug("  Salt:         " + convertByteArrayToString(salt, saltLen));

    struct {
        uint8_t updatedHash[BITLOCKER_STRETCH_KEY_SHA256_LEN];
        uint8_t passwordHash[BITLOCKER_STRETCH_KEY_SHA256_LEN];
        uint8_t salt[BITLOCKER_STRETCH_KEY_SALT_LEN];
        uint64_t hashCount;
    } hashStruct;

    size_t structSize = sizeof(hashStruct);
    memset(&hashStruct, 0, structSize);
    memcpy(hashStruct.passwordHash, passwordHash, BITLOCKER_STRETCH_KEY_SHA256_LEN);
    memcpy(hashStruct.salt, salt, BITLOCKER_STRETCH_KEY_SALT_LEN);

    for (uint32_t i = 0; i < 0x100000; ++i) {
        mbedtls_sha256((unsigned char*)(&hashStruct), structSize, hashStruct.updatedHash, 0);
        hashStruct.hashCount++;
    }

    memcpy(result, hashStruct.updatedHash, BITLOCKER_STRETCH_KEY_SHA256_LEN);
    memset(&hashStruct, 0, structSize);

    return 0;
}

void MetadataValueStretchKey::print() {
    printf("StretchKey\n");
    printf("Salt: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", salt[i]);
    }
    printf("\n");
    if (encryptedKeyEntry != NULL) {
        encryptedKeyEntry->print();
    }
}

MetadataValueStretchKey::~MetadataValueStretchKey() {
    if (encryptedKeyEntry != NULL) {
        delete encryptedKeyEntry;
    }
}

#endif