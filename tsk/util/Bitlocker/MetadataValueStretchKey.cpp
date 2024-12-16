/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueStretchKey.h"

#include "mbedtls/sha256.h"

MetadataValueStretchKey::MetadataValueStretchKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen) : MetadataValue(valueType) {

    if (bufLen < m_headerLen) {
        registerError("MetadataValueStretchKey::MetadataValueStretchKey(): Buffer for creating MetadataValueStretchKey was too short");
        memset(m_salt, 0, 16);
        return;
    }

    m_encryptionType = getEncryptionTypeEnum(tsk_getu16(TSK_LIT_ENDIAN, &(buf[0])));
    memcpy(m_salt, &(buf[4]), 16);

    m_encryptedKeyEntry = MetadataEntry::createMetadataEntry(&(buf[m_headerLen]), bufLen - m_headerLen);
}

/**
* Parse the stetch key entry and generate the stretched key from the given password hash.
*
* @param passwordHash     Previously computed hash of the password/recovery password
* @param passwordHashLen  Length of the password hash
* @param stretchKey       Stretched key will be stored here (should be allocated)
* @param stretchKeyLen    Length of the stretchKey buffer (expected to be BITLOCKER_STRETCH_KEY_SHA256_LEN)
*
* @return SUCCESS on success, GENERAL_ERROR if an error occurs
*/
BITLOCKER_STATUS MetadataValueStretchKey::parseStretchKeyUsingPassword(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* stretchKey, size_t stretchKeyLen) {

    // Generate stretch key
    if (stretchKeyLen != BITLOCKER_STRETCH_KEY_SHA256_LEN) {
        registerError("MetadataValueStretchKey::parseStretchKeyUsingPassword: Incorrect stretch key length");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    if (BITLOCKER_STATUS::SUCCESS != generateStretchedKey(passwordHash, passwordHashLen, m_salt, 16, stretchKey, BITLOCKER_STRETCH_KEY_SHA256_LEN)) {
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("MetadataValueStretchKey::parseStretchKeyUsingPassword Stretched key: " + convertByteArrayToString(stretchKey, BITLOCKER_STRETCH_KEY_SHA256_LEN));

    // There's an encrypted key entry in here but it's unclear how to decrypt it. Ignore for now.
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Generate stretched key from password hash
*
* @param passwordHash     Previously computed hash of the password/recovery password
* @param passwordHashLen  Length of the password hash (should be BITLOCKER_STRETCH_KEY_SHA256_LEN)
* @param salt             The salt from the stretch key entry
* @param saltLen          Length of the salt (should be BITLOCKER_STRETCH_KEY_SALT_LEN)
* @param result           Stretched key will be stored here
* @param resultLen        Length of the result buffer (should be BITLOCKER_STRETCH_KEY_SHA256_LEN)
*
* @return SUCCESS on success, GENERAL_ERROR if an error occurs
*/
BITLOCKER_STATUS MetadataValueStretchKey::generateStretchedKey(uint8_t* passwordHash, size_t passwordHashLen, uint8_t* salt, size_t saltLen, uint8_t* result, size_t resultLen) {

    if (passwordHashLen != BITLOCKER_STRETCH_KEY_SHA256_LEN
        || saltLen != BITLOCKER_STRETCH_KEY_SALT_LEN
        || resultLen != BITLOCKER_STRETCH_KEY_SHA256_LEN) {
        writeError("MetadataValueStretchKey::generateStretchedKey: Incorrect buffer length(s)");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("MetadataValueStretchKey::generateStretchedKey: PasswordHash: " + convertByteArrayToString(passwordHash, passwordHashLen));
    writeDebug("MetadataValueStretchKey::generateStretchedKey: Salt:         " + convertByteArrayToString(salt, saltLen));

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

    return BITLOCKER_STATUS::SUCCESS;
}

MetadataValueStretchKey::~MetadataValueStretchKey() {
    if (m_encryptedKeyEntry != NULL) {
        delete m_encryptedKeyEntry;
    }
}

#endif