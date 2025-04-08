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

#include "MetadataValueAesCcmEncryptedKey.h"

MetadataValueAesCcmEncryptedKey::MetadataValueAesCcmEncryptedKey(BITLOCKER_METADATA_VALUE_TYPE valueType, uint8_t* buf, size_t bufLen)
    : MetadataValue(valueType) {

    memset(m_nonce, 0, m_nonceLen);

    if (bufLen < m_headerLen) {
        registerError("MetadataValueAesCcmEncryptedKey::MetadataValueAesCcmEncryptedKey(): Buffer for creating MetadataValueAesCcmEncryptedKey was too short");
        return;
    }

    m_encryptedDataLen = bufLen - m_headerLen;
    m_encryptedData = (uint8_t*)tsk_malloc(m_encryptedDataLen);
    if (m_encryptedData == NULL) {
        registerError("MetadataValueAesCcmEncryptedKey::MetadataValueAesCcmEncryptedKey(): Failed to allocate buffer for MetadataValueAesCcmEncryptedKey");
        return;
    }

    m_nonceTimestamp = tsk_getu64(TSK_LIT_ENDIAN, &(buf[0]));
    m_nonceCounter = tsk_getu32(TSK_LIT_ENDIAN, &(buf[8]));
    memcpy(m_nonce, &(buf[0]), m_nonceLen);

    memcpy(m_encryptedData, &(buf[m_headerLen]), m_encryptedDataLen);
};

/**
* Decrypt the MetadataValueAesCcmEncryptedKey data using the supplied key and create a MetadataKeyEntry.
*
* @param key      Key bytes
* @param keyLen   Length of the key
* @param keyEntry Will hold decrypted keyEntry object on success. Must be freed by caller.
*
* @return SUCCESS if key is successfully decrypted
*         GENERAL_ERROR if an unspecified error occurs
*         WRONG_PASSWORD if the supplied key appears to be incorrect
*/
BITLOCKER_STATUS MetadataValueAesCcmEncryptedKey::decrypt(uint8_t* key, size_t keyLen, MetadataEntry** keyEntry) {

    // The expectation is that we'll have a 16-byte MAC and then an FVE key entry of variable length
    if (keyLen < BITLOCKER_KEY_MAC_LEN + 8) { // Key entry header is 8 bytes
        writeError("MetadataValueAesCcmEncryptedKey::decrypt: Encrypted data is not long enough to contain MAC and MetadataEntry");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    uint8_t* decryptedData = (uint8_t*)tsk_malloc(m_encryptedDataLen);
    if (decryptedData == nullptr) {
        writeError("MetadataValueAesCcmEncryptedKey::decrypt: Error allocating space for decryptedData");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Decrypt the key entry
    BITLOCKER_STATUS ret = decryptKey(key, keyLen, m_encryptedData, m_encryptedDataLen, decryptedData);
    if (ret != BITLOCKER_STATUS::SUCCESS) {
        memset(decryptedData, 0, m_encryptedDataLen);
        free(decryptedData);
        decryptedData = nullptr;
        return ret; // Propagate the return value in case it indicates an incorrect password
    }

    // Try to create the key entry
    *keyEntry = MetadataEntry::createMetadataEntry(&(decryptedData[BITLOCKER_KEY_MAC_LEN]), m_encryptedDataLen);
    memset(decryptedData, 0, m_encryptedDataLen);
    free(decryptedData);
    decryptedData = nullptr;

    if (keyEntry == nullptr) {
        writeError("MetadataValueAesCcmEncryptedKey::decrypt: Failed to create MetadataEntry from decrypted data");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("MetadataValueAesCcmEncryptedKey::decrypt: Created MetadataEntry of type " + convertMetadataEntryTypeToString((*keyEntry)->getEntryType())
        + " and value " + convertMetadataValueTypeToString((*keyEntry)->getValueType()));

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Decrypt the MetadataValueAesCcmEncryptedKey data using the supplied key.
*
* @param key      Key bytes
* @param keyLen   Length of the key
* @param encryptedData    Buffer to decrypt
* @param encryptedDataLen Length of buffer to decrypt
* @param decryptedData    Will hold decrypted data. Expected to have same length as encryptedData.
*
* @return SUCCESS if key is successfully decrypted
*         GENERAL_ERROR if an unspecified error occurs
*         WRONG_PASSWORD if the supplied key appears to be incorrect
*/
BITLOCKER_STATUS MetadataValueAesCcmEncryptedKey::decryptKey(uint8_t* key, size_t keyLen, uint8_t* encryptedData,
    size_t encryptedDataLen, uint8_t* decryptedData) {

    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Key:    " + convertByteArrayToString(key, keyLen));
    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Nonce:  " + convertByteArrayToString(m_nonce, m_nonceLen));
    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Input:  " + convertByteArrayToString(encryptedData, min(16, (int)encryptedDataLen)) + "...");

    // Set up the IV
    uint8_t nonceLenUint8 = m_nonceLen & 0xff;

    uint8_t iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE];
    memset(iv, 0, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE);
    memcpy(&(iv[1]), m_nonce, m_nonceLen);
    iv[0] = 15 - nonceLenUint8 - 1;

    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: IV:     " + convertByteArrayToString(iv, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));

    // Decrypt the key entry
    mbedtls_aes_context aes_context;
    mbedtls_aes_init(&aes_context);
    mbedtls_aes_setkey_enc(&aes_context, key, 256);

    uint8_t block[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE];
    size_t offset = 0;
    if (encryptedDataLen > BITLOCKER_DECRYPT_KEY_BLOCK_SIZE) {
        while (offset + BITLOCKER_DECRYPT_KEY_BLOCK_SIZE < encryptedDataLen) {
            mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT, iv, block);

            for (int i = 0; i < BITLOCKER_DECRYPT_KEY_BLOCK_SIZE; i++) {
                decryptedData[offset + i] = encryptedData[offset + i] ^ block[i];

            }
            writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Dec  :  " + convertByteArrayToString(&(decryptedData[offset]), BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));

            iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE - 1]++;
            if (iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE - 1] == 0) {
                uint8_t* ivPtr = &iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE - 1];

                do {
                    ivPtr--;
                    (*ivPtr)++;
                } while (*ivPtr == 0 && ivPtr >= &iv[0]);
            }

            offset += BITLOCKER_DECRYPT_KEY_BLOCK_SIZE;
        }
    }

    // Last block
    size_t bytesLeft = encryptedDataLen % BITLOCKER_DECRYPT_KEY_BLOCK_SIZE;
    if (bytesLeft > 0) {
        mbedtls_aes_crypt_ecb(&aes_context, MBEDTLS_AES_ENCRYPT, iv, block);
        for (size_t i = 0; i < bytesLeft; i++) {
            decryptedData[offset + i] = encryptedData[offset + i] ^ block[i];
        }
        writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Dec  :  " + convertByteArrayToString(&(decryptedData[offset]), bytesLeft));
    }

    // Validate decryption using the message authentication code
    uint8_t mac1[BITLOCKER_KEY_MAC_LEN];
    memcpy(mac1, decryptedData, 16);
    uint8_t mac2[BITLOCKER_KEY_MAC_LEN];
    memset(mac2, 0, BITLOCKER_KEY_MAC_LEN);


    if (0 != createMessageAuthenticationCode(&aes_context, m_nonce, nonceLenUint8, &(decryptedData[BITLOCKER_KEY_MAC_LEN]),
        encryptedDataLen - BITLOCKER_KEY_MAC_LEN, mac2)) {
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Mac1: " + convertByteArrayToString(mac1, BITLOCKER_KEY_MAC_LEN));
    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey: Mac2: " + convertByteArrayToString(mac2, BITLOCKER_KEY_MAC_LEN));

    if (memcmp(mac1, mac2, BITLOCKER_KEY_MAC_LEN) != 0) {
        writeError("MetadataValueAesCcmEncryptedKey::decryptKey: MAC not valid. Password may be incorrect.");
        return BITLOCKER_STATUS::WRONG_PASSWORD;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Generate message authentication code from decrypted data
*
* @param aes_context_ptr The initialized AES context
* @param nonce           The nonce
* @param nonceLen Length of the nonce (should be 12, 13, or 14)
* @param data     Data to encrypt
* @param dataLen  Length of data to encrypt
* @param mac      Decrypted MAC
*
* @return 0 on success, -1 on error
*/
int MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode(mbedtls_aes_context* aes_context_ptr, uint8_t* nonce, uint8_t nonceLen,
    uint8_t* data, size_t dataLen, uint8_t* mac) {

    // We should have already checked this
    if (nonceLen > 14) {
        writeError("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode: Invalid nonce length " + nonceLen);
        return -1;
    }

    writeDebug("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode: dataLen: " + to_string(dataLen));

    writeDebug("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode: Nonce:  " + convertByteArrayToString(nonce, nonceLen));

    // Set up IV
    uint8_t iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE];
    memset(iv, 0, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE);
    iv[0] = (14 - nonceLen) | ((BITLOCKER_KEY_MAC_LEN - 2) & 0xfe) << 2;
    memcpy(iv + 1, nonce, nonceLen);

    size_t lenForIv = dataLen;
    for (uint8_t i = 15; i > nonceLen; --i) {
        iv[i] = lenForIv & 0xff;
        lenForIv = lenForIv >> 8;
    }
    writeDebug("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode: IV:     " + convertByteArrayToString(iv, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));

    mbedtls_aes_crypt_ecb(aes_context_ptr, MBEDTLS_AES_ENCRYPT, iv, iv);

    size_t offset = 0;
    if (dataLen > BITLOCKER_DECRYPT_KEY_BLOCK_SIZE) {
        while (offset + BITLOCKER_DECRYPT_KEY_BLOCK_SIZE < dataLen) {

            for (int i = 0; i < BITLOCKER_DECRYPT_KEY_BLOCK_SIZE; i++) {
                iv[i] = data[offset + i] ^ iv[i];
            }
            mbedtls_aes_crypt_ecb(aes_context_ptr, MBEDTLS_AES_ENCRYPT, iv, iv);

            offset += BITLOCKER_DECRYPT_KEY_BLOCK_SIZE;
        }
    }

    // Last block
    size_t bytesLeft = dataLen % BITLOCKER_DECRYPT_KEY_BLOCK_SIZE;
    if (bytesLeft > 0) {
        for (size_t i = 0; i < bytesLeft; i++) {
            iv[i] = data[offset + i] ^ iv[i];
        }

        mbedtls_aes_crypt_ecb(aes_context_ptr, MBEDTLS_AES_ENCRYPT, iv, iv);
    }

    memcpy(mac, iv, BITLOCKER_KEY_MAC_LEN);
    memset(iv, 0, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE);

    return 0;
}

MetadataValueAesCcmEncryptedKey::~MetadataValueAesCcmEncryptedKey() {
    if (m_encryptedData != nullptr) {
        free(m_encryptedData);
        m_encryptedData = nullptr;
    }
};

#endif