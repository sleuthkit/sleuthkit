#ifdef HAVE_LIBMBEDTLS

#include "MetadataValueAesCcmEncryptedKey.h"

MetadataValueAesCcmEncryptedKey::MetadataValueAesCcmEncryptedKey(BITLOCKER_METADATA_VALUE_TYPE a_valueType, uint8_t* buf, size_t bufLen)
    : MetadataValue(a_valueType) {

    memset(nonce, 0, 12);

    if (bufLen < headerLen) {
        registerError("Buffer for creating MetadataValueAesCcmEncryptedKey was too short");
        return;
    }

    encryptedDataLen = bufLen - headerLen;
    encryptedData = (uint8_t*)malloc(encryptedDataLen);
    if (encryptedData == NULL) {
        registerError("Failed to allocate buffer for MetadataValueAesCcmEncryptedKey");
        return;
    }

    nonceTimestamp = tsk_getu64(TSK_LIT_ENDIAN, &(buf[0]));
    nonceCounter = tsk_getu32(TSK_LIT_ENDIAN, &(buf[8]));
    memcpy(nonce, &(buf[0]), 12);

    memcpy(encryptedData, &(buf[headerLen]), encryptedDataLen);
};

BITLOCKER_STATUS MetadataValueAesCcmEncryptedKey::decrypt(uint8_t* key, size_t keyLen, MetadataEntry** keyEntry) {
    writeDebug("MetadataValueAesCcmEncryptedKey::decrypt()");

    // The expectation is that we'll have a 16-byte MAC and then an FVE key entry of variable length
    if (keyLen < BITLOCKER_KEY_MAC_LEN + 8) { // Key entry header is 8 bytes
        writeError("MetadataValueAesCcmEncryptedKey::decrypt(): Encrypted data is not long enough to contain MAC and MetadataEntry");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    uint8_t* decryptedData = (uint8_t*)malloc(encryptedDataLen);
    if (decryptedData == NULL) {
        writeError("MetadataValueAesCcmEncryptedKey::decrypt(): Error allocating space for decryptedData");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Decrypt the key entry
    BITLOCKER_STATUS ret = decryptKey(key, keyLen, nonce, getNonceLen(), encryptedData, encryptedDataLen, decryptedData);
    if (ret != BITLOCKER_STATUS::SUCCESS) {
        memset(decryptedData, 0, encryptedDataLen);
        free(decryptedData);
        return ret; // Propagate the return value in case it indicates an incorrect password
    }

    // Try to create the key entry
    *keyEntry = MetadataEntry::createMetadataEntry(&(decryptedData[BITLOCKER_KEY_MAC_LEN]), encryptedDataLen);
    memset(decryptedData, 0, encryptedDataLen);
    free(decryptedData);

    if (keyEntry == NULL) {
        writeError("MetadataValueAesCcmEncryptedKey::decrypt(): Failed to create MetadataEntry from decrypted data");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("  Created MetadataEntry of type " + convertMetadataEntryTypeToString((*keyEntry)->getEntryType())
        + " and value " + convertMetadataValueTypeToString((*keyEntry)->getValueType()));

    return BITLOCKER_STATUS::SUCCESS;
}

BITLOCKER_STATUS MetadataValueAesCcmEncryptedKey::decryptKey(uint8_t* key, size_t keyLen, uint8_t* nonce, size_t nonceLen, uint8_t* encryptedData,
    size_t encryptedDataLen, uint8_t* decryptedData) {

    writeDebug("MetadataValueAesCcmEncryptedKey::decryptKey()");

    writeDebug("  Key:    " + convertByteArrayToString(key, keyLen));
    writeDebug("  Nonce:  " + convertByteArrayToString(nonce, nonceLen));
    writeDebug("  Input:  " + convertByteArrayToString(encryptedData, min(16, (int)encryptedDataLen)) + "...");

    // Set up the IV
    if (nonceLen > 14 || nonceLen < 12) {
        writeError("decryptKey: Invalid nonce length: " + to_string(nonceLen));
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    uint8_t nonceLenUint8 = nonceLen & 0xff;

    uint8_t iv[BITLOCKER_DECRYPT_KEY_BLOCK_SIZE];
    memset(iv, 0, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE);
    memcpy(&(iv[1]), nonce, nonceLen);
    iv[0] = 15 - nonceLenUint8 - 1;

    writeDebug("  IV:     " + convertByteArrayToString(iv, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));
    writeDebug("");

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
            writeDebug("  Dec  :  " + convertByteArrayToString(&(decryptedData[offset]), BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));

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
        writeDebug("  Dec  :  " + convertByteArrayToString(&(decryptedData[offset]), bytesLeft));
    }

    // Validate decryption using the message authentication code
    uint8_t mac1[BITLOCKER_KEY_MAC_LEN];
    memcpy(mac1, decryptedData, 16);
    uint8_t mac2[BITLOCKER_KEY_MAC_LEN];
    memset(mac2, 0, BITLOCKER_KEY_MAC_LEN);

    
    if (0 != createMessageAuthenticationCode(&aes_context, nonce, nonceLenUint8, &(decryptedData[BITLOCKER_KEY_MAC_LEN]),
        encryptedDataLen - BITLOCKER_KEY_MAC_LEN, mac2)) {
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("  Mac1: " + convertByteArrayToString(mac1, BITLOCKER_KEY_MAC_LEN));
    writeDebug("  Mac2: " + convertByteArrayToString(mac2, BITLOCKER_KEY_MAC_LEN));

    if (memcmp(mac1, mac2, BITLOCKER_KEY_MAC_LEN) != 0) {
        writeError("MetadataValueAesCcmEncryptedKey::decryptKey: MAC not valid. Password may be incorrect.");
        return BITLOCKER_STATUS::WRONG_PASSWORD;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Generate message authentication code from decrypted data
*/
int MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode(mbedtls_aes_context* aes_context_ptr, uint8_t* nonce, uint8_t nonceLen, 
    uint8_t* data, size_t dataLen, uint8_t* mac) {

    writeDebug("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode()");

    // We should have already checked this
    if (nonceLen > 14) {
        writeError("MetadataValueAesCcmEncryptedKey::createMessageAuthenticationCode(): Invalid nonce length " + nonceLen);
        return -1;
    }

    writeDebug("  dataLen: " + to_string(dataLen));

    writeDebug("  Nonce:  " + convertByteArrayToString(nonce, nonceLen));

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
    writeDebug("  IV:     " + convertByteArrayToString(iv, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));

    mbedtls_aes_crypt_ecb(aes_context_ptr, MBEDTLS_AES_ENCRYPT, iv, iv);

    size_t offset = 0;
    if (dataLen > BITLOCKER_DECRYPT_KEY_BLOCK_SIZE) {
        while (offset + BITLOCKER_DECRYPT_KEY_BLOCK_SIZE < dataLen) {

            //writeDebug("  Data:  " + convertByteArrayToString(data, BITLOCKER_DECRYPT_KEY_BLOCK_SIZE));
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

void MetadataValueAesCcmEncryptedKey::print() {
    printf("AesCcmEncryptedKey");
    printf("\nNonce timestamp: 0x%" PRIx64 "\n", nonceTimestamp);
    printf("Nonce counter: 0x%" PRIx32 "\n", nonceCounter);
    printf("Nonce: ");
    for (size_t i = 0; i < 12; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\nEncrypted data: ");
    for (size_t i = 0; i < encryptedDataLen; i++) {
        if (i > 16) {
            printf("...");
            break;
        }
        printf("%02x", encryptedData[i]);
    }
}

MetadataValueAesCcmEncryptedKey::~MetadataValueAesCcmEncryptedKey() {
    if (encryptedData != NULL) {
        free(encryptedData);
    }
};

#endif