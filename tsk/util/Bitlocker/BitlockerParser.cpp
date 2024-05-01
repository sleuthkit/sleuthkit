#ifdef HAVE_LIBMBEDTLS

#include "BitlockerParser.h"

#include <codecvt>

#include "MetadataUtils.h"
#include "MetadataValue.h"
#include "MetadataValueStretchKey.h"
#include "MetadataValueVolumeMasterKey.h"
#include "MetadataValueAesCcmEncryptedKey.h"
#include "MetadataValueOffsetAndSize.h"
#include "mbedtls/sha256.h"

BITLOCKER_STATUS BitlockerParser::initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset, const char* password) {
    writeDebug("BitlockerParser::initialize()");

    // Do a quick check for the bitlocker signature before getting started
    if (!hasBitlockerSignature(a_img_info, a_volumeOffset)) {
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }

    // Proceed with initialization if password is empty
    string passwordStr(password);
    if (passwordStr.empty()) {
        return initialize(a_img_info, a_volumeOffset);
    }

    // Otherwise process the password to use later (we won't know whether it's correct or not at this point)
    if (BITLOCKER_STATUS::SUCCESS != handlePassword(password)) {
        // Don't continue if we failed to hash the password
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    return initialize(a_img_info, a_volumeOffset);
}

BITLOCKER_STATUS BitlockerParser::initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    writeDebug("BitlockerParser::initialize()");

    // Do a quick check for the bitlocker signature before getting started
    if (!hasBitlockerSignature(a_img_info, a_volumeOffset)) {
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }

    return initializeInternal(a_img_info, a_volumeOffset);
}

bool BitlockerParser::hasBitlockerSignature(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    uint8_t signature[8];
    size_t bytesRead = tsk_img_read(a_img_info, a_volumeOffset + 3, (char*)signature, 8);
    if (bytesRead != 8) {
        writeDebug("BitlockerParser::hasBitlockerSignature(): Error reading bitlocker signature from offset " + convertUint64ToString(a_volumeOffset + 3));
        return false;
    }

    if (memcmp(signature, bitlockerSignature, 8)) {
        writeDebug("BitlockerParser::hasBitlockerSignature(): No bitlocker signature");
        return false;
    }
    isBitlocker = true;
}

BITLOCKER_STATUS BitlockerParser::initializeInternal(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    writeDebug("BitlockerParser::initializeInternal()");

    volumeOffset = a_volumeOffset;

    img_info = a_img_info;
    if (img_info == NULL) {
        writeError("BitlockerParser::initialize(): a_img_info was NULL");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Read in the volume header
    bitlocker_volume_header_t* volHeader = (bitlocker_volume_header_t*)malloc(sizeof(bitlocker_volume_header_t));
    if (volHeader == NULL) {
        writeError("BitlockerParser::initialize(): Error allocating memory for volume header");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    size_t bytesRead = tsk_img_read(img_info, volumeOffset, (char*)volHeader, sizeof(bitlocker_volume_header_t));
    if (bytesRead != sizeof(bitlocker_volume_header_t)) {
        writeError("BitlockerParser::initialize(): Error reading first sector (read " + to_string(bytesRead) + " bytes");
        free(volHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // See if it looks like Bitlocker
    writeDebug("  Vol sig:  " + convertByteArrayToString((uint8_t*)volHeader->signature, 8));
    writeDebug("  Expected: " + convertByteArrayToString((uint8_t*)bitlockerSignature, 8));
    if (memcmp(volHeader->signature, bitlockerSignature, 8)) {
        writeDebug("BitlockerParser::initialize(): No bitlocker signature");
        free(volHeader);
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }
    isBitlocker = true;

    // For the moment, we need the FVE metadata offsets and the sector size
    fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset1) + volumeOffset);
    fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset2) + volumeOffset);
    fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset3) + volumeOffset);
    sectorSize = tsk_getu16(TSK_LIT_ENDIAN, volHeader->bytesPerSector);
    free(volHeader);

    // Parse the data at each offset
    bool possibleWrongPassword = false;
    bool possibleMissingPassword = false;
    for (auto it = fveMetadataOffsets.begin(); it != fveMetadataOffsets.end(); ++it) {
        // Clear out any entries from the previous offset
        clearFveMetadataEntries();

        uint64_t currentOffset = *it;

        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataBlockHeader(currentOffset)) {
            continue;
        }

        uint32_t metadataEntriesSize = 0;
        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataHeader(currentOffset, metadataEntriesSize)) {
            continue;
        }
        if (metadataEntriesSize == 0) {
            continue;
        }

        writeDebug("  Loading all metadata entries");
        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataEntries(currentOffset, metadataEntriesSize)) {
            continue;
        }

        writeDebug("  Top-level metadata entries:");
        for (auto it = metadataEntries.begin(); it != metadataEntries.end(); ++it) {
            writeDebug("    " + convertMetadataEntryTypeToString((*it)->getEntryType()) + " - " 
                + convertMetadataValueTypeToString((*it)->getValueType()));
        }

        BITLOCKER_STATUS ret = getVolumeMasterKey();
        if (ret != BITLOCKER_STATUS::SUCCESS) {

            // If we seem to have an incorrect or missing password, save that fact
            if (ret == BITLOCKER_STATUS::WRONG_PASSWORD) {
                possibleWrongPassword = true;
            } else if (ret == BITLOCKER_STATUS::NEED_PASSWORD) {
                possibleMissingPassword = true;
            }
            continue;
        }

        if (BITLOCKER_STATUS::SUCCESS != getFullVolumeEncryptionKey()) {
            continue;
        }

        if (BITLOCKER_STATUS::SUCCESS != parseVolumeHeader()) {
            continue;
        }

        // If we've gotten here then everything is initialized and ready to go.
        writeDebug("  Initialization successful");
        unlockSuccessful = true;
        return BITLOCKER_STATUS::SUCCESS;
    }

    // We were unable to unlock the volume. Clear out the last batch of metadata entries.
    clearFveMetadataEntries();

    if (possibleWrongPassword) {
        return BITLOCKER_STATUS::WRONG_PASSWORD;
    } else if (possibleMissingPassword) {
        return BITLOCKER_STATUS::NEED_PASSWORD;
    }
    return BITLOCKER_STATUS::GENERAL_ERROR;
}

BITLOCKER_STATUS BitlockerParser::readFveMetadataEntries(uint64_t currentOffset, uint32_t metadataEntriesSize) {
    writeDebug("BitlockerParser::readFveMetadataBlockHeader()");
    writeDebug("  Starting offset: " + convertUint64ToString(currentOffset));
    writeDebug("  Size: " + convertUint32ToString(metadataEntriesSize));

    // Read in the raw data for all entries
    uint8_t* entryBuffer = (uint8_t*)malloc(metadataEntriesSize);
    if (entryBuffer == NULL) {
        writeError("BitlockerParser::readFveMetadataEntries(): Error allocating memory for entries");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    size_t bytesRead = tsk_img_read(img_info, currentOffset, (char*)entryBuffer, metadataEntriesSize);
    if (bytesRead != metadataEntriesSize) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Error reading metadata entries (read " + to_string(bytesRead) + " bytes");
        free(entryBuffer);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Parse the metadata entries
    list<string> errorList;
    readMetadataEntries(entryBuffer, metadataEntriesSize, metadataEntries, errorList);
    if (!errorList.empty()) {
        for (auto it = errorList.begin(); it != errorList.end(); ++it) {
            writeError(*it);
        }
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    free(entryBuffer);
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Parse the FVE Metadata Block Header.
* At present this just checks the signature.
*/
BITLOCKER_STATUS BitlockerParser::readFveMetadataBlockHeader(uint64_t& currentOffset) {
    writeDebug("BitlockerParser::readFveMetadataBlockHeader()");
    writeDebug("  Reading metadata block header at offset " + convertUint64ToString(currentOffset));

    // Read in the block header
    bitlocker_fve_metadata_block_header_v2_t* blockHeader = (bitlocker_fve_metadata_block_header_v2_t*)malloc(sizeof(bitlocker_fve_metadata_block_header_v2_t));
    if (blockHeader == NULL) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Error allocating memory for block header");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    size_t bytesRead = tsk_img_read(img_info, currentOffset, (char*)blockHeader, sizeof(bitlocker_fve_metadata_block_header_v2_t));
    if (bytesRead != sizeof(bitlocker_fve_metadata_block_header_v2_t)) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Error reading block header (read " + to_string(bytesRead) + " bytes");
        free(blockHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    currentOffset += bytesRead;

    // Check the signature
    writeDebug("  Block sig: " + convertByteArrayToString((uint8_t*)blockHeader->signature, 8));
    writeDebug("  Expected:  " + convertByteArrayToString((uint8_t*)bitlockerSignature, 8));
    if (memcmp(blockHeader->signature, bitlockerSignature, 8)) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Incorrect signature in block header");
        free(blockHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    free(blockHeader);
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Parse the FVE Metadata Header.
*/
BITLOCKER_STATUS BitlockerParser::readFveMetadataHeader(uint64_t& currentOffset, uint32_t& metadataEntriesSize) {
    writeDebug("BitlockerParser::readFveMetadataHeader()");
    writeDebug("  Reading metadata header at offset " + convertUint64ToString(currentOffset));

    // Read in the block header
    bitlocker_fve_metadata_header_t* header = (bitlocker_fve_metadata_header_t*)malloc(sizeof(bitlocker_fve_metadata_header_t));
    if (header == NULL) {
        writeError("BitlockerParser::readFveMetadataHeader(): Error allocating memory for header");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    size_t bytesRead = tsk_img_read(img_info, currentOffset, (char*)header, sizeof(bitlocker_fve_metadata_header_t));
    if (bytesRead != sizeof(bitlocker_fve_metadata_header_t)) {
        writeError("BitlockerParser::readFveMetadataHeader(): Error reading header (read " + to_string(bytesRead) + " bytes");
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    currentOffset += bytesRead;

    writeDebug("  Metadata size: " + convertUint32ToString(tsk_getu32(TSK_LIT_ENDIAN, header->size)));
    writeDebug("  Header size:   " + convertUint32ToString(sizeof(bitlocker_fve_metadata_header_t)));
    metadataEntriesSize = tsk_getu32(TSK_LIT_ENDIAN, header->size) - sizeof(bitlocker_fve_metadata_header_t);

    // Quick sanity check here - the metadata entries shouldn't be too large
    if (metadataEntriesSize > 0x80000) {
        writeError("BitlockerParser::readFveMetadataHeader(): Metadata entries size appears invalid: " + convertUint32ToString(metadataEntriesSize));
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("  Metadata entries size: " + convertUint32ToString(metadataEntriesSize));

    // Get the encryption method
    uint32_t encVal = tsk_getu32(TSK_LIT_ENDIAN, header->encryptionMethod);
    encryptionType = getEncryptionTypeEnum(encVal & 0xffff);
    if (encryptionType == BITLOCKER_ENCRYPTION_TYPE::UNKNOWN) {
        writeError("BitlockerParser::readFveMetadataHeader(): Unhandled encryption type: " + convertUint32ToString(encVal));
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("  Encryption type: " + convertEncryptionTypeToString(encryptionType) + " (" + convertUint32ToString(encVal) + ")");

    free(header);
    return BITLOCKER_STATUS::SUCCESS;
}

BITLOCKER_STATUS BitlockerParser::getVolumeMasterKey() {
    writeDebug("BitlockerParser::setVolumeMasterKey()");
    decryptedVmkEntry = NULL;

    // Get VMK entries
    list<MetadataEntry*> vmkEntries;
    getMetadataEntries(metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_MASTER_KEY, BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY, vmkEntries);
    if (vmkEntries.empty()) {
        writeError("BitlockerParser::setVolumeMasterKey(): No Volume Master Key entries found");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    BITLOCKER_STATUS ret = BITLOCKER_STATUS::GENERAL_ERROR;
    MetadataEntry* vmk = NULL;
    bool possibleMissingPassword = false;
    bool possibleWrongPassword = false;
    for (auto it = vmkEntries.begin(); it != vmkEntries.end(); ++it) {
        ret = parseVMKEntry(*it, &vmk);
        if (ret == BITLOCKER_STATUS::SUCCESS && vmk != NULL) {
            // Successfully parsed one of the entries - no need to try another
            break;
        }
        else if (ret == BITLOCKER_STATUS::WRONG_PASSWORD) {
            possibleWrongPassword = true;
        }
        else if (ret == BITLOCKER_STATUS::NEED_PASSWORD) {
            possibleMissingPassword = true;
        }
    }

    if (ret != BITLOCKER_STATUS::SUCCESS || vmk == NULL) {
        writeError("BitlockerParser::setVolumeMasterKey(): Failed to extract Volume Master Key");
        if (possibleWrongPassword) {
            return BITLOCKER_STATUS::WRONG_PASSWORD;
        }
        else if (possibleMissingPassword) {
            return BITLOCKER_STATUS::NEED_PASSWORD;
        }
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    writeDebug("BitlockerParser::setVolumeMasterKey(): Extracted Volume Master Key");
    decryptedVmkEntry = vmk;

    return BITLOCKER_STATUS::SUCCESS;
}

BITLOCKER_STATUS BitlockerParser::parseVMKEntry(MetadataEntry* entry, MetadataEntry** vmkEntry) {
    writeDebug("BitlockerParser::parseVMKEntry()");

    if (entry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY) {
        writeError("BitlockerParser::parseVMKEntry(): Volume Master Key did not contain value of type VOLUME_MASTER_KEY");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValue* value = entry->getValue();
    if (value == NULL) {
        writeError("BitlockerParser::parseVMKEntry(): Volume Master Key value was null");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    
    MetadataValueVolumeMasterKey* vmkValue = dynamic_cast<MetadataValueVolumeMasterKey*>(value);
    if (vmkValue == NULL) {
        writeError("BitlockerParser::parseVMKEntry(): Error casting MetadataValueVolumeMasterKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    for (auto it = vmkValue->getProperties().begin(); it != vmkValue->getProperties().end(); ++it) {
        writeDebug("  Have property with type " + convertMetadataValueTypeToString((*it)->getValueType()));
    }

    BITLOCKER_KEY_PROTECTION_TYPE protectionType = vmkValue->getProtectionType();
    if (protectionType == BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD) {
        // If we don't have a password we can't decrypt this
        if (!havePassword) {
            writeError("BitlockerParser::parseVMKEntry(): Can't process password-protected VMK since we have no password");
            return BITLOCKER_STATUS::NEED_PASSWORD;
        }

        // The expectation is that we'll have one stretch key entry
        list<MetadataValue*> stretchKeys;
        getMetadataValues(vmkValue->getProperties(), BITLOCKER_METADATA_VALUE_TYPE::STRETCH_KEY, stretchKeys);
        if (stretchKeys.empty()) {
            writeError("BitlockerParser::parseVMKEntry(): Volume Master Key had no stretch key entry");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        MetadataValueStretchKey* stretchKey = dynamic_cast<MetadataValueStretchKey*>(stretchKeys.front());
        if (stretchKey == NULL) {
            writeError("BitlockerParser::parseVMKEntry(): Error casting MetadataValueStretchKey");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        // Use password to create intermediate stretched key
        uint8_t key[BITLOCKER_STRETCH_KEY_SHA256_LEN];
        stretchKey->parseStretchKeyUsingPassword((uint8_t*)passwordHash, SHA256_DIGEST_LENGTH, key, BITLOCKER_STRETCH_KEY_SHA256_LEN);

        // There should also be one encrypted key entry
        list<MetadataValue*> encryptedKeys;
        getMetadataValues(vmkValue->getProperties(), BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY, encryptedKeys);
        if (encryptedKeys.empty()) {
            writeError("BitlockerParser::parseVMKEntry(): Volume Master Key had no encrypted key entry");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        MetadataValueAesCcmEncryptedKey* aesCcmKey = dynamic_cast<MetadataValueAesCcmEncryptedKey*>(encryptedKeys.front());
        if (aesCcmKey == NULL) {
            writeError("BitlockerParser::parseVMKEntry(): Error casting MetadataValueStretchKey");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        // Decrypt it using the stretched key
        MetadataEntry* keyEntry = NULL;
        BITLOCKER_STATUS ret = aesCcmKey->decrypt(key, BITLOCKER_STRETCH_KEY_SHA256_LEN, &keyEntry);
        if (ret != BITLOCKER_STATUS::SUCCESS) {
            return ret;
        }

        // Make sure the value is of type Key
        if (keyEntry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
            writeError("BitlockerParser::parseVMKEntry(): keyEntry does not have value of type KEY (" 
                + convertMetadataValueTypeToString(keyEntry->getValueType()) + ")");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        // Save the VMK
        *vmkEntry = keyEntry;

        return BITLOCKER_STATUS::SUCCESS;
    }
    else {
        // TODO - support more protection types
        writeError("BitlockerParser::parseVMKEntry(): Unsupported protection type " + convertKeyProtectionTypeToString(protectionType));
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
}

BITLOCKER_STATUS BitlockerParser::getFullVolumeEncryptionKey() {
    writeDebug("BitlockerParser::getFullVolumeEncryptionKey()");

    // Sanity check
    if (decryptedVmkEntry == NULL) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): VMK is not set");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    list<MetadataEntry*> fvekEntries;
    getMetadataEntries(metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::FULL_VOLUME_ENCRYPTION_KEY, 
        BITLOCKER_METADATA_VALUE_TYPE::AES_CCM_ENCRYPTED_KEY, fvekEntries);
    if (fvekEntries.empty()) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): Could not find FVEK metatdata entry");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValueAesCcmEncryptedKey* aesCcmKey = dynamic_cast<MetadataValueAesCcmEncryptedKey*>((fvekEntries.front())->getValue());
    if (aesCcmKey == NULL) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): Error casting MetadataValueAesCcmEncryptedKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Decrypt it using the VMK
    uint8_t* keyBytes = NULL;
    size_t keyLen = 0;
    if (BITLOCKER_STATUS::SUCCESS != getKeyData(decryptedVmkEntry, &keyBytes, keyLen)) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): Error loading keys");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataEntry* keyEntry = NULL;
    BITLOCKER_STATUS ret = aesCcmKey->decrypt(keyBytes, keyLen, &keyEntry);
    if (ret != BITLOCKER_STATUS::SUCCESS || keyEntry == NULL) {
        return ret;
    }

    // Make sure the value is of type Key
    if (keyEntry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
        writeError("BitlockerParser::parseVMKEntry(): keyEntry does not have value of type KEY ("
            + convertMetadataValueTypeToString(keyEntry->getValueType()) + ")");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    return (setKeys(keyEntry));
}

BITLOCKER_STATUS BitlockerParser::getKeyData(MetadataEntry* entry, uint8_t** keyDataPtr, size_t& keyLen) {
    writeDebug("BitlockerParser::getKeyData()");

    if (entry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
        writeError("BitlockerParser::getKeyData(): Incorrect entry type (" + convertMetadataValueTypeToString(entry->getValueType()) + ")");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValueKey* keyValue = dynamic_cast<MetadataValueKey*>(entry->getValue());
    if (keyValue == NULL) {
        writeError("BitlockerParser::getKeyData(): Error casting to MetadataValueKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    *keyDataPtr = keyValue->getKeyBytes();
    keyLen = keyValue->getKeyLen();

    if (keyDataPtr == NULL || keyLen == 0) {
        writeError("BitlockerParser::getKeyData(): Key data is invalid");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

BITLOCKER_STATUS BitlockerParser::setKeys(MetadataEntry* fvekEntry) {
    writeDebug("BitlockerParser::setKeys");

    MetadataValueKey* fvek = dynamic_cast<MetadataValueKey*>(fvekEntry->getValue());
    if (fvek == NULL) {
        writeError("BitlockerParser::setKeys(): Error casting MetadataValueKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    if (BITLOCKER_STATUS::SUCCESS != setKeys(fvek, encryptionType)) {
        // If the encryption type in the FVEK entry is different than the one we got from the header earlier, try
        // using it here
        if ((fvek->getEncryptionType() != encryptionType)
            && (BITLOCKER_STATUS::SUCCESS == setKeys(fvek, fvek->getEncryptionType()))) {

            // If it worked, change the stored encryption type to the this one
            encryptionType = fvek->getEncryptionType();
            return BITLOCKER_STATUS::SUCCESS;
        }

        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

BITLOCKER_STATUS BitlockerParser::setKeys(MetadataValueKey* fvek, BITLOCKER_ENCRYPTION_TYPE type) {

    writeDebug("BitlockerParser::setKeys " + convertEncryptionTypeToString(type));

    // Initialize the AES contexts
    size_t keyBits = fvek->getKeyLen() * 8;
    uint8_t* keyBytes = fvek->getKeyBytes();
    int ret;

    switch (type) {
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128_DIFF:
        // We expect a 128-bit key and 128-bit tweak key
        if (keyBits != 256) {
            writeError("BitlockerParser::setKeys: Expected 256 bits for key and tweak key but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        ret = mbedtls_aes_setkey_enc(&aesFvekEncryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_dec(&aesFvekDecryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_enc(&aesTweakEncryptionContext, &(keyBytes[16]), 128);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256_DIFF:
        // We expect a 256-bit key and 256-bit tweak key
        if (keyBits != 512) {
            writeError("BitlockerParser::setKeys: Expected 512 bits for key and tweak key but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        
        ret = mbedtls_aes_setkey_enc(&aesFvekEncryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_dec(&aesFvekDecryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_enc(&aesTweakEncryptionContext, &(keyBytes[32]), 256);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_128:
        // We expect a 128-bit key
        if (keyBits != 128) {
            writeError("BitlockerParser::setKeys: Expected 128 bits for key but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }

        ret = mbedtls_aes_setkey_enc(&aesFvekEncryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_dec(&aesFvekDecryptionContext, &(keyBytes[0]), 128);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    case BITLOCKER_ENCRYPTION_TYPE::AES_CBC_256:
        // We expect a 256-bit key
        if (keyBits != 256) {
            writeError("BitlockerParser::setKeys: Expected 256 bits for key but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        
        ret = mbedtls_aes_setkey_enc(&aesFvekEncryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_dec(&aesFvekDecryptionContext, &(keyBytes[0]), 256);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    case BITLOCKER_ENCRYPTION_TYPE::AES_XTS_128:
        // We expect a 128-bit key1 and 128-bit key2
        if (keyBits != 256) {
            writeError("BitlockerParser::setKeys: Expected 256 bits for key1 and key2 but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        
        ret = mbedtls_aes_xts_setkey_dec(&aesXtsDecryptionContext, &(keyBytes[0]), 256);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    case BITLOCKER_ENCRYPTION_TYPE::AES_XTS_256:
        // We expect a 256-bit key1 and 256-bit key2
        if (keyBits != 512) {
            writeError("BitlockerParser::setKeys: Expected 512 bits for key1 and key2 but have " + keyBits);
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        
        ret = mbedtls_aes_xts_setkey_dec(&aesXtsDecryptionContext, &(keyBytes[0]), 256);

        if (ret != 0) {
            writeError("BitlockerParser::setKeys: Error setting AES context");
            return BITLOCKER_STATUS::GENERAL_ERROR;
        }
        return BITLOCKER_STATUS::SUCCESS;
    default:
        writeError("BitlockerParser::setKeys: Unhandled encryption type " + convertEncryptionTypeToString(type));
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
}

BITLOCKER_STATUS BitlockerParser::parseVolumeHeader() {
    writeDebug("BitlockerParser::parseVolumeHeader()");

    list<MetadataEntry*> volumeHeaderEntries;
    getMetadataEntries(metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_HEADER_BLOCK,
        BITLOCKER_METADATA_VALUE_TYPE::OFFSET_AND_SIZE, volumeHeaderEntries);
    if (volumeHeaderEntries.empty()) {
        writeError("BitlockerParser::parseVolumeHeader(): Could not find volume header metatdata entry");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValueOffsetAndSize* offsetAndSizeValue = dynamic_cast<MetadataValueOffsetAndSize*>((volumeHeaderEntries.front())->getValue());
    if (offsetAndSizeValue == NULL) {
        writeError("BitlockerParser::parseVolumeHeader(): Error casting MetadataValueOffsetAndSize");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    volumeHeaderOffset = offsetAndSizeValue->getOffset();
    volumeHeaderSize = offsetAndSizeValue->getSize();
    writeDebug("  Volume header offset: " + convertUint64ToString(volumeHeaderOffset));
    writeDebug("  Volume header size  : " + convertUint64ToString(volumeHeaderSize));
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Save the password hash to use as a key later.
* Algorithm:
* - Convert password to UTF16
* - Hash twice with SHA-256
* 
* Returns 0 on success, -1 on error
*/
BITLOCKER_STATUS BitlockerParser::handlePassword(string password) {

    // Convert to UTF16
    writeDebug("BitlockerParser::handlePassword()");
    writeDebug("  Password: " + password);
    string utf8password(password);
    wstring utf16password(L"");
    try {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        utf16password = converter.from_bytes(utf8password);
    }
    catch (...) {
        writeError("BitlockerParser::handlePassword(): Error converting password to UTF16");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("  Bytes to hash: " + convertByteArrayToString((uint8_t*)utf16password.c_str(), utf16password.length() * 2));

    // Hash twice
    uint8_t hashOutput[SHA256_DIGEST_LENGTH];
    mbedtls_sha256((uint8_t*)utf16password.c_str(), utf16password.length() * 2, hashOutput, 0);
    mbedtls_sha256(hashOutput, SHA256_DIGEST_LENGTH, passwordHash, 0);
    havePassword = true;

    writeDebug("  Password hash: " + convertByteArrayToString(passwordHash, SHA256_DIGEST_LENGTH));

    return BITLOCKER_STATUS::SUCCESS;
}

// Returns number of bytes read or -1 on error
ssize_t BitlockerParser::readAndDecryptSectors(TSK_DADDR_T offsetInVolume, size_t len, uint8_t* data) {
    writeDebug("BitlockerParser::readAndDecryptSectors - starting offset: " + convertUint64ToString(offsetInVolume));
    if (!initializationSuccessful()) {
        writeError("BitlockerParser::readAndDecryptSectors(): BitlockerParser has not been initialized");
        return -1;
    }

    if (offsetInVolume > volumeHeaderSize) {
        // All sectors should be in their normal spot on disk
        ssize_t ret_len = tsk_img_read(img_info, offsetInVolume + volumeOffset, (char*)data, len);

        if (ret_len > 0) {
            for (TSK_DADDR_T i = 0; i < len; i += sectorSize) {
                decryptSector(i + offsetInVolume, &(data[i]));
            }
        }
        return ret_len;
    }

    // We're reading the volume header and possibly data after it.
    size_t nRelocatedBytesToRead = min(volumeHeaderSize - offsetInVolume, len);
    if (nRelocatedBytesToRead <= 0) {
        writeError("BitlockerParser::readAndDecryptSectors(): Error reading from volume header");
        return -1;
    }

    TSK_DADDR_T volumeOffsetToRead = convertVolumeOffset(offsetInVolume);
    ssize_t ret_len = tsk_img_read(img_info, volumeOffsetToRead + volumeOffset, (char*)data, nRelocatedBytesToRead);
    if (ret_len == 0) {
        return 0;
    }

    if (ret_len > 0) {
        for (TSK_DADDR_T i = 0; i < len; i += sectorSize) {
            decryptSector(volumeOffsetToRead + i, &(data[i]));
        }
    }

    // We're done under two conditions:
    // - We read in the total bytes we wanted (i.e. we don't need to read any sectors outside the volume header)
    // - We didn't read in the expected number of bytes from the volume header. Just return what we have.
    if (ret_len >= len || ret_len != nRelocatedBytesToRead) { // TODO FIX SIGNED WARNING
        return ret_len;
    }

    // Read in the remaining sectors using their real addresses
    size_t bytesLeft = len - ret_len;
    volumeOffsetToRead = volumeHeaderSize; // Start right after the volume header

    ssize_t ret_len2 = tsk_img_read(img_info, volumeOffsetToRead + volumeOffset, (char*)(&data[ret_len]), bytesLeft);
    if (ret_len2 == 0) {
        return ret_len;
    }

    TSK_DADDR_T offset = volumeOffsetToRead;
    uint8_t* dataPtr = &(data[ret_len]);
    while (bytesLeft > 0) {
        decryptSector(offset, dataPtr);

        offset += sectorSize;
        dataPtr += sectorSize;
        bytesLeft -= sectorSize;
    }

    return ret_len + ret_len2;
}

// volumeOffset should be relative to the start of the volume
int BitlockerParser::decryptSector(TSK_DADDR_T volumeOffset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSector");
    if (!initializationSuccessful()) {
        writeError("BitlockerParser::decryptSector(): BitlockerParser has not been initialized");
        return -1;
    }

    writeDebug("  Encryption type " + convertEncryptionTypeToString(encryptionType));
    if (isAESCBC(encryptionType)) {
        if (usesDiffuser(encryptionType)) {
            writeError("BitlockerParser::decryptSector(): Encryption method not currently supported - " + convertEncryptionTypeToString(encryptionType));
            return -1; 
        }
        else {
            return decryptSectorAESCBC_noDiffuser(volumeOffset, data);
        }
    }
    else if (isAESXTS(encryptionType)) {
        return decryptSectorAESXTS(volumeOffset, data);
    }
    else {
        writeError("BitlockerParser::decryptSector(): Encryption method not currently supported - " + convertEncryptionTypeToString(encryptionType));
        return -1;
    }
}

int BitlockerParser::decryptSectorAESCBC_noDiffuser(uint64_t offset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSectorAESCBC_noDiffuser");

    uint8_t* encryptedData = (uint8_t*)malloc(sectorSize);
    if (encryptedData == NULL) {
        writeError("BitlockerParser::decryptSectorAESCBC_noDiffuser(): Error allocating encryptedData");
        return -1;
    }
    memcpy(encryptedData, data, sectorSize);
    memset(data, 0, sectorSize);

    union {
        uint8_t bytes[16];
        uint64_t offset;
    } iv;

    memset(iv.bytes, 0, 16);
    iv.offset = offset;

    writeDebug("  Data:         " + convertUint64ToString(offset) + "   " + convertByteArrayToString(encryptedData, 32) + "...");
    writeDebug("  Starting IV:  " + convertByteArrayToString(iv.bytes, 16));

    uint8_t encryptedIv[16];
    mbedtls_aes_crypt_ecb(&aesFvekEncryptionContext, MBEDTLS_AES_ENCRYPT, iv.bytes, encryptedIv);
    writeDebug("  Encrypted IV: " + convertByteArrayToString(encryptedIv, 16));

    mbedtls_aes_crypt_cbc(&aesFvekDecryptionContext, MBEDTLS_AES_DECRYPT, sectorSize, encryptedIv, encryptedData, data);
    writeDebug("  Decrypted:    " + convertUint64ToString(offset) + "   " + convertByteArrayToString(data, 32) + "...\n");

    memset(encryptedData, 0, sectorSize);
    free(encryptedData);

    return 0;
}

int BitlockerParser::decryptSectorAESXTS(uint64_t offset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSectorAESXTS");

    uint8_t* encryptedData = (uint8_t*)malloc(sectorSize);
    if (encryptedData == NULL) {
        writeError("BitlockerParser::decryptSectorAESXTS(): Error allocating encryptedData");
        return -1;
    }
    memcpy(encryptedData, data, sectorSize);
    memset(data, 0, sectorSize);

    union {
        uint8_t bytes[16];
        uint64_t offset;
    } iv;

    memset(iv.bytes, 0, 16);
    iv.offset = offset / sectorSize;

    // TODO check sector size first
    writeDebug("  Data:         " + convertByteArrayToString(encryptedData, 16) + "...");
    writeDebug("  Starting IV:  " + convertByteArrayToString(iv.bytes, 16));

    mbedtls_aes_crypt_xts(&aesXtsDecryptionContext, MBEDTLS_AES_DECRYPT, sectorSize, iv.bytes, encryptedData, data);
    writeDebug("  Decrypted:    " + convertByteArrayToString(data, 16) + "...");

    memset(encryptedData, 0, sectorSize);
    free(encryptedData);

    return 0;
}

/**
* Convert the given address to the actual address. This should only be different for sectors
* at the start of the volume that were moved to make room for the Bitlocker volume header.
* 
* Returns the original offset on any kind of error.
*/
TSK_DADDR_T BitlockerParser::convertVolumeOffset(TSK_DADDR_T origOffset) {
    writeDebug("BitlockerParser::convertVolumeOffset(): Converting offset " + convertUint64ToString(origOffset));

    // The expectation is that the first volumeHeaderSize bytes of the volume have been moved to volumeHeaderOffset.
    // So if we're given an offset in that range convert it to the relocated one.
    if (origOffset >= volumeHeaderSize) {
        writeDebug("  Offset is not in the range of relocated sectors - returning original");
        return origOffset;
    }

    TSK_DADDR_T newOffset = volumeHeaderOffset + origOffset;
    // Make sure we didn't overflow
    if (newOffset < volumeHeaderOffset || newOffset < origOffset) {
        return origOffset;
    }

    writeDebug("  Offset is in the range of relocated sectors - returning new offset " + convertUint64ToString(newOffset));
    return newOffset;
}

#endif