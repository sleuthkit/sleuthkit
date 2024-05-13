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

#include "BitlockerParser.h"

#include <regex>
#include <codecvt>
#include <sstream>

#include "MetadataUtils.h"
#include "MetadataValue.h"
#include "MetadataValueStretchKey.h"
#include "MetadataValueVolumeMasterKey.h"
#include "MetadataValueAesCcmEncryptedKey.h"
#include "MetadataValueOffsetAndSize.h"
#include "mbedtls/sha256.h"

/**
* Initialize the BitLocker parser.
* Starts with a quick check for the BitLocker signature then reads in and parses the metadata structures.
* If successful the parser will be ready to decrypt the volume.
* 
* @param a_img_info     The image info object for reading data
* @param a_volumeOffset The offset of the current volume in the image
* @param a_password     The password to use for decryption. Can be a normal password or a recovery password.
* 
* @return SUCCESS if we complete initialization
*         NOT_BITLOCKER if the BitLocker signature was not found
*         GENERAL_ERROR if an unspecified error occurs (we may or may not actually have BitLocker encryption)
*         WRONG_PASSWORD if the supplied password appears to be incorrect (we almost certainly have a BitLocker volume)
*         NEEDS_PASSWORD if we need a password to decrypt the keys (we almost certainly have a BitLocker volume)
*         UNSUPPORTED_KEY_PROTECTION_TYPE if the volume master key is protected by an unsupported method (we almost certainly have a BitLocker volume)    
*/
BITLOCKER_STATUS BitlockerParser::initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset, const char* a_password) {
    writeDebug("BitlockerParser::initialize()");

    // Do a quick check for the bitlocker signature before getting started
    if (!hasBitlockerSignature(a_img_info, a_volumeOffset)) {
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }

    // Proceed with initialization if password is empty
    string passwordStr(a_password);
    if (passwordStr.empty()) {
        return initialize(a_img_info, a_volumeOffset);
    }

    // Otherwise process the password to use later (we won't know whether it's correct or not at this point)
    if (BITLOCKER_STATUS::SUCCESS != handlePassword(a_password)) {
        // Don't continue if we failed to hash the password
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    return initialize(a_img_info, a_volumeOffset);
}

/**
* Initialize the BitLocker parser.
* Starts with a quick check for the BitLocker signature then reads in and parses the metadata structures.
* If successful the parser will be ready to decrypt the volume.
*
* @param a_img_info     The image info object for reading data
* @param a_volumeOffset The offset of the current volume in the image
*
* @return SUCCESS if we complete initialization
*         NOT_BITLOCKER if the BitLocker signature was not found
*         GENERAL_ERROR if an unspecified error occurs (we may or may not actually have BitLocker encryption)
*         WRONG_PASSWORD if the supplied password appears to be incorrect (we almost certainly have a BitLocker volume)
*         NEEDS_PASSWORD if we need a password to decrypt the keys (we almost certainly have a BitLocker volume)
*         UNSUPPORTED_KEY_PROTECTION_TYPE if the volume master key is protected by an unsupported method (we almost certainly have a BitLocker volume)
*/
BITLOCKER_STATUS BitlockerParser::initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    writeDebug("BitlockerParser::initialize()");

    // Do a quick check for the bitlocker signature before getting started
    if (!hasBitlockerSignature(a_img_info, a_volumeOffset)) {
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }

    return initializeInternal(a_img_info, a_volumeOffset);
}

/**
* Does a quick check for the BitLocker signature without doing any initialization.
* The signature "-FVE-FS-" is expected to be found at offset 3 (relative to the start of the volume).
* 
* @param a_img_info     The image info object for reading data
* @param a_volumeOffset The offset of the current volume in the image
* 
* @return true if the signature is found, false otherwise
*/
bool BitlockerParser::hasBitlockerSignature(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    uint8_t signature[8];
    size_t bytesRead = tsk_img_read(a_img_info, a_volumeOffset + 3, (char*)signature, 8);
    if (bytesRead != 8) {
        writeDebug("BitlockerParser::hasBitlockerSignature(): Error reading bitlocker signature from offset " + convertUint64ToString(a_volumeOffset + 3));
        return false;
    }

    if (0 != memcmp(signature, m_bitlockerSignature, 8)) {
        writeDebug("BitlockerParser::hasBitlockerSignature(): No bitlocker signature (" + convertByteArrayToString(signature, 8) + ")");
        return false;
    }
    return true;
}

/**
* Initialize BitLocker.
* High-level overview:
* - Read the first header to get offsets to three locations to start at for the next step
* - Parse some headers and then a series of metadata entries
* - Find the volume master key entry and attempt to extract the key
* - Find the full volume encryption key entry and attempt to use the previous key to decrypt it
* - Find the offset to the original volume header
* 
* There are some errors that we keep track of (like incorrect password). If we've failed to initialize after
* trying all three offsets then we'll return a specific error so it can be displayed to the user. These errors
* will only be returns after we've done enough parsing to be confident that this is a BitLocker-encrypted volume.
*
* @param a_img_info     The image info object for reading data
* @param a_volumeOffset The offset of the current volume in the image
*
* @return BITLOCKER_STATUS enum - see initialize() for description
*/
BITLOCKER_STATUS BitlockerParser::initializeInternal(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset) {
    writeDebug("BitlockerParser::initializeInternal()");

    m_volumeOffset = a_volumeOffset;

    m_img_info = a_img_info;
    if (m_img_info == NULL) {
        writeError("BitlockerParser::initialize(): a_img_info was NULL");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Read in the volume header
    bitlocker_volume_header_t* volHeader = (bitlocker_volume_header_t*)malloc(sizeof(bitlocker_volume_header_t));
    if (volHeader == NULL) {
        writeError("BitlockerParser::initialize(): Error allocating memory for volume header");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    size_t bytesRead = tsk_img_read(m_img_info, m_volumeOffset, (char*)volHeader, sizeof(bitlocker_volume_header_t));
    if (bytesRead != sizeof(bitlocker_volume_header_t)) {
        writeError("BitlockerParser::initialize(): Error reading first sector (read " + to_string(bytesRead) + " bytes");
        free(volHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // See if it looks like Bitlocker
    writeDebug("  Vol sig:  " + convertByteArrayToString((uint8_t*)volHeader->signature, 8));
    writeDebug("  Expected: " + convertByteArrayToString((uint8_t*)m_bitlockerSignature, 8));
    if (memcmp(volHeader->signature, m_bitlockerSignature, 8)) {
        writeDebug("BitlockerParser::initialize(): No bitlocker signature");
        free(volHeader);
        return BITLOCKER_STATUS::NOT_BITLOCKER;
    }
    m_isBitlocker = true;

    // For the moment, we only need the FVE metadata offsets and the sector size
    m_fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset1) + m_volumeOffset);
    m_fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset2) + m_volumeOffset);
    m_fveMetadataOffsets.push_back(tsk_getu64(TSK_LIT_ENDIAN, volHeader->fveMetadataOffset3) + m_volumeOffset);
    m_sectorSize = tsk_getu16(TSK_LIT_ENDIAN, volHeader->bytesPerSector);
    if (m_sectorSize == 0) {
        writeError("BitlockerParser::initialize(): Sector size is zero");
        free(volHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    free(volHeader);

    // Track potential problems we want to report to the user if initialization fails
    bool possibleWrongPassword = false;
    bool possibleMissingPassword = false;
    bool possibleUnhandledProtectionType = false;

    // Attempt to parse the data at each offset
    for (auto it = m_fveMetadataOffsets.begin(); it != m_fveMetadataOffsets.end(); ++it) {
        // Clear out any entries from the previous offset
        clearFveMetadataEntries();

        // Start reading at the given offset. This will be updated as we read headers and entries.
        uint64_t currentOffset = *it;

        // Read the FVE metadata block header
        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataBlockHeader(currentOffset)) {
            continue;
        }

        // Read the FVE metadata header to get the size of the entries
        uint32_t metadataEntriesSize = 0;
        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataHeader(currentOffset, metadataEntriesSize)) {
            continue;
        }
        if (metadataEntriesSize == 0) {
            continue;
        }

        // Read in all the metadata entries
        if (BITLOCKER_STATUS::SUCCESS != readFveMetadataEntries(currentOffset, metadataEntriesSize)) {
            continue;
        }

        writeDebug("  Top-level metadata entries:");
        for (auto it = m_metadataEntries.begin(); it != m_metadataEntries.end(); ++it) {
            writeDebug("    " + convertMetadataEntryTypeToString((*it)->getEntryType()) + " - " 
                + convertMetadataValueTypeToString((*it)->getValueType()));
        }

        // Attempt to get the volume master key
        BITLOCKER_STATUS ret = getVolumeMasterKey();
        if (ret != BITLOCKER_STATUS::SUCCESS) {

            // If we have a special error state, save that we saw it
            if (ret == BITLOCKER_STATUS::WRONG_PASSWORD) {
                possibleWrongPassword = true;
            } else if (ret == BITLOCKER_STATUS::NEED_PASSWORD) {
                possibleMissingPassword = true;
            } else if (ret == BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE) {
                possibleUnhandledProtectionType = true;
            }
            continue;
        }

        // Use the volume master key to decrypt the full volume encryption key
        if (BITLOCKER_STATUS::SUCCESS != getFullVolumeEncryptionKey()) {
            continue;
        }

        // Find the offset and size of the original volume header. BitLocker moves it later in the volume
        // to make room for its own header.
        if (BITLOCKER_STATUS::SUCCESS != parseVolumeHeader()) {
            continue;
        }

        // If we've gotten here then everything is initialized and ready to go.
        writeDebug("  Initialization successful");
        clearIntermediateData();
        m_unlockSuccessful = true;
        writeWarning(getDescription());
        return BITLOCKER_STATUS::SUCCESS;
    }

    // We were unable to unlock the volume. Clear out the last batch of metadata entries.
    clearFveMetadataEntries();

    // If we've failed and saw one of the notable error types, return the appropriate value
    if (possibleWrongPassword) {
        return BITLOCKER_STATUS::WRONG_PASSWORD;
    } else if (possibleMissingPassword) {
        return BITLOCKER_STATUS::NEED_PASSWORD;
    } else if (possibleUnhandledProtectionType) {
        return BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE;
    }
    return BITLOCKER_STATUS::GENERAL_ERROR;
}

/**
* Parse the FVE Metadata Block Header.
* At present this just checks the signature.
* 
* @param currentOffset  The offset to the block header (relative to the start of the image). Will be updated to the offset of the next
*                         byte after the header on success.
* 
* @return SUCCESS if we read the header and the signature is correct, GENERAL_ERROR otherwise
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

    size_t bytesRead = tsk_img_read(m_img_info, currentOffset, (char*)blockHeader, sizeof(bitlocker_fve_metadata_block_header_v2_t));
    if (bytesRead != sizeof(bitlocker_fve_metadata_block_header_v2_t)) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Error reading block header (read " + to_string(bytesRead) + " bytes");
        free(blockHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    currentOffset += bytesRead;

    // Check the signature
    writeDebug("  Block sig: " + convertByteArrayToString((uint8_t*)blockHeader->signature, 8));
    writeDebug("  Expected:  " + convertByteArrayToString((uint8_t*)m_bitlockerSignature, 8));
    if (memcmp(blockHeader->signature, m_bitlockerSignature, 8)) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Incorrect signature in block header");
        free(blockHeader);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    free(blockHeader);
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Parse the FVE Metadata Header.
* We're looking for the size of the metadata entries and the encryption type.
* 
* @param currentOffset  The offset to the header (relative to the start of the image). Will be updated to the offset of the next
*                         byte after the header on success.
* 
* @return SUCCESS if we read the header and found a valid encryption type and reasonable metadata entry size, GENERAL_ERROR otherwise
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

    size_t bytesRead = tsk_img_read(m_img_info, currentOffset, (char*)header, sizeof(bitlocker_fve_metadata_header_t));
    if (bytesRead != sizeof(bitlocker_fve_metadata_header_t)) {
        writeError("BitlockerParser::readFveMetadataHeader(): Error reading header (read " + to_string(bytesRead) + " bytes");
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    currentOffset += bytesRead;

    // Get the size of the metadata entries. The header->size field contains the length of the header plus the entries.
    uint32_t size = tsk_getu32(TSK_LIT_ENDIAN, header->size);
    writeDebug("  Metadata size: " + convertUint32ToString(size));
    writeDebug("  Header size:   " + convertUint32ToString(sizeof(bitlocker_fve_metadata_header_t)));
    if (size <= sizeof(bitlocker_fve_metadata_header_t)) {
        writeError("BitlockerParser::readFveMetadataHeader(): Metadata entries size is too small: " + convertUint32ToString(size));
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    metadataEntriesSize = size - sizeof(bitlocker_fve_metadata_header_t);

    // Quick sanity check here - the metadata entries shouldn't be too large
    if (metadataEntriesSize > 0x80000) {
        writeError("BitlockerParser::readFveMetadataHeader(): Metadata entries size appears invalid: " + convertUint32ToString(metadataEntriesSize));
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("  Metadata entries size: " + convertUint32ToString(metadataEntriesSize));

    // Get the encryption method
    uint32_t encVal = tsk_getu32(TSK_LIT_ENDIAN, header->encryptionMethod);
    m_encryptionType = getEncryptionTypeEnum(encVal & 0xffff);
    if (m_encryptionType == BITLOCKER_ENCRYPTION_TYPE::UNKNOWN) {
        writeError("BitlockerParser::readFveMetadataHeader(): Unhandled encryption type: " + convertUint32ToString(encVal));
        free(header);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }
    writeDebug("  Encryption type: " + convertEncryptionTypeToString(m_encryptionType) + " (" + convertUint32ToString(encVal) + ")");

    free(header);
    return BITLOCKER_STATUS::SUCCESS;
}


/**
* Read and store all the metadata entries.
*
* @param currentOffset        The starting offset for the entries
* @param metadataEntriesSize  The total size of the metadata entries data
* 
* @return SUCCESS if all entries were successfully parsed, GENERAL_ERROR otherwise
*/
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

    size_t bytesRead = tsk_img_read(m_img_info, currentOffset, (char*)entryBuffer, metadataEntriesSize);
    if (bytesRead != metadataEntriesSize) {
        writeError("BitlockerParser::readFveMetadataBlockHeader(): Error reading metadata entries (read " + to_string(bytesRead) + " bytes");
        free(entryBuffer);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Parse the metadata entries
    list<string> errorList;
    if (BITLOCKER_STATUS::SUCCESS != readMetadataEntries(entryBuffer, metadataEntriesSize, m_metadataEntries)) {
        free(entryBuffer);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    free(entryBuffer);
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Get the volume master key.
* General idea is that we're trying to find and parse a volume master key (VMK) entry to get the key
* we will use to decrypt the full volume encryption key. There are frequently more than one of these entries present.
* For example, we might have a password protected entry and a recovery password protected entry. 
* 
* On success, m_decryptedVmkEntry will contain the decrypted key to use in the next step.
* 
* @return SUCCESS if we successfully decrypted the volume master key
*         GENERAL_ERROR if an unspecified error occurs
*         WRONG_PASSWORD if we found a password/recovery password protected VMK but the password we have was incorrect
*         NEEDS_PASSWORD if we found a password/recovery password protected VMK but do not have a password
*         UNSUPPORTED_KEY_PROTECTION_TYPE if we found a VMK entry with a key protected by an unsupported method
*/
BITLOCKER_STATUS BitlockerParser::getVolumeMasterKey() {
    writeDebug("BitlockerParser::setVolumeMasterKey()");
    m_decryptedVmkEntry = NULL;

    // Get VMK entries
    list<MetadataEntry*> vmkEntries;
    getMetadataEntries(m_metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_MASTER_KEY, BITLOCKER_METADATA_VALUE_TYPE::VOLUME_MASTER_KEY, vmkEntries);
    if (vmkEntries.empty()) {
        writeError("BitlockerParser::setVolumeMasterKey(): No Volume Master Key entries found");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Attempt to parse each of the VMK entries, keeping track of some specific errors if they occur.
    BITLOCKER_STATUS ret = BITLOCKER_STATUS::GENERAL_ERROR;
    MetadataEntry* vmk = NULL;
    bool possibleMissingPassword = false;
    bool possibleWrongPassword = false;
    bool possibleUnsupportedProtectionType = false;
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
        else if (ret == BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE) {
            possibleUnsupportedProtectionType = true;
        }
    }

    // If we failed to decrypt any of the VMK entries return a specific error if we have one.
    // Note that the order is important here - if we have a normal password that failed to decrypt the
    // password protected VMK entry, we don't want to report that we didn't have a recovery password to
    // try in the recovery password protected VMK.
    if (ret != BITLOCKER_STATUS::SUCCESS || vmk == NULL) {
        writeError("BitlockerParser::setVolumeMasterKey(): Failed to extract Volume Master Key");
        if (possibleWrongPassword) {
            return BITLOCKER_STATUS::WRONG_PASSWORD;
        }
        else if (possibleMissingPassword) {
            return BITLOCKER_STATUS::NEED_PASSWORD;
        }
        else if (possibleUnsupportedProtectionType) {
            return BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE;
        }
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // We successfully decrypted one of the VMK entries
    writeDebug("BitlockerParser::setVolumeMasterKey(): Extracted Volume Master Key");
    m_decryptedVmkEntry = vmk;

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Attempt to decrypt a volume master key (VMK) entry.
* 
* @param entry    The VMK entry
* @param vmkEntry Will hold the decrypted VMK if successful
* 
* @return SUCCESS if we successfully decrypted the volume master key
*         GENERAL_ERROR if an unspecified error occurs
*         WRONG_PASSWORD if the VMK is protected by a password/recovery password but the password we have was incorrect
*         NEEDS_PASSWORD if the VMK is protected by a password/recovery password but we do not have a password
*         UNSUPPORTED_KEY_PROTECTION_TYPE if the key is protected by an unsupported method (we currently support password and recovery password - clear key TODO)
*/
BITLOCKER_STATUS BitlockerParser::parseVMKEntry(MetadataEntry* entry, MetadataEntry** vmkEntry) {
    writeDebug("BitlockerParser::parseVMKEntry()");

    // Sanity checking - we already filtered entries based type and value type
    if (vmkEntry == NULL) {
        writeError("BitlockerParser::parseVMKEntry(): Null vmkEntry parameter");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

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

    // VMK entries contain a list of properties
    for (auto it = vmkValue->getProperties().begin(); it != vmkValue->getProperties().end(); ++it) {
        writeDebug("  Have property with type " + convertMetadataValueTypeToString((*it)->getValueType()));
    }

    BITLOCKER_KEY_PROTECTION_TYPE protectionType = vmkValue->getProtectionType();
    writeDebug("  VMK protected with " + convertKeyProtectionTypeToString(protectionType));

    // Try to decrypt the VMK based on the protection type
    if (protectionType == BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD
        || protectionType == BITLOCKER_KEY_PROTECTION_TYPE::RECOVERY_PASSWORD) {

        return parsePasswordProtectedVMK(vmkValue, vmkEntry);
    }
    else if (protectionType == BITLOCKER_KEY_PROTECTION_TYPE::CLEAR_KEY) {
        return parseClearKeyProtectedVMK(vmkValue, vmkEntry);
    }
    else {
        // TODO - support more protection types
        writeError("BitlockerParser::parseVMKEntry(): Unsupported protection type " + convertKeyProtectionTypeToString(protectionType));
        m_unsupportedProtectionTypesFound.insert(protectionType);
        return BITLOCKER_STATUS::UNSUPPORTED_KEY_PROTECTION_TYPE;
    }
}

/**
* Attempt to decrypt a volume master key (VMK) entry protected with a password or recovery password.
* 
* @param entry    The VMK entry
* @param vmkEntry Will hold the decrypted VMK if successful
* 
* @return SUCCESS if we successfully decrypted the volume master key
*         GENERAL_ERROR if an unspecified error occurs
*         WRONG_PASSWORD if the VMK is protected by a password/recovery password but the password we have was incorrect
*         NEEDS_PASSWORD if the VMK is protected by a password/recovery password but we do not have a password
*/
BITLOCKER_STATUS BitlockerParser::parsePasswordProtectedVMK(MetadataValueVolumeMasterKey* vmkValue, MetadataEntry** vmkEntry) {
    writeDebug("BitlockerParser::parsePasswordProtectedVMK()");
    BITLOCKER_KEY_PROTECTION_TYPE protectionType = vmkValue->getProtectionType();

    // If we don't have the right type of password we can't decrypt this
    if (!m_havePassword && protectionType == BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD) {
        writeError("BitlockerParser::parseVMKEntry(): Can't process password-protected VMK since we have no password");
        return BITLOCKER_STATUS::NEED_PASSWORD;
    }

    if (!m_haveRecoveryPassword && protectionType == BITLOCKER_KEY_PROTECTION_TYPE::RECOVERY_PASSWORD) {
        writeError("BitlockerParser::parseVMKEntry(): Can't process recovery password-protected VMK since we have no recovery password");
        return BITLOCKER_STATUS::NEED_PASSWORD;
    }

    // The expectation is that we'll have a stretch key entry
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

    // Use password/recovery password to create intermediate stretched key
    uint8_t stretchedKey[BITLOCKER_STRETCH_KEY_SHA256_LEN];
    BITLOCKER_STATUS ret;
    if (protectionType == BITLOCKER_KEY_PROTECTION_TYPE::PASSWORD) {
        ret = stretchKey->parseStretchKeyUsingPassword((uint8_t*)m_passwordHash, SHA256_DIGEST_LENGTH, stretchedKey, BITLOCKER_STRETCH_KEY_SHA256_LEN);
    }
    else if (protectionType == BITLOCKER_KEY_PROTECTION_TYPE::RECOVERY_PASSWORD) {
        ret = stretchKey->parseStretchKeyUsingPassword((uint8_t*)m_recoveryPasswordHash, SHA256_DIGEST_LENGTH, stretchedKey, BITLOCKER_STRETCH_KEY_SHA256_LEN);
    }
    if (ret != BITLOCKER_STATUS::SUCCESS) {
        writeError("BitlockerParser::parseVMKEntry(): Error creating intermediate stretched key");
        memset(stretchedKey, 0, BITLOCKER_STRETCH_KEY_SHA256_LEN);
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // There should also be one encrypted AES-CCM key entry
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

    // Decrypt it using the stretched key, which should produce a MetadataEntry of type KEY.
    // This includes testing a 16-byte message authentication code to verify that
    // the decrypted key is correct.
    MetadataEntry* keyEntry = NULL;
    ret = aesCcmKey->decrypt(stretchedKey, BITLOCKER_STRETCH_KEY_SHA256_LEN, &keyEntry);
    if (ret != BITLOCKER_STATUS::SUCCESS) {
        return ret;
    }

    // Make sure the value is of type Key
    if (keyEntry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
        writeError("BitlockerParser::parseVMKEntry(): keyEntry does not have value of type KEY ("
            + convertMetadataValueTypeToString(keyEntry->getValueType()) + ")");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Save the decrypted VMK and what method we used to decrypt it.
    *vmkEntry = keyEntry;
    m_protectionTypeUsed = protectionType;

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Attempt to decrypt a volume master key (VMK) entry protected with a clear key.
*
* @param entry    The VMK entry
* @param vmkEntry Will hold the decrypted VMK if successful
*
* @return SUCCESS if we successfully decrypted the volume master key
*         GENERAL_ERROR if an unspecified error occurs
*/
BITLOCKER_STATUS BitlockerParser::parseClearKeyProtectedVMK(MetadataValueVolumeMasterKey* vmkValue, MetadataEntry** vmkEntry) {
    writeDebug("BitlockerParser::parseClearKeyProtectedVMK()");
    BITLOCKER_KEY_PROTECTION_TYPE protectionType = vmkValue->getProtectionType();

    // The expectation is that we'll have a key entry
    list<MetadataValue*> keys;
    getMetadataValues(vmkValue->getProperties(), BITLOCKER_METADATA_VALUE_TYPE::KEY, keys);
    if (keys.empty()) {
        writeError("BitlockerParser::parseClearKeyProtectedVMK(): Volume Master Key had no key entry");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValueKey* key = dynamic_cast<MetadataValueKey*>(keys.front());
    if (key == NULL) {
        writeError("BitlockerParser::parseClearKeyProtectedVMK(): Error casting MetadataValueKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // There should also be one encrypted AES-CCM key entry
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

    // Decrypt it using the key, which should produce a MetadataEntry of type KEY.
    // This includes testing a 16-byte message authentication code to verify that
    // the decrypted key is correct.
    MetadataEntry* keyEntry = NULL;
    BITLOCKER_STATUS ret = aesCcmKey->decrypt(key->getKeyBytes(), key->getKeyLen(), &keyEntry);
    if (ret != BITLOCKER_STATUS::SUCCESS) {
        // If something has gone wrong we could potentially get a WRONG_PASSWORD return value here.
        // But this is more of an internal error - either we're processing something wrong or the
        // recorded clear key was incorrect/corrupted. We don't want to tell the user that the
        // password they probably didn't even enter is incorrect.
        writeError("BitlockerParser::parseVMKEntry(): Failed to decrypt VMK using the supplied clear key");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Make sure the value is of type Key
    if (keyEntry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
        writeError("BitlockerParser::parseVMKEntry(): keyEntry does not have value of type KEY ("
            + convertMetadataValueTypeToString(keyEntry->getValueType()) + ")");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Save the decrypted VMK and what method we used to decrypt it.
    *vmkEntry = keyEntry;
    m_protectionTypeUsed = protectionType;

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Use the decrypted volume master key (VMK) entry to get the full volume encryption key (FVEK).
* We should have set m_decryptedVmkEntry prior to calling this method.
* 
* @return SUCCESS on success, GENERAL_ERROR otherwise.
*/
BITLOCKER_STATUS BitlockerParser::getFullVolumeEncryptionKey() {
    writeDebug("BitlockerParser::getFullVolumeEncryptionKey()");

    // Sanity check
    if (m_decryptedVmkEntry == NULL) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): VMK is not set");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Find the FVEK entry
    list<MetadataEntry*> fvekEntries;
    getMetadataEntries(m_metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::FULL_VOLUME_ENCRYPTION_KEY, 
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
    // First get the decrypted key out of the decrypted VMK entry
    uint8_t* keyBytes = NULL;
    size_t keyLen = 0;
    if (BITLOCKER_STATUS::SUCCESS != getKeyData(m_decryptedVmkEntry, &keyBytes, keyLen)) {
        writeError("BitlockerParser::getFullVolumeEncryptionKey(): Error loading keys");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Then use that key to decrypt the FVEK entry, which should produce a MetadataEntry of type KEY.
    // This includes testing a 16-byte message authentication code to verify that
    // the decrypted key is correct.
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

    // Use the decrypted FVEK to intialize the AES contexts we'll use to decrypt the volume
    return (setKeys(keyEntry));
}

/**
* Set pointer to the key stored in a metadata entry with value of type KEY.
* 
* @param entry      The metadata entry. Is expected to have value of type KEY.
* @param keyDataPtr Will be set to the address of the key bytes. Caller should not free this since it's part of the metadata entry.
* @param keyLen     Will be set to the length of the key
* 
* @return SUCCESS on success, GENERAL_ERROR otherwise.
*/
BITLOCKER_STATUS BitlockerParser::getKeyData(MetadataEntry* entry, uint8_t** keyDataPtr, size_t& keyLen) {
    writeDebug("BitlockerParser::getKeyData()");

    // Sanity check
    if (entry->getValueType() != BITLOCKER_METADATA_VALUE_TYPE::KEY) {
        writeError("BitlockerParser::getKeyData(): Incorrect entry type (" + convertMetadataValueTypeToString(entry->getValueType()) + ")");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    MetadataValueKey* keyValue = dynamic_cast<MetadataValueKey*>(entry->getValue());
    if (keyValue == NULL) {
        writeError("BitlockerParser::getKeyData(): Error casting to MetadataValueKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Set pointer to the key data
    *keyDataPtr = keyValue->getKeyBytes();
    keyLen = keyValue->getKeyLen();

    if (keyDataPtr == NULL || keyLen == 0) {
        writeError("BitlockerParser::getKeyData(): Key data is invalid");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Use the decrypted full volume encryption key (FVEK) to initialize the appropriate AES contexts
* 
* @param fvekEntry The entry containing the decrypted FVEK
* 
* @return SUCCESS on success, GENERAL_ERROR otherwise
*/
BITLOCKER_STATUS BitlockerParser::setKeys(MetadataEntry* fvekEntry) {
    writeDebug("BitlockerParser::setKeys");

    MetadataValueKey* fvek = dynamic_cast<MetadataValueKey*>(fvekEntry->getValue());
    if (fvek == NULL) {
        writeError("BitlockerParser::setKeys(): Error casting MetadataValueKey");
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Try to initialize the contexts using the encryption type we read from one of the BitLocker headers
    if (BITLOCKER_STATUS::SUCCESS != setKeys(fvek, m_encryptionType)) {

        // If we failed and the encryption type in the FVEK entry is different than the one we got from the 
        // header earlier, try again using the encryption type from the FVEK entry
        if ((fvek->getEncryptionType() != m_encryptionType)
            && (BITLOCKER_STATUS::SUCCESS == setKeys(fvek, fvek->getEncryptionType()))) {

            // If it worked, change the stored encryption type to this one
            m_encryptionType = fvek->getEncryptionType();
            return BITLOCKER_STATUS::SUCCESS;
        }
        return BITLOCKER_STATUS::GENERAL_ERROR;
    }

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Use the decrypted full volume encryption key (FVEK) to initialize the appropriate AES contexts.
* The given encryption type determines the exact initialization required. 
*
* @param fvekEntry The entry containing the decrypted FVEK
* @param type      The encryption type
*
* @return SUCCESS on success, GENERAL_ERROR otherwise
*/
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

        ret = mbedtls_aes_setkey_enc(&m_aesFvekEncryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_dec(&m_aesFvekDecryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_enc(&m_aesTweakEncryptionContext, &(keyBytes[16]), 128);

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
        
        ret = mbedtls_aes_setkey_enc(&m_aesFvekEncryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_dec(&m_aesFvekDecryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_enc(&m_aesTweakEncryptionContext, &(keyBytes[32]), 256);

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

        ret = mbedtls_aes_setkey_enc(&m_aesFvekEncryptionContext, &(keyBytes[0]), 128);
        ret |= mbedtls_aes_setkey_dec(&m_aesFvekDecryptionContext, &(keyBytes[0]), 128);

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
        
        ret = mbedtls_aes_setkey_enc(&m_aesFvekEncryptionContext, &(keyBytes[0]), 256);
        ret |= mbedtls_aes_setkey_dec(&m_aesFvekDecryptionContext, &(keyBytes[0]), 256);

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
        
        ret = mbedtls_aes_xts_setkey_dec(&m_aesXtsDecryptionContext, &(keyBytes[0]), 256);

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
        
        ret = mbedtls_aes_xts_setkey_dec(&m_aesXtsDecryptionContext, &(keyBytes[0]), 256);

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

/**
* Find and parse the volume header entry to get the offset that the original volume header
* was moved to.
* 
* @return SUCCESS on success, GENERAL_ERROR otherwise
*/
BITLOCKER_STATUS BitlockerParser::parseVolumeHeader() {
    writeDebug("BitlockerParser::parseVolumeHeader()");

    // Find the volume header entry which should contain an offset and size value
    list<MetadataEntry*> volumeHeaderEntries;
    getMetadataEntries(m_metadataEntries, BITLOCKER_METADATA_ENTRY_TYPE::VOLUME_HEADER_BLOCK,
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

    // Store the new offset for the start of the volume and the number of bytes moved. We will need this to read
    // the beginning of the volume.
    m_volumeHeaderOffset = offsetAndSizeValue->getOffset();
    m_volumeHeaderSize = offsetAndSizeValue->getSize();
    writeDebug("  Volume header offset: " + convertUint64ToString(m_volumeHeaderOffset));
    writeDebug("  Volume header size  : " + convertUint64ToString(m_volumeHeaderSize));
    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Save the password hash and optional recovery password hash to use as a key later.
* If the password matches the format of a recovery password we will also process it as a
* recovery password.
* 
* Password algorithm:
* - Convert password to UTF16
* - Hash twice with SHA-256
* Recovery password algorithm:
* - Divide each segment by 11 to get a 16-byte value
* - Hash once with SHA-256
* 
* @param password The password (should be UTF8)
* 
* @return SUCCESS if the we successfully process the password as a normal password or a recovery key
*/
BITLOCKER_STATUS BitlockerParser::handlePassword(string password) {

    // Create the password hash first
    BITLOCKER_STATUS ret;
    try {
        writeDebug("BitlockerParser::handlePassword()");
        writeDebug("  Password: " + password);
        writeDebug("  Processing as a normal password");

        // Convert to UTF16
        string utf8password(password);
        wstring utf16password(L"");
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        utf16password = converter.from_bytes(utf8password);

        writeDebug("  Bytes to hash: " + convertByteArrayToString((uint8_t*)utf16password.c_str(), utf16password.length() * 2));

        // Hash twice
        uint8_t hashOutput[SHA256_DIGEST_LENGTH];
        mbedtls_sha256((uint8_t*)utf16password.c_str(), utf16password.length() * 2, hashOutput, 0);
        mbedtls_sha256(hashOutput, SHA256_DIGEST_LENGTH, m_passwordHash, 0);
        m_havePassword = true;

        writeDebug("  Password hash: " + convertByteArrayToString(m_passwordHash, SHA256_DIGEST_LENGTH));

        // Whether the recovery password parsing works or not, we'll return SUCCESS because we have a password ready to go
        ret = BITLOCKER_STATUS::SUCCESS;
    }
    catch (...) {
        writeError("BitlockerParser::handlePassword(): Error converting password to UTF16");
        // We'll return this error if we fail to parse it as a recovery password
        ret = BITLOCKER_STATUS::GENERAL_ERROR;
    }

    // Try to parse the password as a recovery password. We don't really want to add another password field to TSK
    // so we'll just use any supplied password as a normal password and potentially as a recovery password (if it has the right format).
    // Example: 162294-601403-607013-155265-438779-479028-357148-102091
    // Each part should be divisible by 11 to produce a 16-bit value. Those eight values are combined to form a 16 byte key.
    std::regex recoveryPasswordPattern("^(\\d{1,6})-(\\d{1,6})-(\\d{1,6})-(\\d{1,6})-(\\d{1,6})-(\\d{1,6})-(\\d{1,6})-(\\d{1,6})$");
    std::match_results<std::string::const_iterator> match;
    if (!std::regex_search(password, match, recoveryPasswordPattern) || (match.size() != 9)) {
        writeDebug("  Password is not a recovery password");
        return ret;
    }

    // For each segment, convert and divide by 11 to produce two bytes of the key
    writeDebug("  Password may be a recovery password");
    uint8_t recoveryPasswordKey[16];
    for (int i = 0; i < 8; i++) {
        try {
            unsigned long val = stoul(match[i + 1]);
            if (val % 11 != 0) {
                writeDebug("  Value is not a multiple of 11 (" + to_string(val) + ")");
            }

            val = val / 11;
            if (val > 0xffff) {
                writeDebug("  Value too large to be part of valid recovery password (" + to_string(val) + ")");
                return ret;
            }

            ((uint16_t*)recoveryPasswordKey)[i] = (uint16_t)val;
        }
        catch (...) {
            writeDebug("BitlockerParser::handlePassword(): Error converting recovery password value to integer");
            memset(recoveryPasswordKey, 0, 16);
            return ret;
        }
    }

    writeDebug("  Key from recovery password: " + convertByteArrayToString(recoveryPasswordKey, 16));

    // Only hash this once
    mbedtls_sha256(recoveryPasswordKey, 16, m_recoveryPasswordHash, 0);
    m_haveRecoveryPassword = true;

    writeDebug("  Recovery password hash: " + convertByteArrayToString(m_recoveryPasswordHash, SHA256_DIGEST_LENGTH));

    return BITLOCKER_STATUS::SUCCESS;
}

/**
* Reads and decrypts one or more sectors starting at the given offset.
* The offset is expected to be sector-aligned and the length should be a multiple of the sector size.
* 
* @param offsetInVolume   Offset to start reading at (relative to the start of the volume)
* @param len              Number of bytes to read
* @param data             Will hold decrypted data
* 
* @return Number of bytes read or -1 on error
*/
ssize_t BitlockerParser::readAndDecryptSectors(TSK_DADDR_T offsetInVolume, size_t len, uint8_t* data) {
    writeDebug("BitlockerParser::readAndDecryptSectors - starting offset: " + convertUint64ToString(offsetInVolume));
    if (!initializationSuccessful()) {
        writeError("BitlockerParser::readAndDecryptSectors(): BitlockerParser has not been initialized");
        return -1;
    }

    if (offsetInVolume % m_sectorSize != 0) {
        writeError("BitlockerParser::readAndDecryptSectors(): Starting offset is not sector-aligned (offset: " + convertUint64ToString(offsetInVolume) + ")");
        return -1;
    }

    if (len % m_sectorSize != 0) {
        writeError("BitlockerParser::readAndDecryptSectors(): Length of bytes to read is not a multiple of the sector size (length: " + convertUint32ToString(len) + ")");
        return -1;
    }

    if (offsetInVolume > m_volumeHeaderSize) {
        // All sectors should be in their normal spot on disk
        ssize_t ret_len = tsk_img_read(m_img_info, offsetInVolume + m_volumeOffset, (char*)data, len);

        if (ret_len > 0) {
            for (TSK_DADDR_T i = 0; i < len; i += m_sectorSize) {
                decryptSector(i + offsetInVolume, &(data[i]));
            }
        }
        return ret_len;
    }

    // We're reading the volume header and possibly data after it.
    size_t nRelocatedBytesToRead = m_volumeHeaderSize - offsetInVolume; // TODO fix warning
    if (len < nRelocatedBytesToRead) {
        nRelocatedBytesToRead = len;
    }
    if (nRelocatedBytesToRead <= 0) {
        writeError("BitlockerParser::readAndDecryptSectors(): Error reading from volume header");
        return -1;
    }

    // Read from the relocated offset
    TSK_DADDR_T volumeOffsetToRead = convertVolumeOffset(offsetInVolume);
    ssize_t ret_len = tsk_img_read(m_img_info, volumeOffsetToRead + m_volumeOffset, (char*)data, nRelocatedBytesToRead);
    if (ret_len == 0) {
        return 0;
    }

    if (ret_len > 0) {
        for (TSK_DADDR_T i = 0; i < len; i += m_sectorSize) {
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
    volumeOffsetToRead = m_volumeHeaderSize; // Start right after the volume header

    ssize_t ret_len2 = tsk_img_read(m_img_info, volumeOffsetToRead + m_volumeOffset, (char*)(&data[ret_len]), bytesLeft);
    if (ret_len2 == 0) {
        return ret_len;
    }

    TSK_DADDR_T offset = volumeOffsetToRead;
    uint8_t* dataPtr = &(data[ret_len]);
    while (bytesLeft > 0) {
        decryptSector(offset, dataPtr);

        offset += m_sectorSize;
        dataPtr += m_sectorSize;
        bytesLeft -= m_sectorSize;
    }

    return ret_len + ret_len2;
}

/**
* Decrypt the data that was read from the given offset.
* 
* @volumeOffset Offset to the data relative to the start of the volume. Expected to be sector-aligned.
* @data         Data to decrypt. Will hold the decrypted data.
* 
* @return 0 on success, -1 on error.
*/
int BitlockerParser::decryptSector(TSK_DADDR_T volumeOffset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSector");
    if (!initializationSuccessful()) {
        writeError("BitlockerParser::decryptSector(): BitlockerParser has not been initialized");
        return -1;
    }

    writeDebug("  Encryption type " + convertEncryptionTypeToString(m_encryptionType));
    if (isAESCBC(m_encryptionType)) {
        if (usesDiffuser(m_encryptionType)) {
            writeError("BitlockerParser::decryptSector(): Encryption method not currently supported - " + convertEncryptionTypeToString(m_encryptionType));
            return -1; 
        }
        else {
            return decryptSectorAESCBC_noDiffuser(volumeOffset, data);
        }
    }
    else if (isAESXTS(m_encryptionType)) {
        return decryptSectorAESXTS(volumeOffset, data);
    }
    else {
        writeError("BitlockerParser::decryptSector(): Encryption method not currently supported - " + convertEncryptionTypeToString(m_encryptionType));
        return -1;
    }
}

/**
* Decrypt the data that was read from the given offset using AES-CBC with no diffuser (128 or 256 bit)
*
* @volumeOffset Offset to the data relative to the start of the volume. Expected to be sector-aligned.
* @data         Data to decrypt. Will hold the decrypted data.
*
* @return 0 on success, -1 on error.
*/
int BitlockerParser::decryptSectorAESCBC_noDiffuser(uint64_t offset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSectorAESCBC_noDiffuser");

    // Make temporary buffer to copy encrypted data to
    uint8_t* encryptedData = (uint8_t*)malloc(m_sectorSize);
    if (encryptedData == NULL) {
        writeError("BitlockerParser::decryptSectorAESCBC_noDiffuser(): Error allocating encryptedData");
        return -1;
    }
    memcpy(encryptedData, data, m_sectorSize);
    memset(data, 0, m_sectorSize);

    // The volume offset is used to create the IV
    union {
        uint8_t bytes[16];
        uint64_t offset;
    } iv;

    memset(iv.bytes, 0, 16);
    iv.offset = offset;

    writeDebug("  Data:         " + convertUint64ToString(offset) + "   " + convertByteArrayToString(encryptedData, 32) + "...");
    writeDebug("  Starting IV:  " + convertByteArrayToString(iv.bytes, 16));

    uint8_t encryptedIv[16];
    mbedtls_aes_crypt_ecb(&m_aesFvekEncryptionContext, MBEDTLS_AES_ENCRYPT, iv.bytes, encryptedIv);
    writeDebug("  Encrypted IV: " + convertByteArrayToString(encryptedIv, 16));

    mbedtls_aes_crypt_cbc(&m_aesFvekDecryptionContext, MBEDTLS_AES_DECRYPT, m_sectorSize, encryptedIv, encryptedData, data);
    writeDebug("  Decrypted:    " + convertUint64ToString(offset) + "   " + convertByteArrayToString(data, 32) + "...\n");

    memset(encryptedData, 0, m_sectorSize);
    free(encryptedData);

    return 0;
}

/**
* Decrypt the data that was read from the given offset using AES-XTS (128 or 256 bit)
*
* @volumeOffset Offset to the data relative to the start of the volume. Expected to be sector-aligned.
* @data         Data to decrypt. Will hold the decrypted data.
*
* @return 0 on success, -1 on error.
*/
int BitlockerParser::decryptSectorAESXTS(uint64_t offset, uint8_t* data) {
    writeDebug("BitlockerParser::decryptSectorAESXTS");

    // Make temporary buffer to copy encrypted data to
    uint8_t* encryptedData = (uint8_t*)malloc(m_sectorSize);
    if (encryptedData == NULL) {
        writeError("BitlockerParser::decryptSectorAESXTS(): Error allocating encryptedData");
        return -1;
    }
    memcpy(encryptedData, data, m_sectorSize);
    memset(data, 0, m_sectorSize);

    // The volume offset divided by the sector size is used to create the IV
    union {
        uint8_t bytes[16];
        uint64_t offset;
    } iv;

    memset(iv.bytes, 0, 16);
    iv.offset = offset / m_sectorSize;

    // TODO check sector size first
    writeDebug("  Data:         " + convertByteArrayToString(encryptedData, 16) + "...");
    writeDebug("  Starting IV:  " + convertByteArrayToString(iv.bytes, 16));

    mbedtls_aes_crypt_xts(&m_aesXtsDecryptionContext, MBEDTLS_AES_DECRYPT, m_sectorSize, iv.bytes, encryptedData, data);
    writeDebug("  Decrypted:    " + convertByteArrayToString(data, 16) + "...");

    memset(encryptedData, 0, m_sectorSize);
    free(encryptedData);

    return 0;
}

/**
* Convert the given address to the actual address. This should only be different for sectors
* at the start of the volume that were moved to make room for the Bitlocker volume header.
* 
* @param origOffset  The offset in the original image
* 
* @return The converted offset or the original offset on any kind of error.
*/
TSK_DADDR_T BitlockerParser::convertVolumeOffset(TSK_DADDR_T origOffset) {
    writeDebug("BitlockerParser::convertVolumeOffset(): Converting offset " + convertUint64ToString(origOffset));

    // The expectation is that the first volumeHeaderSize bytes of the volume have been moved to volumeHeaderOffset.
    // So if we're given an offset in that range convert it to the relocated one.
    if (origOffset >= m_volumeHeaderSize) {
        writeDebug("  Offset is not in the range of relocated sectors - returning original");
        return origOffset;
    }

    TSK_DADDR_T newOffset = m_volumeHeaderOffset + origOffset;
    // Make sure we didn't overflow
    if (newOffset < m_volumeHeaderOffset || newOffset < origOffset) {
        return origOffset;
    }

    writeDebug("  Offset is in the range of relocated sectors - returning new offset " + convertUint64ToString(newOffset));
    return newOffset;
}

/**
* Get a short description of the BitLocker encryption.
* Will include the encryption method and the key protection method used to decrypt the VMK.
* Intended to be used if BitLocker was initialized successfully.
* 
* @return A user friendly description of the BitLocker settings
*/
string BitlockerParser::getDescription() {
    if (!m_isBitlocker) {
        return "BitLocker not detected";
    }

    if (!m_unlockSuccessful) {
        return "BitLocker not successfully intialized";
    }

    // Make a string similar to: "BitLocker AES-CBC 128 bit decrypted using password"
    stringstream ss;
    ss << "BitLocker " << convertEncryptionTypeToString(m_encryptionType) << " encryption, ";
    ss << "decrypted using " << convertKeyProtectionTypeToString(m_protectionTypeUsed);
    return ss.str();
}

/**
* Returns a comma-separated list of the unsupported protection type found.
* Used for writing a detailed error message for error type UNSUPPORTED_KEY_PROTECTION_TYPE.
* Note that if the image is opened successfully this list may not be complete since we stop as soon
* as we decrypt the VMK successfully, i.e., if we have clear key and TPM and the clear key entry 
* shows up first, we won't record that we also had a TPM entry.
* 
* @return comma-separated list of key protection types or "none" if empty
*/
string BitlockerParser::getUnsupportedProtectionTypes() {
    if (m_unsupportedProtectionTypesFound.empty()) {
        return "none";
    }

    stringstream ss;
    for (auto it = m_unsupportedProtectionTypesFound.begin(); it != m_unsupportedProtectionTypesFound.end(); ++it) {
        if (it != m_unsupportedProtectionTypesFound.begin()) {
            ss << ", ";
        }
        ss << convertKeyProtectionTypeToString(*it);
    }
    return ss.str();
}

#endif