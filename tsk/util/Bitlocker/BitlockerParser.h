/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

/**
* BitLocker Parser (beta).
* Should support Win7 and newer images protected with password, recovery password, or clear key.
*/

#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <stdio.h>
#include <set>
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"

#include "MetadataEntry.h"
#include "MetadataValue.h"
#include "MetadataUtils.h"
#include "MetadataValueKey.h"
#include "MetadataValueVolumeMasterKey.h"
#include "BitlockerUtils.h"

#include "mbedtls/aes.h"

// BitLocker header structures
typedef struct {
    uint8_t bootEntryPoint[3];
    char signature[8];

    uint8_t bytesPerSector[2];
    uint8_t sectorsPerClusterBlock;
    uint8_t reservedSectors[2];
    uint8_t nFat;
    uint8_t nDentries[2];
    uint8_t nSectors1[2];
    uint8_t mediaDesc;
    uint8_t sectorsPerFAT[2];
    uint8_t sectorsPerTrack[2];
    uint8_t nHeads[2];
    uint8_t nHiddenSectors[4];
    uint8_t nSectors2[4];
    uint8_t sectorsPerFat2[4];
    uint8_t fatFlags[2];
    uint8_t version[2];
    uint8_t rootDirCluster[4];
    uint8_t fsInfoSector[2];
    uint8_t copySector[2];
    uint8_t unknown1[12];
    uint8_t physicalDriveNum;
    uint8_t unknown2;
    uint8_t extBootSig;
    uint8_t serialNum[4];
    char volLabel[11];
    char fileSystemSig[8];
    uint8_t bootcode[70];
    uint8_t bitlockerId[16];
    uint8_t fveMetadataOffset1[8];
    uint8_t fveMetadataOffset2[8];
    uint8_t fveMetadataOffset3[8];
    uint8_t unknown3[310];
    uint8_t sectorSignature[2];
} bitlocker_volume_header_win7_t;

// Version 2 is used in Win7 and later
typedef struct {
    char signature[8];
    uint8_t unknown1[2];
    uint8_t version[2];
    uint8_t unknown2[4];
    uint8_t encryptedVolSize[8];
    uint8_t unknown3[4];
    uint8_t nVolHeaderSectors[4];
    uint8_t fveMetadataBlockOffset1[8];
    uint8_t fveMetadataBlockOffset2[8];
    uint8_t fveMetadataBlockOffset3[8];
    uint8_t volumeHeaderOffset[8];
} bitlocker_fve_metadata_block_header_v2_t;

typedef struct {
    uint8_t size[4];
    uint8_t version[4];
    uint8_t headerSize[4];
    uint8_t sizeCopy[4];
    uint8_t volumeId[16];
    uint8_t nextNonceCounter[4];
    uint8_t encryptionMethod[4];
    uint8_t createTime[8];
} bitlocker_fve_metadata_header_t;

class BitlockerParser {
public:
	BitlockerParser() {
        memset(m_bitlockerRecoveryKeyId, 0, 16);
        memset(m_passwordHash, 0, SHA256_DIGEST_LENGTH);
        memset(m_recoveryPasswordHash, 0, SHA256_DIGEST_LENGTH);
        mbedtls_aes_init(&m_aesFvekEncryptionContext);
        mbedtls_aes_init(&m_aesFvekDecryptionContext);
        mbedtls_aes_init(&m_aesTweakEncryptionContext);
        mbedtls_aes_xts_init(&m_aesXtsDecryptionContext);
        tsk_init_lock(&m_decrypt_sector_lock);
    };

    BITLOCKER_STATUS initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset, const char* a_password);
    BITLOCKER_STATUS initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);

	bool initializationSuccessful() { return m_isBitlocker & m_unlockSuccessful; }

    string getDescription();
    string getUnsupportedProtectionTypes();
    string getRecoveryKeyIdStr();

    uint16_t getSectorSize() {
        return m_sectorSize;
    }
    ssize_t readAndDecryptSectors(TSK_DADDR_T offsetInVolume, size_t len, uint8_t* data);

    ~BitlockerParser() {
        clearIntermediateData();
        mbedtls_aes_free(&m_aesFvekEncryptionContext);
        mbedtls_aes_free(&m_aesFvekDecryptionContext);
        mbedtls_aes_free(&m_aesTweakEncryptionContext);
        mbedtls_aes_xts_free(&m_aesXtsDecryptionContext);
        if (m_encryptedDataBuffer != nullptr) {
            memset(m_encryptedDataBuffer, 0, m_sectorSize);
            free(m_encryptedDataBuffer);
            m_encryptedDataBuffer = nullptr;
        }
        if (m_diffuserTempBuffer != nullptr) {
            memset(m_diffuserTempBuffer, 0, m_sectorSize);
            free(m_diffuserTempBuffer);
            m_diffuserTempBuffer = nullptr;
        }
        tsk_deinit_lock(&m_decrypt_sector_lock);
    }

private:
    bool hasBitlockerSignature(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);
    BITLOCKER_STATUS initializeInternal(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);
    BITLOCKER_STATUS handlePassword(string password);
    BITLOCKER_STATUS readFveMetadataBlockHeader(uint64_t& currentOffset);
    BITLOCKER_STATUS readFveMetadataHeader(uint64_t& currentOffset, uint32_t& metadataEntriesSize);
    BITLOCKER_STATUS readFveMetadataEntries(uint64_t currentOffset, uint32_t metadataEntriesSize);
    BITLOCKER_STATUS getVolumeMasterKey();
    BITLOCKER_STATUS parseVMKEntry(MetadataEntry* entry, MetadataEntry** vmkEntry);
    BITLOCKER_STATUS parsePasswordProtectedVMK(MetadataValueVolumeMasterKey* vmkValue, MetadataEntry** vmkEntry);
    BITLOCKER_STATUS parseClearKeyProtectedVMK(MetadataValueVolumeMasterKey* vmkValue, MetadataEntry** vmkEntry);
    BITLOCKER_STATUS getFullVolumeEncryptionKey();
    BITLOCKER_STATUS getKeyData(MetadataEntry* entry, uint8_t** keyDataPtr, size_t& keyLen);
    BITLOCKER_STATUS parseVolumeHeader();
    BITLOCKER_STATUS setKeys(MetadataEntry* fvekEntry);
    BITLOCKER_STATUS setKeys(MetadataValueKey* fvek, BITLOCKER_ENCRYPTION_TYPE type);

    void clearFveMetadataEntries() {
        for (auto it = m_metadataEntries.begin(); it != m_metadataEntries.end(); ++it) {
            delete *it;
        }
        m_metadataEntries.clear();
    }

    void clearIntermediateData() {
        clearFveMetadataEntries();
        memset(m_passwordHash, 0, SHA256_DIGEST_LENGTH);
        memset(m_recoveryPasswordHash, 0, SHA256_DIGEST_LENGTH);
        if (m_decryptedVmkEntry != nullptr) {
            delete m_decryptedVmkEntry;
            m_decryptedVmkEntry = nullptr;
        }
    }

    TSK_DADDR_T convertVolumeOffset(TSK_DADDR_T origOffset);
    int decryptSector(TSK_DADDR_T offset, uint8_t* data);
    int decryptSectorAESCBC_noDiffuser(uint64_t offset, uint8_t* data);
    int decryptSectorAESCBC_diffuser(uint64_t offset, uint8_t* data);
    void decryptDiffuserA(uint8_t* data, uint16_t dataLen, uint8_t* result);
    void decryptDiffuserB(uint8_t* data, uint16_t dataLen, uint8_t* result);
    int decryptSectorAESXTS(uint64_t offset, uint8_t* data);

    // If allocated, both with have size m_sectorSize
    uint8_t* m_encryptedDataBuffer = nullptr;
    uint8_t* m_diffuserTempBuffer = nullptr;

    list<uint64_t> m_fveMetadataOffsets;
    list<MetadataEntry*> m_metadataEntries;
    MetadataEntry* m_decryptedVmkEntry = NULL;

    BITLOCKER_ENCRYPTION_TYPE m_encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
    mbedtls_aes_context m_aesFvekEncryptionContext;
    mbedtls_aes_context m_aesFvekDecryptionContext;
    mbedtls_aes_context m_aesTweakEncryptionContext;
    mbedtls_aes_xts_context m_aesXtsDecryptionContext;

    const uint8_t m_bitlockerSignature[8] = { 0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D }; // "-FVE-FS-"

	bool m_isBitlocker = false;
	bool m_unlockSuccessful = false;

    // Track which protection types were used/found
    BITLOCKER_KEY_PROTECTION_TYPE m_protectionTypeUsed = BITLOCKER_KEY_PROTECTION_TYPE::UNKNOWN;
    set<BITLOCKER_KEY_PROTECTION_TYPE> m_unsupportedProtectionTypesFound;

    TSK_IMG_INFO* m_img_info = NULL;
    uint64_t m_volumeOffset; // All offsets are relative to the start of the volume
    uint16_t m_sectorSize = 0;
    uint64_t m_encryptedVolumeSize = 0;
    tsk_lock_t m_decrypt_sector_lock;
    bool m_haveRecoveryKeyId = false;
    uint8_t m_bitlockerRecoveryKeyId[16];

    bool m_havePassword = false;
    uint8_t m_passwordHash[SHA256_DIGEST_LENGTH];

    bool m_haveRecoveryPassword = false;
    uint8_t m_recoveryPasswordHash[SHA256_DIGEST_LENGTH];

    // Offset and size of the original volume header
    uint64_t m_volumeHeaderOffset = 0;
    uint64_t m_volumeHeaderSize = 0;
};

#endif