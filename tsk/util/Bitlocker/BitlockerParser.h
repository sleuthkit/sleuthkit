#pragma once

#ifdef HAVE_LIBMBEDTLS

#include <stdio.h>
#include "tsk/base/tsk_base_i.h"
#include "tsk/img/tsk_img_i.h"

#include "MetadataEntry.h"
#include "MetadataValue.h"
#include "MetadataUtils.h"
#include "MetadataValueKey.h"

#include "mbedtls/aes.h"

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
} bitlocker_volume_header_t;

// Version 1 (Vista) is the same size and has the signature in the same place, which is all we currently use
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
        memset(passwordHash, 0, SHA256_DIGEST_LENGTH);
        memset(recoveryPasswordHash, 0, SHA256_DIGEST_LENGTH);
        mbedtls_aes_init(&aesFvekEncryptionContext);
        mbedtls_aes_init(&aesFvekDecryptionContext);
        mbedtls_aes_init(&aesTweakEncryptionContext);
        mbedtls_aes_xts_init(&aesXtsDecryptionContext);
    };

    BITLOCKER_STATUS initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset, const char* password);
    BITLOCKER_STATUS initialize(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);

	bool initializationSuccessful() { return isBitlocker & unlockSuccessful; }

    uint16_t getSectorSize() {
        return sectorSize;
    }
    ssize_t readAndDecryptSectors(TSK_DADDR_T offsetInVolume, size_t len, uint8_t* data);
    int decryptSector(TSK_DADDR_T offset, uint8_t* data);
    TSK_DADDR_T convertVolumeOffset(TSK_DADDR_T origOffset);

    ~BitlockerParser() {
        writeDebug("Deleting BitlockerParser");
        memset(passwordHash, 0, SHA256_DIGEST_LENGTH);
        memset(recoveryPasswordHash, 0, SHA256_DIGEST_LENGTH);
        clearFveMetadataEntries();
        if (decryptedVmkEntry != NULL) {
            delete decryptedVmkEntry;
        }

        mbedtls_aes_free(&aesFvekEncryptionContext);
        mbedtls_aes_free(&aesFvekDecryptionContext);
        mbedtls_aes_free(&aesTweakEncryptionContext);
        mbedtls_aes_xts_free(&aesXtsDecryptionContext);
    }

private:
    bool hasBitlockerSignature(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);
    BITLOCKER_STATUS initializeInternal(TSK_IMG_INFO* a_img_info, uint64_t a_volumeOffset);
    BITLOCKER_STATUS handlePassword(string password);
    BITLOCKER_STATUS readFveMetadataBlockHeader(uint64_t& currentOffset);
    BITLOCKER_STATUS readFveMetadataHeader(uint64_t& currentOffset, uint32_t& metadataEntriesSize);
    BITLOCKER_STATUS readFveMetadataEntries(uint64_t currentOffset, uint32_t metadataEntriesSize);
    void clearFveMetadataEntries() {
        for (auto it = metadataEntries.begin(); it != metadataEntries.end(); ++it) {
            delete(*it);
        }
        metadataEntries.clear();
    }
    BITLOCKER_STATUS getVolumeMasterKey();
    BITLOCKER_STATUS parseVMKEntry(MetadataEntry* entry, MetadataEntry** vmkEntry);
    BITLOCKER_STATUS getFullVolumeEncryptionKey();
    BITLOCKER_STATUS getKeyData(MetadataEntry* entry, uint8_t** keyDataPtr, size_t& keyLen);
    BITLOCKER_STATUS parseVolumeHeader();
    BITLOCKER_STATUS setKeys(MetadataEntry* fvekEntry);
    BITLOCKER_STATUS setKeys(MetadataValueKey* fvek, BITLOCKER_ENCRYPTION_TYPE type);

    int decryptSectorAESCBC_noDiffuser(uint64_t offset, uint8_t* data);
    int decryptSectorAESXTS(uint64_t offset, uint8_t* data);

    list<MetadataEntry*> metadataEntries;
    MetadataEntry* decryptedVmkEntry = NULL;

    uint64_t volumeOffset; // All offsets appear to be relative to the start of the volume

    mbedtls_aes_context aesFvekEncryptionContext;
    mbedtls_aes_context aesFvekDecryptionContext;
    mbedtls_aes_context aesTweakEncryptionContext;
    mbedtls_aes_xts_context aesXtsDecryptionContext;

    const uint8_t bitlockerSignature[8] = { 0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D }; // "-FVE-FS-"

	bool isBitlocker = false;
	bool unlockSuccessful = false;

    TSK_IMG_INFO* img_info = NULL;
    list<uint64_t> fveMetadataOffsets;

    bool havePassword = false;
    uint8_t passwordHash[SHA256_DIGEST_LENGTH];

    bool haveRecoveryPassword = false;
    uint8_t recoveryPasswordHash[SHA256_DIGEST_LENGTH];

    uint64_t volumeHeaderOffset = 0;
    uint64_t volumeHeaderSize = 0;

    uint16_t sectorSize = 0;

    BITLOCKER_ENCRYPTION_TYPE encryptionType = BITLOCKER_ENCRYPTION_TYPE::UNKNOWN;
};

#endif