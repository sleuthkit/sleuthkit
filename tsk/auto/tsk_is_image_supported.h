/*
 ** The Sleuth Kit
 ** 
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 **
 */

/**
 * \file tsk_is_image_supported.cpp
 * Class to test whether a given image can be processed by tsk
 * 
 * Usage:
 *  Create a TskIsImageSupported object
 *  Call openImage
 *  Call findFilesInImg
 *  Call isImageSupported - if this returns true then the image is supported. If false or
 *                            if there was an error along the way, the image is not supported
 *  Or call getResultJson for the outcome of every volume, e.g. which BitLocker volumes stayed locked
 */


#include "tsk/tsk_tools_i.h"
#include "tsk/util/detect_encryption.h"

class TskIsImageSupported:public TskAuto {


public:
    TskIsImageSupported();
    virtual TSK_RETVAL_ENUM processFile(TSK_FS_FILE * fs_file, const char *path);
    virtual TSK_FILTER_ENUM filterVol(const TSK_VS_PART_INFO * vs_part);
    virtual TSK_FILTER_ENUM filterPool(const TSK_POOL_INFO * pool_info);
    virtual TSK_FILTER_ENUM filterPoolVol(const TSK_POOL_VOLUME_INFO * pool_vol);
    virtual TSK_FILTER_ENUM filterFs(TSK_FS_INFO * fs_info);
    virtual uint8_t handleError();
    std::string getMessageForIsImageSupportedNat();
    std::string getResultJson();
    bool isImageSupported();
    bool isImageEncrypted();
    std::string getSingleLineErrorMessage();
    void printResults();

    /**
     * What happened when one volume (or, with no volume system, the whole image) was opened.
     * status is one of: opened, bitlocker_needs_key, bitlocker_wrong_key,
     * bitlocker_unsupported_protector, bitlocker_error, encrypted, possibly_encrypted,
     * no_file_system, multiple_file_systems, error, not_tried.
     */
    struct VolumeResult {
        int64_t addr;               // Partition address in the volume system, -1 if there is none
        TSK_OFF_T offset;           // Byte offset of the volume in the image
        TSK_OFF_T length;           // In bytes
        std::string description;    // Partition type
        std::string status;
        std::string fileSystem;     // Set when opened
        std::string encryption;     // Set when opened and encrypted, e.g. "BitLocker AES-XTS 128 bit, unlocked using password"
        int keyIndex;               // Which of the '\n'-separated keys unlocked it, -1 for none
        std::string recoveryKeyId;  // BitLocker recovery key identifier from the error, if any
        std::string message;        // TSK error text when not opened
    };
    const std::vector<VolumeResult>& getVolumeResults() const { return m_volumes; }

private:
    VolumeResult* getCurrentVolume(TSK_OFF_T a_offset);
    std::vector<VolumeResult> m_volumes;
    int m_currentVolume;            // Index into m_volumes, -1 when outside a volume
    bool m_sawVolumeSystem;         // filterVol() was called, so there is no whole-image file system

    bool m_wasDataFound;
    bool m_wasEncryptionFound;
    bool m_wasPossibleEncryptionFound;
    bool m_wasFileSystemFound;
    bool m_wasUnsupported;
    bool m_bitlockerError;
    char m_encryptionDesc[TSK_ERROR_STRING_MAX_LENGTH + 1];
    char m_possibleEncryptionDesc[TSK_ERROR_STRING_MAX_LENGTH + 1];
    char m_unsupportedDesc[TSK_ERROR_STRING_MAX_LENGTH + 1];
    char m_bitlockerDesc[TSK_ERROR_STRING_MAX_LENGTH + 1];
};