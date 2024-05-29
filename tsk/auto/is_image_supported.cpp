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
 */

#include "tsk_is_image_supported.h"

TskIsImageSupported::TskIsImageSupported()
{
    m_wasDataFound = false;
    m_wasEncryptionFound = false;
    m_wasPossibleEncryptionFound = false;
    m_wasFileSystemFound = false;
    m_wasUnsupported = false;
    m_bitlockerError = false;
    m_encryptionDesc[0] = '\0';
    m_possibleEncryptionDesc[0] = '\0';
    m_unsupportedDesc[0] = '\0';
    m_bitlockerDesc[0] = '\0';
}

bool TskIsImageSupported::isImageSupported()
{
    return m_wasDataFound;
}

bool TskIsImageSupported::isImageEncrypted()
{
    return m_wasEncryptionFound;
}

/**
* Idea is to try to give the user a simple error message explaining the most likely 
* reason the image is not supported
*/
std::string TskIsImageSupported::getSingleLineErrorMessage() {
    // If we have this, we are very confident we have a BitLocker-protected partition
    // and that we have a message to show the user. Most commonly this is a missing
    // or incorrect password.
    if (m_bitlockerError) {
        if (strnlen(m_bitlockerDesc, 1024) > 0) {
            return std::string(m_bitlockerDesc);
        }
        return "BitLocker error"; // Safety message - we should always have a description saved
    }

    // Check if we have a known unsupported image type
    if (strnlen(m_unsupportedDesc, 1024) > 0) {
        return "Unsupported image type (" + std::string(m_unsupportedDesc) + ")";
    }

    // Now report any encryption/possible encryption
    if (m_wasEncryptionFound || m_wasPossibleEncryptionFound) {
        std::string encDesc = "";
        if (m_wasEncryptionFound) {
            encDesc = "Encryption detected";
            if (strnlen(m_encryptionDesc, 1024) > 0) {
                encDesc += " (" + std::string(m_encryptionDesc) + ")";
            }
        }
        else {
            encDesc = "Possible encryption detected";
            if (strnlen(m_possibleEncryptionDesc, 1024) > 0) {
                encDesc += " (" + std::string(m_possibleEncryptionDesc) + ")";
            }
        }
        return encDesc;
    }

    // Default message
    return "Error loading file systems";
}

void TskIsImageSupported::printResults() {

    printf("Encryption: ");
    if (!m_wasEncryptionFound && !m_wasPossibleEncryptionFound) {
        printf("None");
    }
    else if (m_wasEncryptionFound) {
        if (m_wasFileSystemFound) {
            printf("Partial");
        }
        else {
            printf("Full Disk");
        }
    }
    else {
        if (m_wasFileSystemFound) {
            printf("Possible Partial");
        }
        else {
            printf("Possible Full Disk");
        }
    }
    printf("\n");

    printf("Encryption Type: ");
    if (strnlen(m_encryptionDesc, 1024) > 0) {
        printf("%s", m_encryptionDesc);
    } 
    else if (strnlen(m_possibleEncryptionDesc, 1024) > 0) {
        printf("%s", m_possibleEncryptionDesc);
    }
    else {
        printf("None");
    }
    printf("\n");


    printf("TSK Support: ");
    if (m_wasFileSystemFound) {
        printf("Yes");
    }
    else {
        printf("No");
        if (strnlen(m_unsupportedDesc, 1024) > 0) {
            printf(" (%s)", m_unsupportedDesc);
        }
    }
    printf("\n");
}

uint8_t TskIsImageSupported::handleError() 
{
    // If encryption was found, update the flags
    TSK_ERROR_INFO* lastError = tsk_error_get_info();
    if (lastError != NULL) {
        uint32_t errCode = lastError->t_errno;

        if (errCode == TSK_ERR_FS_ENCRYPTED || errCode == TSK_ERR_VS_ENCRYPTED) {
            strncpy(m_encryptionDesc, lastError->errstr, 1024);
            m_wasEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_FS_BITLOCKER_ERROR) {
            // This is the case where we're confident we have BitLocker encryption but
            // failed to initialize it. The most common cause would be a missing
            // or incorrect password.
            strncpy(m_encryptionDesc, "BitLocker", 1024);
            m_wasEncryptionFound = true;
            m_bitlockerError = true;
            strncpy(m_bitlockerDesc, "BitLocker status - ", 1024);
            strncat(m_bitlockerDesc, lastError->errstr, 950);
        }
        else if (errCode == TSK_ERR_FS_POSSIBLY_ENCRYPTED) {
            strncpy(m_possibleEncryptionDesc, lastError->errstr, 1024);
            m_wasPossibleEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_IMG_UNSUPTYPE) {
            strncpy(m_unsupportedDesc, lastError->errstr, 1024);
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_VS_MULTTYPE) {
            // errstr only contains the "MAC or DOS" part, so add more context
            strncpy(m_unsupportedDesc, "Multiple volume system types found - ", 1024);
            strncat(m_unsupportedDesc, lastError->errstr, 950);
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_FS_MULTTYPE) {
            // errstr only contains the "UFS or NTFS" part, so add more context
            strncpy(m_unsupportedDesc, "Multiple file system types found - ", 1024);
            strncat(m_unsupportedDesc, lastError->errstr, 950);
            m_wasUnsupported = true;
        }

    }
    return 0;
}

/**
* Prepare the result for dataModel_SleuthkitJNI::isImageSupportedNat.
* There's some complexity here because BitLocker drives appear to have a very small unencrypted
* volume followed by the encrypted volume. So we need to check for BitLocker errors instead
* of just going by whether we were able to open a file system. 
* 
* @return Empty string if image is supported, error string if not
*/
std::string TskIsImageSupported::getMessageForIsImageSupportedNat() {
    // General approach:
    // - If we have a BitLocker error then report it, even if we opened at least one file system
    // - If we did open at least one file system and had no Bitlocker errors, return empty string
    // - Otherwise return the error string

    if (m_bitlockerError) {
        return getSingleLineErrorMessage();
    }

    if (isImageSupported()) {
        return "";
    }

    return getSingleLineErrorMessage();
}

TSK_RETVAL_ENUM TskIsImageSupported::processFile(TSK_FS_FILE * /*fs_file*/,
                                                 const char * /*path*/)
{
    return TSK_OK;
}

TSK_FILTER_ENUM
TskIsImageSupported::filterFs(TSK_FS_INFO * /*fs_info*/)
{
    m_wasDataFound = true;
    m_wasFileSystemFound = true;
    return TSK_FILTER_SKIP;
}

TSK_FILTER_ENUM
TskIsImageSupported::filterPool(const TSK_POOL_INFO * pool_info)
{
    // There's nothing to do, but we need to override this to allow the pool
    // to be processed.
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskIsImageSupported::filterPoolVol(const TSK_POOL_VOLUME_INFO * pool_vol)
{
    // There's nothing to do, but we need to override this to allow the pool
    // to be processed.
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskIsImageSupported::filterVol(const TSK_VS_PART_INFO * /*vs_part*/)
{
    m_wasDataFound = true;
    return TSK_FILTER_CONT;
}
