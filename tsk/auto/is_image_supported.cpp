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
    m_encryptionDesc[0] = '\0';
    m_possibleEncryptionDesc[0] = '\0';
    m_unsupportedDesc[0] = '\0';
}

bool TskIsImageSupported::isImageSupported()
{
    return m_wasDataFound;
}

bool TskIsImageSupported::isImageEncrypted()
{
    return m_wasEncryptionFound;
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
