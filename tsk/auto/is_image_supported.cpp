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
#include <sstream>
#include <algorithm>

TskIsImageSupported::TskIsImageSupported():
    m_wasDataFound(false),
    m_wasEncryptionFound(false),
    m_wasPossibleEncryptionFound(false),
    m_wasFileSystemFound(false),
    m_wasUnsupported(false),
    m_bitlockerError(false)
{}

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
        if (!m_bitlockerDesc.empty()) {
            return m_bitlockerDesc;
        }
        return "BitLocker error"; // Safety message - we should always have a description saved
    }

    // Check if we have a known unsupported image type
    if (!m_unsupportedDesc.empty()) {
        return "Unsupported image type (" + m_unsupportedDesc + ")";
    }

    // Now report any encryption/possible encryption
    if (m_wasEncryptionFound || m_wasPossibleEncryptionFound) {
        if (m_wasEncryptionFound) {
            return "Encryption detected" + (!m_encryptionDesc.empty() ? " (" + m_encryptionDesc + ')' : "");
        }
        else {
            return "Possible encryption detected" + (!m_possibleEncryptionDesc.empty() ? " (" + m_possibleEncryptionDesc + ')' : "");
        }
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
    if (!m_encryptionDesc.empty()) {
        printf("%s", m_encryptionDesc.c_str());
    }
    else if (!m_possibleEncryptionDesc.empty()) {
        printf("%s", m_possibleEncryptionDesc.c_str());
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
        if (!m_unsupportedDesc.empty()) {
            printf(" (%s)", m_unsupportedDesc.c_str());
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
            m_encryptionDesc = lastError->errstr;
            m_wasEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_FS_BITLOCKER_ERROR) {
            // This is the case where we're confident we have BitLocker encryption but
            // failed to initialize it. The most common cause would be a missing
            // or incorrect password.
            m_encryptionDesc = "BitLocker";
            m_wasEncryptionFound = true;
            m_bitlockerError = true;
            m_bitlockerDesc = std::string("BitLocker status - ") + lastError->errstr;
        }
        else if (errCode == TSK_ERR_FS_POSSIBLY_ENCRYPTED) {
            m_possibleEncryptionDesc = lastError->errstr;
            m_wasPossibleEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_IMG_UNSUPTYPE) {
            m_unsupportedDesc = lastError->errstr;
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_VS_MULTTYPE) {
            // errstr only contains the "MAC or DOS" part, so add more context
            m_unsupportedDesc = std::string("Multiple volume system types found - ") + lastError->errstr;
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_FS_MULTTYPE) {
            // errstr only contains the "UFS or NTFS" part, so add more context
            m_unsupportedDesc = std::string("Multiple file system types found - ") + lastError->errstr;
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

    // We've seen a lot of issues with .vmdk files. If the image has a .vmdk extension, try to open again
    // to get a more specific error string.
    if ((TSTRLEN(m_img_info->images[0]) > 5) && (TSTRICMP(&(m_img_info->images[0][TSTRLEN(m_img_info->images[0]) - 5]), _TSK_T(".vmdk")) == 0)) {
        TSK_IMG_INFO* tempInfo = tsk_img_open(m_img_info->num_img, m_img_info->images, TSK_IMG_TYPE_VMDK_VMDK, m_img_info->sector_size);
        if (tempInfo == NULL) {
            // The vmdk open code failed. The first line should contain everything we need.
            std::stringstream ss(tsk_error_get_errstr());
            std::string firstLine = "";
            std::getline(ss, firstLine);
            if (!firstLine.empty()) { // The error really shouldn't be empty, but if this somehow happens default to the normal error handling code

                // Remove any trailing newline
                firstLine.erase(std::remove(firstLine.begin(), firstLine.end(), '\n'), firstLine.cend());
                firstLine.erase(std::remove(firstLine.begin(), firstLine.end(), '\r'), firstLine.cend());

                // To make the output look nicer make sure any open parens get closed (the close paren was likely on the last line of the original error message)
                // For example we want to add a close paren to this line:
                //   vmdk_open file: r:\work\images\renamedVM.vmdke: Error opening (libcfile_file_open_wide_with_error_code: no such file: \\?\R:\work\images\renamedVM.vmdke.
                int nOpenParens = std::count(firstLine.begin(), firstLine.end(), '(');
                int nCloseParens = std::count(firstLine.begin(), firstLine.end(), ')');
                for (int i = nCloseParens; i < nOpenParens; i++) {
                    firstLine += ")";
                }

                return std::string("Error opening VMDK (" + firstLine + ")");
            }
        }
        else {
            // This is the case where we successfully opened the vmdk but it perhaps did not have a file system.
            tsk_img_close(tempInfo);
        }
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
TskIsImageSupported::filterPool([[maybe_unused]] const TSK_POOL_INFO * pool_info)
{
    // There's nothing to do, but we need to override this to allow the pool
    // to be processed.
    return TSK_FILTER_CONT;
}

TSK_FILTER_ENUM
TskIsImageSupported::filterPoolVol([[maybe_unused]] const TSK_POOL_VOLUME_INFO * pool_vol)
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
