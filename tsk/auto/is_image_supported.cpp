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
#include "tsk/fs/encryptionHelper.h"
#include <sstream>
#include <algorithm>
#include <regex>

TskIsImageSupported::TskIsImageSupported()
{
    m_currentVolume = -1;
    m_sawVolumeSystem = false;
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
            snprintf(m_encryptionDesc, sizeof(m_encryptionDesc), "%s", lastError->errstr);
            m_wasEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_FS_BITLOCKER_ERROR) {
            // This is the case where we're confident we have BitLocker encryption but
            // failed to initialize it. The most common cause would be a missing
            // or incorrect password.
            snprintf(m_encryptionDesc, sizeof(m_encryptionDesc), "BitLocker");
            m_wasEncryptionFound = true;
            m_bitlockerError = true;
            // %.*s limits the errstr field width so prefix + errstr fits in the buffer.
            snprintf(m_bitlockerDesc, sizeof(m_bitlockerDesc), "BitLocker status - %.*s",
                (int)(sizeof(m_bitlockerDesc) - sizeof("BitLocker status - ")), lastError->errstr);
        }
        else if (errCode == TSK_ERR_FS_POSSIBLY_ENCRYPTED) {
            snprintf(m_possibleEncryptionDesc, sizeof(m_possibleEncryptionDesc), "%s", lastError->errstr);
            m_wasPossibleEncryptionFound = true;
        }
        else if (errCode == TSK_ERR_IMG_UNSUPTYPE) {
            snprintf(m_unsupportedDesc, sizeof(m_unsupportedDesc), "%s", lastError->errstr);
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_VS_MULTTYPE) {
            // errstr only contains the "MAC or DOS" part, so add more context.
            // %.*s limits the errstr field width so prefix + errstr fits in the buffer.
            snprintf(m_unsupportedDesc, sizeof(m_unsupportedDesc), "Multiple volume system types found - %.*s",
                (int)(sizeof(m_unsupportedDesc) - sizeof("Multiple volume system types found - ")), lastError->errstr);
            m_wasUnsupported = true;
        }
        else if (errCode == TSK_ERR_FS_MULTTYPE) {
            // errstr only contains the "UFS or NTFS" part, so add more context.
            // %.*s limits the errstr field width so prefix + errstr fits in the buffer.
            snprintf(m_unsupportedDesc, sizeof(m_unsupportedDesc), "Multiple file system types found - %.*s",
                (int)(sizeof(m_unsupportedDesc) - sizeof("Multiple file system types found - ")), lastError->errstr);
            m_wasUnsupported = true;
        }

        // A file system error belongs to the volume being opened; record why it did not open
        VolumeResult* volPtr = ((errCode & ~TSK_ERR_MASK) == TSK_ERR_FS) ? getCurrentVolume(0) : nullptr;
        if (volPtr != nullptr) {
            VolumeResult& vol = *volPtr;
            if (vol.status != "opened") {
                std::string msg(lastError->errstr);
                if (errCode == TSK_ERR_FS_BITLOCKER_ERROR) {
                    if (msg.rfind(TSK_BITLOCKER_MSG_WRONG_PASSWORD, 0) == 0) {
                        vol.status = "bitlocker_wrong_key";
                    }
                    else if (msg.rfind(TSK_BITLOCKER_MSG_NEED_PASSWORD, 0) == 0) {
                        vol.status = "bitlocker_needs_key";
                    }
                    else if (msg.rfind(TSK_BITLOCKER_MSG_UNSUPPORTED_PROTECTION, 0) == 0) {
                        vol.status = "bitlocker_unsupported_protector";
                    }
                    else {
                        vol.status = "bitlocker_error";
                    }
                    std::smatch match;
                    if (std::regex_search(msg, match, std::regex("Recovery key identifier: ([0-9A-Fa-f-]+)"))) {
                        vol.recoveryKeyId = match[1].str();
                    }
                }
                else if (errCode == TSK_ERR_FS_ENCRYPTED) {
                    vol.status = "encrypted";
                }
                else if (errCode == TSK_ERR_FS_POSSIBLY_ENCRYPTED) {
                    vol.status = "possibly_encrypted";
                }
                else if (errCode == TSK_ERR_FS_UNKTYPE) {
                    vol.status = "no_file_system";
                }
                else if (errCode == TSK_ERR_FS_MULTTYPE) {
                    vol.status = "multiple_file_systems";
                }
                else {
                    vol.status = "error";
                }
                vol.message = msg;
            }
        }
    }
    return 0;
}

/**
* The volume being processed, adding an entry for the whole image when there is no
* volume system (TskAuto then opens a file system at the start of the image).
*
* @param a_offset Byte offset of the file system, used only for that whole-image entry
*
* @return The volume, or nullptr inside a volume system but outside an allocated partition
*/
TskIsImageSupported::VolumeResult* TskIsImageSupported::getCurrentVolume(TSK_OFF_T a_offset) {
    if (m_currentVolume < 0) {
        if (m_sawVolumeSystem) {
            return nullptr;
        }
        VolumeResult vol;
        vol.addr = -1;
        vol.offset = a_offset;
        vol.length = (m_img_info != nullptr) ? m_img_info->size - a_offset : 0;
        vol.description = "No volume system";
        vol.status = "not_tried";
        vol.keyIndex = -1;
        m_volumes.push_back(vol);
        m_currentVolume = (int)m_volumes.size() - 1;
    }
    return &m_volumes[m_currentVolume];
}

static std::string jsonEscape(const std::string& a_str) {
    std::ostringstream out;
    for (unsigned char c : a_str) {
        switch (c) {
        case '"':  out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out << buf;
            }
            else {
                out << c;
            }
        }
    }
    return out.str();
}

/**
* The outcome for the image and each of its volumes, as JSON:
*
*   {"message": "<getMessageForIsImageSupportedNat()>",
*    "fileSystemFound": true,
*    "volumes": [{"addr": 2, "offset": 16777216, "length": 67108864, "description": "Basic data partition",
*                 "status": "opened", "fileSystem": "ntfs", "encryption": "BitLocker ...", "keyIndex": 0,
*                 "recoveryKeyId": "", "message": ""}, ...]}
*
* "message" keeps the old all-or-nothing verdict: empty only if no volume hit a BitLocker error.
* "fileSystemFound" is true if any file system opened, so a caller can still use an image
* where some BitLocker volumes stay locked. Only allocated partitions are listed.
*/
std::string TskIsImageSupported::getResultJson() {
    std::ostringstream out;
    out << "{\"message\":\"" << jsonEscape(getMessageForIsImageSupportedNat()) << "\""
        << ",\"fileSystemFound\":" << (m_wasFileSystemFound ? "true" : "false")
        << ",\"volumes\":[";
    for (size_t i = 0; i < m_volumes.size(); i++) {
        const VolumeResult& vol = m_volumes[i];
        if (i > 0) {
            out << ",";
        }
        out << "{\"addr\":" << vol.addr
            << ",\"offset\":" << vol.offset
            << ",\"length\":" << vol.length
            << ",\"description\":\"" << jsonEscape(vol.description) << "\""
            << ",\"status\":\"" << jsonEscape(vol.status) << "\""
            << ",\"fileSystem\":\"" << jsonEscape(vol.fileSystem) << "\""
            << ",\"encryption\":\"" << jsonEscape(vol.encryption) << "\""
            << ",\"keyIndex\":" << vol.keyIndex
            << ",\"recoveryKeyId\":\"" << jsonEscape(vol.recoveryKeyId) << "\""
            << ",\"message\":\"" << jsonEscape(vol.message) << "\"}";
    }
    out << "]}";
    return out.str();
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
                firstLine.erase(std::remove(firstLine.begin(), firstLine.end(), '\n'), firstLine.end());
                firstLine.erase(std::remove(firstLine.begin(), firstLine.end(), '\r'), firstLine.end());

                // To make the output look nicer make sure any open parens get closed (the close paren was likely on the last line of the original error message)
                // For example we want to add a close paren to this line:
                //   vmdk_open file: r:\work\images\renamedVM.vmdke: Error opening (libcfile_file_open_wide_with_error_code: no such file: \\?\R:\work\images\renamedVM.vmdke.
                int nOpenParens = (int)std::count(firstLine.begin(), firstLine.end(), '(');
                int nCloseParens = (int)std::count(firstLine.begin(), firstLine.end(), ')');
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
TskIsImageSupported::filterFs(TSK_FS_INFO * fs_info)
{
    m_wasDataFound = true;
    m_wasFileSystemFound = true;

    VolumeResult* vol = (fs_info != nullptr) ? getCurrentVolume(fs_info->offset) : nullptr;
    if (vol != nullptr) {
        vol->status = "opened";
        vol->message.clear();
        vol->recoveryKeyId.clear();
        vol->fileSystem = tsk_fs_type_toname(fs_info->ftype);
        if (fs_info->encryption_type != TSK_FS_ENCRYPTION_TYPE_NONE) {
            char desc[256];
            tsk_fs_get_encryption_description(fs_info, desc, sizeof(desc));
            vol->encryption = desc;
            vol->keyIndex = tsk_fs_get_encryption_key_index(fs_info);
        }
    }
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
TskIsImageSupported::filterVol(const TSK_VS_PART_INFO * vs_part)
{
    m_wasDataFound = true;
    m_sawVolumeSystem = true;
    m_currentVolume = -1;

    // Only allocated partitions get a file system attempt whose failure is reported
    if (vs_part != nullptr && (vs_part->flags & TSK_VS_PART_FLAG_ALLOC)) {
        VolumeResult vol;
        vol.addr = vs_part->addr;
        vol.offset = (TSK_OFF_T)(vs_part->start * vs_part->vs->block_size) + vs_part->vs->offset;
        vol.length = (TSK_OFF_T)(vs_part->len * vs_part->vs->block_size);
        vol.description = (vs_part->desc != nullptr) ? vs_part->desc : "";
        vol.status = "not_tried";
        vol.keyIndex = -1;
        m_volumes.push_back(vol);
        m_currentVolume = (int)m_volumes.size() - 1;
    }
    return TSK_FILTER_CONT;
}
