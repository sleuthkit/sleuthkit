/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "detect_encryption.h"

// Scans the buffer and returns 1 if the given signature is found, 0 otherwise.
// Looks for the signature starting at each byte from startingOffset to endingOffset.
int
detectSignature(const char * signature, size_t signatureLen, size_t startingOffset, size_t endingOffset, const char * buf, size_t bufLen) {

    for (size_t offset = startingOffset; offset <= endingOffset; offset++) {
        if (offset + signatureLen >= bufLen) {
            return 0;
        }

        if (memcmp(signature, buf + offset, signatureLen) == 0) {
            return 1;
        }
    }
    return 0;
}

// Returns 1 if LUKS signature is found, 0 otherwise
int
detectLUKS(const char * buf, size_t len) {
    const char * signature = "LUKS\xba\xbe";
    return detectSignature(signature, strlen(signature), 0, 0, buf, len);
}

// Returns 1 if BitLocker signature is found, 0 otherwise
int
detectBitLocker(const char * buf, size_t len) {

    // Look for the signature near the beginning of the buffer
    const char * signature = "-FVE-FS-";
    return detectSignature(signature, strlen(signature), 0, 32, buf, len);
}

// Returns 1 if FileVault is found, 0 otherwise
int
detectFileVault(const char * buf, size_t len) {
    // Look for the signature near the beginning of the buffer
    const char * signature = "encrdsa";
    return detectSignature(signature, strlen(signature), 0, 32, buf, len);
}

// Returns the entropy of the beginning of the image.
double
calculateEntropy(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    // Initialize frequency counts
    int byteCounts[256];
    for (int i = 0; i < 256; i++) {
        byteCounts[i] = 0;
    }

    // Read in blocks of 65536 bytes, skipping the first one that is more likely to contain header data.
    size_t bufLen = 65536;
    char buf[65536];
    size_t bytesRead = 0;
    for (uint64_t i = 1; i < 100; i++) {
        if ((i + 1) * bufLen > (uint64_t)img_info->size - offset) {
            break;
        }

        if (tsk_img_read(img_info, offset + i * bufLen, buf, bufLen) != bufLen) {
            break;
        }

        for (int j = 0; j < bufLen; j++) {
            unsigned char b = buf[j] & 0xff;
            byteCounts[b]++;
        }
        bytesRead += bufLen;
    }

    // Calculate entropy
    double entropy = 0.0;
    double log2 = log(2);
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = (double)(byteCounts[i]) / bytesRead;
            entropy -= p * log(p) / log2;
        }
    }
    return entropy;
}

/**
 * Detect volume-type encryption in the image starting at the given offset.
 * May return null on error. Note that client is responsible for freeing the result.
 * 
 * @param img_info The open image
 * @param offset   The offset for the beginning of the volume
 *
 * @return encryption_detected_result containing the result of the check. null for certain types of errors.
*/
encryption_detected_result*
detectVolumeEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    encryption_detected_result* result = (encryption_detected_result*)tsk_malloc(sizeof(encryption_detected_result));
    if (result == NULL) {
        return result;
    }
    result->encryptionType = ENCRYPTION_DETECTED_NONE;
    result->desc[0] = '\0';

    if (img_info == NULL) {
        return result;
    }
    if (offset > (uint64_t)img_info->size) {
        return result;
    }

    // Read the beginning of the image. There should be room for all the signature searches.
    size_t len = 1024;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return result;
    }
    if (tsk_img_read(img_info, offset, buf, len) != len) {
        free(buf);
        return result;
    }

    // Look for BitLocker signature
    if (detectBitLocker(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "BitLocker encryption detected");
        free(buf);
        return result;
    }

    // Look for Linux Unified Key Setup (LUKS) signature
    if (detectLUKS(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "LUKS encryption detected");
        free(buf);
        return result;
    }

    // Look for FileVault
    if (detectFileVault(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "FileVault encryption detected");
        free(buf);
        return result;
    }

    free(buf);

    // Final test - check entropy
    double entropy = calculateEntropy(img_info, offset);
    if (entropy > 7.5) {
        result->encryptionType = ENCRYPTION_DETECTED_ENTROPY;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "High entropy detected (%1.2lf)", entropy);
        return result;
    }

    return result;
}



