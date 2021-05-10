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

int
detectSignature(const char * signature, size_t signatureLen, int startingOffset, int endingOffset, const char * buf, size_t bufLen) {

    for (int offset = startingOffset; offset <= endingOffset; offset++) {
        if (offset + signatureLen >= bufLen) {
            return 0;
        }

        if (memcmp(signature, buf + offset, signatureLen) == 0) {
            return 1;
        }
    }
    return 0;
}

int
detectLUKS(const char * buf, size_t len) {
    const char * signature = "LUKS\xba\xbe";
    return detectSignature(signature, strlen(signature), 0, 0, buf, len);
}

// Returns 1 if bitlocker signature is found, 0 otherwise
int
detectBitLocker(const char * buf, size_t len) {

    // Look for the signature near the beginning of the buffer
    const char * signature = "-FVE-FS-";
    return detectSignature(signature, strlen(signature), 0, 32, buf, len);
}

double
calculateEntropy(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {
    int byteCounts[256];
    for (int i = 0; i < 256; i++) {
        byteCounts[i] = 0;
    }

    size_t bufLen = 65536;
    char buf[65536];
    size_t bytesRead = 0;
    for (int i = 1; i < 100; i++) {
        // TODO more bounds checking
        if (offset + i * bufLen > img_info->size) {
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

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (byteCounts[i] > 0) {
            double p = (double)(byteCounts[i]) / bytesRead;
            entropy -= p * log(p) / log(2);
        }
    }
    printf("Entropy: %lf\n", entropy);
    return entropy;
}

// May return null on error.
// Client must free the result when finished. 
encryption_detected_result*
detectEncryption(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    encryption_detected_result* result = (encryption_detected_result*)tsk_malloc(sizeof(encryption_detected_result));
    if (result == NULL) {
        return result;
    }
    result->encryptionType = ENCRYPTION_DETECTED_NONE;
    result->desc[0] = '\0';

    if (img_info == NULL) {
        return result;
    }

    size_t len = 1024;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return result;
    }

    if (tsk_img_read(img_info, offset, buf, len) != len) {
        free(buf);
        return result;
    }



    if (detectBitLocker(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "BitLocker encryption detected");
        free(buf);
        return result;
    }

    if (detectLUKS(buf, len)) {
        result->encryptionType = ENCRYPTION_DETECTED_SIGNATURE;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "LUKS encryption detected");
        free(buf);
        return result;
    }

    free(buf);

    // Final test - check entropy
    double entropy = calculateEntropy(img_info, offset);
    if (entropy > 6.5) {
        result->encryptionType = ENCRYPTION_DETECTED_ENTROPY;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "High entropy detected (%1.2lf)", entropy);
        free(buf);
        return result;
    }

    return result;
}



