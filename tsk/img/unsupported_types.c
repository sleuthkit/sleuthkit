/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

#include "unsupported_types.h"

/**
 * Compare the beginning of the buffer with the given signature.
 *
 * @return 1 if the signature is found, 0 otherwise
 */
int
detectImageSignature(const char * signature, size_t signatureLen, const char * buf, size_t bufLen) {

    if (signatureLen >= bufLen) {
        return 0;
    }

    if (memcmp(signature, buf, signatureLen) == 0) {
        return 1;
    }
    return 0;
}

/**
 * Check if the given raw image is a known but unsupported type.
 * Return string should be freed by caller.
 *
 * @return The name of the image type or null if it doesn't match a known type.
 */
char* detectUnsupportedImageType(TSK_IMG_INFO * img_info) {

    // Read the beginning of the image. There should be room for all the signature searches.
    size_t len = 32;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return NULL;
    }

    if (tsk_img_read(img_info, 0, buf, len) != len) {
        free(buf);
        return NULL;
    }

    char * result = (char*) tsk_malloc(256);
    if (result == NULL) {
        free(buf);
        return NULL;
    }
    result[0] = '\0';

    if (detectImageSignature("ADSEGMENTEDFILE", 15, buf, len)) {
        strcpy(result, "Custom Content Image (AD1)");
    }
    else if (detectImageSignature("EVF2\r\n\x81\x00", 8, buf, len)) {
        strcpy(result, "EWF Version 2 (Ex01)");
    }
    else if (detectImageSignature("Rar!\x1a\x07", 6, buf, len)) {
        strcpy(result, "RAR Archive");
    }
    else if (detectImageSignature("7z\xbc\xaf\x27\x1c", 6, buf, len)) {
        strcpy(result, "7-Zip Archive");
    }
    else if (detectImageSignature("[Dumps]", 7, buf, len)) {
        strcpy(result, "Cellebrite (UFD)");
    }
    else if (detectImageSignature("PK\x03\x04", 4, buf, len) || detectImageSignature("PK\x05\x06", 4, buf, len)
        || (detectImageSignature("PK\x07\x08", 4, buf, len))) {
        strcpy(result, "Zip Archive");
    }
    else if (detectImageSignature("BZh", 3, buf, len)) {
        strcpy(result, "Bzip Archive");
    }
    else if (detectImageSignature("\x1f\x8b", 2, buf, len)) {
        strcpy(result, "Gzip Archive");
    }

    free(buf);
    if (strlen(result) > 0) {
        return result;
    }

    free(result);
    result = NULL;
    return NULL;
}