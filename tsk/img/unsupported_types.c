/*
** The Sleuth Kit
**
** Copyright (c) 2021 Basis Technology Corp.  All rights reserved
** Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
**
** This software is distributed under the Common Public License 1.0
**
*/

int
detectSignature(const char * signature, size_t signatureLen, size_t startingOffset, const char * buf, size_t bufLen) {

    if (offset + signatureLen >= bufLen) {
        return 0;
    }

    if (memcmp(signature, buf + offset, signatureLen) == 0) {
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
const char * detectUnsupportedType(TSK_IMG_INFO * img_info) {

    // Read the beginning of the image. There should be room for all the signature searches.
    size_t len = 1024;
    char* buf = (char*)tsk_malloc(len);
    if (buf == NULL) {
        return NULL;
    }
    if (tsk_img_read(img_info, offset, buf, len) != len) {
        free(buf);
        return NULL;
    }

    char * result = (char*) tsk_malloc(256);
    if (result == NULL) {
        free(buf);
        return NULL;
    }
    result[0] = '\0';

    if (detectSignature("EVF2\r\n\x81\x00", 8, buf, len)) {
        strcpy(result, "EWF Version 2 (Ex01)");
    }
    else if (detectSignature("ADSEGMENTEDFILE", 15, buf, len)) {
        strcpy(result, "Custom Content Image (AD1)");
    }
    else if (detectSignature("Rar!\x1a\x07", 6, buf, len)) {
        strcpy(result, "RAR Archive");
    }
    else if (detectSignature("7z\xbc\xaf\x27\x1c", 6, buf, len)) {
        strcpy(result, "7-Zip Archive");
    }
    else if (detectSignature("PK", 2, buf, len)) {
        strcpy(result, "Zip Archive");
    }
    else if (detectSignature("\x1f\x8b", 2, buf, len)) {
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