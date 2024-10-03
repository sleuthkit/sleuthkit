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
detectImageSignatureWithOffset(const char * signature, size_t signatureLen, size_t offset, const char * buf, size_t bufLen) {

    if (signatureLen + offset > bufLen) {
        return 0;
    }

    if (memcmp(signature, buf + offset, signatureLen) == 0) {
        return 1;
    }
    return 0;
}

/**
* Compare the beginning of the buffer with the given signature.
*
* @return 1 if the signature is found, 0 otherwise
*/
int
detectImageSignature(const char * signature, size_t signatureLen, const char * buf, size_t bufLen) {
    return detectImageSignatureWithOffset(signature, signatureLen, 0, buf, bufLen);
}

/**
* Calculate the checksum on the first block to see if matches the tar format.
*
* @return 1 if the checksum is valid, 0 otherwise
*/
int
verifyTarChecksum(const char * buf, size_t bufLen) {
    if (bufLen < 512) {
        return 0;
    }

    // Calculate checksum of first 512 bytes.
    unsigned int cksum = 0;
    const int cksumOffset = 148;
    const int cksumLength = 8;
    for (int i = 0; i < 512; i++) {
        // Add each byte. For the checksum bytes, add a space.
        if ((i < cksumOffset) || (i >= cksumOffset + cksumLength)) {
            cksum += (unsigned char)buf[i];
        }
        else {
            cksum += ' ';
        }
    }

    // Convert the checksum field (octal) to a number
    unsigned int savedCksum = 0;

    // Skip leading spaces
    int startingOffset = cksumOffset;
    for (int i = 0; i < cksumLength; i++) {
        unsigned char b = buf[cksumOffset + i];
        if (b == ' ') {
            startingOffset++;
        }
        else {
            // Hit a non-space character
            break;
        }
    }

    // If the checksum is all spaces, it is not valid
    if (startingOffset == cksumOffset + cksumLength) {
        return 0;
    }

    // Convert octal digits
    for (int offset = startingOffset; offset < cksumOffset + cksumLength; offset++) {
        unsigned char b = buf[offset];

        if (b == 0 || b == ' ') {
            // We're done reading the checksum
            break;
        }

        if (b < '0' || b > '7') {
            // Found an illegal character
            return 0;
        }

        // Add the next digit
        savedCksum = savedCksum << 3 | (b - '0');
    }

    if (savedCksum == cksum) {
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

    // Read the beginning of the image. Try to read in enough bytes for all signatures.
    // The tar checksum calculation requires 512 bytes.
    size_t maxLen = 512; // Bytes to read
    size_t len;          // The actual number of bytes read
    char* buf = (char*)tsk_malloc(maxLen);
    if (buf == NULL) {
        return NULL;
    }

    len = tsk_img_read(img_info, 0, buf, maxLen);
    if (len == 0) {
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
    else if (detectImageSignatureWithOffset("ustar", 5, 257, buf, len)) {
        strcpy(result, "Tar Archive");
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
    else if (verifyTarChecksum(buf, len)) {
        strcpy(result, "Tar Archive");
    }

    free(buf);
    if (strlen(result) > 0) {
        return result;
    }

    free(result);
    result = NULL;
    return NULL;
}