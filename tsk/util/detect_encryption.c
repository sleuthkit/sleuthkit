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

// Returns 1 if bitlocker signature is found, 0 otherwise
int
detect_bitlocker(char * buf, int len) {

    // Look for the signature near the beginning of the buffer
    const char * signature = "-FVE-FS-";
    for (int i = 0; i < 32; i++) {
        if (i + strlen(signature) >= len) {
            break;
        }

       // printf("detect_bitlocker: ");
        //for (int j = 0; j < strlen(signature); j++) {
        //    printf("%02x ", buf[i + j] & 0xff);
        //}
        //printf(" : ");
        
        if (strncmp(signature, &buf[i], strlen(signature)) == 0) {
          //  printf("matches!\n");
            return 1;
        }
        //printf("no match\n");
        fflush(stdout);
    }


    return 0;
}


double
calculate_entropy(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {
    int byteCounts[256];
    for (int i = 0; i < 256; i++) {
        byteCounts[i] = 0;
    }
    for (int i = 0; i < 256; i++) {
        printf("%d ", byteCounts[i]);
    }
    printf("\n");

    int bufLen = 65536;
    char buf[65536];
    int bytesRead = 0;
    for (int i = 1; i < 100; i++) {

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
    printf("Processed %d bytes\n", bytesRead);
    printf("Entropy! %lf\n", entropy);
    return entropy;
}

// May return null on error.
// Client must free the result when finished. 
encryption_detected_result*
isEncrypted(TSK_IMG_INFO * img_info, TSK_DADDR_T offset) {

    printf("detect_encryption - offset = 0x%llx\n", offset);
    encryption_detected_result* result = (encryption_detected_result*)tsk_malloc(sizeof(encryption_detected_result));
    if (result == NULL) {
        return result;
    }
    result->isEncrypted = 0;
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

    calculate_entropy(img_info, offset);

    if (detect_bitlocker(buf, len)) {
        result->isEncrypted = 1;
        snprintf(result->desc, TSK_ERROR_STRING_MAX_LENGTH, "BitLocker encryption detected");
        return result;
    }

    // TODO - threshold
    //if (calculate_entropy(img_info, offset) > 80) {
        // TODO
    //}

    free(buf);

    return result;
}



