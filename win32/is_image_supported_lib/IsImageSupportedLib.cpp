/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */

// Library to check if an image can be opened by TSK
#include "pch.h"
#include "IsImageSupportedLib.h"

#include "tsk/auto/tsk_is_image_supported.h"
#include "tsk/tsk_tools_i.h"
#include "tsk/fs/apfs_fs.h"
#include <stdlib.h>


/**
* Try to open an image. Use the password if supplied.
* 
* @param path  Path to the image
* @param password Password. May be null.
* 
* @return On success: Empty string
          On failure: Non-empty string containing the reason image opening failed if the tests were completed
                      Null pointer if tests could not be run (memory allocation or path conversion issues)
          If return value is non-null it must be freed by the caller
*/
char* isImageSupported(const char* path, const char* password) {
    if (path == nullptr) {
        return nullptr;
    }

    TskIsImageSupported tskIsImage;
    if (password != NULL) {
        std::string passwordStr(password);
        if (!passwordStr.empty()) {
            tskIsImage.setFileSystemPassword(password);
        }
    }
    
    TSK_TCHAR* imagePathT = NULL;
#ifdef TSK_WIN32
    // If we're on Windows, TSK_TCHAR is a wchar so we need to convert the path
    size_t pathLen = strlen(path);
    imagePathT = (TSK_TCHAR*)tsk_malloc((pathLen + 1) * sizeof(TSK_TCHAR));
    if (imagePathT == nullptr) {
        return nullptr;
    }

    UTF8* utf8 = (UTF8*)path;
    UTF16* utf16 = (UTF16*)imagePathT;
    int ret = tsk_UTF8toUTF16((const UTF8**)&utf8, &utf8[pathLen],
            &utf16, &utf16[pathLen], TSKlenientConversion);
    if (ret != TSKconversionOK) {
        free(imagePathT);
        return nullptr;
    }
#else
    // If we're not on Windows then TSK_TCHAR is just char and we don't need to convert
    imagePathT = path;
#endif

    TSK_TCHAR** imagePaths = (TSK_TCHAR**)tsk_malloc((1) * sizeof(TSK_TCHAR*));
    imagePaths[0] = imagePathT;
    std::string resultStr = "";
    if (tskIsImage.openImage(1, imagePaths, TSK_IMG_TYPE_DETECT, 0)) {
        resultStr = "Error opening image";
    }
    else {
        tskIsImage.findFilesInImg();
        resultStr = tskIsImage.getMessageForIsImageSupportedNat();
    }

    // Cleanup
    tskIsImage.closeImage();
    free(imagePaths);
#ifdef TSK_WIN32
    if (imagePathT != nullptr) {
        free(imagePathT);
    }
#endif

    // Make a new result string to return to the caller
    char* result_cStr = nullptr;
    if (resultStr.empty()) {
        result_cStr = (char*)malloc(1 * sizeof(char));
        if (result_cStr != nullptr) {
            result_cStr[0] = '\0';
        } // We return nullptr on error so we're already good
    }
    else {
        size_t resultLen = resultStr.size();
        result_cStr = (char*)malloc((resultLen + 1) * sizeof(char));
        if (result_cStr != nullptr) {
            strncpy_s(result_cStr, resultLen + 1, resultStr.c_str(), resultLen);
        }// We return nullptr on error so we're already good
    }

    return result_cStr;
}

/**
* Free a string. Intended to be used to free the result of isImageSupported();
* 
* @param str  The string to free
*/
void freeString(char* str) {
	if (str != NULL) {
		free(str);
	}
}