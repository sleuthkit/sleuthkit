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
#include <algorithm>
#include <string>
#include <vector>


/**
* Open the image and look for file systems in it.
*
* @param path         Path to the image (UTF-8)
* @param tskIsImage   Tester, with any password already set
* @param getResult    Called with the tester while the image is still open; its return value is the result
* @param resultStr    Will hold the result, or "Error opening image" if the image could not be opened
*
* @return false if the test could not be run (memory allocation or path conversion issues)
*/
template <typename F>
static bool runImageTest(const char* path, TskIsImageSupported& tskIsImage, F getResult, std::string& resultStr) {
    TSK_TCHAR* imagePathT = NULL;
#ifdef TSK_WIN32
    // If we're on Windows, TSK_TCHAR is a wchar so we need to convert the path
    size_t pathLen = strlen(path);
    imagePathT = (TSK_TCHAR*)tsk_malloc((pathLen + 1) * sizeof(TSK_TCHAR));
    if (imagePathT == nullptr) {
        return false;
    }

    UTF8* utf8 = (UTF8*)path;
    UTF16* utf16 = (UTF16*)imagePathT;
    int ret = tsk_UTF8toUTF16((const UTF8**)&utf8, &utf8[pathLen],
            &utf16, &utf16[pathLen], TSKlenientConversion);
    if (ret != TSKconversionOK) {
        free(imagePathT);
        return false;
    }
#else
    // If we're not on Windows then TSK_TCHAR is just char and we don't need to convert
    imagePathT = path;
#endif

    TSK_TCHAR** imagePaths = (TSK_TCHAR**)tsk_malloc((1) * sizeof(TSK_TCHAR*));
    imagePaths[0] = imagePathT;
    if (tskIsImage.openImage(1, imagePaths, TSK_IMG_TYPE_DETECT, 0)) {
        resultStr = "Error opening image";
    }
    else {
        tskIsImage.findFilesInImg();
        resultStr = getResult(tskIsImage);
    }

    // Cleanup
    tskIsImage.closeImage();
    free(imagePaths);
#ifdef TSK_WIN32
    if (imagePathT != nullptr) {
        free(imagePathT);
    }
#endif
    return true;
}

/**
* Copy a string to memory the caller frees with freeString().
*
* @return The copy, or nullptr if memory could not be allocated
*/
static char* copyResult(const std::string& resultStr) {
    size_t resultLen = resultStr.size();
    char* result_cStr = (char*)malloc((resultLen + 1) * sizeof(char));
    if (result_cStr != nullptr) {
        memcpy(result_cStr, resultStr.c_str(), resultLen + 1);
    }
    return result_cStr;
}

/**
* Try to open an image. Use the password if supplied.
*
* @param path  Path to the image
* @param password Password. May be null. May hold several keys separated by '\n'.
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

    std::string resultStr = "";
    if (!runImageTest(path, tskIsImage, [](TskIsImageSupported& t) { return t.getMessageForIsImageSupportedNat(); }, resultStr)) {
        return nullptr;
    }
    return copyResult(resultStr);
}

/**
* Try to open an image with several keys and report what happened to each volume. Every
* encrypted volume is tried with each key, so an image whose BitLocker volumes have
* different passwords or recovery passwords can be checked in one call.
*
* @param path     Path to the image (UTF-8)
* @param keys     Passwords or recovery passwords (UTF-8). Null or empty entries, and entries containing a
*                 line break, are skipped; a volume's "keyIndex" is still an index into this array.
*                 May be null when numKeys is 0.
* @param numKeys  Number of entries in keys
*
* @return JSON from TskIsImageSupported::getResultJson(): the old one-line "message", whether any
*         file system was found, and the status of each volume (including which key opened it and the
*         recovery key identifier of a volume that stayed locked). If the image could not be opened:
*         {"message":"Error opening image","fileSystemFound":false,"volumes":[]}.
*         Null pointer if the test could not be run. Free a non-null result with freeString().
*/
char* isImageSupportedWithKeys(const char* path, const char* const* keys, int numKeys) {
    if (path == nullptr || numKeys < 0 || (keys == nullptr && numKeys > 0)) {
        return nullptr;
    }

    // A null key is kept as an empty one, so every key keeps its index ("keyIndex" in the result)
    std::vector<std::string> keyList;
    keyList.reserve((size_t)numKeys);
    for (int i = 0; i < numKeys; i++) {
        keyList.push_back(keys[i] != nullptr ? keys[i] : "");
    }
    TskIsImageSupported tskIsImage;
    tskIsImage.setFileSystemPasswords(keyList);
    for (auto it = keyList.begin(); it != keyList.end(); ++it) {
        std::fill(it->begin(), it->end(), '\0');
    }

    std::string resultStr = "";
    if (!runImageTest(path, tskIsImage, [](TskIsImageSupported& t) { return t.getResultJson(); }, resultStr)) {
        return nullptr;
    }
    if (resultStr == "Error opening image") {
        resultStr = "{\"message\":\"Error opening image\",\"fileSystemFound\":false,\"volumes\":[]}";
    }
    return copyResult(resultStr);
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