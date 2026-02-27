/*
 ** The Sleuth Kit
 **
 ** Brian Carrier [carrier <at> sleuthkit [dot] org]
 ** Copyright (c) 2024 Sleuth Kit Labs, LLC. All Rights reserved
 ** Copyright (c) 2010-2021 Brian Carrier.  All Rights reserved
 **
 ** This software is distributed under the Common Public License 1.0
 */
#pragma once

#ifdef ISIMAGESUPPORTEDLIB_EXPORTS
#define ISIMAGESUPPORTEDLIB_API __declspec(dllexport)
#else
#define ISIMAGESUPPORTEDLIB_API __declspec(dllimport)
#endif

extern "C" ISIMAGESUPPORTEDLIB_API char* isImageSupported(const char* path, const char* password);
extern "C" ISIMAGESUPPORTEDLIB_API void freeString(char* str);