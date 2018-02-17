/*
 *
 * The Sleuth Kit
 *
 * Copyright 2013-2015 Basis Technology Corp.
 * Contact: carrier <at> sleuthkit <dot> org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 * See https://github.com/williballenthin/Rejistry for the original Java version.
 */

/**
 * \file RegistryHiveFile.cpp
 *
 */

#include <Windows.h>
#include <exception>

// Local includes
#include "RegistryHiveFile.h"
#include "RejistryException.h"

namespace Rejistry {

    RegistryHiveFile::RegistryHiveFile(const std::wstring& filePath) {
        HANDLE fileHandle = CreateFile(filePath.c_str(), GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (fileHandle == INVALID_HANDLE_VALUE) {
            throw RegistryParseException(getErrorMessage().c_str());
        }

        LARGE_INTEGER fileSize;
        if (!GetFileSizeEx(fileHandle, &fileSize)) {
            throw RegistryParseException("Failed to get file size.");
        }

        if (fileSize.QuadPart == 0L || fileSize.QuadPart > INT_MAX) {
            CloseHandle(fileHandle);
            throw RegistryParseException("File is either too large to process or is empty.");
        }

        HANDLE fileMappingHandle = CreateFileMapping(fileHandle, NULL, PAGE_READONLY, 0, 0, NULL);
        if (fileMappingHandle == NULL) {
            CloseHandle(fileHandle);
            throw RegistryParseException(getErrorMessage().c_str());
        }

        void * mappedFile = MapViewOfFile(fileMappingHandle, FILE_MAP_READ, 0, 0, 0);

        if (mappedFile == NULL) {
            CloseHandle(fileMappingHandle);
            CloseHandle(fileHandle);
            throw RegistryParseException(getErrorMessage().c_str());
        }

        _buffer = new RegistryByteBuffer(new ByteBuffer((const uint8_t*)mappedFile, (const uint32_t)fileSize.LowPart));

        UnmapViewOfFile(mappedFile);
        CloseHandle(fileMappingHandle);
        CloseHandle(fileHandle);
    }

    RegistryHiveFile::~RegistryHiveFile() {
        if (_buffer != NULL) {
            delete _buffer;
            _buffer = NULL;
        }
    }

    RegistryKey * RegistryHiveFile::getRoot() const {
        return new RegistryKey(getHeader()->getRootNKRecord());
    }

    REGFHeader * RegistryHiveFile::getHeader() const {
        return new REGFHeader(*_buffer, 0x0);
    }

    std::string RegistryHiveFile::getErrorMessage() const {
        DWORD errCode = GetLastError();
        LPVOID lpMsgBuf;

        FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR) &lpMsgBuf, 0, NULL);

        std::string errMsg((LPSTR)lpMsgBuf);
        LocalFree(lpMsgBuf);
        return errMsg;
    }
};
