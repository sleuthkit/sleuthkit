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
 * \file RegistryByteBuffer.cpp
 *
 */
#include <stdexcept>
#include <sstream>
#include <locale>
#include <codecvt>
#include <iostream>

// Local includes
#include "RegistryByteBuffer.h"

namespace Rejistry {

    RegistryByteBuffer::RegistryByteBuffer(ByteBuffer * buffer) {
        if (buffer == NULL) {
            throw std::invalid_argument("Buffer must not be null.");
        }
        _byteBuffer = buffer;
    }

    RegistryByteBuffer::~RegistryByteBuffer() {
        if (_byteBuffer != NULL) {
            delete _byteBuffer;
            _byteBuffer = NULL;
        }
    }

    uint16_t RegistryByteBuffer::getWord(const uint32_t offset) const {
        return _byteBuffer->getShort(offset) & 0xFFFF;
    }

    uint32_t RegistryByteBuffer::getDWord(const uint32_t offset) const {
        return _byteBuffer->getInt(offset) & 0xFFFFFFFF;
    }

    uint64_t RegistryByteBuffer::getQWord(const uint32_t offset) const {
        return _byteBuffer->getLong(offset) & 0xFFFFFFFFFFFFFFFF;
    }

    std::string RegistryByteBuffer::getASCIIString() const {
        return getASCIIString(0, _byteBuffer->limit());
    }

    std::string RegistryByteBuffer::getASCIIString(const uint32_t offset, const uint32_t length) const {
        if (length == 0) {
            return "";
        }

        ByteBuffer::ByteArray &data = getData(offset, length);

        return std::string(data.begin(), data.end());
    }

    std::wstring RegistryByteBuffer::getUTF16String() const {
        return getUTF16String(0, _byteBuffer->limit());
    }

    std::wstring RegistryByteBuffer::getUTF16String(const uint32_t offset, const uint32_t length) const {
        if (length == 0) {
            return L"";
        }

        ByteBuffer::ByteArray &data = getData(offset, length);
        if (data.size() % 2 != 0) {
            data.push_back('\0');
        }

        std::wstring_convert<std::codecvt_utf16<wchar_t, 0x10ffff, std::little_endian>, wchar_t> conv;
        std::wstring result;

        try {
            result = conv.from_bytes(reinterpret_cast<const char*>(&data[0]), reinterpret_cast<const char*>(&data[0] + data.size()));
        }
        catch (std::exception& e)
        {
            return L"Error: Failed to convert string";
        }

        std::size_t firstNull = result.find_first_of(L'\0');
        if (firstNull != std::string::npos) {
            result.erase(firstNull, result.size());
        }
        return result;
    }

    ByteBuffer::ByteArray RegistryByteBuffer::getData() const {
        return getData(0, _byteBuffer->limit());
    }

    ByteBuffer::ByteArray RegistryByteBuffer::getData(const uint32_t offset, const uint32_t length) const {
        uint32_t savedPosition = _byteBuffer->position();
        _byteBuffer->position(offset);
        ByteBuffer::ByteArray data;
        data.resize(length);
        _byteBuffer->get(data, 0, length);
        _byteBuffer->position(savedPosition);
        return data;
    }

    std::vector<std::wstring> RegistryByteBuffer::getStringList() const {
        return getStringList(0, _byteBuffer->limit());
    }

    std::vector<std::wstring> RegistryByteBuffer::getStringList(const uint32_t offset, const uint32_t length) const {
        std::vector<std::wstring> stringList;
        ByteBuffer::ByteArray data = getData(offset, length);

        uint32_t i = 0;
        uint32_t pos = 0;

        while (i < data.size()) {
            if (data[i] == '\0' && data[++i] == '\0') {
                stringList.push_back(std::wstring((wchar_t*)&data[pos]));
                pos = i;
                while (i < data.size() && data[i] == '\0') {
                    pos++; i++;
                }
            }
            else {
                i++;
            }
        }

        return stringList;
    }
};
