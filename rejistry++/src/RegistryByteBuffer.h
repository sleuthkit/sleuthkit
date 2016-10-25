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
 * \file RegistryByteBuffer.h
 *
 */
#ifndef _REJISTRY_REGISTRYBYTEBUFFER_H
#define _REJISTRY_REGISTRYBYTEBUFFER_H

#include <cstdint>

// Local includes
#include "ByteBuffer.h"

namespace Rejistry {

    /**
     *
     */
    class RegistryByteBuffer {
    public:
        RegistryByteBuffer(ByteBuffer * buffer);
        virtual ~RegistryByteBuffer();

        uint16_t getWord(const uint32_t offset) const;

        uint32_t getDWord(const uint32_t offset) const;

        uint64_t getQWord(const uint32_t offset) const;

        std::string getASCIIString() const;
        std::string getASCIIString(const uint32_t offset, const uint32_t length) const;

        std::wstring getUTF16String() const;
        std::wstring getUTF16String(const uint32_t offset, const uint32_t length) const;

        ByteBuffer::ByteArray getData() const;
        ByteBuffer::ByteArray getData(const uint32_t offset, const uint32_t length) const;

        std::vector<std::wstring> getStringList() const;
        std::vector<std::wstring> getStringList(const uint32_t offset, const uint32_t length) const;

    private:
        RegistryByteBuffer();
        RegistryByteBuffer(const RegistryByteBuffer &);
        RegistryByteBuffer& operator=(const RegistryByteBuffer &);

        ByteBuffer * _byteBuffer;

    };
};

#endif
