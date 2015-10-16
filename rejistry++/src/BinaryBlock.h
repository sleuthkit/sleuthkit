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
 * \file BinaryBlock.h
 *
 */
#ifndef _REJISTRY_BINARYBLOCK_H
#define _REJISTRY_BINARYBLOCK_H

#include <cstdint>

// Local includes
#include "RegistryByteBuffer.h"

namespace Rejistry {

    /**
     *
     */
    class BinaryBlock {
    public:
        BinaryBlock(RegistryByteBuffer& buf, uint32_t offset) {
            _buf = &buf;
            _offset = offset;
        }

    private:

    protected:
        BinaryBlock() {};

        RegistryByteBuffer * _buf;
        uint32_t _offset;

        uint16_t getWord(uint32_t offset) const;

        uint32_t getDWord(uint32_t offset) const;

        uint64_t getQWord(uint32_t offset) const;
        
        std::string getASCIIString(uint32_t offset, uint32_t length) const;

        std::wstring getUTF16String(uint32_t offset, uint32_t length) const;

        uint32_t getAbsoluteOffset(uint32_t offset) const;

        ByteBuffer::ByteArray getData(uint32_t offset, uint32_t length) const;
    };
};

#endif
