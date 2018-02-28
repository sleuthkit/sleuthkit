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
 * \file BinaryBlock.cpp
 *
 */

// Local includes
#include "BinaryBlock.h"

namespace Rejistry {

    /**
    * @returns 0 if offset is too large.
    */
    uint16_t BinaryBlock::getWord(uint32_t offset) const {
        return _buf->getWord(_offset + offset);
    }

    /**
    * @returns 0 if offset is too large.
    */
    uint32_t BinaryBlock::getDWord(uint32_t offset) const {
        return _buf->getDWord(_offset + offset);
    }

    /**
    * @returns 0 if offset is too large.
    */
    uint64_t BinaryBlock::getQWord(uint32_t offset) const {
        return _buf->getQWord(_offset + offset);
    }

    /**
     * Throws exception if offset or length is too large.
     */
    std::string BinaryBlock::getASCIIString(uint32_t offset, uint32_t length) const {
        return _buf->getASCIIString(_offset + offset, length);
    }

    std::wstring BinaryBlock::getUTF16String(uint32_t offset, uint32_t length) const {
        return _buf->getUTF16String(_offset + offset, length);
    }

    uint32_t BinaryBlock::getAbsoluteOffset(uint32_t offset) const {
        return _offset + offset;
    }

    ByteBuffer::ByteArray BinaryBlock::getData(uint32_t offset, uint32_t length) const {
        return _buf->getData(_offset + offset, length);
    }
};
