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
 * \file ByteBuffer.h
 *
 */
#ifndef _REJISTRY_BYTEBUFFER_H
#define _REJISTRY_BYTEBUFFER_H

#include <cstdint>
#include <vector>

// Local includes
#include "Buffer.h"

namespace Rejistry {

    /**
     *
     */
    class ByteBuffer : public Buffer {
    public:
        typedef std::vector<uint8_t> ByteArray;

        ByteBuffer(const uint32_t capacity);
        ByteBuffer(const uint8_t * buf, const uint32_t length);
        ByteBuffer(const ByteArray& buf, const uint32_t length);
        virtual ~ByteBuffer() { _buffer.clear(); }

        /// Get one byte from the current position in the buffer.
        uint8_t get(uint32_t offset) const;

        /**
         * Copy 'length' bytes from this buffer into the given destination,
         * starting at the current position in this buffer and at the given
         * offset in the destination. The position of this buffer is incremented
         * by length.
         * @param dst The destination into which to copy bytes.
         * @param offset The offset within the destination buffer to copy bytes to.
         * @param length The number of bytes to copy from this buffer.
         * @throws RegistryParseException
         */
        void get(ByteArray& dst, const uint32_t offset, const uint32_t length);

        /// Get two bytes from the current position in the buffer.
        uint16_t getShort(uint32_t offset) const;
        /// Get four bytes from the current position in the buffer.
        uint32_t getInt(uint32_t offset) const;
        /// Get eight bytes from the current position in the buffer.
        uint64_t getLong(uint32_t offset) const;

    private:
        ByteBuffer() {}
        ByteArray _buffer;

        void initializeBuffer(const uint8_t * buf, const uint32_t length);

        template <typename T> T read() const {
            T bytes = read<T>(_position);
            if (bytes != NULL) {
                _position += sizeof(T);
            }
            return bytes;
        }

        template <typename T> T read(uint32_t offset) const {
            if (offset + sizeof(T) <= _limit) {
                return *((T*)&_buffer[offset]);
            }
            return NULL;
        }
    };
};

#endif
