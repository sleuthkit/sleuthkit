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
 * \file ByteBuffer.cpp
 *
 */

// Local includes
#include "ByteBuffer.h"
#include "RejistryException.h"

namespace Rejistry {

        ByteBuffer::ByteBuffer(const uint32_t capacity) : Buffer(capacity) {
            _buffer.resize(capacity);
        }

        /**
         * Makes a copy of the passed in buffer.
         * @throws RegistryParseException if memory can't be allocated
         */
        ByteBuffer::ByteBuffer(const uint8_t * buf, const uint32_t length) : Buffer(length) {
            initializeBuffer(buf, length);
        }

        /**
        * Makes a copy of the passed in buffer.
        * @throws RegistryParseException if memory can't be allocated
        */
        ByteBuffer::ByteBuffer(const ByteArray& buf, const uint32_t length) : Buffer(length) {
            if (buf.size() > 0) {
                initializeBuffer(&buf[0], length);
            }
        }

        void ByteBuffer::initializeBuffer(const uint8_t * buf, const uint32_t length) {
            try {
                _buffer.resize(length);
            } 
            catch (std::bad_alloc &e)
            {
                throw RegistryParseException("Cannot allocate memory for registry byte buffer.");
            }

            if (buf != NULL) {
                memcpy(&_buffer[0], buf, length);
            }
        }

        uint8_t ByteBuffer::get(uint32_t offset) const {
            return read<uint8_t>(offset);
        }

        /**
         * Throws exception if offset or length are too large. */
        void ByteBuffer::get(ByteArray& dst, const uint32_t offset, const uint32_t length) {
            if (length == 0) {
                // No data requested.
                return;
            }

            if (offset > dst.size()) {
                throw RegistryParseException("Offset is greater than destination buffer size.");
            }

            if ((dst.size() - offset) > length) {
                throw RegistryParseException("Length is greater than available space in destination buffer.");
            }

            if ((_position + offset) > _limit) {
                throw RegistryParseException("Starting position is beyond end of buffer.");
            }

            if ((_position + offset + length) > _limit) {
                throw RegistryParseException("Number of requested bytes exceeds buffer size.");
            }

            memcpy(&dst[0], &_buffer[_position + offset], length);
            _position += offset;
        }

        /**
         * @returns 0 if offset is too large.
         */
        uint16_t ByteBuffer::getShort(uint32_t offset) const {
            return read<uint16_t>(offset);
        }

        /**
        * @returns 0 if offset is too large.
        */
        uint32_t ByteBuffer::getInt(uint32_t offset) const {
            return read<uint32_t>(offset);
        }

        /**
        * @returns 0 if offset is too large.
        */
        uint64_t ByteBuffer::getLong(uint32_t offset) const {
            return read<uint64_t>(offset);
        }
};
