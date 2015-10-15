/*
 *
 *  The Sleuth Kit
 *
 *  Contact: Brian Carrier [carrier <at> sleuthkit [dot] org]
 *  Copyright (c) 2010-2015 Basis Technology Corporation. All Rights
 *  reserved.
 *
 *  This software is distributed under the Common Public License 1.0
 *
 *  This is a C++ port of the Rejistry library developed by Willi Ballenthin.
 *  See https://github.com/williballenthin/Rejistry for the original Java version.
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

        ByteBuffer::ByteBuffer(const uint8_t * buf, const uint32_t length) : Buffer(length) {
            initializeBuffer(buf, length);
        }

        ByteBuffer::ByteBuffer(const ByteArray& buf, const uint32_t length) : Buffer(length) {
            initializeBuffer(&buf[0], length);
        }

        void ByteBuffer::initializeBuffer(const uint8_t * buf, const uint32_t length) {
            _buffer.resize(length);
            if (buf != NULL) {
                memcpy(&_buffer[0], buf, length);
            }
        }

        uint8_t ByteBuffer::get(uint32_t offset) const {
            return read<uint8_t>(offset);
        }

        void ByteBuffer::get(ByteArray& dst, const uint32_t offset, const uint32_t length) {
            if (offset > dst.size()) {
                throw RegistryParseException("Offset is greater than destination buffer size.");
            }

            if ((dst.size() - offset) > length) {
                throw RegistryParseException("Length is greater than available space in destination buffer.");
            }

            memcpy(&dst[0], &_buffer[_position + offset], length);
            _position += offset;
        }

        uint16_t ByteBuffer::getShort(uint32_t offset) const {
            return read<uint16_t>(offset);
        }

        uint32_t ByteBuffer::getInt(uint32_t offset) const {
            return read<uint32_t>(offset);
        }

        uint64_t ByteBuffer::getLong(uint32_t offset) const {
            return read<uint64_t>(offset);
        }

};
