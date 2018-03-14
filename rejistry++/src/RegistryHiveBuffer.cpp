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
 * \file RegistryHiveBuffer.cpp
 *
 */

// Local includes
#include "RegistryHiveBuffer.h"

namespace Rejistry {

    /**
    * Makes a copy of the passed in buffer.
    * @throws RegistryParseException if memory can't be allocated
    */
    RegistryHiveBuffer::RegistryHiveBuffer(const uint8_t * buffer, const uint32_t size) {
        _buffer = new RegistryByteBuffer(new ByteBuffer(buffer, size));
    }

    RegistryHiveBuffer::~RegistryHiveBuffer() {
        if (_buffer != NULL) {
            delete _buffer;
            _buffer = NULL;
        }
    }

    RegistryKey * RegistryHiveBuffer::getRoot() const {
        return new RegistryKey(getHeader()->getRootNKRecord());
    }

    REGFHeader * RegistryHiveBuffer::getHeader() const {
        return new REGFHeader(*_buffer, 0x0);
    }
};
