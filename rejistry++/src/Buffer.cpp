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
 * \file Buffer.cpp
 *
 */
#include <stdexcept>

#include "Buffer.h"
#include "RejistryException.h"

namespace Rejistry {

        Buffer&  Buffer::limit(const uint32_t newLimit) {
            if (newLimit > _capacity) {
                throw RegistryParseException("Buffer limit greater than capacity");
            }
            _limit = newLimit;
            return *this;
        }

        /**
         * Throws exception if position is too large. 
         */
        Buffer& Buffer::position(const uint32_t newPosition) {
            if (newPosition > _limit) {
                throw RegistryParseException("Buffer position greater than limit");
            }
            _position = newPosition;
            return *this;
        }

        Buffer::Buffer(const uint32_t capacity) {
            _capacity = capacity;
            _limit = capacity;
            _position = 0L;
        }

        Buffer::Buffer(const Buffer& buffer) {
            _capacity = buffer._capacity;
            _limit = buffer._limit;
            _position = buffer._position;
        }

        Buffer::~Buffer() {}

};
