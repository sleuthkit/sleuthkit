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
 * \file Buffer.h
 *
 */
#ifndef _REJISTRY_BUFFER_H
#define _REJISTRY_BUFFER_H

#include <cstdint>

namespace Rejistry {

    /**
     *
     */
    class Buffer {
    public:
        uint32_t capacity() const { return _capacity; }
        uint32_t limit() const { return _limit; }
        Buffer & limit(const uint32_t newLimit);
        uint32_t position() const { return _position; }
        Buffer & position(const uint32_t newPosition);

    protected:
        Buffer() {}
        Buffer(const uint32_t capacity);
        Buffer(const Buffer& );
        Buffer& operator=(const Buffer& );

        virtual ~Buffer();

        uint32_t _capacity;
        uint32_t _limit;
        uint32_t _position;
    };
};

#endif
