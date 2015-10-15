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
 * \file Buffer.cpp
 *
 */
#include <stdexcept>

#include "Buffer.h"

namespace Rejistry {

        Buffer&  Buffer::limit(const uint32_t newLimit) {
            if (newLimit > _capacity) {
                throw std::invalid_argument("Buffer limit greater than capacity");
            }
            _limit = newLimit;
            return *this;
        }

        Buffer& Buffer::position(const uint32_t newPosition) {
            if (newPosition > _limit) {
                throw std::invalid_argument("Buffer position greater than limit");
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
