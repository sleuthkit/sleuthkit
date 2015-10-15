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
